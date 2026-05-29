import * as nodeCrypto from "node:crypto";
import * as fsSync    from "node:fs";
import { toHex }      from "viem";

import {
  generateDocumentKey,
  encryptDocument,
  serializeEncryptedDocument,
  splitSecret,
  computeThreshold,
  encryptShare,
  encryptDocumentKey,
  encryptChallenge,
} from "./crypto.js";

import { addFile, getFile, pin, unpin } from "../ipfs/helia-node.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AuthorityEntry {
  address: `0x${string}`;
  pub: string; // RSA public key PEM
}

export interface ExternalVerifyResult {
  canPresent: boolean;
  cMeta:      string; // hex-encoded RSA-OAEP encrypted metadata
  hMeta:      string; // hex SHA-256 of plaintext metadata
  didDocA:    any;
  didDocU:    any;
  pkU:        string; // PEM
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function writeReport(lines: string[]): void {
  try { fsSync.writeFileSync("report.md", lines.join("\n")); } catch {}
}

function banner(title: string, fields: [string, string][]): void {
  const SEP = "═".repeat(66);
  console.log(`\n╔${SEP}`);
  console.log(`║  ${title}`);
  for (const [k, v] of fields) console.log(`║    ${k.padEnd(16)} ${v}`);
  console.log(`╚${SEP}\n`);
}

// ── Archival Workflow ─────────────────────────────────────────────────────────

/**
 * Simulates the Oracle OUTBOUND workflow triggered by DocumentCertified.
 * Performs real Helia storage and real on-chain storeShares / storeCID.
 */
export async function runArchivalWorkflow(
  documentHash:       `0x${string}`,
  document:           Buffer,
  blockNumber:        bigint,
  certifiedBy:        `0x${string}`,
  timestamp:          bigint,
  certifyingAuthPriv: string,       // sk_A PEM
  certifyingAuthPub:  string,       // pk_A PEM
  allAuthorities:     AuthorityEntry[],
  contracts:          any,           // viem contracts signed as certifying authority
  reportLines:        string[]
): Promise<void> {
  const N = allAuthorities.length;
  const t = computeThreshold(N);

  banner("[ORACLE] Event detected: DocumentCertified", [
    ["documentHash:", documentHash],
    ["certifiedBy:",  certifiedBy],
    ["timestamp:",    String(timestamp)],
    ["Block:",        String(blockNumber)],
  ]);

  // ── Phase 1 ──────────────────────────────────────────────────────────────
  console.log("  Phase 1: k_doc random 32B; c = AES-256-GCM(k_doc, document)...");
  const kDoc   = generateDocumentKey();
  const encDoc = encryptDocument(document, kDoc);
  const blob   = serializeEncryptedDocument(encDoc);
  console.log(`  ✓ Phase 1: ciphertext ${blob.length} bytes`);

  // ── Phase 2 ──────────────────────────────────────────────────────────────
  console.log("  Phase 2: addFile(c) → CID; pin(CID)...");
  const cid = await addFile(blob);
  pin(cid);
  console.log(`  ✓ Phase 2: CID ${cid}  pin ✓`);

  // ── Phase 3 ──────────────────────────────────────────────────────────────
  console.log(`  Phase 3: SSS split k_doc → ${N} shares (t=${t}); Enc(pk_i, share_i); E_A = Enc(pk_A, k_doc)...`);
  const shares     = splitSecret(kDoc, N);
  const encShares  = shares.map((s: Buffer, i: number) => encryptShare(s, allAuthorities[i].pub));
  const eA         = encryptDocumentKey(kDoc, certifyingAuthPub);
  kDoc.fill(0);
  console.log(`  ✓ Phase 3: ${N} shares encrypted; E_A ready; k_doc.fill(0) ✓`);

  // ── Phase 4 ──────────────────────────────────────────────────────────────
  console.log("  Phase 4: KeyShareRegistry.storeShares(...) tx + DocumentRegistry.storeCID(...) tx...");
  const authAddresses  = allAuthorities.map(a => a.address);
  const shareIndices   = allAuthorities.map((_, i) => BigInt(i + 1));
  const encSharesHex   = encShares.map((s: Buffer) => toHex(s) as `0x${string}`);
  const eAHex          = toHex(eA) as `0x${string}`;

  const txShares = await contracts.keyShareRegistry.write.storeShares([
    documentHash,
    authAddresses,
    shareIndices,
    encSharesHex,
    BigInt(t),
    eAHex,
  ]);
  console.log(`  ✓ Phase 4a: SharesStored  tx: ${txShares}`);

  const txCID = await contracts.documentRegistry.write.storeCID([documentHash, cid]);
  console.log(`  ✓ Phase 4b: CIDStored     tx: ${txCID}`);

  reportLines.push(
    `## [ORACLE] Archival Workflow — DocumentCertified`,
    `- documentHash: ${documentHash}`,
    `- block: ${blockNumber}`,
    `- CID: ${cid}`,
    `- pinned: true`,
    `- shares: ${N}  threshold: ${t}`,
    `- txSharesStored: ${txShares}`,
    `- txCIDStored: ${txCID}`,
    ``
  );
  writeReport(reportLines);
}

// ── Revocation Workflow ───────────────────────────────────────────────────────

/**
 * Simulates the Oracle OUTBOUND workflow triggered by DocumentRevoked.
 * Unpins the CID from the local Helia store.
 */
export async function runRevocationWorkflow(
  documentHash: `0x${string}`,
  reason:       string,
  blockNumber:  bigint,
  timestamp:    bigint,
  contracts:    any,
  reportLines:  string[]
): Promise<void> {
  banner("[ORACLE] Event detected: DocumentRevoked", [
    ["documentHash:", documentHash],
    ["reason:",       reason],
    ["timestamp:",    String(timestamp)],
    ["Block:",        String(blockNumber)],
  ]);

  let cid = "";
  try {
    cid = await contracts.documentRegistry.read.getCID([documentHash]) as string;
  } catch { /* not yet archived */ }

  if (cid && cid.length > 0) {
    unpin(cid);
    console.log(`  ✓ Phase 4: unpin(${cid}) — ciphertext no longer served`);
  } else {
    console.log(`  Phase 4: no CID on-chain (document was not archived)`);
  }
  console.log(`  Note: shares remain on-chain but checkAndApproveRead will revert (REVOKED)`);

  reportLines.push(
    `## [ORACLE] Revocation Workflow — DocumentRevoked`,
    `- documentHash: ${documentHash}`,
    `- reason: ${reason}`,
    `- block: ${blockNumber}`,
    `- CID unpinned: ${cid || "N/A"}`,
    ``
  );
  writeReport(reportLines);
}

// ── External Verification (Oracle INBOUND) ────────────────────────────────────

/**
 * Simulates the Oracle INBOUND handler for external verifier queries.
 * Phases 3-5 of WP2 External Verification.
 */
export async function runExternalVerification(
  didA:         string,
  documentHash: `0x${string}`,
  didU:         string,
  contracts:    any,
  reportLines:  string[]
): Promise<ExternalVerifyResult> {
  banner("[ORACLE INBOUND] External Verifier query received", [
    ["did_A:", didA],
    ["h:",     documentHash],
    ["did_U:", didU],
  ]);

  // ── Phase 3 ──────────────────────────────────────────────────────────────
  console.log("  Phase 3: resolve(did_A); canPresentExternally(addr_U, h); getMetadata(h)...");
  const didDocA    = await contracts.didRegistry.read.resolve([didA])  as any;
  const didDocU    = await contracts.didRegistry.read.resolve([didU])  as any;
  const canPresent = await contracts.accessControl.read.canPresentExternally([didU, documentHash]) as boolean;
  console.log(`  ✓ Phase 3: canPresentExternally(${didU}, h) → ${canPresent}`);

  if (!canPresent) {
    console.log("  ✗ Oracle: canPresentExternally = false — aborting");
    return { canPresent: false, cMeta: "", hMeta: "", didDocA, didDocU, pkU: "" };
  }

  const record = await contracts.documentRegistry.read.getRecord([documentHash]) as any;
  const statuses = ["Pending", "Certified", "Revoked"];

  // ── Phase 4 ──────────────────────────────────────────────────────────────
  console.log("  Phase 4: c_meta = RSA-OAEP(pk_U, metadata+timestamp); H(metadata)...");
  const pkU = didDocU.activePublicKey as string;
  const meta = Buffer.from(JSON.stringify({
    documentHash,
    status:      statuses[Number(record.status)] ?? String(record.status),
    ownerDID:    record.ownerDID,
    certifiedBy: record.certifiedBy,
    certifiedAt: record.certifiedAt.toString(),
    ts:          Date.now(),
  }));

  const cMeta = encryptChallenge(meta, pkU);
  const hMeta = nodeCrypto.createHash("sha256").update(meta).digest("hex");
  console.log(`  ✓ Phase 4: c_meta = Enc(pk_U, metadata)  H(metadata) = ${hMeta.slice(0, 16)}...`);

  // ── Phase 5 ──────────────────────────────────────────────────────────────
  console.log("  Phase 5: return (c_meta, H(metadata), DIDDoc_A, DIDDoc_U)");
  console.log("  Note: Constant-time/structure response (anti side-channel) — structure identical regardless of outcome");

  reportLines.push(
    `## [ORACLE INBOUND] External Verification`,
    `- did_A: ${didA}`,
    `- did_U: ${didU}`,
    `- documentHash: ${documentHash}`,
    `- canPresentExternally: ${canPresent}`,
    `- H(metadata): ${hMeta}`,
    ``
  );
  writeReport(reportLines);

  return { canPresent, cMeta, hMeta, didDocA, didDocU, pkU };
}

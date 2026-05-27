import type { ContractClients } from "./contracts.js";
import type { HeliaNode } from "./ipfs.js";
import {
  generateDocumentKey,
  encryptDocument,
  encryptDocumentKey,
  serializeEncryptedDocument,
  splitSecret,
  encryptShare,
  computeThreshold,
} from "./crypto.js";
import {
  getAuthorities,
  getActivePublicKey,
  storeCID,
  storeShares,
  getRecord,
} from "./contracts.js";
import { uploadFile, unpinFile } from "./ipfs.js";
import { toHex } from "viem";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface OracleConfig {
  contracts:        ContractClients;
  helia:            HeliaNode;
  authorityAddress: `0x${string}`;
  privateKeyPem:    string;
  publicKeyPem:     string;
  pendingDocuments: Map<string, Buffer>; // shared with server.ts
}

// ── Certification event listener ──────────────────────────────────────────────

/**
 * Listen for DocumentCertified events emitted by DocumentRegistry.
 * Upon detection, retrieve the document from pendingDocuments and
 * trigger the archival workflow.
 *
 * WP2 §Archival:
 * "The CertificationEvent emitted by DocumentRegistry is detected by
 *  Authority node acting as part of the Collective Oracle, which
 *  independently initiates the archival procedure."
 *
 * The document raw content is held temporarily in pendingDocuments
 * by server.ts after POST /document/certify — the oracle reads it
 * here and deletes it after successful archival.
 */
export function listenCertificationEvents(
  config:   OracleConfig,
  onError?: (err: unknown) => void
): () => void {
  const { contracts } = config;

  const unwatch = contracts.publicClient.watchContractEvent({
    address:   contracts.addresses.documentRegistry,
    abi:       contracts.documentRegistry.abi as any,
    eventName: "DocumentCertified",
    onLogs: async (logs) => {
      for (const log of logs) {
        const { documentHash } = log.args as any;
        if (!documentHash) continue;

        try {
          const record = await getRecord(contracts, documentHash);

          // Only process documents certified by this authority
          if (record.certifiedBy.toLowerCase() !== config.authorityAddress.toLowerCase()) continue;

          // Retrieve document from pending store
          const document = config.pendingDocuments.get(documentHash);
          if (!document) {
            console.warn(`[Oracle] No pending document for ${documentHash} — archival skipped`);
            continue;
          }

          await runArchivalWorkflow(documentHash, config, document);
          config.pendingDocuments.delete(documentHash);

        } catch (err) {
          onError?.(err);
        }
      }
    },
  });

  return unwatch;
}

// ── Revocation event listener ─────────────────────────────────────────────────

/**
 * Listen for DocumentRevoked events emitted by DocumentRegistry.
 * Upon detection, unpin the ciphertext from the local IPFS node.
 *
 * WP2 §Revocation Phase 4:
 * "Authority A's pinning service, acting as an outbound oracle on the
 *  REVOKED event, unpins the ciphertext from its local IPFS node."
 */
export function listenRevocationEvents(
  config:   OracleConfig,
  onError?: (err: unknown) => void
): () => void {
  const { contracts } = config;

  const unwatch = contracts.publicClient.watchContractEvent({
    address:   contracts.addresses.documentRegistry,
    abi:       contracts.documentRegistry.abi as any,
    eventName: "DocumentRevoked",
    onLogs: async (logs) => {
      for (const log of logs) {
        const { documentHash } = log.args as any;
        if (!documentHash) continue;

        try {
          const record = await getRecord(contracts, documentHash);

          // Only unpin documents certified by this authority
          if (record.certifiedBy.toLowerCase() !== config.authorityAddress.toLowerCase()) continue;
          if (!record.cid || record.cid.length === 0) continue;

          await unpinFile(config.helia, record.cid);
          console.log(`[Oracle] Unpinned ${record.cid} for revoked document ${documentHash}`);

        } catch (err) {
          onError?.(err);
        }
      }
    },
  });

  return unwatch;
}

// ── Archival workflow ─────────────────────────────────────────────────────────

/**
 * Execute the complete archival workflow for a certified document.
 * Triggered by listenCertificationEvents.
 *
 * WP2 §Archival Phases 1-4:
 *   Phase 1 — Encrypt document with fresh k_doc (AES-256-GCM)
 *   Phase 2 — Upload ciphertext to IPFS and pin locally
 *   Phase 3 — Split k_doc with SSS, encrypt each share with pk_i,
 *              encrypt k_doc with pk_A as E_A, destroy k_doc
 *   Phase 4 — Store shares, E_A, and CID on-chain
 *
 * @param documentHash  H(document) from the CertificationEvent
 * @param config        Oracle configuration
 * @param document      Raw document content from pendingDocuments
 */
export async function runArchivalWorkflow(
  documentHash: `0x${string}`,
  config:       OracleConfig,
  document:     Buffer
): Promise<void> {
  const { contracts, helia, privateKeyPem, publicKeyPem } = config;

  // Phase 1 — Generate k_doc and encrypt document
  const k_doc     = generateDocumentKey();
  const encrypted = encryptDocument(document, k_doc);
  const blob      = serializeEncryptedDocument(encrypted);

  // Phase 2 — Upload ciphertext to IPFS and pin locally
  const cid = await uploadFile(helia, blob);
  console.log(`[Oracle] Uploaded ${documentHash} to IPFS: ${cid}`);

  // Phase 3 — Key splitting and share encryption
  const authorities = await getAuthorities(contracts);
  const total       = authorities.length;
  const threshold   = BigInt(computeThreshold(total));
  const shares      = splitSecret(k_doc, total);

  const authorityAddresses: `0x${string}`[] = [];
  const shareIndices:        bigint[]        = [];
  const encryptedShares:     `0x${string}`[] = [];

  for (let i = 0; i < total; i++) {
    const authorityDID = await contracts.didRegistry.read.lookupDID(
      [authorities[i]]
    ) as string;
    const pk_i = await getActivePublicKey(contracts, authorityDID);
    const E_i  = encryptShare(shares[i], pk_i);

    authorityAddresses.push(authorities[i]);
    shareIndices.push(BigInt(i + 1));
    encryptedShares.push(toHex(E_i) as `0x${string}`);
  }

  // Encrypt k_doc with pk_A → E_A
  const E_A = encryptDocumentKey(k_doc, publicKeyPem);

  // Destroy k_doc from memory
  k_doc.fill(0);

  // Phase 4 — Store shares, E_A, and CID on-chain
  await storeShares(
    contracts,
    documentHash,
    authorityAddresses,
    shareIndices,
    encryptedShares,
    threshold,
    toHex(E_A) as `0x${string}`
  );

  await storeCID(contracts, documentHash, cid);
  console.log(`[Oracle] Archival complete for ${documentHash}`);
}
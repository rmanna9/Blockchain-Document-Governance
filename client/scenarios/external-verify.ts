import { keccak256, toHex } from "viem";
import { createHash } from "node:crypto";
import {
  initClientContracts,
  requestCertification,
  checkAndApproveRead,
  resolveDID,
  getActivePublicKey,
  getRecord,
} from "../src/contracts.js";
import { certifyDocument, retrieveDocument } from "../src/api.js";
import { verifyAuthoritySignature, decryptChallenge } from "../src/crypto.js";

/**
 * External Verification scenario.
 * WP2 §External Verification
 *
 * Phase 1  — User presents (document, σ_A, did_A, did_U) to External Verifier
 * Phase 2  — External Verifier computes h = H(document) locally
 * Phase 3  — External Verifier queries Oracle with (did_A, h, did_U)
 * Phase 4  — Oracle resolves did_A, checks ReadApproved for (address, h)
 * Phase 5  — Oracle encrypts metadata with pk_U as c_meta
 * Phase 6  — Oracle returns (c_meta, H(metadata), DIDDoc_A, DIDDoc_U)
 * Phase 7  — External Verifier verifies σ_A against pk_A and h
 * Phase 8  — External Verifier challenges User with c_meta
 *            User decrypts with sk_U and returns plaintext
 *            External Verifier verifies H(metadata)
 */
async function main() {
  const RPC_URL       = process.env.RPC_URL       ?? "http://localhost:8545";
  const ADDRESSES     = process.env.ADDRESSES     ?? "scripts/addresses.json";
  const AUTHORITY_URL = process.env.AUTHORITY_URL ?? "http://localhost:3001";
  const ORACLE_URL    = process.env.ORACLE_URL    ?? "http://localhost:3001";

  const USER_PRIVATE_KEY = process.env.USER_PRIVATE_KEY ?? "";
  const USER_DID         = process.env.USER_DID         ?? "";
  const USER_PK_PEM      = process.env.USER_PK_PEM      ?? "";
  const AUTHORITY_DID    = process.env.AUTHORITY_DID    ?? "";

  if (!USER_PRIVATE_KEY || !USER_DID || !USER_PK_PEM || !AUTHORITY_DID) {
    console.error("Missing required environment variables");
    process.exit(1);
  }

  const contracts = initClientContracts(RPC_URL, USER_PRIVATE_KEY, ADDRESSES);

  // Certify a document first
  const document     = Buffer.from("Document for external verification scenario.");
  const documentHash = keccak256(new Uint8Array(document)) as `0x${string}`;
  const zero         = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;

  console.log("[Setup] Certifying document...");
  await requestCertification(contracts, documentHash, zero, USER_DID);
  const { signature: sigHex } = await certifyDocument(
    AUTHORITY_URL,
    { did: USER_DID, privateKeyPem: USER_PK_PEM },
    documentHash,
    document
  );
  await new Promise(r => setTimeout(r, 3000));
  console.log("[Setup] Document certified");

  // ── External Verification ─────────────────────────────────────────────────

  // Phase 1 — User presents (document, σ_A, did_A, did_U)
  // WP2: "The User transmits to the External Verifier the tuple
  //       (document, σ_A, did_A, did_U)"
  console.log("\n[Phase 1] User presents document to External Verifier");
  const presentation = { document, sigAuthority: sigHex, didAuthority: AUTHORITY_DID, didUser: USER_DID };

  // Phase 2 — External Verifier computes h = H(document) locally
  // WP2 note: External Verifier does not receive hash from User —
  // computes it independently. Verifying σ_A against h proves both
  // authenticity and integrity in Phase 7.
  console.log("[Phase 2] External Verifier computing H(document)...");
  const h = keccak256(new Uint8Array(presentation.document));
  console.log(`[Phase 2] h = ${h}`);

  // Phase 3 — External Verifier queries Oracle
  // WP2: "The External Verifier submits (did_A, h, did_U) to the Oracle"
  console.log("[Phase 3] Querying Oracle...");
  const oracleRes = await fetch(`${ORACLE_URL}/oracle/verify`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      didAuthority: presentation.didAuthority,
      documentHash: h,
      didUser:      presentation.didUser,
    }),
  });

  if (!oracleRes.ok) {
    console.error("[Phase 3] Oracle query failed");
    process.exit(1);
  }

  // Phase 6 — Oracle returns (c_meta, H(metadata), DIDDoc_A, DIDDoc_U)
  const {
    encryptedMetadata,
    metadataHash,
    didDocumentAuthority,
    didDocumentUser,
  } = await oracleRes.json() as {
    encryptedMetadata:    string;
    metadataHash:         string;
    didDocumentAuthority: any;
    didDocumentUser:      any;
  };
  console.log("[Phase 6] Oracle response received");

  // Phase 7 — Verify σ_A against pk_A and h
  // WP2: "The External Verifier extracts pk_A from DIDDocument_A and
  //       verifies σ_A = Sign(sk_A, h) against pk_A and h.
  //       This confirms that the document was certified by an Authority
  //       belonging to the consortium and that the hash has not been
  //       tampered with."
  console.log("[Phase 7] Verifying authority signature σ_A...");
  const pk_A = didDocumentAuthority.activePublicKey as string;
  const sigValid = verifyAuthoritySignature(h, presentation.sigAuthority, pk_A);

  if (!sigValid) {
    console.error("[Phase 7] ✗ Invalid authority signature — document not certified");
    process.exit(1);
  }
  console.log("[Phase 7] ✓ Authority signature valid");

  // Phase 8 — Challenge-response for proof of possession
  // WP2: "The External Verifier forwards c_meta to the User as a challenge.
  //       The User decrypts it as metadata = Dec(sk_U, c_meta) and returns
  //       the plaintext. The External Verifier recomputes H(metadata) and
  //       verifies that it matches the value received from the Oracle."
  console.log("[Phase 8] Challenging User with c_meta...");
  const metadata  = decryptChallenge(encryptedMetadata, USER_PK_PEM);
  const computedMetadataHash = createHash("sha256").update(metadata).digest("hex");

  if (computedMetadataHash !== metadataHash) {
    console.error("[Phase 8] ✗ Metadata hash mismatch — proof of possession failed");
    process.exit(1);
  }
  console.log("[Phase 8] ✓ Proof of possession verified");
  console.log("\n✓ External verification complete — document is authentic and valid");
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
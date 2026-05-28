import { keccak256, toBytes, toHex } from "viem";
import { initClientContracts, requestCertification, checkAndApproveRead } from "../src/contracts.js";
import { certifyDocument, retrieveDocument, checkHealth } from "../src/api.js";
import { readFileSync } from "fs";

/**
 * Full document lifecycle scenario.
 * WP2 §Certification + §Retrieval
 *
 * 1. User commits H(document) on-chain — requestCertification() Phase 1
 * 2. User sends document to Authority A — /document/certify Phase 2+3
 * 3. Oracle archives on IPFS — Archival Phase 1-4
 * 4. User approves read on-chain — checkAndApproveRead() Retrieval Phase 1
 * 5. User retrieves document — /document/retrieve Retrieval Phase 2-5
 * 6. Verify received document matches original
 */
async function main() {
  const RPC_URL       = process.env.RPC_URL       ?? "http://localhost:8545";
  const ADDRESSES     = process.env.ADDRESSES     ?? "scripts/addresses.json";
  const AUTHORITY_URL = process.env.AUTHORITY_URL ?? "http://localhost:3001";
  const PRIVATE_KEY   = process.env.PRIVATE_KEY   ?? "";
  const USER_DID      = process.env.USER_DID      ?? "";
  const USER_KEYS_DIR = process.env.USER_KEYS_DIR ?? "/data/user-keys";
  const USER_PK_PEM   = readFileSync(`${USER_KEYS_DIR}/private.pem`, "utf-8");

  if (!PRIVATE_KEY || !USER_DID) {
    console.error("Missing required environment variables");
    process.exit(1);
  }

  // Check authority is up
  const healthy = await checkHealth(AUTHORITY_URL);
  if (!healthy) {
    console.error(`Authority at ${AUTHORITY_URL} is not responding`);
    process.exit(1);
  }
  console.log(`[1/6] Authority ${AUTHORITY_URL} is healthy`);

  // Init contracts
  const contracts = initClientContracts(RPC_URL, PRIVATE_KEY, ADDRESSES);

  // Document content
  const document     = Buffer.from("This is a test document for the full lifecycle scenario.");
  const documentHash = keccak256(new Uint8Array(document)) as `0x${string}`;
  const zero         = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;

  console.log(`[2/6] Document hash: ${documentHash}`);

  // Phase 1 — Commit hash on-chain
  // WP2: "The User computes h_new = H(document) and invokes
  //       DocumentRegistry.requestCertification(h_new, null, ownerDID)"
  console.log("[3/6] Committing hash on-chain...");
  await requestCertification(contracts, documentHash, zero, USER_DID);
  console.log("[3/6] Hash committed — status: PENDING");

  // Phase 2+3 — Send document to authority for certification
  // WP2: "The User authenticates to Authority A and transmits the document.
  //       Authority A recomputes H(document) and certifies on-chain."
  console.log("[4/6] Sending document to authority for certification...");
  const { signature } = await certifyDocument(
    AUTHORITY_URL,
    { did: USER_DID, privateKeyPem: USER_PK_PEM },
    documentHash,
    document
  );
  console.log(`[4/6] Document certified — σ_A: ${signature.slice(0, 20)}...`);

  // Wait for oracle to archive (CID stored on-chain)
  console.log("[4/6] Waiting for archival...");
  await new Promise(r => setTimeout(r, 3000));

  // Retrieval Phase 1 — Approve read on-chain
  // WP2: "The User invokes DocumentAccessControl.checkAndApproveRead(h)
  //       — emits ReadApproved(user_address, h, timestamp)"
  console.log("[5/6] Approving read on-chain...");
  await checkAndApproveRead(contracts, documentHash);
  console.log("[5/6] ReadApproved event emitted");

  // Retrieval Phase 2-5 — Retrieve document from authority
  // WP2: "The User authenticates to Authority A.
  //       Authority retrieves ciphertext, decrypts k_doc from E_A,
  //       decrypts document and sends plaintext to User."
  console.log("[6/6] Retrieving document from authority...");
  const retrieved = await retrieveDocument(
    AUTHORITY_URL,
    { did: USER_DID, privateKeyPem: USER_PK_PEM },
    documentHash
  );

  // Verify integrity
  const retrievedHash = keccak256(new Uint8Array(retrieved));
  if (retrievedHash.toLowerCase() === documentHash.toLowerCase()) {
    console.log("[6/6] ✓ Document retrieved and verified — hash matches");
    console.log(`      Content: ${retrieved.toString()}`);
  } else {
    console.error("[6/6] ✗ Hash mismatch — document integrity violation");
    process.exit(1);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
import { keccak256, toBytes } from "viem";
import {
  initClientContracts,
  requestCertification,
  checkAndApproveRead,
  delegate,
  hasPermission,
} from "../src/contracts.js";
import { certifyDocument, retrieveDocument } from "../src/api.js";

/**
 * Delegation scenario.
 * WP2 §Permission and Delegation Model — RF7
 *
 * 1. User1 certifies a document
 * 2. User1 delegates canRead to User2
 * 3. User2 approves read on-chain
 * 4. User2 retrieves document via authority
 * 5. Verify User2 receives same document as User1
 */
async function main() {
  const RPC_URL       = process.env.RPC_URL       ?? "http://localhost:8545";
  const ADDRESSES     = process.env.ADDRESSES     ?? "scripts/addresses.json";
  const AUTHORITY_URL = process.env.AUTHORITY_URL ?? "http://localhost:3001";

  const USER1_PRIVATE_KEY = process.env.USER1_PRIVATE_KEY ?? "";
  const USER1_DID         = process.env.USER1_DID         ?? "";
  const USER1_PK_PEM      = process.env.USER1_PK_PEM      ?? "";

  const USER2_PRIVATE_KEY = process.env.USER2_PRIVATE_KEY ?? "";
  const USER2_DID         = process.env.USER2_DID         ?? "";
  const USER2_PK_PEM      = process.env.USER2_PK_PEM      ?? "";

  if (!USER1_PRIVATE_KEY || !USER1_DID || !USER1_PK_PEM ||
      !USER2_PRIVATE_KEY || !USER2_DID || !USER2_PK_PEM) {
    console.error("Missing required environment variables");
    process.exit(1);
  }

  // Init contracts for both users
  const contracts1 = initClientContracts(RPC_URL, USER1_PRIVATE_KEY, ADDRESSES);
  const contracts2 = initClientContracts(RPC_URL, USER2_PRIVATE_KEY, ADDRESSES);

  const document     = Buffer.from("Document for delegation scenario.");
  const documentHash = keccak256(new Uint8Array(document)) as `0x${string}`;
  const zero         = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;

  console.log(`[1/6] Document hash: ${documentHash}`);

  // Step 1 — User1 certifies document
  console.log("[2/6] User1 committing hash on-chain...");
  await requestCertification(contracts1, documentHash, zero, USER1_DID);

  console.log("[3/6] User1 sending document to authority...");
  await certifyDocument(
    AUTHORITY_URL,
    { did: USER1_DID, privateKeyPem: USER1_PK_PEM },
    documentHash,
    document
  );
  console.log("[3/6] Document certified");

  await new Promise(r => setTimeout(r, 3000));

  // Step 2 — User1 delegates canRead to User2
  // WP2 §Delegation Workflow:
  // "A User holding canRead with canDelegate=true may issue a derived
  //  delegation by invoking DocumentAccessControl.delegate()"
  console.log("[4/6] User1 delegating canRead to User2...");
  await delegate(
    contracts1,
    USER2_DID,
    documentHash,
    1,     // CanRead
    false, // canDelegate — User2 cannot further delegate
    false,
    false,
    0n
  );

  // Verify User2 has permission
  const hasPerm = await hasPermission(contracts2, USER2_DID, documentHash, 1);
  console.log(`[4/6] User2 hasPermission(canRead): ${hasPerm}`);

  if (!hasPerm) {
    console.error("[4/6] ✗ Delegation failed — User2 has no canRead");
    process.exit(1);
  }

  // Step 3 — User2 approves read on-chain
  // WP2 §Retrieval Phase 1
  console.log("[5/6] User2 approving read on-chain...");
  await checkAndApproveRead(contracts2, documentHash);
  console.log("[5/6] ReadApproved event emitted for User2");

  // Step 4 — User2 retrieves document
  console.log("[6/6] User2 retrieving document...");
  const retrieved = await retrieveDocument(
    AUTHORITY_URL,
    { did: USER2_DID, privateKeyPem: USER2_PK_PEM },
    documentHash
  );

  // Step 5 — Verify
  const retrievedHash = keccak256(new Uint8Array(retrieved));
  if (retrievedHash.toLowerCase() === documentHash.toLowerCase()) {
    console.log("[6/6] ✓ User2 retrieved document successfully — hash matches");
    console.log(`      Content: ${retrieved.toString()}`);
  } else {
    console.error("[6/6] ✗ Hash mismatch");
    process.exit(1);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
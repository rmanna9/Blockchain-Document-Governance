import { keccak256, encodeFunctionData } from "viem";
import {
  initClientContracts,
  requestCertification,
  checkAndApproveRead,
} from "../src/contracts.js";
import { certifyDocument, forcedRead } from "../src/api.js";

/**
 * Governance scenario.
 * WP2 §Governance and Policy Management — RF2, RF3
 *
 * 1. Founding authorities admit authority-a via governance (admitAuthority)
 * 2. Document is certified by authority-a
 * 3. Governance approves forced read (RF3)
 * 4. Aggregator authority collects shares, reconstructs k_doc, returns document
 */
async function main() {
  const RPC_URL       = process.env.RPC_URL       ?? "http://localhost:8545";
  const ADDRESSES     = process.env.ADDRESSES     ?? "scripts/addresses.json";
  const AUTHORITY_URL = process.env.AUTHORITY_URL ?? "http://localhost:3001";

  // Founding authorities private keys
  const FOUNDING1_KEY = process.env.FOUNDING1_KEY ?? "";
  const FOUNDING2_KEY = process.env.FOUNDING2_KEY ?? "";
  const FOUNDING3_KEY = process.env.FOUNDING3_KEY ?? "";

  // User credentials
  const USER_PRIVATE_KEY = process.env.USER_PRIVATE_KEY ?? "";
  const USER_DID         = process.env.USER_DID         ?? "";
  const USER_PK_PEM      = process.env.USER_PK_PEM      ?? "";

  // Aggregator authority (the one that collects shares for forced read)
  const AGGREGATOR_URL     = process.env.AGGREGATOR_URL     ?? "http://localhost:3001";
  const AGGREGATOR_DID     = process.env.AGGREGATOR_DID     ?? "";
  const AGGREGATOR_PK_PEM  = process.env.AGGREGATOR_PK_PEM  ?? "";

  if (!FOUNDING1_KEY || !FOUNDING2_KEY || !FOUNDING3_KEY ||
      !USER_PRIVATE_KEY || !USER_DID || !USER_PK_PEM) {
    console.error("Missing required environment variables");
    process.exit(1);
  }

  const contracts1 = initClientContracts(RPC_URL, FOUNDING1_KEY, ADDRESSES);
  const contracts2 = initClientContracts(RPC_URL, FOUNDING2_KEY, ADDRESSES);
  const contracts3 = initClientContracts(RPC_URL, FOUNDING3_KEY, ADDRESSES);
  const userContracts = initClientContracts(RPC_URL, USER_PRIVATE_KEY, ADDRESSES);

  // ── Step 1: Certify a document ──────────────────────────────────────────────

  const document     = Buffer.from("Document for governance forced read scenario.");
  const documentHash = keccak256(new Uint8Array(document)) as `0x${string}`;
  const zero         = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;

  console.log("[1/4] Certifying document...");
  await requestCertification(userContracts, documentHash, zero, USER_DID);
  await certifyDocument(
    AUTHORITY_URL,
    { did: USER_DID, privateKeyPem: USER_PK_PEM },
    documentHash,
    document
  );
  await new Promise(r => setTimeout(r, 3000));
  console.log("[1/4] Document certified and archived");

  // ── Step 2: Governance proposes forced read (RF3) ───────────────────────────

  // WP2 §Forced Document Retrieval via Governance:
  // "The consortium may exercise a forced read of a document certified by
  //  any authority, without requiring the cooperation of the certifying
  //  authority. Supermajority threshold > 2/3."
  console.log("[2/4] Proposing forced read via governance...");

  const calldata = encodeFunctionData({
    abi: [{
      name:            "forcedRead",
      type:            "function",
      stateMutability: "nonpayable",
      inputs:          [{ name: "documentHash", type: "bytes32" }],
      outputs:         [],
    }],
    functionName: "forcedRead",
    args:         [documentHash],
  });

  await contracts1.governance.write.propose([
    "Forced read of document",
    contracts1.addresses.governanceContract,
    calldata,
    1, // Supermajority
  ]);

  const proposalId = 1n;

  // Advance time past voting delay
  const client = contracts1.publicClient;
  await (client as any).request({ method: "evm_increaseTime", params: [3601] });
  await (client as any).request({ method: "evm_mine", params: [] });

  // All three founding authorities vote For
  await contracts1.governance.write.castVote([proposalId, 1]);
  await contracts2.governance.write.castVote([proposalId, 1]);
  await contracts3.governance.write.castVote([proposalId, 1]);

  // Advance past voting period
  await (client as any).request({ method: "evm_increaseTime", params: [3 * 24 * 3600 + 1] });
  await (client as any).request({ method: "evm_mine", params: [] });

  await contracts1.governance.write.queue([proposalId]);

  // Advance past timelock
  await (client as any).request({ method: "evm_increaseTime", params: [24 * 3600 + 1] });
  await (client as any).request({ method: "evm_mine", params: [] });

  await contracts1.governance.write.execute([proposalId]);
  console.log("[2/4] Governance proposal executed");

  // ── Step 3: Approve read on-chain ───────────────────────────────────────────

  console.log("[3/4] Approving read on-chain...");
  await checkAndApproveRead(userContracts, documentHash);

  // ── Step 4: Forced read via aggregator ─────────────────────────────────────

  // WP2: "The authorities that voted in favour proceed to decrypt and submit
  //       their individual shares to a designated aggregator."
  console.log("[4/4] Requesting forced read from aggregator...");
  const retrieved = await forcedRead(
    AGGREGATOR_URL,
    { did: AGGREGATOR_DID, privateKeyPem: AGGREGATOR_PK_PEM },
    documentHash
  );

  const retrievedHash = keccak256(new Uint8Array(retrieved));
  if (retrievedHash.toLowerCase() === documentHash.toLowerCase()) {
    console.log("[4/4] ✓ Forced read successful — document retrieved and verified");
    console.log(`      Content: ${retrieved.toString()}`);
  } else {
    console.error("[4/4] ✗ Hash mismatch");
    process.exit(1);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
import * as readline from "readline";
import * as fs        from "fs";
import * as path      from "path";
import * as nodeCrypto from "crypto";
import {
  createPublicClient, createWalletClient, http, getContract,
  keccak256, toHex, encodeFunctionData, decodeAbiParameters,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { hardhat }             from "viem/chains";

import {
  generateRSAKeyPair,
  signDocumentHash,
  verifySignature,
  verifyAuthoritySignature,
  signNonce,
  decryptDocumentKey,
  deserializeEncryptedDocument, decryptDocument,
  combineShares, decryptShare,
  decryptChallenge,
} from "./crypto.js";

import { addFile, getFile, stopNode, listPinned } from "../ipfs/helia-node.js";

import {
  runArchivalWorkflow, runRevocationWorkflow, runExternalVerification,
  type AuthorityEntry, type ExternalVerifyResult,
} from "./oracle-sim.js";

import DIDRegistryABI           from "../artifacts/contracts/DIDRegistry.sol/DIDRegistry.json"           with { type: "json" };
import DocumentRegistryABI      from "../artifacts/contracts/DocumentRegistry.sol/DocumentRegistry.json"  with { type: "json" };
import DocumentAccessControlABI from "../artifacts/contracts/DocumentAccessControl.sol/DocumentAccessControl.json" with { type: "json" };
import KeyShareRegistryABI      from "../artifacts/contracts/KeyShareRegistry.sol/KeyShareRegistry.json"  with { type: "json" };
import GovernanceContractABI    from "../artifacts/contracts/GovernanceContract.sol/GovernanceContract.json" with { type: "json" };
import AuditLogABI              from "../artifacts/contracts/AuditLog.sol/AuditLog.json"                  with { type: "json" };

// ── Constants ─────────────────────────────────────────────────────────────────

const SHARED_DIR = path.resolve("./shared");
const RPC_URL    = "http://127.0.0.1:8545";
const ZERO_HASH  = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;

const ACCOUNTS: Record<string, { address: `0x${string}`; privateKey: `0x${string}` }> = {
  deployer:      { address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" },
  "authority-a": { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", privateKey: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" },
  "authority-b": { address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", privateKey: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" },
  "authority-c": { address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906", privateKey: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" },
  "authority-d": { address: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", privateKey: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" },
  "authority-e": { address: "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc", privateKey: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" },
  "user-1":      { address: "0x976EA74026E726554dB657fA54763abd0C3a0aa9", privateKey: "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e" },
  "user-2":      { address: "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955", privateKey: "0x4bbb98b5ef1bff2d6de9c43e2e4e56e67ba7975c0c4cd34f7dce9736d37ab6e9" },
  "user-3":      { address: "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f", privateKey: "0xdbda1821b80551c9d65939329250132c0f83cd8db8d4e01d2b7e48ef1def1e0b" },
  "user-4":      { address: "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720", privateKey: "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6" },
};

// ── Types ─────────────────────────────────────────────────────────────────────

interface UserEntry {
  address:       `0x${string}`;
  ethPrivateKey: `0x${string}`;
  rsaPrivateKey: string;
  rsaPublicKey:  string;
}

interface Addresses {
  auditLog:           `0x${string}`;
  didRegistry:        `0x${string}`;
  governanceContract: `0x${string}`;
  documentRegistry:   `0x${string}`;
  accessControl:      `0x${string}`;
  keyShareRegistry:   `0x${string}`;
  authorities: {
    a: { address: string; did: string; privateKey: string };
    b: { address: string; did: string; privateKey: string };
    c: { address: string; did: string; privateKey: string };
  };
}

// ── Runtime state ─────────────────────────────────────────────────────────────

const users       = new Map<string, UserEntry>(); // did → entry
const reportLines: string[] = [];

let addresses:    Addresses;
let authorityKeys: {
  a: { priv: string; pub: string };
  b: { priv: string; pub: string };
  c: { priv: string; pub: string };
};

// ── Chain / viem helpers ──────────────────────────────────────────────────────

function makeChain() {
  return { ...hardhat, id: 1337, rpcUrls: { default: { http: [RPC_URL] }, public: { http: [RPC_URL] } } };
}

function makeClients(privateKey: `0x${string}`) {
  const chain   = makeChain();
  const account = privateKeyToAccount(privateKey);
  const pub     = createPublicClient({ chain, transport: http(RPC_URL) });
  const wal     = createWalletClient({ chain, transport: http(RPC_URL), account });
  return { pub, wal, account };
}

function makeContracts(privateKey: `0x${string}`) {
  const { pub, wal } = makeClients(privateKey);
  const client = { public: pub, wallet: wal };
  return {
    pub,
    wal,
    didRegistry:      getContract({ address: addresses.didRegistry,       abi: DIDRegistryABI.abi,           client }),
    documentRegistry: getContract({ address: addresses.documentRegistry,  abi: DocumentRegistryABI.abi,      client }),
    accessControl:    getContract({ address: addresses.accessControl,     abi: DocumentAccessControlABI.abi, client }),
    keyShareRegistry: getContract({ address: addresses.keyShareRegistry,  abi: KeyShareRegistryABI.abi,      client }),
    governance:       getContract({ address: addresses.governanceContract, abi: GovernanceContractABI.abi,   client }),
    auditLog:         getContract({ address: addresses.auditLog,           abi: AuditLogABI.abi,             client }),
  };
}

// ── Report helpers ────────────────────────────────────────────────────────────

function appendReport(
  op: string,
  params: Record<string, string>,
  result: string,
  txHash?: string,
  extra?: Record<string, string>
) {
  const ts = new Date().toTimeString().slice(0, 8);
  const lines = [`## [${ts}] ${op}`];
  for (const [k, v] of Object.entries(params)) lines.push(`- ${k}: ${v}`);
  lines.push(`- result: ${result}`);
  if (txHash) lines.push(`- tx: ${txHash}`);
  if (extra)  for (const [k, v] of Object.entries(extra)) lines.push(`- ${k}: ${v}`);
  lines.push("");
  reportLines.push(...lines);
  try { fs.writeFileSync("report.md", reportLines.join("\n")); } catch {}
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
function ask(q: string): Promise<string> {
  return new Promise(res => rl.question(q, ans => res(ans.trim())));
}

function errMsg(e: any): string {
  return e?.shortMessage ?? e?.message ?? String(e);
}

// helper: map certifiedBy address → authority letter (a/b/c)
function authLetterFor(addr: string): "a" | "b" | "c" | null {
  const a = addr.toLowerCase();
  if (a === addresses.authorities.a.address.toLowerCase()) return "a";
  if (a === addresses.authorities.b.address.toLowerCase()) return "b";
  if (a === addresses.authorities.c.address.toLowerCase()) return "c";
  return null;
}

// ── Menu operations ───────────────────────────────────────────────────────────

async function opRegisterUser() {
  const did      = await ask("User DID (e.g. did:consortium:user-1): ");
  const acctName = await ask("Account name (e.g. user-1): ");
  const authName = await ask("Signing authority (authority-a/b/c): ");

  const acct = ACCOUNTS[acctName];
  const auth = ACCOUNTS[authName];
  if (!acct || !auth) { console.log("✗ Unknown account"); return; }

  const { privateKey: rsaPriv, publicKey: rsaPub } = generateRSAKeyPair();

  try {
    const c  = makeContracts(auth.privateKey);
    const tx = await c.didRegistry.write.registerUser([did, rsaPub, rsaPub, acct.address, 0n]);
    users.set(did, { address: acct.address, ethPrivateKey: acct.privateKey, rsaPrivateKey: rsaPriv, rsaPublicKey: rsaPub });
    console.log(`✓ User registered: ${did}  address: ${acct.address}`);
    appendReport("Register User", { did, account: acctName, authority: authName }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Register User", { did }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opRegisterAuthority() {
  const did         = await ask("New authority DID: ");
  const address     = await ask("Authority Ethereum address (0x...): ");
  const acctName    = await ask("Proposer account (authority-a/b/c): ");
  const description = await ask("Proposal description: ");

  const auth = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }

  const { privateKey: rsaPriv, publicKey: rsaPub } = generateRSAKeyPair();

  try {
    const c        = makeContracts(auth.privateKey);
    const calldata = encodeFunctionData({
      abi:          GovernanceContractABI.abi,
      functionName: "admitAuthority",
      args:         [address as `0x${string}`, did, rsaPub, rsaPub],
    });

    const txPropose = await c.governance.write.propose([description, addresses.governanceContract, calldata, 1]);
    console.log(`✓ Proposal submitted: tx ${txPropose}`);

    const proposalId = await (async () => {
      for (let i = 100n; i >= 1n; i--) {
        try {
          const p = await c.governance.read.getProposal([i]) as any;
          if (p.proposer.toLowerCase() === auth.address.toLowerCase()) return i;
        } catch { continue; }
      }
      return 1n;
    })();

    console.log(`  Proposal ID: ${proposalId}`);
    console.log("  Use options 16 (Vote) and 17 (Execute) to complete.");
    appendReport("Register Authority (propose)", { did, address, proposer: acctName }, "✓ PROPOSED", txPropose, { proposalId: String(proposalId) });
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Register Authority", { did }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opDeactivateDID() {
  const did      = await ask("DID to deactivate: ");
  const acctName = await ask("Caller account: ");
  const auth     = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }
  try {
    const c  = makeContracts(auth.privateKey);
    const tx = await c.didRegistry.write.deactivate([did]);
    console.log(`✓ DID deactivated: ${did}`);
    appendReport("Deactivate DID", { did, caller: acctName }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Deactivate DID", { did }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opResolveDID() {
  const did = await ask("DID to resolve: ");
  try {
    const c   = makeContracts(ACCOUNTS["deployer"].privateKey);
    const doc = await c.didRegistry.read.resolve([did]) as any;
    console.log("DID Document:");
    console.log(`  did:             ${doc.did}`);
    console.log(`  entityAddress:   ${doc.entityAddress}`);
    console.log(`  entityType:      ${["Authority", "User", "Auditor"][doc.entityType]}`);
    console.log(`  isActive:        ${doc.isActive}`);
    console.log(`  domainAuthority: ${doc.domainAuthority}`);
    console.log(`  createdAt:       ${new Date(Number(doc.createdAt) * 1000).toISOString()}`);
    console.log(`  activePublicKey: ${doc.activePublicKey.slice(0, 60)}...`);
    appendReport("Resolve DID", { did }, "✓ SUCCESS");
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Resolve DID", { did }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opListActiveDIDs() {
  console.log("Registered users (in-session):");
  if (users.size === 0) { console.log("  (none registered this session)"); return; }
  for (const [did, u] of users) console.log(`  ${did}  ${u.address}`);
  console.log("Founding authorities:");
  for (const [k, v] of Object.entries(addresses.authorities))
    console.log(`  authority-${k}: ${v.did}  ${v.address}`);
}

async function opRequestCertification() {
  const did      = await ask("User DID: ");
  const docText  = await ask("Document content: ");
  const acctName = await ask("Account name: ");
  const auth     = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }

  const docBuf  = Buffer.from(docText);
  const docHash = keccak256(new Uint8Array(docBuf)) as `0x${string}`;

  try {
    const c  = makeContracts(auth.privateKey);
    const tx = await c.documentRegistry.write.requestCertification([docHash, ZERO_HASH, did]);
    console.log(`✓ Certification requested  documentHash: ${docHash}`);
    appendReport("Request Certification", { did, docHash }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Request Certification", { did }, `✗ FAILED: ${errMsg(e)}`);
  }
}

// ── Option 7: Certify Document ────────────────────────────────────────────────

async function opCertifyDocument() {
  const docHash  = await ask("Document hash (0x...): ") as `0x${string}`;
  const docText  = await ask("Document content (must match hash): ");
  const authName = await ask("Certifying authority (authority-a/b/c): ");

  const authAcct = ACCOUNTS[authName];
  if (!authAcct) { console.log("✗ Unknown account"); return; }

  const authLetter = authName.split("-")[1] as "a" | "b" | "c";
  if (!authorityKeys[authLetter]) { console.log("✗ Unknown authority letter"); return; }

  const docBuf    = Buffer.from(docText);
  const computedH = keccak256(new Uint8Array(docBuf));
  if (computedH.toLowerCase() !== docHash.toLowerCase()) {
    console.log("✗ Document hash mismatch");
    return;
  }

  try {
    const c = makeContracts(authAcct.privateKey);

    // Step 1: sign hash and certify on-chain
    const hashBuf = Buffer.from(docHash.replace(/^0x/, ""), "hex");
    const sig     = signDocumentHash(hashBuf, authorityKeys[authLetter].priv);
    const sigHex  = toHex(sig) as `0x${string}`;

    console.log("  Calling DocumentRegistry.certify()...");
    const txCertHash = await c.documentRegistry.write.certify([docHash, sigHex]);
    const receipt    = await c.pub.waitForTransactionReceipt({ hash: txCertHash });
    const block      = await c.pub.getBlock({ blockNumber: receipt.blockNumber });
    console.log(`  ✓ DocumentCertified  block: ${receipt.blockNumber}  tx: ${txCertHash}`);

    // Step 2: run oracle archival workflow (Helia + on-chain storeShares/storeCID)
    const allAuthorities: AuthorityEntry[] = [
      { address: addresses.authorities.a.address as `0x${string}`, pub: authorityKeys.a.pub },
      { address: addresses.authorities.b.address as `0x${string}`, pub: authorityKeys.b.pub },
      { address: addresses.authorities.c.address as `0x${string}`, pub: authorityKeys.c.pub },
    ];

    await runArchivalWorkflow(
      docHash,
      docBuf,
      receipt.blockNumber,
      authAcct.address,
      block.timestamp,
      authorityKeys[authLetter].priv,
      authorityKeys[authLetter].pub,
      allAuthorities,
      c,
      reportLines
    );

    console.log(`\n✓ Document certified and archived`);
    appendReport("Certify Document", { docHash, authority: authName }, "✓ SUCCESS", txCertHash);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Certify Document", { docHash }, `✗ FAILED: ${errMsg(e)}`);
  }
}

// ── Option 8: Retrieve Document (ordinary — E_A path, NOT SSS combine) ────────

async function opRetrieveDocument() {
  const docHash   = await ask("Document hash (0x...): ") as `0x${string}`;
  const acctName  = await ask("Requester account (e.g. user-1): ");
  const callerDID = await ask("Requester DID: ");
  const auth      = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }

  try {
    const c = makeContracts(auth.privateKey);

    // ── Phase 1: checkAndApproveRead → ReadApproved ───────────────────────
    console.log("\n  ── Phase 1: checkAndApproveRead(h) → ReadApproved ──────────────────");
    let txRead: string;
    try {
      txRead = await c.accessControl.write.checkAndApproveRead([docHash]);
    } catch (e) {
      console.log(`  ✗ Phase 1 FAILED: ${errMsg(e)}`);
      console.log(`  → Document may be REVOKED or caller has no read permission`);
      appendReport("Retrieve Document", { docHash, account: acctName }, `✗ BLOCKED: ${errMsg(e)}`);
      return;
    }
    console.log(`  ✓ ReadApproved  tx: ${txRead}`);

    // ── Phase 2: Lightweight auth simulation ─────────────────────────────
    console.log("\n  ── Phase 2: Lightweight Auth (nonce → sign sk_U → verify pk_U) ──────");
    const userEntry = users.get(callerDID);
    if (userEntry) {
      const nonce    = nodeCrypto.randomBytes(32).toString("hex");
      const sigHex   = signNonce(nonce, userEntry.rsaPrivateKey);
      const sigBuf   = Buffer.from(sigHex, "hex");
      const nonceBuf = Buffer.from(nonce, "hex");
      const ok       = verifySignature(nonceBuf, sigBuf, userEntry.rsaPublicKey);
      console.log(`  ✓ nonce generated (32B) → signed with sk_U → verified with pk_U: ${ok}`);
      console.log(`  ✓ verifica record: DID ${callerDID} → address ${userEntry.address}`);
    } else {
      console.log(`  ⚠ DID ${callerDID} not in session — lightweight auth skipped`);
    }

    // ── Phase 3: getCID + getFile from Helia ─────────────────────────────
    console.log("\n  ── Phase 3: CID = getStorage(h); c = getFile(CID) from Helia ─────────");
    const cid = await c.documentRegistry.read.getCID([docHash]) as string;
    if (!cid || cid.length === 0) { console.log("  ✗ No CID on-chain — not yet archived"); return; }
    console.log(`  CID: ${cid}`);
    const blobU8 = await getFile(cid);
    const blob   = Buffer.from(blobU8);
    console.log(`  ✓ ciphertext retrieved from Helia: ${blob.length} bytes`);

    // ── Phase 4: E_A → k_doc → decrypt document ───────────────────────────
    console.log("\n  ── Phase 4: E_A = getEncryptedKey(h); k_doc = Dec(sk_A, E_A); decrypt ─");
    const record = await c.documentRegistry.read.getRecord([docHash]) as any;
    const letter = authLetterFor(record.certifiedBy as string);
    if (!letter) { console.log("  ✗ Certifying authority not found in known set"); return; }

    const eAHex    = await c.keyShareRegistry.read.getEncryptedKey([docHash]) as string;
    const eABuf    = Buffer.from(eAHex.replace(/^0x/, ""), "hex");
    const kDoc     = decryptDocumentKey(eABuf, authorityKeys[letter].priv);
    const encDoc   = deserializeEncryptedDocument(blob);
    const plainBuf = decryptDocument(encDoc, kDoc);
    kDoc.fill(0);
    console.log(`  ✓ E_A decrypted with sk_A (authority-${letter}); k_doc obtained; document decrypted`);

    // ── Phase 5: show plaintext ───────────────────────────────────────────
    console.log("\n  ── Phase 5: Plaintext ───────────────────────────────────────────────────");
    const content = plainBuf.toString();
    console.log(`\n✓ Document retrieved:\n  ${content}`);
    appendReport("Retrieve Document", { docHash, account: acctName, callerDID }, "✓ SUCCESS", txRead, { content: content.slice(0, 80) });
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Retrieve Document", { docHash }, `✗ FAILED: ${errMsg(e)}`);
  }
}

// ── Option 9: Revoke Document ─────────────────────────────────────────────────

async function opRevokeDocument() {
  const docHash  = await ask("Document hash (0x...): ") as `0x${string}`;
  const reason   = await ask("Revocation reason: ");
  const acctName = await ask("Authority account: ");
  const auth     = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }

  try {
    const c       = makeContracts(auth.privateKey);
    const txHash  = await c.documentRegistry.write.revoke([docHash, reason]);
    const receipt = await c.pub.waitForTransactionReceipt({ hash: txHash });
    const block   = await c.pub.getBlock({ blockNumber: receipt.blockNumber });
    console.log(`✓ DocumentRevoked  block: ${receipt.blockNumber}  tx: ${txHash}`);

    await runRevocationWorkflow(
      docHash,
      reason,
      receipt.blockNumber,
      block.timestamp,
      c,
      reportLines
    );

    appendReport("Revoke Document", { docHash, reason, authority: acctName }, "✓ SUCCESS", txHash);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Revoke Document", { docHash }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opGetDocumentStatus() {
  const docHash = await ask("Document hash (0x...): ") as `0x${string}`;
  try {
    const c      = makeContracts(ACCOUNTS["deployer"].privateKey);
    const status = await c.documentRegistry.read.getStatus([docHash]) as bigint;
    const labels = ["Pending", "Certified", "Revoked"];
    console.log(`Status: ${labels[Number(status)] ?? status}`);
    const record = await c.documentRegistry.read.getRecord([docHash]) as any;
    console.log(`  certifiedBy: ${record.certifiedBy}`);
    console.log(`  ownerDID:    ${record.ownerDID}`);
    console.log(`  version:     ${record.version}`);
    console.log(`  cid:         ${record.cid}`);
    appendReport("Get Document Status", { docHash }, `✓ ${labels[Number(status)]}`);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Get Document Status", { docHash }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opGrantCreate() {
  const holderDID = await ask("Holder DID: ");
  const authName  = await ask("Authority account: ");
  const auth      = ACCOUNTS[authName];
  if (!auth) { console.log("✗ Unknown account"); return; }
  try {
    const c  = makeContracts(auth.privateKey);
    const tx = await c.accessControl.write.grantCreate([holderDID, 0n]);
    console.log(`✓ canCreate granted to ${holderDID}`);
    appendReport("Grant canCreate", { holderDID, authority: authName }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Grant canCreate", { holderDID }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opDelegatePermission() {
  const delegateeDID = await ask("Delegatee DID: ");
  const docHash      = await ask("Document hash (0x...): ") as `0x${string}`;
  const actionRaw    = await ask("Action type (0=CanCreate, 1=CanRead, 2=CanUpdate): ");
  const canDelegate  = (await ask("canDelegate (y/n): ")) === "y";
  const acctName     = await ask("Delegator account: ");
  const auth         = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }
  try {
    const c  = makeContracts(auth.privateKey);
    const tx = await c.accessControl.write.delegate([delegateeDID, docHash, Number(actionRaw), canDelegate, false, false, 0n]);
    console.log(`✓ Permission delegated to ${delegateeDID}`);
    appendReport("Delegate Permission", { delegateeDID, docHash, actionType: actionRaw }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Delegate Permission", { delegateeDID, docHash }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opRevokePermission() {
  const permId   = await ask("Permission/Delegation ID (0x...): ") as `0x${string}`;
  const type_    = await ask("Type (permission/delegation): ");
  const acctName = await ask("Account: ");
  const auth     = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }
  try {
    const c  = makeContracts(auth.privateKey);
    const tx = type_ === "delegation"
      ? await c.accessControl.write.revokeDelegation([permId])
      : await c.accessControl.write.revokePermission([permId]);
    console.log(`✓ ${type_} revoked: ${permId}`);
    appendReport("Revoke Permission", { id: permId, type: type_ }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Revoke Permission", { id: permId }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opCheckPermission() {
  const holderDID = await ask("Holder DID: ");
  const docHash   = await ask("Document hash (0x...): ") as `0x${string}`;
  const actionRaw = await ask("Action type (0=CanCreate, 1=CanRead, 2=CanUpdate): ");
  try {
    const c   = makeContracts(ACCOUNTS["deployer"].privateKey);
    const has = await c.accessControl.read.hasPermission([holderDID, docHash, Number(actionRaw)]) as boolean;
    console.log(`hasPermission: ${has}`);
    appendReport("Check Permission", { holderDID, docHash, actionType: actionRaw }, `✓ ${has}`);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Check Permission", { holderDID, docHash }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opProposeAction() {
  const description  = await ask("Description: ");
  const targetAddr   = await ask("Target contract address (0x...): ") as `0x${string}`;
  const calldataHex  = await ask("Calldata (hex, 0x...): ") as `0x${string}`;
  const thresholdRaw = await ask("Threshold (0=Majority, 1=Supermajority): ");
  const acctName     = await ask("Proposer authority account: ");
  const auth         = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }
  try {
    const c  = makeContracts(auth.privateKey);
    const tx = await c.governance.write.propose([description, targetAddr, calldataHex, Number(thresholdRaw)]);
    console.log(`✓ Proposal submitted: ${tx}`);
    appendReport("Propose Action", { description, target: targetAddr }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Propose Action", { description }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opVoteOnProposal() {
  const proposalId = BigInt(await ask("Proposal ID: "));
  const support    = Number(await ask("Vote (0=Against, 1=For, 2=Abstain): "));
  const acctName   = await ask("Authority account: ");
  const auth       = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }
  try {
    const c  = makeContracts(auth.privateKey);
    const tx = await c.governance.write.castVote([proposalId, support]);
    console.log(`✓ Vote cast on proposal ${proposalId}`);
    appendReport("Vote on Proposal", { proposalId: String(proposalId), support: String(support), voter: acctName }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Vote on Proposal", { proposalId: String(proposalId) }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opExecuteProposal() {
  const proposalId = BigInt(await ask("Proposal ID: "));
  const action     = await ask("Action (queue/execute): ");
  const acctName   = await ask("Authority account: ");
  const auth       = ACCOUNTS[acctName];
  if (!auth) { console.log("✗ Unknown account"); return; }
  try {
    const c  = makeContracts(auth.privateKey);
    const tx = action === "queue"
      ? await c.governance.write.queue([proposalId])
      : await c.governance.write.execute([proposalId]);
    console.log(`✓ Proposal ${proposalId} ${action}d`);
    appendReport("Execute Proposal", { proposalId: String(proposalId), action }, "✓ SUCCESS", tx);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Execute Proposal", { proposalId: String(proposalId) }, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opGetProposalStatus() {
  const proposalId = BigInt(await ask("Proposal ID: "));
  try {
    const c = makeContracts(ACCOUNTS["deployer"].privateKey);
    const p = await c.governance.read.getProposal([proposalId]) as any;
    const statusLabels = ["Pending", "Active", "Succeeded", "Defeated", "Executed", "Cancelled"];
    console.log(`Proposal ${proposalId}:`);
    console.log(`  description: ${p.description}`);
    console.log(`  status:      ${statusLabels[p.status] ?? p.status}`);
    console.log(`  forVotes:    ${p.forVotes}`);
    console.log(`  againstVotes:${p.againstVotes}`);
    console.log(`  votingEnd:   ${new Date(Number(p.votingEnd) * 1000).toISOString()}`);
    appendReport("Get Proposal Status", { proposalId: String(proposalId) }, `✓ ${statusLabels[p.status]}`);
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Get Proposal Status", { proposalId: String(proposalId) }, `✗ FAILED: ${errMsg(e)}`);
  }
}

// ── Option 19: External Verify (WP2 Phases 1-7) ───────────────────────────────

async function opExternalVerify() {
  const docHash   = await ask("Document hash (0x...): ") as `0x${string}`;
  const didA      = await ask("Authority DID (did_A): ");
  const didU      = await ask("User/Presenter DID (did_U): ");

  try {
    const c = makeContracts(ACCOUNTS["deployer"].privateKey);

    // Phases 1-2: fetch σ_A from chain record
    console.log("\n  ── Phases 1-2: fetch σ_A and pk_A from DocumentRegistry + DIDRegistry ─");
    const record  = await c.documentRegistry.read.getRecord([docHash]) as any;
    const sigHex  = record.sigAuthority as string;
    const didDocA = await c.didRegistry.read.resolve([didA]) as any;
    const pkA     = didDocA.activePublicKey as string;
    console.log(`  σ_A: ${sigHex.slice(0, 18)}...  pk_A from DIDDoc_A ✓`);

    // Phases 3-5: Oracle INBOUND
    const result: ExternalVerifyResult = await runExternalVerification(
      didA, docHash, didU, c, reportLines
    );

    if (!result.canPresent) {
      console.log("\n✗ External Verification FAILED — canPresentExternally = false");
      appendReport("External Verify", { docHash, didA, didU }, "✗ FAILED: canPresentExternally = false");
      return;
    }

    // Phase 6: verifier verifies σ_A against pk_A
    console.log("\n  ── Phase 6: Verifier checks σ_A = Sign(sk_A, h) with pk_A from DIDDoc_A ─");
    const sigValid = verifyAuthoritySignature(docHash, sigHex, pkA);
    console.log(`  ✓ Phase 6: verifyAuthoritySignature(h, σ_A, pk_A) → ${sigValid}`);

    // Phase 7: user decrypts c_meta with sk_U; verifier recomputes H(metadata)
    console.log("\n  ── Phase 7: User decrypts c_meta with sk_U; verifier checks H(metadata) ─");
    const userEntry = users.get(didU);
    let phase7Result = "⚠ User sk_U not in session — cannot decrypt c_meta";

    if (userEntry) {
      const decrypted  = decryptChallenge(result.cMeta, userEntry.rsaPrivateKey);
      const recomputed = nodeCrypto.createHash("sha256").update(decrypted).digest("hex");
      const match      = recomputed === result.hMeta;
      console.log(`  ✓ Dec(sk_U, c_meta) succeeded  H(metadata) match: ${match}`);
      console.log(`    Note: outcome (valid/invalid) is encoded ONLY inside the encrypted payload`);
      phase7Result = `match=${match}`;
    } else {
      console.log(`  ${phase7Result}`);
    }

    const outcome = sigValid ? "VALID" : "INVALID";
    console.log(`\n✓ External Verification complete — σ_A: ${outcome}`);
    appendReport("External Verify", { docHash, didA, didU }, `✓ ${outcome}`, undefined, { sigValid: String(sigValid), phase7: phase7Result });
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("External Verify", { docHash: docHash as string, didA, didU }, `✗ FAILED: ${errMsg(e)}`);
  }
}

// ── NEW Option 20: Forced Read (Governance) — SSS combine ────────────────────

async function opForcedRead() {
  const docHash = await ask("Document hash (0x...): ") as `0x${string}`;

  try {
    const c = makeContracts(ACCOUNTS["deployer"].privateKey);

    // ── Governance simulation ─────────────────────────────────────────────
    const N = 3;
    const SEP = "═".repeat(66);
    console.log(`\n╔${SEP}`);
    console.log(`║  [GOVERNANCE] Forced-Read Proposal`);
    console.log(`║    Proposal #1   description: emergency forced-read`);
    console.log(`║    Votes:  FOR ${N}/${N}  (>${Math.ceil((2*N)/3)-1}/3 threshold satisfied)`);
    console.log(`║    Timelock: elapsed`);
    console.log(`║    Status:  APPROVED — forced read authorised`);
    console.log(`╚${SEP}\n`);

    // ── Collect shares from authorities ────────────────────────────────────
    console.log("  Collecting encrypted shares from on-chain KeyShareRegistry...");
    const threshold = Number(await c.keyShareRegistry.read.getThreshold([docHash]) as bigint);
    console.log(`  threshold t=${threshold}  collecting from all 3 authorities`);

    const authLetters = ["a", "b", "c"] as const;
    const plainShares: Buffer[] = [];

    for (const letter of authLetters) {
      const addr  = addresses.authorities[letter].address as `0x${string}`;
      const data  = await c.keyShareRegistry.read.getShare([docHash, addr]) as any;
      const encBuf = Buffer.from((data.encryptedShare as string).replace(/^0x/, ""), "hex");
      const share  = decryptShare(encBuf, authorityKeys[letter].priv);
      plainShares.push(share);
      console.log(`  ✓ authority-${letter} share[${data.shareIndex}] decrypted (${share.length} bytes)`);
      if (plainShares.length >= threshold) break;
    }

    // ── Aggregator: SSS combine ────────────────────────────────────────────
    console.log(`\n  Aggregator: SSS combine(${plainShares.length} shares) → k_doc...`);
    const kDoc = combineShares(plainShares);
    console.log(`  ✓ k_doc reconstructed (${kDoc.length} bytes)`);

    // ── Fetch from Helia + decrypt ─────────────────────────────────────────
    const cid    = await c.documentRegistry.read.getCID([docHash]) as string;
    if (!cid || cid.length === 0) { console.log("  ✗ No CID on-chain"); return; }
    console.log(`\n  Fetching ciphertext from Helia: ${cid}...`);
    const blobU8 = await getFile(cid);
    const blob   = Buffer.from(blobU8);
    const encDoc = deserializeEncryptedDocument(blob);
    const plain  = decryptDocument(encDoc, kDoc);
    kDoc.fill(0);

    console.log(`\n✓ Forced Read complete:`);
    console.log(`  Content: ${plain.toString()}`);

    reportLines.push(
      `## [GOVERNANCE] Forced Read`,
      `- documentHash: ${docHash}`,
      `- sharesUsed: ${plainShares.length}  threshold: ${threshold}`,
      `- k_doc reconstructed: true`,
      `- CID: ${cid}`,
      `- content: ${plain.toString().slice(0, 80)}`,
      ``
    );
    try { fs.writeFileSync("report.md", reportLines.join("\n")); } catch {}

    appendReport("Forced Read (Governance)", { docHash }, "✓ SUCCESS", undefined, { cid, sharesUsed: String(plainShares.length) });
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Forced Read (Governance)", { docHash: docHash as string }, `✗ FAILED: ${errMsg(e)}`);
  }
}

// ── Audit / System ────────────────────────────────────────────────────────────

const AUDIT_TYPE_LABELS = [
  "DIDRegistered", "DIDDeactivated", "CertificationRequested",
  "DocumentCertified", "DocumentRevoked", "CIDStored", "SharesStored",
  "PermissionGranted", "PermissionRevoked", "DelegationIssued",
  "DelegationRevoked", "ProposalSubmitted", "VoteCast", "ProposalExecuted",
  "AnomalyReported", "ReadApproved",
];

function decodePayload(actionType: number, payload: `0x${string}`): string {
  if (!payload || payload === "0x") return "";
  try {
    if (actionType === 7) {
      const [permId, holderDID, actType] = decodeAbiParameters(
        [{ type: "bytes32" }, { type: "string" }, { type: "uint8" }], payload
      );
      return `permissionId:${permId}  holderDID:${holderDID}  actionType:${actType}`;
    }
    if (actionType === 0) {
      const [did, , entityAddress] = decodeAbiParameters(
        [{ type: "string" }, { type: "uint8" }, { type: "address" }, { type: "address" }], payload
      );
      return `did:${did}  address:${entityAddress}`;
    }
  } catch { /* skip */ }
  return "";
}

async function opQueryAuditLog() {
  const fromEntry = BigInt(await ask("From entry ID (default 1): ") || "1");
  const maxCount  = Number(await ask("Max entries to show (default 20): ") || "20");
  try {
    const c     = makeContracts(ACCOUNTS["deployer"].privateKey);
    const total = await c.auditLog.read.totalEntries([]) as bigint;
    console.log(`Total entries: ${total}`);
    const end = BigInt(Math.min(Number(fromEntry) + maxCount - 1, Number(total)));
    for (let i = fromEntry; i <= end; i++) {
      const e       = await c.auditLog.read.getEntry([i]) as any;
      const label   = AUDIT_TYPE_LABELS[e.actionType] ?? String(e.actionType);
      const decoded = decodePayload(Number(e.actionType), e.payload as `0x${string}`);
      console.log(`  [${i}] ${label.padEnd(24)}  actor:${(e.actor as string).slice(0, 10)}...  block:${e.blockNumber}`);
      if (decoded) console.log(`       data: ${decoded}`);
    }
    appendReport("Query Audit Log", { from: String(fromEntry), max: String(maxCount) }, "✓ SUCCESS");
  } catch (e) {
    console.log(`✗ ${errMsg(e)}`);
    appendReport("Query Audit Log", {}, `✗ FAILED: ${errMsg(e)}`);
  }
}

async function opShowState() {
  console.log("\n=== System State ===");
  console.log("Contract addresses:");
  console.log(`  AuditLog:           ${addresses.auditLog}`);
  console.log(`  DIDRegistry:        ${addresses.didRegistry}`);
  console.log(`  GovernanceContract: ${addresses.governanceContract}`);
  console.log(`  DocumentRegistry:   ${addresses.documentRegistry}`);
  console.log(`  AccessControl:      ${addresses.accessControl}`);
  console.log(`  KeyShareRegistry:   ${addresses.keyShareRegistry}`);
  console.log("\nFounding authorities:");
  for (const [k, v] of Object.entries(addresses.authorities))
    console.log(`  authority-${k}: ${v.address}  did: ${v.did}`);
  console.log(`\nHelia pinned CIDs: ${listPinned().length}`);
  for (const cid of listPinned()) console.log(`  ${cid}`);
  console.log(`Session users:     ${users.size}`);
  console.log(`Report lines:      ${reportLines.length}`);
}

async function opExportReport() {
  const out = "report.md";
  fs.writeFileSync(out, reportLines.join("\n"));
  console.log(`✓ Report written to ${out} (${reportLines.length} lines)`);
}

// ── Menu ──────────────────────────────────────────────────────────────────────

function printMenu() {
  console.log(`
[IDENTITY]
  1.  Register User
  2.  Register Authority (via governance)
  3.  Deactivate DID
  4.  Resolve DID
  5.  List active DIDs

[DOCUMENT LIFECYCLE]
  6.  Request Certification
  7.  Certify Document (authority)          ← oracle archival auto-runs
  8.  Retrieve Document                     ← WP2 E_A path
  9.  Revoke Document                       ← oracle revocation auto-runs
  10. Get Document Status

[PERMISSIONS]
  11. Grant canCreate
  12. Delegate Permission
  13. Revoke Permission
  14. Check Permission

[GOVERNANCE]
  15. Propose Action
  16. Vote on Proposal
  17. Execute Proposal
  18. Get Proposal Status

[VERIFICATION]
  19. External Verify                       ← WP2 Phases 1-7
  20. Forced Read (Governance)              ← SSS combine

[AUDIT]
  21. Query Audit Log

[SYSTEM]
  22. Show system state
  23. Export report.md
  0.  Exit
`);
}

// ── Startup ───────────────────────────────────────────────────────────────────

async function startup() {
  const addrPath = path.join(SHARED_DIR, "addresses.json");
  if (!fs.existsSync(addrPath)) {
    console.error(`ERROR: ${addrPath} not found. Run the deploy script first.`);
    process.exit(1);
  }

  addresses = JSON.parse(fs.readFileSync(addrPath, "utf-8")) as Addresses;

  const readPem = (name: string) => fs.readFileSync(path.join(SHARED_DIR, name), "utf-8");
  authorityKeys = {
    a: { priv: readPem("authority-a-private.pem"), pub: readPem("authority-a-public.pem") },
    b: { priv: readPem("authority-b-private.pem"), pub: readPem("authority-b-public.pem") },
    c: { priv: readPem("authority-c-private.pem"), pub: readPem("authority-c-public.pem") },
  };

  console.log("=== Blockchain Document Governance CLI ===");
  await opShowState();
}

// ── Main loop ─────────────────────────────────────────────────────────────────

async function main() {
  await startup();

  while (true) {
    printMenu();
    const choice = await ask("Choice: ");

    switch (choice) {
      case "1":  await opRegisterUser();        break;
      case "2":  await opRegisterAuthority();   break;
      case "3":  await opDeactivateDID();       break;
      case "4":  await opResolveDID();          break;
      case "5":  await opListActiveDIDs();      break;
      case "6":  await opRequestCertification(); break;
      case "7":  await opCertifyDocument();     break;
      case "8":  await opRetrieveDocument();    break;
      case "9":  await opRevokeDocument();      break;
      case "10": await opGetDocumentStatus();   break;
      case "11": await opGrantCreate();         break;
      case "12": await opDelegatePermission();  break;
      case "13": await opRevokePermission();    break;
      case "14": await opCheckPermission();     break;
      case "15": await opProposeAction();       break;
      case "16": await opVoteOnProposal();      break;
      case "17": await opExecuteProposal();     break;
      case "18": await opGetProposalStatus();   break;
      case "19": await opExternalVerify();      break;
      case "20": await opForcedRead();          break;
      case "21": await opQueryAuditLog();       break;
      case "22": await opShowState();           break;
      case "23": await opExportReport();        break;
      case "0":
        await opExportReport();
        console.log("Stopping Helia node...");
        await stopNode();
        console.log("Goodbye.");
        rl.close();
        process.exit(0);
      default:
        console.log("Unknown choice.");
    }
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

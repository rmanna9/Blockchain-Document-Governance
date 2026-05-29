import { network } from "hardhat";
import { writeFileSync, mkdirSync } from "fs";
import { generateKeyPairSync } from "crypto";

const SHARED = "./shared";

function genRSA() {
  return generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

async function main() {
  const { viem } = await network.connect();
  const [deployer, authorityA, authorityB, authorityC] = await viem.getWalletClients();

  console.log("Deployer:    ", deployer.account.address);
  console.log("Authority A: ", authorityA.account.address);
  console.log("Authority B: ", authorityB.account.address);
  console.log("Authority C: ", authorityC.account.address);

  // ── 1. Generate RSA keypairs in memory ───────────────────────────────────
  console.log("\n[0/6] Generating RSA-4096 keypairs...");
  const kpA = genRSA();
  const kpB = genRSA();
  const kpC = genRSA();
  console.log("  RSA keypairs generated in memory");

  // ── 2. Deploy AuditLog ───────────────────────────────────────────────────
  console.log("\n[1/6] Deploying AuditLog...");
  const auditLog = await viem.deployContract("AuditLog");
  console.log("AuditLog:             ", auditLog.address);

  // ── 3. Deploy DIDRegistry ────────────────────────────────────────────────
  console.log("\n[2/6] Deploying DIDRegistry...");
  const authorities = [
    authorityA.account.address,
    authorityB.account.address,
    authorityC.account.address,
  ] as `0x${string}`[];
  const dids = [
    "did:consortium:authority-a",
    "did:consortium:authority-b",
    "did:consortium:authority-c",
  ];
  const activeKeys   = [kpA.publicKey, kpB.publicKey, kpC.publicKey];
  const recoveryKeys = [kpA.publicKey, kpB.publicKey, kpC.publicKey];

  const didRegistry = await viem.deployContract("DIDRegistry", [
    authorities,
    dids,
    activeKeys,
    recoveryKeys,
    auditLog.address,
  ]);
  console.log("DIDRegistry:          ", didRegistry.address);

  // ── 4. Deploy GovernanceContract ─────────────────────────────────────────
  console.log("\n[3/6] Deploying GovernanceContract...");
  const governance = await viem.deployContract("GovernanceContract", [
    authorities,
    dids,
    didRegistry.address,
    auditLog.address,
  ]);
  console.log("GovernanceContract:   ", governance.address);

  // ── 5. Deploy DocumentRegistry ───────────────────────────────────────────
  console.log("\n[4/6] Deploying DocumentRegistry...");
  const documentRegistry = await viem.deployContract("DocumentRegistry", [
    didRegistry.address,
    auditLog.address,
  ]);
  console.log("DocumentRegistry:     ", documentRegistry.address);

  // ── 6. Deploy DocumentAccessControl ──────────────────────────────────────
  console.log("\n[5/6] Deploying DocumentAccessControl...");
  const accessControl = await viem.deployContract("DocumentAccessControl", [
    didRegistry.address,
    documentRegistry.address,
    auditLog.address,
  ]);
  console.log("DocumentAccessControl:", accessControl.address);

  // ── 7. Deploy KeyShareRegistry ────────────────────────────────────────────
  console.log("\n[6/6] Deploying KeyShareRegistry...");
  const keyShareRegistry = await viem.deployContract("KeyShareRegistry", [
    didRegistry.address,
    auditLog.address,
  ]);
  console.log("KeyShareRegistry:     ", keyShareRegistry.address);

  // ── Wire up contracts ────────────────────────────────────────────────────
  console.log("\n[Setup] Wiring contracts...");

  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

  async function sendTx(fn: () => Promise<`0x${string}`>, label: string) {
    for (let attempt = 1; attempt <= 5; attempt++) {
      try {
        const hash = await fn();
        console.log(`  ✓ ${label}`);
        return hash;
      } catch (e: any) {
        console.warn(`  ✗ ${label} (attempt ${attempt}/5): ${e.shortMessage ?? e.message}`);
        if (attempt < 5) await sleep(2000 * attempt);
        else throw e;
      }
    }
  }

  await sendTx(() => didRegistry.write.setGovernanceContract([governance.address]), "didRegistry.setGovernanceContract");
  await sendTx(() => didRegistry.write.setAccessControl([accessControl.address]), "didRegistry.setAccessControl");
  await sendTx(() => documentRegistry.write.setAccessControl([accessControl.address]), "documentRegistry.setAccessControl");
  await sendTx(() => documentRegistry.write.setGovernanceContract([governance.address]), "documentRegistry.setGovernanceContract");
  await sendTx(() => accessControl.write.setGovernanceContract([governance.address]), "accessControl.setGovernanceContract");

  await sendTx(() => auditLog.write.addWriter([didRegistry.address]), "auditLog.addWriter(didRegistry)");
  await sendTx(() => auditLog.write.addWriter([governance.address]), "auditLog.addWriter(governance)");
  await sendTx(() => auditLog.write.addWriter([documentRegistry.address]), "auditLog.addWriter(documentRegistry)");
  await sendTx(() => auditLog.write.addWriter([accessControl.address]), "auditLog.addWriter(accessControl)");
  await sendTx(() => auditLog.write.addWriter([keyShareRegistry.address]), "auditLog.addWriter(keyShareRegistry)");
  await sendTx(() => auditLog.write.renounceAdmin(), "auditLog.renounceAdmin");

  console.log("AuditLog writers frozen.");

  // ── Save to /shared ──────────────────────────────────────────────────────
  const addresses = {
    auditLog:           auditLog.address,
    didRegistry:        didRegistry.address,
    governanceContract: governance.address,
    documentRegistry:   documentRegistry.address,
    accessControl:      accessControl.address,
    keyShareRegistry:   keyShareRegistry.address,
    authorities: {
      a: {
        address:    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        did:        "did:consortium:authority-a",
        privateKey: "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
      },
      b: {
        address:    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        did:        "did:consortium:authority-b",
        privateKey: "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
      },
      c: {
        address:    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        did:        "did:consortium:authority-c",
        privateKey: "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
      },
    },
  };

  mkdirSync(SHARED, { recursive: true });
  writeFileSync(`${SHARED}/addresses.json`, JSON.stringify(addresses, null, 2));
  writeFileSync(`${SHARED}/authority-a-private.pem`, kpA.privateKey, { mode: 0o600 });
  writeFileSync(`${SHARED}/authority-a-public.pem`,  kpA.publicKey);
  writeFileSync(`${SHARED}/authority-b-private.pem`, kpB.privateKey, { mode: 0o600 });
  writeFileSync(`${SHARED}/authority-b-public.pem`,  kpB.publicKey);
  writeFileSync(`${SHARED}/authority-c-private.pem`, kpC.privateKey, { mode: 0o600 });
  writeFileSync(`${SHARED}/authority-c-public.pem`,  kpC.publicKey);

  console.log("\nFiles written to ./shared:");
  console.log("  addresses.json");
  console.log("  authority-{a,b,c}-private.pem");
  console.log("  authority-{a,b,c}-public.pem");
  console.log("\nDeployment complete.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

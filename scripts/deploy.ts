import { network } from "hardhat";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

async function main() {
  const { viem } = await network.connect();
  const [deployer, authorityA, authorityB, authorityC] =
    await viem.getWalletClients();

  console.log("Deployer:    ", deployer.account.address);
  console.log("Authority A: ", authorityA.account.address);
  console.log("Authority B: ", authorityB.account.address);
  console.log("Authority C: ", authorityC.account.address);

  // ── 1. Deploy AuditLog ───────────────────────────────────────────────────
  console.log("\n[1/6] Deploying AuditLog...");
  const auditLog = await viem.deployContract("AuditLog");
  console.log("AuditLog:             ", auditLog.address);

  // ── 2. Deploy DIDRegistry ────────────────────────────────────────────────
  console.log("\n[2/6] Deploying DIDRegistry...");
  const authorities = [
    authorityA.account.address,
    authorityB.account.address,
    authorityC.account.address,
  ];
  const dids = [
    "did:consortium:authority-a",
    "did:consortium:authority-b",
    "did:consortium:authority-c",
  ];
  const activeKeys   = ["pk-a-placeholder", "pk-b-placeholder", "pk-c-placeholder"];
  const recoveryKeys = ["rk-a-placeholder", "rk-b-placeholder", "rk-c-placeholder"];

  const didRegistry = await viem.deployContract("DIDRegistry", [
    authorities,
    dids,
    activeKeys,
    recoveryKeys,
    auditLog.address,   // nuovo parametro
  ]);
  console.log("DIDRegistry:          ", didRegistry.address);

  // ── 3. Deploy GovernanceContract ─────────────────────────────────────────
  console.log("\n[3/6] Deploying GovernanceContract...");
  const governance = await viem.deployContract("GovernanceContract", [
    authorities,
    dids,
    didRegistry.address,
    auditLog.address,
  ]);
  console.log("GovernanceContract:   ", governance.address);

  // ── 4. Deploy DocumentRegistry ───────────────────────────────────────────
  console.log("\n[4/6] Deploying DocumentRegistry...");
  const documentRegistry = await viem.deployContract("DocumentRegistry", [
    didRegistry.address,
    auditLog.address,
  ]);
  console.log("DocumentRegistry:     ", documentRegistry.address);

  // ── 5. Deploy DocumentAccessControl ──────────────────────────────────────
  console.log("\n[5/6] Deploying DocumentAccessControl...");
  const accessControl = await viem.deployContract("DocumentAccessControl", [
    didRegistry.address,
    documentRegistry.address,
    auditLog.address,
  ]);
  console.log("DocumentAccessControl:", accessControl.address);

  // ── 6. Deploy KeyShareRegistry ────────────────────────────────────────────
  console.log("\n[6/6] Deploying KeyShareRegistry...");
  const keyShareRegistry = await viem.deployContract("KeyShareRegistry", [
    didRegistry.address,
    auditLog.address,
  ]);
  console.log("KeyShareRegistry:     ", keyShareRegistry.address);

  // ── Wire up contracts ────────────────────────────────────────────────────
  console.log("\n[Setup] Wiring contracts...");

  // DIDRegistry
  await didRegistry.write.setGovernanceContract([governance.address]);
  await didRegistry.write.setAccessControl([accessControl.address]);

  // DocumentRegistry
  await documentRegistry.write.setAccessControl([accessControl.address]);
  await documentRegistry.write.setGovernanceContract([governance.address]);

  // DocumentAccessControl
  await accessControl.write.setGovernanceContract([governance.address]);

  // AuditLog: register all writers then freeze
  await auditLog.write.addWriter([didRegistry.address]);
  await auditLog.write.addWriter([governance.address]);
  await auditLog.write.addWriter([documentRegistry.address]);
  await auditLog.write.addWriter([accessControl.address]);
  await auditLog.write.addWriter([keyShareRegistry.address]);
  await auditLog.write.renounceAdmin();
  console.log("AuditLog writers frozen.");

  // ── Save addresses ───────────────────────────────────────────────────────
  const addresses = {
    auditLog:           auditLog.address,
    didRegistry:        didRegistry.address,
    governanceContract: governance.address,
    documentRegistry:   documentRegistry.address,
    accessControl:      accessControl.address,
    keyShareRegistry:   keyShareRegistry.address,
    authorities: {
      a: authorityA.account.address,
      b: authorityB.account.address,
      c: authorityC.account.address,
    },
    dids: {
      a: dids[0],
      b: dids[1],
      c: dids[2],
    },
  };

  try {
    mkdirSync("/shared", { recursive: true });
    writeFileSync("/shared/addresses.json", JSON.stringify(addresses, null, 2));
    console.log("Addresses written to /shared/addresses.json");
  } catch {
    // Running locally
  }

  writeFileSync(
    join(process.cwd(), "scripts", "addresses.json"),
    JSON.stringify(addresses, null, 2)
  );
  console.log("Addresses written to scripts/addresses.json");
  console.log("\nDeployment complete.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
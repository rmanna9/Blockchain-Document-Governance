import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { keccak256, toBytes, toHex, encodeFunctionData } from "viem";

describe("DocumentRegistry", async () => {
  const { viem } = await network.connect();

  async function setup() {
    const [deployer, authorityA, authorityB, user1, user2, outsider] =
      await viem.getWalletClients();

    const auditLog = await viem.deployContract("AuditLog");

    const didRegistry = await viem.deployContract("DIDRegistry", [
      [authorityA.account.address, authorityB.account.address],
      ["did:consortium:authority-a", "did:consortium:authority-b"],
      ["pk-a", "pk-b"],
      ["rk-a", "rk-b"],
      auditLog.address,
    ]);

    const governance = await viem.deployContract("GovernanceContract", [
      [authorityA.account.address, authorityB.account.address],
      ["did:consortium:authority-a", "did:consortium:authority-b"],
      didRegistry.address,
      auditLog.address,
    ]);

    const documentRegistry = await viem.deployContract("DocumentRegistry", [
      didRegistry.address,
      auditLog.address,
    ]);

    const accessControl = await viem.deployContract("DocumentAccessControl", [
      didRegistry.address,
      documentRegistry.address,
      auditLog.address,
    ]);

    await auditLog.write.addWriter([didRegistry.address]);
    await auditLog.write.addWriter([governance.address]);
    await auditLog.write.addWriter([documentRegistry.address]);
    await auditLog.write.addWriter([accessControl.address]);
    await auditLog.write.renounceAdmin();

    await didRegistry.write.setGovernanceContract([governance.address]);
    await didRegistry.write.setAccessControl([accessControl.address]);
    await documentRegistry.write.setAccessControl([accessControl.address]);
    await documentRegistry.write.setGovernanceContract([governance.address]);
    await accessControl.write.setGovernanceContract([governance.address]);

    // Register users
    await didRegistry.write.registerUser(
      ["did:consortium:user-1", "pk-user1", "rk-user1", user1.account.address, 0n],
      { account: authorityA.account }
    );
    await didRegistry.write.registerUser(
      ["did:consortium:user-2", "pk-user2", "rk-user2", user2.account.address, 0n],
      { account: authorityB.account }
    );

    // Grant canCreate to user1
    await accessControl.write.grantCreate(
      ["did:consortium:user-1", 0n],
      { account: authorityA.account }
    );

    const zero = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
    const docHash  = keccak256(toBytes("document content v1"));
    const docHash2 = keccak256(toBytes("document content v2"));
    const sigA     = toHex(toBytes("sig-authority-a"));
    const sigAv2   = toHex(toBytes("sig-authority-a-v2"));

    return {
      documentRegistry,
      accessControl,
      didRegistry,
      governance,
      auditLog,
      deployer,
      authorityA,
      authorityB,
      user1,
      user2,
      outsider,
      zero,
      docHash,
      docHash2,
      sigA,
      sigAv2,
    };
  }

  async function increaseTime(seconds: number) {
    const client = await viem.getPublicClient();
    await (client as any).request({ method: "evm_increaseTime", params: [seconds] });
    await (client as any).request({ method: "evm_mine", params: [] });
  }

  async function deactivateViaGovernance(
    ctx: Awaited<ReturnType<typeof setup>>,
    did: string
  ) {
    const calldata = encodeFunctionData({
      abi: [{
        name: "deactivate",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [{ name: "did", type: "string" }],
        outputs: []
      }],
      functionName: "deactivate",
      args: [did as any],
    });

    await ctx.governance.write.propose(
      [`Deactivate ${did}`, ctx.didRegistry.address, calldata, 0],
      { account: ctx.authorityA.account }
    );

    const client = await viem.getPublicClient();
    await (client as any).request({ method: "evm_increaseTime", params: [3601] });
    await (client as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.castVote([1n, 1], { account: ctx.authorityA.account });
    await ctx.governance.write.castVote([1n, 1], { account: ctx.authorityB.account });

    await (client as any).request({ method: "evm_increaseTime", params: [3 * 24 * 3600 + 1] });
    await (client as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.queue([1n], { account: ctx.authorityA.account });

    await (client as any).request({ method: "evm_increaseTime", params: [24 * 3600 + 1] });
    await (client as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.execute([1n], { account: ctx.authorityA.account });
  }

  // Helper: full certification flow
  async function certifyDoc(
    ctx: Awaited<ReturnType<typeof setup>>,
    docHash: `0x${string}`,
    previousHash: `0x${string}`,
    ownerDID: string = ""
  ) {
    await ctx.documentRegistry.write.requestCertification(
      [docHash, previousHash, ownerDID],
      { account: ctx.user1.account }
    );
    await ctx.documentRegistry.write.certify(
      [docHash, ctx.sigA],
      { account: ctx.authorityA.account }
    );
  }

  // ── RF4/RF5: Phase 1 — Hash commitment ───────────────────────────────────

  it("should allow registered user with canCreate to request certification — RF5", async () => {
    const { documentRegistry, user1, docHash, zero } = await setup();

    await documentRegistry.write.requestCertification(
      [docHash, zero, ""],
      { account: user1.account }
    );

    const record = await documentRegistry.read.getRecord([docHash]);
    assert.equal(record.status, 0); // Pending
    assert.equal(record.creatorDID, "did:consortium:user-1");
  });

  it("should reject requestCertification from user without canCreate — RF5", async () => {
    const { documentRegistry, user2, docHash, zero } = await setup();

    await assert.rejects(
      documentRegistry.write.requestCertification(
        [docHash, zero, ""],
        { account: user2.account }
      )
    );
  });

  it("should reject requestCertification from unregistered caller", async () => {
    const { documentRegistry, outsider, docHash, zero } = await setup();

    await assert.rejects(
      documentRegistry.write.requestCertification(
        [docHash, zero, ""],
        { account: outsider.account }
      )
    );
  });

  it("should default ownerDID to creatorDID for new document — WP2 Phase 1", async () => {
    const { documentRegistry, user1, docHash, zero } = await setup();

    await documentRegistry.write.requestCertification(
      [docHash, zero, ""],
      { account: user1.account }
    );

    const record = await documentRegistry.read.getRecord([docHash]);
    assert.equal(record.ownerDID, "did:consortium:user-1");
    assert.equal(record.creatorDID, "did:consortium:user-1");
  });

  it("should allow specifying a different ownerDID", async () => {
    const { documentRegistry, user1, docHash, zero } = await setup();

    await documentRegistry.write.requestCertification(
      [docHash, zero, "did:consortium:user-2"],
      { account: user1.account }
    );

    const record = await documentRegistry.read.getRecord([docHash]);
    assert.equal(record.ownerDID, "did:consortium:user-2");
    assert.equal(record.creatorDID, "did:consortium:user-1");
  });

  it("should reject duplicate hash", async () => {
    const { documentRegistry, user1, docHash, zero } = await setup();

    await documentRegistry.write.requestCertification(
      [docHash, zero, ""],
      { account: user1.account }
    );

    await assert.rejects(
      documentRegistry.write.requestCertification(
        [docHash, zero, ""],
        { account: user1.account }
      )
    );
  });

  // ── RF4/RF5: Phase 3 — Certification ─────────────────────────────────────

  it("should allow domain authority to certify a pending document — RF4 Phase 3", async () => {
    const ctx = await setup();

    await ctx.documentRegistry.write.requestCertification(
      [ctx.docHash, ctx.zero, ""],
      { account: ctx.user1.account }
    );

    await ctx.documentRegistry.write.certify(
      [ctx.docHash, ctx.sigA],
      { account: ctx.authorityA.account }
    );

    const record = await ctx.documentRegistry.read.getRecord([ctx.docHash]);
    assert.equal(record.status, 1); // Certified
    assert.equal(record.certifiedBy.toLowerCase(), ctx.authorityA.account.address.toLowerCase());
    assert.equal(record.version, 1n);
  });

  it("should reject certification by non-domain authority", async () => {
    const ctx = await setup();

    await ctx.documentRegistry.write.requestCertification(
      [ctx.docHash, ctx.zero, ""],
      { account: ctx.user1.account }
    );

    await assert.rejects(
      ctx.documentRegistry.write.certify(
        [ctx.docHash, ctx.sigA],
        { account: ctx.authorityB.account }
      )
    );
  });

  it("should reject certifying a non-pending document", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    await assert.rejects(
      ctx.documentRegistry.write.certify(
        [ctx.docHash, ctx.sigA],
        { account: ctx.authorityA.account }
      )
    );
  });

  it("should assign canRead and canUpdate to creator at certification — RF5 Phase 3.1", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    const hasRead = await ctx.accessControl.read.hasPermission([
      "did:consortium:user-1", ctx.docHash, 1
    ]);
    const hasUpdate = await ctx.accessControl.read.hasPermission([
      "did:consortium:user-1", ctx.docHash, 2
    ]);

    assert.equal(hasRead, true);
    assert.equal(hasUpdate, true);
  });

  // ── RF4: CID storage — Phase 4 ────────────────────────────────────────────

  it("should allow certifying authority to store CID — RF4 Phase 4", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    await ctx.documentRegistry.write.storeCID(
      [ctx.docHash, "bafkreigh2akiscaild"],
      { account: ctx.authorityA.account }
    );

    const cid = await ctx.documentRegistry.read.getCID([ctx.docHash]);
    assert.equal(cid, "bafkreigh2akiscaild");
  });

  it("should reject CID storage by non-certifying authority", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    await assert.rejects(
      ctx.documentRegistry.write.storeCID(
        [ctx.docHash, "bafkreigh2akiscaild"],
        { account: ctx.authorityB.account }
      )
    );
  });

  // ── RF4: Versioning ───────────────────────────────────────────────────────

  it("should certify a new version and link the version chain — RF4", async () => {
    const ctx = await setup();

    // Certify v1
    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    // Grant canUpdate to user1 for v2 (already has it from certification)
    // Request v2
    await ctx.documentRegistry.write.requestCertification(
      [ctx.docHash2, ctx.docHash, ""],
      { account: ctx.user1.account }
    );
    await ctx.documentRegistry.write.certify(
      [ctx.docHash2, ctx.sigAv2],
      { account: ctx.authorityA.account }
    );

    const v1 = await ctx.documentRegistry.read.getRecord([ctx.docHash]);
    const v2 = await ctx.documentRegistry.read.getRecord([ctx.docHash2]);

    assert.equal(v2.version, 2n);
    assert.equal(v2.previousVersion, ctx.docHash);
    assert.equal(v1.followingVersion, ctx.docHash2);
  });

  it("should default ownerDID to previous version ownerDID on update — WP2 Phase 1", async () => {
    const ctx = await setup();

    // v1 with explicit owner = user2
    await ctx.documentRegistry.write.requestCertification(
      [ctx.docHash, ctx.zero, "did:consortium:user-2"],
      { account: ctx.user1.account }
    );
    await ctx.documentRegistry.write.certify(
      [ctx.docHash, ctx.sigA],
      { account: ctx.authorityA.account }
    );

    // v2 with no explicit owner — should default to user2 (owner of v1)
    await ctx.documentRegistry.write.requestCertification(
      [ctx.docHash2, ctx.docHash, ""],
      { account: ctx.user1.account }
    );

    const v2 = await ctx.documentRegistry.read.getRecord([ctx.docHash2]);
    assert.equal(v2.ownerDID, "did:consortium:user-2");
  });

  it("should reject update to a non-latest version", async () => {
    const ctx = await setup();

    const docHash3 = keccak256(toBytes("document content v3"));

    await certifyDoc(ctx, ctx.docHash, ctx.zero);
    await ctx.documentRegistry.write.requestCertification(
      [ctx.docHash2, ctx.docHash, ""],
      { account: ctx.user1.account }
    );
    await ctx.documentRegistry.write.certify(
      [ctx.docHash2, ctx.sigAv2],
      { account: ctx.authorityA.account }
    );

    // Try to update v1 again — should fail
    await assert.rejects(
      ctx.documentRegistry.write.requestCertification(
        [docHash3, ctx.docHash, ""],
        { account: ctx.user1.account }
      )
    );
  });

  it("should reject update without canUpdate permission — RF5", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    // user2 has no canUpdate on docHash
    await assert.rejects(
      ctx.documentRegistry.write.requestCertification(
        [ctx.docHash2, ctx.docHash, ""],
        { account: ctx.user2.account }
      )
    );
  });

  // ── RF4: Revocation ───────────────────────────────────────────────────────

  it("should allow certifying authority to revoke — RF4", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    await ctx.documentRegistry.write.revoke(
      [ctx.docHash, "policy violation"],
      { account: ctx.authorityA.account }
    );

    const status = await ctx.documentRegistry.read.getStatus([ctx.docHash]);
    assert.equal(status, 2); // Revoked
  });

  it("should reject revocation by non-certifying authority", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    await assert.rejects(
      ctx.documentRegistry.write.revoke(
        [ctx.docHash, "unauthorized"],
        { account: ctx.authorityB.account }
      )
    );
  });

  it("should reject double revocation", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);
    await ctx.documentRegistry.write.revoke(
      [ctx.docHash, "reason"],
      { account: ctx.authorityA.account }
    );

    await assert.rejects(
      ctx.documentRegistry.write.revoke(
        [ctx.docHash, "reason again"],
        { account: ctx.authorityA.account }
      )
    );
  });

  // ── Lazy authority check on documents ─────────────────────────────────────

  it("getStatus should return Revoked if certifying authority is deactivated — lazy check", async () => {
    const ctx = await setup();

    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    // Deactivate authorityA via governance
    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    // Document is still Certified in storage but getStatus returns Revoked
    const status = await ctx.documentRegistry.read.getStatus([ctx.docHash]);
    assert.equal(status, 2); // Revoked — lazy check
  });

  it("should reject requestCertification from user whose authority is deactivated — lazy check", async () => {
    const ctx = await setup();

    // Deactivate authorityA
    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    // user1 is under authorityA — isFullyActive = false
    await assert.rejects(
      ctx.documentRegistry.write.requestCertification(
        [ctx.docHash, ctx.zero, ""],
        { account: ctx.user1.account }
      )
    );
  });

  it("should reject update from user with canUpdate but deactivated authority — lazy check", async () => {
    const ctx = await setup();

    // Certify v1 while authorityA is active
    await certifyDoc(ctx, ctx.docHash, ctx.zero);

    // Now deactivate authorityA
    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    // user1 has canUpdate on docHash but its authority is deactivated
    await assert.rejects(
      ctx.documentRegistry.write.requestCertification(
        [ctx.docHash2, ctx.docHash, ""],
        { account: ctx.user1.account }
      )
    );
  });
});
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { keccak256, toBytes, toHex, encodeFunctionData } from "viem";

describe("DocumentAccessControl", async () => {
  const { viem } = await network.connect();

  async function setup() {
    const [deployer, authorityA, authorityB, user1, user2, user3, outsider] =
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

    // Register users — all under authorityA for simplicity
    await didRegistry.write.registerUser(
      ["did:consortium:user-1", "pk-u1", "rk-u1", user1.account.address, 0n],
      { account: authorityA.account }
    );
    await didRegistry.write.registerUser(
      ["did:consortium:user-2", "pk-u2", "rk-u2", user2.account.address, 0n],
      { account: authorityA.account }
    );
    await didRegistry.write.registerUser(
      ["did:consortium:user-3", "pk-u3", "rk-u3", user3.account.address, 0n],
      { account: authorityA.account }
    );

    const zero    = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
    const docHash = keccak256(toBytes("document content"));
    const sigA    = toHex(toBytes("sig-authority-a"));

    async function certifyDoc() {
      await accessControl.write.grantCreate(
        ["did:consortium:user-1", 0n],
        { account: authorityA.account }
      );
      await documentRegistry.write.requestCertification(
        [docHash, zero, ""],
        { account: user1.account }
      );
      await documentRegistry.write.certify(
        [docHash, sigA],
        { account: authorityA.account }
      );
    }

    return {
      accessControl,
      documentRegistry,
      didRegistry,
      governance,
      auditLog,
      deployer,
      authorityA,
      authorityB,
      user1,
      user2,
      user3,
      outsider,
      zero,
      docHash,
      sigA,
      certifyDoc,
    };
  }

  async function increaseTime(seconds: number) {
    const client = await viem.getPublicClient();
    await (client as any).request({ method: "evm_increaseTime", params: [seconds] });
    await (client as any).request({ method: "evm_mine", params: [] });
  }

  async function deactivateViaGovernance(
    ctx: Awaited<ReturnType<typeof setup>>,
    did: string,
    proposalId: bigint = 1n
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

    await ctx.governance.write.castVote([proposalId, 1], { account: ctx.authorityA.account });
    await ctx.governance.write.castVote([proposalId, 1], { account: ctx.authorityB.account });

    await (client as any).request({ method: "evm_increaseTime", params: [3 * 24 * 3600 + 1] });
    await (client as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.queue([proposalId], { account: ctx.authorityA.account });

    await (client as any).request({ method: "evm_increaseTime", params: [24 * 3600 + 1] });
    await (client as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.execute([proposalId], { account: ctx.authorityA.account });
  }

  // ── RF5: canCreate ────────────────────────────────────────────────────────

  it("should grant canCreate to user by domain authority — RF5", async () => {
    const { accessControl, authorityA } = await setup();

    await accessControl.write.grantCreate(
      ["did:consortium:user-1", 0n],
      { account: authorityA.account }
    );

    const has = await accessControl.read.hasCreatePermission(["did:consortium:user-1"]);
    assert.equal(has, true);
  });

  it("should reject canCreate grant by non-domain authority", async () => {
    const { accessControl, authorityB } = await setup();

    await assert.rejects(
      accessControl.write.grantCreate(
        ["did:consortium:user-1", 0n],
        { account: authorityB.account }
      )
    );
  });

  it("hasCreatePermission should return false if authority is deactivated — lazy check", async () => {
    const ctx = await setup();

    await ctx.accessControl.write.grantCreate(
      ["did:consortium:user-1", 0n],
      { account: ctx.authorityA.account }
    );

    // Deactivate authorityA
    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    const has = await ctx.accessControl.read.hasCreatePermission(["did:consortium:user-1"]);
    assert.equal(has, false);
  });

  // ── RF5: Automatic permission assignment at certification ─────────────────

  it("should assign canRead and canUpdate to creator at certification — RF5 Phase 3.1", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    const hasRead   = await ctx.accessControl.read.hasPermission(["did:consortium:user-1", ctx.docHash, 1]);
    const hasUpdate = await ctx.accessControl.read.hasPermission(["did:consortium:user-1", ctx.docHash, 2]);

    assert.equal(hasRead, true);
    assert.equal(hasUpdate, true);
  });

  it("should not assign permissions to unrelated user at certification", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    const hasRead = await ctx.accessControl.read.hasPermission(["did:consortium:user-2", ctx.docHash, 1]);
    assert.equal(hasRead, false);
  });

  it("hasPermission should return false if document is revoked", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await ctx.documentRegistry.write.revoke(
      [ctx.docHash, "reason"],
      { account: ctx.authorityA.account }
    );

    const hasRead = await ctx.accessControl.read.hasPermission(["did:consortium:user-1", ctx.docHash, 1]);
    assert.equal(hasRead, false);
  });

  it("hasPermission should return false if holder authority is deactivated — lazy check", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    const hasRead = await ctx.accessControl.read.hasPermission(["did:consortium:user-1", ctx.docHash, 1]);
    assert.equal(hasRead, false);
  });

  // ── RF5: checkAndApproveRead ──────────────────────────────────────────────

  it("should allow creator to approve read — RF5", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user1.account }
    );
  });

  it("should reject read approval for user without permission", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user2.account }
      )
    );
  });

  it("should reject read approval if user authority is deactivated — lazy check", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user1.account }
      )
    );
  });

  it("should reject read approval on revoked document", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await ctx.documentRegistry.write.revoke(
      [ctx.docHash, "revoked"],
      { account: ctx.authorityA.account }
    );

    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user1.account }
      )
    );
  });

  // ── RF7: Delegation ───────────────────────────────────────────────────────

  it("should allow creator to delegate canRead to another user — RF7", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user1.account }
    );

    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user2.account }
    );
  });

  it("should reject delegation of canCreate — RF7", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await assert.rejects(
      ctx.accessControl.write.delegate(
        ["did:consortium:user-2", ctx.docHash, 0, false, false, false, 0n],
        { account: ctx.user1.account }
      )
    );
  });

  it("should reject delegation when caller has no permission", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await assert.rejects(
      ctx.accessControl.write.delegate(
        ["did:consortium:user-3", ctx.docHash, 1, false, false, false, 0n],
        { account: ctx.user2.account }
      )
    );
  });

  it("should reject delegation if delegator authority is deactivated — lazy check", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    await assert.rejects(
      ctx.accessControl.write.delegate(
        ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
        { account: ctx.user1.account }
      )
    );
  });

  it("should reject checkAndApproveRead for delegatee with deactivated authority — lazy check", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // Delegate canRead to user2 while everything is active
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user1.account }
    );

    // Verify user2 has access
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user2.account }
    );

    // Now deactivate authorityA (domain of user2)
    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    // user2 can no longer read — lazy check
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user2.account }
      )
    );
  });

  // ── RF7: Cascading revocation ─────────────────────────────────────────────

  it("should cascade revoke delegations when permission is revoked — RF7", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 delegates to user2
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user1.account }
    );

    // user2 has access
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user2.account }
    );

    // Authority revokes root permission
    const publicClient = await viem.getPublicClient();
    const events = await publicClient.getContractEvents({
      address: ctx.accessControl.address,
      abi: ctx.accessControl.abi,
      eventName: "PermissionGranted",
      fromBlock: 0n,
    });
    const canReadEvent = events.find(
      (e: any) => e.args.holderDID === "did:consortium:user-1" && e.args.actionType === 1
    );
    const permId = canReadEvent!.args.permissionId as `0x${string}`;

    await ctx.accessControl.write.revokePermission(
      [permId],
      { account: ctx.authorityA.account }
    );

    // user2 delegation is cascade-revoked
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user2.account }
      )
    );
  });

  it("should allow delegatee to revoke sub-delegation — RF7", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 delegates to user2 with canDelegate=true
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, true, true, false, 0n],
      { account: ctx.user1.account }
    );

    // user2 delegates to user3
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-3", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user2.account }
    );

    // user3 has access
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user3.account }
    );

    // Get user2→user3 delegation id
    const publicClient = await viem.getPublicClient();
    const delEvents = await publicClient.getContractEvents({
      address: ctx.accessControl.address,
      abi: ctx.accessControl.abi,
      eventName: "DelegationIssued",
      fromBlock: 0n,
    });
    const delId = delEvents[1].args.delegationId as `0x${string}`;

    await ctx.accessControl.write.revokeDelegation(
      [delId],
      { account: ctx.user2.account }
    );

    // user3 no longer has access
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user3.account }
      )
    );
  });

  // ── invalidateUserPermissions — WP2 §Entity Deregistration ───────────────

  it("should invalidate all permissions when user is deactivated — WP2 §Entity Deregistration", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 has canRead — verify
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user1.account }
    );

    // Deactivate user1 via domain authority
    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-1"],
      { account: ctx.authorityA.account }
    );

    // Permission record should be inactive
    const hasRead = await ctx.accessControl.read.hasPermission([
      "did:consortium:user-1", ctx.docHash, 1
    ]);
    assert.equal(hasRead, false);
  });

  it("should cascade invalidate delegations when user is deactivated — WP2 §Entity Deregistration", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 delegates to user2
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user1.account }
    );

    // user2 has access
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user2.account }
    );

    // Deactivate user1 — should cascade to user2's delegation
    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-1"],
      { account: ctx.authorityA.account }
    );

    // user2 delegation is cascade-revoked
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user2.account }
      )
    );
  });

  // ── Lazy check: delegatee deactivated ────────────────────────────────────

  it("should reject checkAndApproveRead for deactivated delegatee — user deactivated", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 delegates to user2
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user1.account }
    );

    // user2 has access
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user2.account }
    );

    // Deactivate user2 directly
    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-2"],
      { account: ctx.authorityA.account }
    );

    // user2 deactivated — cannot read
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user2.account }
      )
    );
  });

  it("should reject checkAndApproveRead in chain when intermediate delegator is deactivated", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 → user2 (canDelegate=true) → user3
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, true, true, false, 0n],
      { account: ctx.user1.account }
    );
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-3", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user2.account }
    );

    // user3 has access
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user3.account }
    );

    // Deactivate user2 (intermediate node)
    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-2"],
      { account: ctx.authorityA.account }
    );

    // user3 delegation was cascade-revoked when user2 was deactivated
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user3.account }
      )
    );
  });

  it("should reject delegation to deactivated user", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // Deactivate user2
    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-2"],
      { account: ctx.authorityA.account }
    );

    // user1 cannot delegate to deactivated user2
    await assert.rejects(
      ctx.accessControl.write.delegate(
        ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
        { account: ctx.user1.account }
      )
    );
  });

  it("should reject delegation from deactivated user", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // Deactivate user1
    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-1"],
      { account: ctx.authorityA.account }
    );

    // user1 deactivated — cannot delegate
    await assert.rejects(
      ctx.accessControl.write.delegate(
        ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
        { account: ctx.user1.account }
      )
    );
  });

  it("should reject checkAndApproveRead in chain when root user is deactivated — cascade", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 (root) → user2 → user3
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, true, true, false, 0n],
      { account: ctx.user1.account }
    );
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-3", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user2.account }
    );

    // user2 and user3 have access
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user2.account }
    );
    await ctx.accessControl.write.checkAndApproveRead(
      [ctx.docHash],
      { account: ctx.user3.account }
    );

    // Deactivate user1 (root) — invalidateUserPermissions cascades to user2 and user3
    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-1"],
      { account: ctx.authorityA.account }
    );

    // user2 delegation cascade-revoked
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user2.account }
      )
    );

    // user3 delegation cascade-revoked
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user3.account }
      )
    );
  });

  // ── canPresentExternally — WP2 §External Verification ────────────────────

  it("creator should be able to present externally — has delegable canRead", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // Creator has canRead with canDelegate=true delegableRead=true
    // assigned at certification — can present externally
    const can = await ctx.accessControl.read.canPresentExternally([
      "did:consortium:user-1", ctx.docHash
    ]);
    assert.equal(can, true);
  });

  it("user without canRead cannot present externally", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    const can = await ctx.accessControl.read.canPresentExternally([
      "did:consortium:user-2", ctx.docHash
    ]);
    assert.equal(can, false);
  });

  it("delegatee with canDelegate=true can present externally", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 delegates canRead with canDelegate=true to user2
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, true, true, false, 0n],
      { account: ctx.user1.account }
    );

    const can = await ctx.accessControl.read.canPresentExternally([
      "did:consortium:user-2", ctx.docHash
    ]);
    assert.equal(can, true);
  });

  it("delegatee with canDelegate=false cannot present externally", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    // user1 delegates canRead with canDelegate=false to user2
    await ctx.accessControl.write.delegate(
      ["did:consortium:user-2", ctx.docHash, 1, false, false, false, 0n],
      { account: ctx.user1.account }
    );

    const can = await ctx.accessControl.read.canPresentExternally([
      "did:consortium:user-2", ctx.docHash
    ]);
    assert.equal(can, false);
  });

  it("canPresentExternally returns false if document is revoked", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await ctx.documentRegistry.write.revoke(
      [ctx.docHash, "revoked"],
      { account: ctx.authorityA.account }
    );

    const can = await ctx.accessControl.read.canPresentExternally([
      "did:consortium:user-1", ctx.docHash
    ]);
    assert.equal(can, false);
  });

  it("canPresentExternally returns false if holder authority is deactivated", async () => {
    const ctx = await setup();
    await ctx.certifyDoc();

    await deactivateViaGovernance(ctx, "did:consortium:authority-a");

    const can = await ctx.accessControl.read.canPresentExternally([
      "did:consortium:user-1", ctx.docHash
    ]);
    assert.equal(can, false);
  });
});
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";

describe("DIDRegistry", async () => {
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

    // Deploy a minimal governance mock — just needs to be an address
    // that DIDRegistry accepts as governance
    const governance = await viem.deployContract("GovernanceContract", [
      [authorityA.account.address, authorityB.account.address],
      ["did:consortium:authority-a", "did:consortium:authority-b"],
      didRegistry.address,
      auditLog.address,
    ]);

    await auditLog.write.addWriter([didRegistry.address]);
    await auditLog.write.addWriter([governance.address]);
    await auditLog.write.renounceAdmin();

    await didRegistry.write.setGovernanceContract([governance.address]);

    return {
      didRegistry,
      auditLog,
      governance,
      deployer,
      authorityA,
      authorityB,
      user1,
      user2,
      outsider,
    };
  }

  // Helper: register user1 under authorityA
  async function registerUser1(ctx: Awaited<ReturnType<typeof setup>>) {
    await ctx.didRegistry.write.registerUser(
      ["did:consortium:user-1", "pk-user1", "rk-user1", ctx.user1.account.address, 0n],
      { account: ctx.authorityA.account }
    );
  }

  // ── RF1: Genesis ──────────────────────────────────────────────────────────

  it("should register founding authorities in constructor", async () => {
    const { didRegistry, authorityA, authorityB } = await setup();

    const docA = await didRegistry.read.resolve(["did:consortium:authority-a"]);
    const docB = await didRegistry.read.resolve(["did:consortium:authority-b"]);

    assert.equal(docA.isActive, true);
    assert.equal(docB.isActive, true);
    assert.equal(docA.entityAddress.toLowerCase(), authorityA.account.address.toLowerCase());
    assert.equal(docB.entityAddress.toLowerCase(), authorityB.account.address.toLowerCase());
    assert.equal(docA.domainAuthority, "0x0000000000000000000000000000000000000000");
  });

  it("should resolve DID from address", async () => {
    const { didRegistry, authorityA } = await setup();
    const did = await didRegistry.read.lookupDID([authorityA.account.address]);
    assert.equal(did, "did:consortium:authority-a");
  });

  it("should return active public key", async () => {
    const { didRegistry } = await setup();
    const pk = await didRegistry.read.getActivePublicKey(["did:consortium:authority-a"]);
    assert.equal(pk, "pk-a");
  });

  // ── RF1: User registration ────────────────────────────────────────────────

  it("should allow authority to register a user", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    const doc = await ctx.didRegistry.read.resolve(["did:consortium:user-1"]);
    assert.equal(doc.isActive, true);
    assert.equal(doc.entityAddress.toLowerCase(), ctx.user1.account.address.toLowerCase());
    assert.equal(doc.domainAuthority.toLowerCase(), ctx.authorityA.account.address.toLowerCase());
    assert.equal(doc.entityType, 1); // User
  });

  it("should set domainAuthority to the registering authority", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    const doc = await ctx.didRegistry.read.resolve(["did:consortium:user-1"]);
    assert.equal(doc.domainAuthority.toLowerCase(), ctx.authorityA.account.address.toLowerCase());
  });

  it("should reject user registration from non-authority", async () => {
    const ctx = await setup();
    await assert.rejects(
      ctx.didRegistry.write.registerUser(
        ["did:consortium:user-1", "pk-user1", "rk-user1", ctx.user1.account.address, 0n],
        { account: ctx.outsider.account }
      )
    );
  });

  it("should reject duplicate DID registration", async () => {
    const ctx = await setup();
    await registerUser1(ctx);
    await assert.rejects(
      ctx.didRegistry.write.registerUser(
        ["did:consortium:user-1", "pk-user2", "rk-user2", ctx.user2.account.address, 0n],
        { account: ctx.authorityA.account }
      )
    );
  });

  it("should reject duplicate address registration", async () => {
    const ctx = await setup();
    await registerUser1(ctx);
    await assert.rejects(
      ctx.didRegistry.write.registerUser(
        ["did:consortium:user-1b", "pk-user1b", "rk-user1b", ctx.user1.account.address, 0n],
        { account: ctx.authorityA.account }
      )
    );
  });

  // ── RF1: Auditor registration via governance ──────────────────────────────

  it("should reject auditor registration from non-governance", async () => {
    const ctx = await setup();
    await assert.rejects(
      ctx.didRegistry.write.registerAuditor(
        ["did:consortium:auditor-1", "pk-aud", "rk-aud", ctx.outsider.account.address],
        { account: ctx.authorityA.account }
      )
    );
  });

  // ── RF1: Deactivation ─────────────────────────────────────────────────────

  it("should allow domain authority to deactivate its user — RF1", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-1"],
      { account: ctx.authorityA.account }
    );

    const isActive = await ctx.didRegistry.read.isActive(["did:consortium:user-1"]);
    assert.equal(isActive, false);
  });

  it("should reject deactivation by non-domain authority", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    await assert.rejects(
      ctx.didRegistry.write.deactivate(
        ["did:consortium:user-1"],
        { account: ctx.authorityB.account }
      )
    );
  });

  it("should reject deactivation of authority by non-governance — RF3", async () => {
    const ctx = await setup();
    await assert.rejects(
      ctx.didRegistry.write.deactivate(
        ["did:consortium:authority-a"],
        { account: ctx.authorityB.account }
      )
    );
  });

  it("should reject double deactivation", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-1"],
      { account: ctx.authorityA.account }
    );

    await assert.rejects(
      ctx.didRegistry.write.deactivate(
        ["did:consortium:user-1"],
        { account: ctx.authorityA.account }
      )
    );
  });

  // ── RF3: Governance can deactivate any entity ─────────────────────────────

  it("should allow governance to deactivate a user bypassing domain authority — RF3", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    // Governance encodes deactivate() in calldata and executes via proposal
    // For this test we verify the governance contract CAN call deactivate()
    // by calling it directly as the governance address using low-level interaction
    const { encodeFunctionData } = await import("viem");
    const calldata = encodeFunctionData({
      abi: [{
        name: "deactivate",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [{ name: "did", type: "string" }],
        outputs: []
      }],
      functionName: "deactivate",
      args: ["did:consortium:user-1"],
    });

    // Execute via governance proposal
    await ctx.governance.write.propose(
      ["Remove user-1", ctx.didRegistry.address, calldata, 0],
      { account: ctx.authorityA.account }
    );

    const publicClient = await viem.getPublicClient();
    await (publicClient as any).request({ method: "evm_increaseTime", params: [3601] });
    await (publicClient as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.castVote([1n, 1], { account: ctx.authorityA.account });
    await ctx.governance.write.castVote([1n, 1], { account: ctx.authorityB.account });

    await (publicClient as any).request({ method: "evm_increaseTime", params: [3 * 24 * 3600 + 1] });
    await (publicClient as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.queue([1n], { account: ctx.authorityA.account });

    await (publicClient as any).request({ method: "evm_increaseTime", params: [24 * 3600 + 1] });
    await (publicClient as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.execute([1n], { account: ctx.authorityA.account });

    const isActive = await ctx.didRegistry.read.isActive(["did:consortium:user-1"]);
    assert.equal(isActive, false);
  });

  // ── Lazy authority check: isFullyActive() ─────────────────────────────────

  it("isFullyActive should return true for active user with active authority", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    const result = await ctx.didRegistry.read.isFullyActive(["did:consortium:user-1"]);
    assert.equal(result, true);
  });

  it("isFullyActive should return false for deactivated user", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    await ctx.didRegistry.write.deactivate(
      ["did:consortium:user-1"],
      { account: ctx.authorityA.account }
    );

    const result = await ctx.didRegistry.read.isFullyActive(["did:consortium:user-1"]);
    assert.equal(result, false);
  });

  it("isFullyActive should return false for user whose authority was deactivated — lazy check", async () => {
    const ctx = await setup();
    await registerUser1(ctx);

    // Governance deactivates authorityA
    const { encodeFunctionData } = await import("viem");
    const calldata = encodeFunctionData({
      abi: [{
        name: "deactivate",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [{ name: "did", type: "string" }],
        outputs: []
      }],
      functionName: "deactivate",
      args: ["did:consortium:authority-a"],
    });

    await ctx.governance.write.propose(
      ["Remove authority-a", ctx.didRegistry.address, calldata, 0],
      { account: ctx.authorityA.account }
    );

    const publicClient = await viem.getPublicClient();
    await (publicClient as any).request({ method: "evm_increaseTime", params: [3601] });
    await (publicClient as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.castVote([1n, 1], { account: ctx.authorityA.account });
    await ctx.governance.write.castVote([1n, 1], { account: ctx.authorityB.account });

    await (publicClient as any).request({ method: "evm_increaseTime", params: [3 * 24 * 3600 + 1] });
    await (publicClient as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.queue([1n], { account: ctx.authorityA.account });

    await (publicClient as any).request({ method: "evm_increaseTime", params: [24 * 3600 + 1] });
    await (publicClient as any).request({ method: "evm_mine", params: [] });

    await ctx.governance.write.execute([1n], { account: ctx.authorityA.account });

    // user1 is still isActive=true individually
    const isActive = await ctx.didRegistry.read.isActive(["did:consortium:user-1"]);
    assert.equal(isActive, true);

    // but isFullyActive returns false because its authority is deactivated
    const isFullyActive = await ctx.didRegistry.read.isFullyActive(["did:consortium:user-1"]);
    assert.equal(isFullyActive, false);
  });

  it("isFullyActive should return true for authority — no domainAuthority chain", async () => {
    const ctx = await setup();
    const result = await ctx.didRegistry.read.isFullyActive(["did:consortium:authority-a"]);
    assert.equal(result, true);
  });
});
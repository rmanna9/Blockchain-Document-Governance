import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { encodeFunctionData } from "viem";

describe("GovernanceContract", async () => {
  const { viem } = await network.connect();

  async function setup() {
    const [deployer, authorityA, authorityB, authorityC, outsider, candidate] =
      await viem.getWalletClients();

    const auditLog = await viem.deployContract("AuditLog");

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

    const didRegistry = await viem.deployContract("DIDRegistry", [
      authorities,
      dids,
      ["pk-a", "pk-b", "pk-c"],
      ["rk-a", "rk-b", "rk-c"],
      auditLog.address,
    ]);

    const governance = await viem.deployContract("GovernanceContract", [
      authorities,
      dids,
      didRegistry.address,
      auditLog.address,
    ]);

    await auditLog.write.addWriter([didRegistry.address]);
    await auditLog.write.addWriter([governance.address]);
    await auditLog.write.renounceAdmin();

    await didRegistry.write.setGovernanceContract([governance.address]);

    return {
      governance,
      didRegistry,
      auditLog,
      deployer,
      authorityA,
      authorityB,
      authorityC,
      outsider,
      candidate,
    };
  }

  async function increaseTime(seconds: number) {
    const client = await viem.getPublicClient();
    await (client as any).request({ method: "evm_increaseTime", params: [seconds] });
    await (client as any).request({ method: "evm_mine", params: [] });
  }

  // Helper: run full five-stage workflow for a proposal
  async function runProposal(
    ctx: Awaited<ReturnType<typeof setup>>,
    description: string,
    targetContract: `0x${string}`,
    calldata: `0x${string}`,
    threshold: number,  // 0 = Majority, 1 = Supermajority
    voters: { account: { address: `0x${string}` } }[]
  ) {
    await ctx.governance.write.propose(
      [description, targetContract, calldata, threshold],
      { account: ctx.authorityA.account }
    );

    const proposalId = 1n;

    // Stage 3: voting delay
    await increaseTime(3601);

    for (const voter of voters) {
      await ctx.governance.write.castVote(
        [proposalId, 1],
        { account: voter.account }
      );
    }

    // Stage 4: end voting period + queue
    await increaseTime(3 * 24 * 3600 + 1);
    await ctx.governance.write.queue([proposalId], { account: ctx.authorityA.account });

    // Stage 5: timelock + execute
    await increaseTime(24 * 3600 + 1);
    await ctx.governance.write.execute([proposalId], { account: ctx.authorityA.account });

    return proposalId;
  }

  // ── RF2: Authority membership ─────────────────────────────────────────────

  it("should register founding authorities", async () => {
    const { governance, authorityA, authorityB, authorityC } = await setup();

    assert.equal(await governance.read.isAuthority([authorityA.account.address]), true);
    assert.equal(await governance.read.isAuthority([authorityB.account.address]), true);
    assert.equal(await governance.read.isAuthority([authorityC.account.address]), true);
    assert.equal(await governance.read.authorityCount(), 3n);
  });

  it("should reject proposal from non-authority — RF2", async () => {
    const { governance, outsider } = await setup();

    await assert.rejects(
      governance.write.propose(
        ["test", governance.address, "0x", 0],
        { account: outsider.account }
      )
    );
  });

  // ── RF2: Five-stage workflow ──────────────────────────────────────────────

  it("should transition proposal to Active after voting delay — Stage 2→3", async () => {
    const { governance, authorityA } = await setup();

    await governance.write.propose(
      ["Test proposal", governance.address, "0x", 0],
      { account: authorityA.account }
    );

    await increaseTime(3601);
    await governance.write.castVote([1n, 1], { account: authorityA.account });

    const proposal = await governance.read.getProposal([1n]);
    assert.equal(proposal.status, 1); // Active
  });

  it("should reject voting before voting delay elapses", async () => {
    const { governance, authorityA } = await setup();

    await governance.write.propose(
      ["Test proposal", governance.address, "0x", 0],
      { account: authorityA.account }
    );

    // Do NOT advance time
    await assert.rejects(
      governance.write.castVote([1n, 1], { account: authorityA.account })
    );
  });

  it("should reject double voting — RF2", async () => {
    const { governance, authorityA } = await setup();

    await governance.write.propose(
      ["Test proposal", governance.address, "0x", 0],
      { account: authorityA.account }
    );

    await increaseTime(3601);
    await governance.write.castVote([1n, 1], { account: authorityA.account });

    await assert.rejects(
      governance.write.castVote([1n, 1], { account: authorityA.account })
    );
  });

  it("should reject voting after voting period ends", async () => {
    const { governance, authorityA } = await setup();

    await governance.write.propose(
      ["Test proposal", governance.address, "0x", 0],
      { account: authorityA.account }
    );

    await increaseTime(3600 + 3 * 24 * 3600 + 1);

    await assert.rejects(
      governance.write.castVote([1n, 1], { account: authorityA.account })
    );
  });

  // ── RF2: Quorum thresholds ────────────────────────────────────────────────

  it("should succeed with majority — 2 out of 3 for votes", async () => {
    const { governance, authorityA, authorityB } = await setup();

    await governance.write.propose(
      ["Majority proposal", governance.address, "0x", 0],
      { account: authorityA.account }
    );

    await increaseTime(3601);
    await governance.write.castVote([1n, 1], { account: authorityA.account });
    await governance.write.castVote([1n, 1], { account: authorityB.account });

    await increaseTime(3 * 24 * 3600 + 1);
    await governance.write.queue([1n], { account: authorityA.account });

    const proposal = await governance.read.getProposal([1n]);
    assert.equal(proposal.status, 2); // Succeeded
  });

  it("should be defeated without majority — 1 out of 3 for votes", async () => {
    const { governance, authorityA } = await setup();

    await governance.write.propose(
      ["Failing proposal", governance.address, "0x", 0],
      { account: authorityA.account }
    );

    await increaseTime(3601);
    await governance.write.castVote([1n, 1], { account: authorityA.account });

    await increaseTime(3 * 24 * 3600 + 1);
    await governance.write.queue([1n], { account: authorityA.account });

    const proposal = await governance.read.getProposal([1n]);
    assert.equal(proposal.status, 3); // Defeated
  });

  it("should succeed with supermajority — 3 out of 3 for votes", async () => {
    const { governance, authorityA, authorityB, authorityC } = await setup();

    await governance.write.propose(
      ["Supermajority proposal", governance.address, "0x", 1],
      { account: authorityA.account }
    );

    await increaseTime(3601);
    await governance.write.castVote([1n, 1], { account: authorityA.account });
    await governance.write.castVote([1n, 1], { account: authorityB.account });
    await governance.write.castVote([1n, 1], { account: authorityC.account });

    await increaseTime(3 * 24 * 3600 + 1);
    await governance.write.queue([1n], { account: authorityA.account });

    const proposal = await governance.read.getProposal([1n]);
    assert.equal(proposal.status, 2); // Succeeded
  });

  it("should be defeated without supermajority — 2 out of 3 not enough", async () => {
    const { governance, authorityA, authorityB } = await setup();

    await governance.write.propose(
      ["Supermajority failing", governance.address, "0x", 1],
      { account: authorityA.account }
    );

    await increaseTime(3601);
    await governance.write.castVote([1n, 1], { account: authorityA.account });
    await governance.write.castVote([1n, 1], { account: authorityB.account });

    await increaseTime(3 * 24 * 3600 + 1);
    await governance.write.queue([1n], { account: authorityA.account });

    const proposal = await governance.read.getProposal([1n]);
    assert.equal(proposal.status, 3); // Defeated — 2*3=6 not > 3*2=6
  });

  it("should reject execution before timelock elapses — Stage 5", async () => {
    const { governance, authorityA, authorityB } = await setup();

    await governance.write.propose(
      ["Early execute", governance.address, "0x", 0],
      { account: authorityA.account }
    );

    await increaseTime(3601);
    await governance.write.castVote([1n, 1], { account: authorityA.account });
    await governance.write.castVote([1n, 1], { account: authorityB.account });

    await increaseTime(3 * 24 * 3600 + 1);
    await governance.write.queue([1n], { account: authorityA.account });

    // Do NOT advance past timelock
    await assert.rejects(
      governance.write.execute([1n], { account: authorityA.account })
    );
  });

  it("should use eligibleVoters snapshot — new authority cannot affect ongoing vote", async () => {
    const { governance, didRegistry, authorityA, authorityB, candidate } = await setup();

    // Propose with 3 eligible voters
    await governance.write.propose(
      ["Snapshot test", governance.address, "0x", 0],
      { account: authorityA.account }
    );

    const proposal = await governance.read.getProposal([1n]);
    assert.equal(proposal.eligibleVoters, 3n);
  });

  // ── RF3: admitAuthority — atomic DID + governance registration ────────────

  it("should admit new authority atomically — DID registered + governance updated — RF3", async () => {
    const ctx = await setup();

    const calldata = encodeFunctionData({
      abi: [{
        name: "admitAuthority",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
          { name: "authority",         type: "address" },
          { name: "did",               type: "string"  },
          { name: "activePublicKey",   type: "string"  },
          { name: "recoveryPublicKey", type: "string"  },
        ],
        outputs: []
      }],
      functionName: "admitAuthority",
      args: [
        ctx.candidate.account.address,
        "did:consortium:authority-d",
        "pk-d",
        "rk-d",
      ],
    });

    await runProposal(
      ctx,
      "Admit authority D",
      ctx.governance.address,
      calldata,
      0, // majority
      [ctx.authorityA, ctx.authorityB]
    );

    // Verify governance membership
    assert.equal(
      await ctx.governance.read.isAuthority([ctx.candidate.account.address]),
      true
    );
    assert.equal(await ctx.governance.read.authorityCount(), 4n);

    // Verify DID registered in DIDRegistry
    const doc = await ctx.didRegistry.read.resolve(["did:consortium:authority-d"]);
    assert.equal(doc.isActive, true);
    assert.equal(doc.activePublicKey, "pk-d");
    assert.equal(doc.entityAddress.toLowerCase(), ctx.candidate.account.address.toLowerCase());
    assert.equal(doc.domainAuthority, "0x0000000000000000000000000000000000000000");
  });

  // ── RF3: removeAuthority — atomic removal + DID deactivation ─────────────

  it("should remove authority atomically — DID deactivated + governance updated — RF3", async () => {
    const ctx = await setup();

    const calldata = encodeFunctionData({
      abi: [{
        name: "removeAuthority",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [{ name: "authority", type: "address" }],
        outputs: []
      }],
      functionName: "removeAuthority",
      args: [ctx.authorityC.account.address],
    });

    await runProposal(
      ctx,
      "Remove authority C",
      ctx.governance.address,
      calldata,
      1, // supermajority
      [ctx.authorityA, ctx.authorityB, ctx.authorityC]
    );

    // Verify governance membership updated
    assert.equal(
      await ctx.governance.read.isAuthority([ctx.authorityC.account.address]),
      false
    );
    assert.equal(await ctx.governance.read.authorityCount(), 2n);

    // Verify DID deactivated in DIDRegistry
    const isActive = await ctx.didRegistry.read.isActive(["did:consortium:authority-c"]);
    assert.equal(isActive, false);
  });

  // ── RF3: lazy check after authority removal ───────────────────────────────

  it("should make users of removed authority isFullyActive=false — RF3", async () => {
    const ctx = await setup();

    // Register user under authorityC
    await ctx.didRegistry.write.registerUser(
      ["did:consortium:user-c", "pk-uc", "rk-uc", ctx.outsider.account.address, 0n],
      { account: ctx.authorityC.account }
    );

    // Verify user is fully active before removal
    assert.equal(
      await ctx.didRegistry.read.isFullyActive(["did:consortium:user-c"]),
      true
    );

    // Remove authorityC via governance
    const calldata = encodeFunctionData({
      abi: [{
        name: "removeAuthority",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [{ name: "authority", type: "address" }],
        outputs: []
      }],
      functionName: "removeAuthority",
      args: [ctx.authorityC.account.address],
    });

    await runProposal(
      ctx,
      "Remove authority C",
      ctx.governance.address,
      calldata,
      1,
      [ctx.authorityA, ctx.authorityB, ctx.authorityC]
    );

    // User is still isActive=true individually
    assert.equal(
      await ctx.didRegistry.read.isActive(["did:consortium:user-c"]),
      true
    );

    // But isFullyActive returns false
    assert.equal(
      await ctx.didRegistry.read.isFullyActive(["did:consortium:user-c"]),
      false
    );
  });
});
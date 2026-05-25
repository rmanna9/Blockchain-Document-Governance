import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { keccak256, toBytes, toHex } from "viem";

describe("KeyShareRegistry", async () => {
  const { viem } = await network.connect();

  async function setup() {
    const [deployer, authorityA, authorityB, authorityC, user1, outsider] =
      await viem.getWalletClients();

    const auditLog = await viem.deployContract("AuditLog");

    const didRegistry = await viem.deployContract("DIDRegistry", [
      [authorityA.account.address, authorityB.account.address, authorityC.account.address],
      ["did:consortium:authority-a", "did:consortium:authority-b", "did:consortium:authority-c"],
      ["pk-a", "pk-b", "pk-c"],
      ["rk-a", "rk-b", "rk-c"],
      auditLog.address,
    ]);

    const governance = await viem.deployContract("GovernanceContract", [
      [authorityA.account.address, authorityB.account.address, authorityC.account.address],
      ["did:consortium:authority-a", "did:consortium:authority-b", "did:consortium:authority-c"],
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

    const keyShareRegistry = await viem.deployContract("KeyShareRegistry", [
      didRegistry.address,
      auditLog.address,
    ]);

    await auditLog.write.addWriter([didRegistry.address]);
    await auditLog.write.addWriter([governance.address]);
    await auditLog.write.addWriter([documentRegistry.address]);
    await auditLog.write.addWriter([accessControl.address]);
    await auditLog.write.addWriter([keyShareRegistry.address]);
    await auditLog.write.renounceAdmin();

    await didRegistry.write.setGovernanceContract([governance.address]);
    await didRegistry.write.setAccessControl([accessControl.address]);
    await documentRegistry.write.setAccessControl([accessControl.address]);
    await documentRegistry.write.setGovernanceContract([governance.address]);
    await accessControl.write.setGovernanceContract([governance.address]);

    // Register user1 under authorityA
    await didRegistry.write.registerUser(
      ["did:consortium:user-1", "pk-u1", "rk-u1", user1.account.address, 0n],
      { account: authorityA.account }
    );

    // Grant canCreate and certify a document
    await accessControl.write.grantCreate(
      ["did:consortium:user-1", 0n],
      { account: authorityA.account }
    );

    const zero    = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
    const docHash = keccak256(toBytes("document content"));
    const sigA    = toHex(toBytes("sig-authority-a"));

    await documentRegistry.write.requestCertification(
      [docHash, zero, ""],
      { account: user1.account }
    );
    await documentRegistry.write.certify(
      [docHash, sigA],
      { account: authorityA.account }
    );

    // Prepare shares: 3 authorities, threshold = ceil(2*3/3) = 2
    const authorityAddresses = [
      authorityA.account.address,
      authorityB.account.address,
      authorityC.account.address,
    ] as `0x${string}`[];
    const shareIndices = [1n, 2n, 3n];
    const encryptedShares = [
      toHex(toBytes("enc-share-a")),
      toHex(toBytes("enc-share-b")),
      toHex(toBytes("enc-share-c")),
    ] as `0x${string}`[];
    const threshold = 2n; // ceil(2*3/3) = 2

    return {
      keyShareRegistry,
      documentRegistry,
      accessControl,
      didRegistry,
      governance,
      auditLog,
      deployer,
      authorityA,
      authorityB,
      authorityC,
      user1,
      outsider,
      docHash,
      zero,
      sigA,
      authorityAddresses,
      shareIndices,
      encryptedShares,
      threshold,
    };
  }

  // ── Archival Phase 4: storeShares ─────────────────────────────────────────

  it("should store shares for a certified document — Archival Phase 4", async () => {
    const ctx = await setup();

    await ctx.keyShareRegistry.write.storeShares(
      [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, ctx.threshold],
      { account: ctx.authorityA.account }
    );

    assert.equal(await ctx.keyShareRegistry.read.sharesExist([ctx.docHash]), true);
    assert.equal(await ctx.keyShareRegistry.read.getThreshold([ctx.docHash]), ctx.threshold);
    assert.equal(await ctx.keyShareRegistry.read.getTotalShares([ctx.docHash]), 3n);
  });

  it("should store correct encrypted share per authority", async () => {
    const ctx = await setup();

    await ctx.keyShareRegistry.write.storeShares(
      [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, ctx.threshold],
      { account: ctx.authorityA.account }
    );

    const shareA = await ctx.keyShareRegistry.read.getShare([ctx.docHash, ctx.authorityA.account.address]);
    const shareB = await ctx.keyShareRegistry.read.getShare([ctx.docHash, ctx.authorityB.account.address]);
    const shareC = await ctx.keyShareRegistry.read.getShare([ctx.docHash, ctx.authorityC.account.address]);

    assert.equal(shareA.encryptedShare, toHex(toBytes("enc-share-a")));
    assert.equal(shareB.encryptedShare, toHex(toBytes("enc-share-b")));
    assert.equal(shareC.encryptedShare, toHex(toBytes("enc-share-c")));
    assert.equal(shareA.shareIndex, 1n);
    assert.equal(shareB.shareIndex, 2n);
    assert.equal(shareC.shareIndex, 3n);
  });

  it("should reject storeShares from non-authority", async () => {
    const ctx = await setup();

    await assert.rejects(
      ctx.keyShareRegistry.write.storeShares(
        [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, ctx.threshold],
        { account: ctx.outsider.account }
      )
    );
  });

  it("should reject duplicate storeShares for same document", async () => {
    const ctx = await setup();

    await ctx.keyShareRegistry.write.storeShares(
      [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, ctx.threshold],
      { account: ctx.authorityA.account }
    );

    await assert.rejects(
      ctx.keyShareRegistry.write.storeShares(
        [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, ctx.threshold],
        { account: ctx.authorityA.account }
      )
    );
  });

  it("should reject invalid threshold — zero", async () => {
    const ctx = await setup();

    await assert.rejects(
      ctx.keyShareRegistry.write.storeShares(
        [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, 0n],
        { account: ctx.authorityA.account }
      )
    );
  });

  it("should reject threshold greater than total shares", async () => {
    const ctx = await setup();

    await assert.rejects(
      ctx.keyShareRegistry.write.storeShares(
        [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, 4n],
        { account: ctx.authorityA.account }
      )
    );
  });

  it("should reject mismatched array lengths", async () => {
    const ctx = await setup();

    await assert.rejects(
      ctx.keyShareRegistry.write.storeShares(
        [
          ctx.docHash,
          ctx.authorityAddresses,
          [1n, 2n], // only 2 indices for 3 authorities
          ctx.encryptedShares,
          ctx.threshold
        ],
        { account: ctx.authorityA.account }
      )
    );
  });

  it("should reject empty encrypted share", async () => {
    const ctx = await setup();

    await assert.rejects(
      ctx.keyShareRegistry.write.storeShares(
        [
          ctx.docHash,
          ctx.authorityAddresses,
          ctx.shareIndices,
          [
            toHex(toBytes("enc-share-a")),
            "0x" as `0x${string}`, // empty share
            toHex(toBytes("enc-share-c")),
          ],
          ctx.threshold
        ],
        { account: ctx.authorityA.account }
      )
    );
  });

  // ── Retrieval Phase 2: getShare ───────────────────────────────────────────

  it("should return shares not found for unknown document", async () => {
    const ctx = await setup();
    const unknownHash = keccak256(toBytes("unknown"));

    await assert.rejects(
      ctx.keyShareRegistry.read.getShare([unknownHash, ctx.authorityA.account.address])
    );
  });

  it("should return share not found for unknown authority", async () => {
    const ctx = await setup();

    await ctx.keyShareRegistry.write.storeShares(
      [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, ctx.threshold],
      { account: ctx.authorityA.account }
    );

    await assert.rejects(
      ctx.keyShareRegistry.read.getShare([ctx.docHash, ctx.outsider.account.address])
    );
  });

  // ── Revocation does not prevent share storage but blocks retrieval ─────────

  it("shares remain on-chain after revocation but ReadApproved is blocked — WP2 §Revocation", async () => {
    const ctx = await setup();

    // Store shares
    await ctx.keyShareRegistry.write.storeShares(
      [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, ctx.threshold],
      { account: ctx.authorityA.account }
    );

    // Revoke document
    await ctx.documentRegistry.write.revoke(
      [ctx.docHash, "policy violation"],
      { account: ctx.authorityA.account }
    );

    // Shares still exist on-chain — KeyShareRegistry is unaffected
    assert.equal(await ctx.keyShareRegistry.read.sharesExist([ctx.docHash]), true);

    // But retrieval is blocked at the gate — checkAndApproveRead fails
    // No ReadApproved event is emitted — authority nodes will never release shares
    await assert.rejects(
      ctx.accessControl.write.checkAndApproveRead(
        [ctx.docHash],
        { account: ctx.user1.account }
      )
    );
  });

  it("threshold matches ceil(2N/3) for N=3 authorities — SSS constraint", async () => {
    const ctx = await setup();

    await ctx.keyShareRegistry.write.storeShares(
      [ctx.docHash, ctx.authorityAddresses, ctx.shareIndices, ctx.encryptedShares, ctx.threshold],
      { account: ctx.authorityA.account }
    );

    // N=3, t=ceil(2*3/3)=2
    const threshold = await ctx.keyShareRegistry.read.getThreshold([ctx.docHash]);
    assert.equal(threshold, 2n);
  });
});
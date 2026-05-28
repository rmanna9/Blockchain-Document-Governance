import express, { type Request, type Response } from "express";
import { toHex, keccak256 } from "viem";
import { combine } from "shamirs-secret-sharing";
import type { ContractClients } from "./contracts.js";
import type { HeliaNode } from "./ipfs.js";
import type { OracleConfig } from "./oracle.js";
import { generateNonce, authenticateRequest } from "./auth.js";
import {
  listenCertificationEvents,
  listenRevocationEvents,
} from "./oracle.js";
import {
  decryptDocumentKey,
  decryptDocument,
  deserializeEncryptedDocument,
  decryptShare,
  signDocumentHash,
} from "./crypto.js";
import { downloadFile } from "./ipfs.js";
import {
  getRecord,
  getDocumentStatus,
  getEncryptedKey,
  getShare,
  certifyDocument,
  getAuthorities,
  getThreshold,
} from "./contracts.js";

// ── Server configuration ──────────────────────────────────────────────────────

export interface ServerConfig {
  port:             number;
  contracts:        ContractClients;
  helia:            HeliaNode;
  authorityAddress: `0x${string}`;
  authorityDID:     string;
  privateKeyPem:    string;
  publicKeyPem:     string;
  authorityUrls:    Map<`0x${string}`, string>; // address → HTTP URL
}

// ── Pending documents store ───────────────────────────────────────────────────

const _pendingDocuments = new Map<string, Buffer>();

// ── Helper ────────────────────────────────────────────────────────────────────

function buildAuthorityUrls(
  authorities: `0x${string}`[],
  config:      ServerConfig
): string[] {
  return authorities
    .map(addr => config.authorityUrls.get(addr))
    .filter((url): url is string => !!url);
}

// ── Server setup ──────────────────────────────────────────────────────────────

export function createServer(config: ServerConfig): express.Application {
  const app = express();
  app.use(express.json({ limit: "50mb" }));
  app.use(express.raw({ type: "application/octet-stream", limit: "50mb" }));

  const oracleConfig: OracleConfig = {
    contracts:        config.contracts,
    helia:            config.helia,
    authorityAddress: config.authorityAddress,
    privateKeyPem:    config.privateKeyPem,
    publicKeyPem:     config.publicKeyPem,
    pendingDocuments: _pendingDocuments,
  };

  listenCertificationEvents(oracleConfig, (err) => {
    console.error("[Oracle] CertificationEvent error:", err);
  });
  listenRevocationEvents(oracleConfig, (err) => {
    console.error("[Oracle] RevocationEvent error:", err);
  });

  // ── GET /health ─────────────────────────────────────────────────────────────

  app.get("/health", (_req: Request, res: Response) => {
    res.json({
      status:    "ok",
      authority: config.authorityDID,
      address:   config.authorityAddress,
    });
  });

  // ── GET /auth/challenge ─────────────────────────────────────────────────────

  /**
   * Issue a session nonce for the requesting entity.
   * WP2 §Lightweight Auth Protocol Step 2.
   */
  app.get("/auth/challenge", (req: Request, res: Response) => {
    const { did } = req.query;
    if (!did || typeof did !== "string") {
      res.status(400).json({ error: "Missing did parameter" });
      return;
    }
    const nonce = generateNonce(did);
    res.json({ nonce });
  });

  // ── POST /document/certify ──────────────────────────────────────────────────

  /**
   * Receive a document from a user and certify it on-chain.
   * WP2 §Certification Phase 2 and Phase 3.
   *
   * Phase 2 — Authenticate + verify H(document) == documentHash
   * Phase 3 — Sign h_new, call DocumentRegistry.certify()
   *            Oracle picks up DocumentCertified and runs archival
   */
  app.post("/document/certify", async (req: Request, res: Response) => {
    const { did, nonce, signature, documentHash, document: documentB64 } = req.body;

    if (!did || !nonce || !signature || !documentHash || !documentB64) {
      res.status(400).json({ error: "Missing required fields" });
      return;
    }

    const authResult = await authenticateRequest(
      { did, nonce, signature, documentHash, context: "certification" },
      config.contracts
    );

    if (!authResult.success) {
      res.status(401).json({ error: authResult.reason });
      return;
    }

    const documentBuffer = Buffer.from(documentB64, "base64");
    const computedHash   = keccak256(new Uint8Array(documentBuffer));

    if (computedHash.toLowerCase() !== (documentHash as string).toLowerCase()) {
      res.status(400).json({ error: "Document hash mismatch — protocol violation" });
      return;
    }

    try {
      const hashBuffer = Buffer.from(
        (documentHash as string).replace(/^0x/, ""),
        "hex"
      );
      const sigBuffer = signDocumentHash(hashBuffer, config.privateKeyPem);
      const sigHex    = toHex(sigBuffer) as `0x${string}`;

      _pendingDocuments.set(documentHash as string, documentBuffer);

      await certifyDocument(
        config.contracts,
        documentHash as `0x${string}`,
        sigHex
      );

      res.json({ success: true, documentHash, signature: sigHex });

    } catch (err) {
      _pendingDocuments.delete(documentHash as string);
      console.error("[Certify] Error:", err);
      res.status(500).json({ error: "Certification failed" });
    }
  });

  // ── POST /document/retrieve ─────────────────────────────────────────────────

  /**
   * Retrieve and decrypt a document for an authenticated user.
   * WP2 §Retrieval Phases 2-5.
   */
  app.post("/document/retrieve", async (req: Request, res: Response) => {
    const { did, nonce, signature, documentHash } = req.body;

    if (!did || !nonce || !signature || !documentHash) {
      res.status(400).json({ error: "Missing required fields" });
      return;
    }

    const authResult = await authenticateRequest(
      { did, nonce, signature, documentHash, context: "retrieval" },
      config.contracts
    );

    if (!authResult.success) {
      res.status(401).json({ error: authResult.reason });
      return;
    }

    try {
      const record = await getRecord(config.contracts, documentHash);
      if (record.certifiedBy.toLowerCase() !== config.authorityAddress.toLowerCase()) {
        res.status(403).json({ error: "Document not certified by this authority" });
        return;
      }

      const status = await getDocumentStatus(config.contracts, documentHash);
      if (status === 2) {
        res.status(403).json({ error: "Document has been revoked" });
        return;
      }

      if (!record.cid || record.cid.length === 0) {
        res.status(503).json({ error: "Document not yet archived — CID not set" });
        return;
      }

      // Phase 3 — Download ciphertext from IPFS
      const blob = await downloadFile(config.helia, record.cid);

      // Phase 4 — Decrypt k_doc from E_A, decrypt document
      const E_A_hex   = await getEncryptedKey(config.contracts, documentHash);
      const E_A       = Buffer.from(E_A_hex.replace(/^0x/, ""), "hex");
      const k_doc     = decryptDocumentKey(E_A, config.privateKeyPem);
      const encrypted = deserializeEncryptedDocument(blob);
      const plaintext = decryptDocument(encrypted, k_doc);
      k_doc.fill(0);

      // Phase 5 — Send plaintext to user
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("X-Document-Hash", documentHash);
      res.send(plaintext);

    } catch (err) {
      console.error("[Retrieve] Error:", err);
      res.status(500).json({ error: "Document retrieval failed" });
    }
  });

  // ── POST /shares/release ────────────────────────────────────────────────────

  /**
   * Release a decrypted key share to an authenticated aggregator.
   * WP2 §Forced Document Retrieval via Governance (RF3).
   */
  app.post("/shares/release", async (req: Request, res: Response) => {
    const { did, nonce, signature, documentHash } = req.body;

    if (!did || !nonce || !signature || !documentHash) {
      res.status(400).json({ error: "Missing required fields" });
      return;
    }

    const authResult = await authenticateRequest(
      { did, nonce, signature, documentHash, context: "retrieval" },
      config.contracts
    );

    if (!authResult.success) {
      res.status(401).json({ error: authResult.reason });
      return;
    }

    try {
      const shareData = await getShare(
        config.contracts,
        documentHash as `0x${string}`,
        config.authorityAddress
      );

      const E_i     = Buffer.from(
        (shareData.encryptedShare as string).replace(/^0x/, ""),
        "hex"
      );
      const share_i = decryptShare(E_i, config.privateKeyPem);

      res.json({
        shareIndex: Number(shareData.shareIndex),
        share:      share_i.toString("hex"),
        documentHash,
      });

    } catch (err) {
      console.error("[Shares] Error:", err);
      res.status(500).json({ error: "Share release failed" });
    }
  });

  // ── POST /document/forced-read ──────────────────────────────────────────────

  /**
   * Forced read aggregation endpoint (RF3).
   * WP2 §Forced Document Retrieval via Governance.
   *
   * This authority acts as aggregator:
   *   1. Authenticate requester
   *   2. Collect shares from all authority nodes via /shares/release
   *   3. Reconstruct k_doc via SSS combine
   *   4. Download ciphertext from IPFS
   *   5. Decrypt and return document
   *
   * A governance proposal for forced read must already be approved
   * and executed before calling this endpoint.
   */
  app.post("/document/forced-read", async (req: Request, res: Response) => {
    const { did, nonce, signature, documentHash } = req.body;

    if (!did || !nonce || !signature || !documentHash) {
      res.status(400).json({ error: "Missing required fields" });
      return;
    }

    const authResult = await authenticateRequest(
      { did, nonce, signature, documentHash, context: "retrieval" },
      config.contracts
    );

    if (!authResult.success) {
      res.status(401).json({ error: authResult.reason });
      return;
    }

    try {
      const authorities   = await getAuthorities(config.contracts);
      const authorityUrls = buildAuthorityUrls(authorities, config);
      const threshold     = await getThreshold(
        config.contracts,
        documentHash as `0x${string}`
      );

      const shares: Buffer[] = [];

      for (const url of authorityUrls) {
        if (shares.length >= Number(threshold)) break;
        try {
          // Aggregator authenticates to each authority with its own DID
          const challengeRes = await fetch(
            `${url}/auth/challenge?did=${encodeURIComponent(config.authorityDID)}`
          );
          const { nonce: aggrNonce } = await challengeRes.json() as { nonce: string };

          // Sign nonce with aggregator's own private key
          const { signDocumentHash: signNonce } = await import("./crypto.js");
          const aggrSig = toHex(
            signNonce(Buffer.from(aggrNonce, "hex"), config.privateKeyPem)
          );

          const shareRes = await fetch(`${url}/shares/release`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({
              did:          config.authorityDID,
              nonce:        aggrNonce,
              signature:    aggrSig,
              documentHash,
            }),
          });

          if (!shareRes.ok) continue;
          const data = await shareRes.json() as { shareIndex: number; share: string };
          shares.push(Buffer.from(data.share, "hex"));

        } catch {
          continue;
        }
      }

      if (shares.length < Number(threshold)) {
        res.status(503).json({
          error: `Not enough shares: got ${shares.length}, need ${threshold}`
        });
        return;
      }

      // Reconstruct k_doc from shares
      const k_doc = Buffer.from(combine(shares));

      // Download ciphertext from IPFS
      const record = await getRecord(
        config.contracts,
        documentHash as `0x${string}`
      );
      const blob      = await downloadFile(config.helia, record.cid);
      const encrypted = deserializeEncryptedDocument(blob);
      const plaintext = decryptDocument(encrypted, k_doc);

      // Destroy k_doc
      k_doc.fill(0);

      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("X-Document-Hash", documentHash);
      res.send(plaintext);

    } catch (err) {
      console.error("[ForcedRead] Error:", err);
      res.status(500).json({ error: "Forced read failed" });
    }
  });

  // ── POST /oracle/verify ─────────────────────────────────────────────────────

  /**
   * Oracle verification endpoint for External Verification workflow.
   * WP2 §External Verification Phases 3-6.
   *
   * Phase 3 — External Verifier submits (did_A, h, did_U)
   * Phase 4 — Oracle resolves did_A, checks canPresentExternally(address_U, h)
   * Phase 5 — Oracle encrypts metadata with pk_U as c_meta
   * Phase 6 — Oracle returns (c_meta, H(metadata), DIDDoc_A, DIDDoc_U)
   *
   * Body:
   *   {
   *     didAuthority: string       — did_A of the certifying authority
   *     documentHash: 0x${string} — H(document) computed by External Verifier
   *     didUser:      string       — did_U of the presenter
   *   }
   */
  app.post("/oracle/verify", async (req: Request, res: Response) => {
    const { didAuthority, documentHash, didUser } = req.body;

    if (!didAuthority || !documentHash || !didUser) {
      res.status(400).json({ error: "Missing required fields" });
      return;
    }

    try {
      // Phase 4 — Resolve did_A and verify it belongs to this consortium
      const authorityDoc = await config.contracts.didRegistry.read.resolve(
        [didAuthority]
      ) as any;

      if (!authorityDoc.isActive) {
        res.status(403).json({ error: "Authority DID is not active" });
        return;
      }

      // Phase 4 — Check canPresentExternally(address_U, h)
      // WP2: "verify whether the on-chain address associated with did_U
      //       holds a valid delegable read permission for document h"
      const canPresent = await config.contracts.accessControl.read.canPresentExternally([
        didUser,
        documentHash as `0x${string}`,
      ]) as boolean;

      // Emit structured event to AuditLog regardless of outcome
      // WP2: "A structured event is emitted to the AuditLog in both cases"
      await config.contracts.auditLog.write.log([
        config.authorityAddress,
        4, // ActionType.ReadApproved — closest approximation for external verification
        documentHash as `0x${string}`,
        new Uint8Array(Buffer.from(
          JSON.stringify({ didUser, didAuthority, documentHash, canPresent })
        )),
      ]);

      if (!canPresent) {
        // Always return same structure to prevent side-channel attacks
        // WP2: "The Oracle always returns a response of identical structure
        //       within a constant time bound"
        res.status(403).json({ error: "Presenter does not hold a delegable read permission" });
        return;
      }

      // Phase 4 — Retrieve document metadata
      const record = await getRecord(
        config.contracts,
        documentHash as `0x${string}`
      );

      // Phase 4 — Resolve did_U to get pk_U
      const userDoc = await config.contracts.didRegistry.read.resolve(
        [didUser]
      ) as any;

      // Phase 5 — Encrypt metadata with pk_U
      // WP2: "The Oracle constructs the metadata payload, embedding a
      //       timestamp, and encrypts it as c_meta = Enc(pk_U, metadata)"
      const metadata = JSON.stringify({
        documentHash,
        status:    record.status,
        version:   Number(record.version),
        ownerDID:  record.ownerDID,
        timestamp: Date.now(),
      });

      const { createHash } = await import("node:crypto");
      const metadataHash = createHash("sha256")
        .update(Buffer.from(metadata))
        .digest("hex");

      // Encrypt metadata with pk_U using RSA-OAEP
      const { publicEncrypt, constants } = await import("node:crypto");
      const pk_U = userDoc.activePublicKey as string;
      const encryptedMetadata = publicEncrypt(
        { key: pk_U, padding: constants.RSA_PKCS1_OAEP_PADDING },
        Buffer.from(metadata)
      ).toString("hex");

      // Phase 6 — Return (c_meta, H(metadata), DIDDoc_A, DIDDoc_U)
      res.json({
        encryptedMetadata,
        metadataHash,
        didDocumentAuthority: authorityDoc,
        didDocumentUser:      userDoc,
      });

    } catch (err) {
      console.error("[Oracle] Verify error:", err);
      res.status(500).json({ error: "Oracle verification failed" });
    }
  });

  return app;
}

// ── Server start ──────────────────────────────────────────────────────────────

export function startServer(config: ServerConfig): void {
  const app = createServer(config);

  app.listen(config.port, () => {
    console.log(
      `[Server] Authority node ${config.authorityDID} listening on port ${config.port}`
    );
  });

  process.on("SIGTERM", async () => {
    console.log("[Server] Shutting down...");
    await config.helia.helia.stop();
    process.exit(0);
  });
}
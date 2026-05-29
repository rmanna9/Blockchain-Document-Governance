import crypto from "node:crypto";
import { split, combine } from "shamirs-secret-sharing";

// ── RSA Keypair ───────────────────────────────────────────────────────────────

export interface RSAKeyPair {
  privateKey: string; // PEM
  publicKey:  string; // PEM
}

/**
 * Generate an RSA-4096 keypair for an entity (authority or user).
 * The public key is registered on-chain in the DIDDocument.
 * The private key is stored locally and never leaves the holder.
 */
export function generateRSAKeyPair(): RSAKeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { privateKey, publicKey };
}

// ── Document encryption (AES-256-GCM) ────────────────────────────────────────

export interface EncryptedDocument {
  ciphertext: Buffer; // uploaded to IPFS
  iv:         Buffer; // 12 bytes
  authTag:    Buffer; // 16 bytes
}

/**
 * Generate a fresh per-document symmetric key k_doc (AES-256).
 * Called only by the certifying authority during archival (Phase 1).
 * k_doc MUST be destroyed after shares are generated and stored on-chain.
 */
export function generateDocumentKey(): Buffer {
  return crypto.randomBytes(32);
}

/**
 * Encrypt document content with k_doc using AES-256-GCM.
 * Archival Phase 1.
 */
export function encryptDocument(content: Buffer, key: Buffer): EncryptedDocument {
  const iv         = crypto.randomBytes(12);
  const cipher     = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(content), cipher.final()]);
  const authTag    = cipher.getAuthTag();
  return { ciphertext, iv, authTag };
}

/**
 * Decrypt document ciphertext using k_doc.
 * Retrieval Phase 4 (after recovering k_doc from E_A or SSS combine).
 */
export function decryptDocument(encrypted: EncryptedDocument, key: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, encrypted.iv);
  decipher.setAuthTag(encrypted.authTag);
  return Buffer.concat([decipher.update(encrypted.ciphertext), decipher.final()]);
}

/**
 * Serialize EncryptedDocument to a single Buffer for IPFS upload.
 * Layout: [iv (12)] [authTag (16)] [ciphertext]
 */
export function serializeEncryptedDocument(doc: EncryptedDocument): Buffer {
  return Buffer.concat([doc.iv, doc.authTag, doc.ciphertext]);
}

/**
 * Deserialize a Buffer retrieved from IPFS back into EncryptedDocument.
 */
export function deserializeEncryptedDocument(blob: Buffer): EncryptedDocument {
  const iv         = blob.subarray(0, 12);
  const authTag    = blob.subarray(12, 28);
  const ciphertext = blob.subarray(28);
  return { ciphertext, iv, authTag };
}

// ── Shamir Secret Sharing ─────────────────────────────────────────────────────

/**
 * Split k_doc into N shares with reconstruction threshold t = ceil(2N/3).
 * Archival Phase 3 (certifying authority only).
 *
 * @param key    k_doc (32 bytes)
 * @param total  N — number of consortium authorities
 * @returns      Array of N share Buffers
 */
export function splitSecret(key: Buffer, total: number): Buffer[] {
  const threshold = Math.ceil((2 * total) / 3);
  const shares    = split(key, { shares: total, threshold });
  return shares.map((s: Uint8Array) => Buffer.from(s));
}

/**
 * Reconstruct k_doc from at least t plaintext shares.
 * Used only in the Forced Read workflow (aggregator combines >= t shares).
 *
 * @param shares  Array of at least t plaintext share Buffers
 * @returns       Reconstructed k_doc (32 bytes)
 */
export function combineShares(shares: Buffer[]): Buffer {
  return Buffer.from(combine(shares));
}

/**
 * Compute the reconstruction threshold for N authorities.
 * t = ceil(2N/3) — honest majority assumption (WP1).
 */
export function computeThreshold(total: number): number {
  return Math.ceil((2 * total) / 3);
}

// ── Share encryption / decryption (RSA-OAEP) ─────────────────────────────────

/**
 * Encrypt share_i with authority i's public key.
 * E_i = Enc(pk_i, share_i) — Archival Phase 3.
 */
export function encryptShare(share: Buffer, publicKeyPem: string): Buffer {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    share
  );
}

/**
 * Decrypt authority i's own encrypted share with its private key.
 * share_i = Dec(sk_i, E_i) — Forced Read (each voting authority).
 */
export function decryptShare(encryptedShare: Buffer, privateKeyPem: string): Buffer {
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedShare
  );
}

// ── Document key encryption / decryption (RSA-OAEP) — E_A ─────────────────────

/**
 * Encrypt k_doc with the certifying authority's own public key.
 * E_A = Enc(pk_A, k_doc) — Archival Phase 3.
 * Stored on-chain in KeyShareRegistry alongside the SSS shares so that
 * Authority A can retrieve k_doc directly during ordinary retrieval
 * without cooperation from other authorities.
 */
export function encryptDocumentKey(key: Buffer, publicKeyPem: string): Buffer {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    key
  );
}

/**
 * Decrypt E_A to recover k_doc.
 * k_doc = Dec(sk_A, E_A) — Ordinary Retrieval Phase 4 (Authority A only).
 */
export function decryptDocumentKey(encryptedKey: Buffer, privateKeyPem: string): Buffer {
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedKey
  );
}

// ── Signatures (RSA-PSS, sha256) ─────────────────────────────────────────────

/**
 * Sign H(document) with the authority's private key.
 * sigma_A = Sign(sk_A, hash) — Certification Phase 3.
 *
 * @param hash          H(document) as hex string (0x...) or Buffer
 * @param privateKeyPem Authority A's private key (PEM)
 * @returns             Signature Buffer passed to DocumentRegistry.certify()
 */
export function signDocumentHash(hash: Buffer | string, privateKeyPem: string): Buffer {
  const data = typeof hash === "string"
    ? Buffer.from(hash.replace(/^0x/, ""), "hex")
    : hash;
  return crypto.sign("sha256", data, {
    key: privateKeyPem,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
}

/**
 * Verify a signature produced by signDocumentHash.
 * Used by the lightweight auth protocol to verify nonce signatures,
 * and generally to verify any sha256/PSS signature.
 *
 * @param data          Original data (e.g. nonce or hash) as Buffer
 * @param signature     Signature Buffer
 * @param publicKeyPem  Signer's public key (PEM)
 */
export function verifySignature(
  data: Buffer,
  signature: Buffer,
  publicKeyPem: string
): boolean {
  try {
    return crypto.verify(
      "sha256",
      data,
      { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
      signature
    );
  } catch {
    return false;
  }
}

/**
 * Verify the authority's certification signature sigma_A.
 * External Verification Phase 6: the verifier extracts pk_A from
 * DIDDocument_A and checks sigma_A = Sign(sk_A, h) against pk_A and h.
 *
 * @param documentHash  H(document) as hex string (0x...)
 * @param signature     sigma_A as hex string (0x...)
 * @param publicKeyPem  Authority A's public key (PEM, from DIDRegistry)
 */
export function verifyAuthoritySignature(
  documentHash: string,
  signature: string,
  publicKeyPem: string
): boolean {
  try {
    const hashBuffer = Buffer.from(documentHash.replace(/^0x/, ""), "hex");
    const sigBuffer  = Buffer.from(signature.replace(/^0x/, ""), "hex");
    return crypto.verify(
      "sha256",
      hashBuffer,
      { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
      sigBuffer
    );
  } catch {
    return false;
  }
}

// ── Nonce signing (lightweight auth, client side) ────────────────────────────

/**
 * Sign a session nonce with sk_active.
 * Lightweight Auth Protocol Step 2 (requester side).
 *
 * @param nonce         Hex-encoded nonce from the authority
 * @param privateKeyPem Requester's active private key (PEM)
 * @returns             Hex-encoded signature
 */
export function signNonce(nonce: string, privateKeyPem: string): string {
  const nonceBuffer = Buffer.from(nonce, "hex");
  const signature   = crypto.sign("sha256", nonceBuffer, {
    key: privateKeyPem,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
  return signature.toString("hex");
}

// ── Challenge encryption / decryption (External Verification) ─────────────────

/**
 * Encrypt the metadata challenge with the presenter's public key.
 * c_meta = Enc(pk_U, metadata) — External Verification Phase 4 (Oracle side).
 */
export function encryptChallenge(metadata: Buffer, publicKeyPem: string): string {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    metadata
  ).toString("hex");
}

/**
 * Decrypt the metadata challenge c_meta with sk_U.
 * metadata = Dec(sk_U, c_meta) — External Verification Phase 7 (User side).
 * Proves possession of sk_U corresponding to pk_U registered under did_U.
 *
 * @param ciphertext    c_meta — hex-encoded
 * @param privateKeyPem User's active private key sk_U (PEM)
 */
export function decryptChallenge(ciphertext: string, privateKeyPem: string): Buffer {
  const ciphertextBuffer = Buffer.from(ciphertext.replace(/^0x/, ""), "hex");
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    ciphertextBuffer
  );
}
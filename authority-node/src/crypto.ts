import crypto from "node:crypto";
import { split, combine } from "shamirs-secret-sharing";

// ── RSA Keypair ───────────────────────────────────────────────────────────────

export interface RSAKeyPair {
  privateKey: string; // PEM
  publicKey:  string; // PEM
}

/**
 * Generate an RSA-4096 keypair for the authority node.
 * The public key is registered on-chain in the DIDDocument.
 * The private key is stored locally and never leaves the node.
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
  iv:         Buffer; // 12 bytes, stored alongside ciphertext
  authTag:    Buffer; // 16 bytes, stored alongside ciphertext
}

/**
 * Generate a fresh per-document symmetric key k_doc.
 * Called only by the certifying authority during archival (Phase 1).
 * k_doc MUST be destroyed after shares are generated and stored on-chain.
 */
export function generateDocumentKey(): Buffer {
  return crypto.randomBytes(32); // AES-256
}

/**
 * Encrypt document content with k_doc using AES-256-GCM.
 * Called only by the certifying authority during archival (Phase 1).
 *
 * The returned ciphertext, iv, and authTag are concatenated and
 * uploaded to IPFS as a single blob:
 *   [iv (12 bytes)] [authTag (16 bytes)] [ciphertext (N bytes)]
 */
export function encryptDocument(content: Buffer, key: Buffer): EncryptedDocument {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const ciphertext = Buffer.concat([cipher.update(content), cipher.final()]);
  const authTag    = cipher.getAuthTag();

  return { ciphertext, iv, authTag };
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
 * Called only by the certifying authority during archival (Phase 3).
 *
 * @param key    k_doc — the per-document symmetric key (32 bytes)
 * @param total  N — total number of consortium authorities
 * @returns      Array of N share Buffers
 */
export function splitSecret(key: Buffer, total: number): Buffer[] {
  const threshold = Math.ceil((2 * total) / 3);
  const shares    = split(key, { shares: total, threshold });
  return shares.map((s: Uint8Array) => Buffer.from(s));
}

/**
 * Reconstruct k_doc from at least t plaintext shares.
 * Called only by the client after collecting enough shares.
 *
 * @param shares  Array of at least t plaintext share Buffers
 * @returns       Reconstructed k_doc (32 bytes)
 */
export function combineShares(shares: Buffer[]): Buffer {
  return Buffer.from(combine(shares));
}

/**
 * Compute the reconstruction threshold for N authorities.
 * t = ceil(2N/3) — consistent with the honest majority assumption (WP1).
 */
export function computeThreshold(total: number): number {
  return Math.ceil((2 * total) / 3);
}

// ── Share encryption / decryption (RSA-OAEP) ─────────────────────────────────

/**
 * Encrypt share_i with authority i's public key.
 * E_i = Enc(pk_i, share_i)
 * Called only by the certifying authority during archival (Phase 3).
 *
 * @param share         Plaintext share Buffer
 * @param publicKeyPem  Authority i's public key (PEM, from DIDRegistry)
 * @returns             Encrypted share Buffer stored on-chain in KeyShareRegistry
 */
export function encryptShare(share: Buffer, publicKeyPem: string): Buffer {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    share
  );
}

/**
 * Decrypt authority i's own encrypted share using its private key.
 * share_i = Dec(sk_i, E_i)
 * Called by each authority node during retrieval (Phase 2).
 *
 * @param encryptedShare  E_i retrieved from KeyShareRegistry on-chain
 * @param privateKeyPem   Authority i's private key (local, never on-chain)
 * @returns               Plaintext share_i transmitted to the requesting user
 */
export function decryptShare(encryptedShare: Buffer, privateKeyPem: string): Buffer {
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedShare
  );
}

// ── Document signing (for certification σ_A) ─────────────────────────────────

/**
 * Sign H(document) with the authority's private key.
 * σ_A = Sign(sk_A, hash)
 * Called by the certifying authority during certification (Phase 3).
 *
 * @param hash          H(document) as a hex string or Buffer
 * @param privateKeyPem Authority A's private key (PEM)
 * @returns             Signature Buffer passed to DocumentRegistry.certify()
 */
export function signDocumentHash(
  hash: Buffer | string,
  privateKeyPem: string
): Buffer {
  const data = typeof hash === "string" ? Buffer.from(hash.replace(/^0x/, ""), "hex") : hash;
  return crypto.sign("sha256", data, { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING });
}

// ── Document key encryption / decryption (RSA-OAEP) ──────────────────────────

/**
 * Encrypt k_doc with Authority A's own public key.
 * E_A = Enc(pk_A, k_doc)
 * Called by the certifying authority during archival (Phase 3).
 * E_A is stored on-chain in KeyShareRegistry alongside the SSS shares.
 * This allows Authority A to retrieve k_doc directly during retrieval
 * without requiring cooperation from other authorities.
 *
 * @param key           k_doc — the per-document symmetric key (32 bytes)
 * @param publicKeyPem  Authority A's own public key (PEM)
 * @returns             Encrypted k_doc Buffer stored on-chain
 */
export function encryptDocumentKey(key: Buffer, publicKeyPem: string): Buffer {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    key
  );
}

/**
 * Decrypt E_A to recover k_doc.
 * k_doc = Dec(sk_A, E_A)
 * Called by Authority A during retrieval (Phase 4).
 * Only Authority A can perform this operation — it requires sk_A
 * which never leaves the authority node.
 *
 * @param encryptedKey  E_A retrieved from KeyShareRegistry on-chain
 * @param privateKeyPem Authority A's private key (PEM, local only)
 * @returns             k_doc — the per-document symmetric key (32 bytes)
 */
export function decryptDocumentKey(
  encryptedKey:  Buffer,
  privateKeyPem: string
): Buffer {
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedKey
  );
}

/**
 * Decrypt document ciphertext using k_doc.
 * document = Dec(k_doc, c)
 * Called by Authority A during retrieval (Phase 4) after recovering k_doc.
 * The plaintext document is then sent to the requesting user over TLS.
 *
 * @param encrypted  EncryptedDocument — ciphertext + iv + authTag
 * @param key        k_doc — the per-document symmetric key (32 bytes)
 * @returns          Plaintext document Buffer
 */
export function decryptDocument(encrypted: EncryptedDocument, key: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, encrypted.iv);
  decipher.setAuthTag(encrypted.authTag);
  return Buffer.concat([decipher.update(encrypted.ciphertext), decipher.final()]);
}
import crypto from "node:crypto";

// ── Nonce signing ─────────────────────────────────────────────────────────────

/**
 * Sign a nonce received from an authority node.
 * WP2 §Lightweight Auth Protocol Step 2:
 * "The requester signs it with sk_active and returns the signature."
 *
 * @param nonce         Hex-encoded nonce from GET /auth/challenge
 * @param privateKeyPem Client's active private key (PEM)
 * @returns             Hex-encoded signature
 */
export function signNonce(nonce: string, privateKeyPem: string): string {
  const nonceBuffer = Buffer.from(nonce, "hex");
  const signature   = crypto.sign(
    "sha256",
    nonceBuffer,
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }
  );
  return signature.toString("hex");
}

// ── Authority signature verification ─────────────────────────────────────────

/**
 * Verify the authority's certification signature σ_A.
 * WP2 §External Verification Phase 7:
 * "The External Verifier extracts pk_A from the received DIDDocument_A
 *  and verifies the certification signature σ_A = Sign(sk_A, h) against
 *  pk_A and h. This confirms that the document was certified by an
 *  Authority belonging to the consortium."
 *
 * @param documentHash  H(document) as hex string
 * @param signature     σ_A — hex-encoded signature from DocumentRegistry
 * @param publicKeyPem  Authority A's public key (PEM, from DIDRegistry)
 * @returns             true if signature is valid
 */
export function verifyAuthoritySignature(
  documentHash: string,
  signature:    string,
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

// ── Challenge decryption ──────────────────────────────────────────────────────

/**
 * Decrypt the challenge c_meta received from the External Verifier.
 * WP2 §External Verification Phase 8:
 * "The User decrypts it as metadata = Dec(sk_U, c_meta) and returns
 *  the plaintext. The External Verifier recomputes H(metadata) and
 *  verifies that it matches the value received from the Oracle."
 *
 * c_meta = Enc(pk_U, metadata) — encrypted with RSA-OAEP by the Oracle.
 * The User decrypts it with its own sk_U to prove possession.
 *
 * @param ciphertext    c_meta — hex-encoded encrypted metadata
 * @param privateKeyPem User's active private key sk_U (PEM)
 * @returns             Plaintext metadata Buffer
 */
export function decryptChallenge(
  ciphertext:    string,
  privateKeyPem: string
): Buffer {
  const ciphertextBuffer = Buffer.from(ciphertext.replace(/^0x/, ""), "hex");
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    ciphertextBuffer
  );
}

// ── RSA keypair generation ────────────────────────────────────────────────────

export interface RSAKeyPair {
  privateKey: string; // PEM
  publicKey:  string; // PEM
}

/**
 * Generate an RSA-4096 keypair for the client entity.
 * The public key is registered on-chain in the DIDDocument.
 * The private key is stored locally and never leaves the client.
 */
export function generateRSAKeyPair(): RSAKeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { privateKey, publicKey };
}
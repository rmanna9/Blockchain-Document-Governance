import { signNonce } from "./crypto.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AuthCredentials {
  did:           string;
  privateKeyPem: string;
}

// ── Auth helper ───────────────────────────────────────────────────────────────

/**
 * Perform Steps 1-2 of the lightweight authentication protocol.
 * WP2 §Lightweight Auth Protocol:
 * Step 1 — GET /auth/challenge?did=<did> — receive nonce
 * Step 2 — Sign nonce with sk_active
 */
async function getAuthTokens(
  authorityUrl: string,
  creds:        AuthCredentials
): Promise<{ nonce: string; signature: string }> {
  const res       = await fetch(`${authorityUrl}/auth/challenge?did=${encodeURIComponent(creds.did)}`);
  const { nonce } = await res.json() as { nonce: string };
  const signature = signNonce(nonce, creds.privateKeyPem);
  return { nonce, signature };
}

// ── Document certification ────────────────────────────────────────────────────

/**
 * Transmit a document to an authority for certification.
 * WP2 §Certification Phase 2 — Off-chain document transfer.
 *
 * The document hash must already be committed on-chain via
 * DocumentRegistry.requestCertification() before calling this.
 *
 * @param authorityUrl  Base URL of the authority node
 * @param creds         Client DID and private key
 * @param documentHash  H(document) committed on-chain in Phase 1
 * @param document      Raw document Buffer
 * @returns             { signature: σ_A } from the authority
 */
export async function certifyDocument(
  authorityUrl: string,
  creds:        AuthCredentials,
  documentHash: string,
  document:     Buffer
): Promise<{ signature: string }> {
  const { nonce, signature } = await getAuthTokens(authorityUrl, creds);

  const res = await fetch(`${authorityUrl}/document/certify`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      did:          creds.did,
      nonce,
      signature,
      documentHash,
      document:     document.toString("base64"),
    }),
  });

  if (!res.ok) {
    const err = await res.json() as { error: string };
    throw new Error(`Certification failed: ${err.error}`);
  }

  return res.json() as Promise<{ signature: string }>;
}

// ── Document retrieval ────────────────────────────────────────────────────────

/**
 * Retrieve a document from the certifying authority.
 * WP2 §Retrieval Phases 2-5.
 *
 * The user must have called DocumentAccessControl.checkAndApproveRead()
 * on-chain before calling this — emitting a ReadApproved event.
 *
 * @param authorityUrl  Base URL of the certifying authority
 * @param creds         Client DID and private key
 * @param documentHash  H(document) to retrieve
 * @returns             Plaintext document Buffer
 */
export async function retrieveDocument(
  authorityUrl: string,
  creds:        AuthCredentials,
  documentHash: string
): Promise<Buffer> {
  const { nonce, signature } = await getAuthTokens(authorityUrl, creds);

  const res = await fetch(`${authorityUrl}/document/retrieve`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      did: creds.did,
      nonce,
      signature,
      documentHash,
    }),
  });

  if (!res.ok) {
    const err = await res.json() as { error: string };
    throw new Error(`Retrieval failed: ${err.error}`);
  }

  const arrayBuffer = await res.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

// ── Forced read (RF3) ─────────────────────────────────────────────────────────

/**
 * Request forced read of a document via the aggregator authority.
 * WP2 §Forced Document Retrieval via Governance (RF3).
 *
 * The governance proposal must already be approved and executed
 * before calling this. The aggregator authority collects shares
 * from other authorities, reconstructs k_doc, and returns the
 * plaintext document.
 *
 * @param aggregatorUrl  Base URL of the aggregator authority
 * @param creds          Client DID and private key
 * @param documentHash   H(document) to retrieve
 * @returns              Plaintext document Buffer
 */
export async function forcedRead(
  aggregatorUrl: string,
  creds:         AuthCredentials,
  documentHash:  string
): Promise<Buffer> {
  const { nonce, signature } = await getAuthTokens(aggregatorUrl, creds);

  const res = await fetch(`${aggregatorUrl}/document/forced-read`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      did: creds.did,
      nonce,
      signature,
      documentHash,
    }),
  });

  if (!res.ok) {
    const err = await res.json() as { error: string };
    throw new Error(`Forced read failed: ${err.error}`);
  }

  const arrayBuffer = await res.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

// ── Health check ──────────────────────────────────────────────────────────────

export async function checkHealth(authorityUrl: string): Promise<boolean> {
  try {
    const res = await fetch(`${authorityUrl}/health`);
    return res.ok;
  } catch {
    return false;
  }
}
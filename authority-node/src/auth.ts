import crypto from "node:crypto";
import { verifySignature } from "./crypto.js";
import type { ContractClients } from "./contracts.js";
import { resolveDID, isFullyActive, getReadApprovedEventsFromDAC } from "./contracts.js";

// ── Nonce store ───────────────────────────────────────────────────────────────

const NONCE_TTL_MS = 5 * 60 * 1000;

interface NonceEntry {
  nonce:     string;
  createdAt: number;
  consumed:  boolean;
}

const _nonceStore = new Map<string, NonceEntry>();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of _nonceStore.entries()) {
    if (now - entry.createdAt > NONCE_TTL_MS) _nonceStore.delete(key);
  }
}, 60_000);

// ── Nonce generation ──────────────────────────────────────────────────────────

/**
 * Generate a fresh session nonce for a requesting DID.
 * WP2 §Lightweight Auth Protocol Step 2.
 * Called by GET /auth/challenge?did=<did>
 */
export function generateNonce(did: string): string {
  const nonce = crypto.randomBytes(32).toString("hex");
  _nonceStore.set(did, { nonce, createdAt: Date.now(), consumed: false });
  return nonce;
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type AuthContext = "retrieval" | "certification";

export interface AuthRequest {
  did:          string;
  nonce:        string;
  signature:    string;
  documentHash: `0x${string}`;
  context:      AuthContext;
}

export interface AuthResult {
  success:  boolean;
  did:      string;
  address:  string;
  reason?:  string;
}

// ── Lightweight Authentication Protocol ──────────────────────────────────────

/**
 * Authenticate a requesting entity using the lightweight authentication
 * protocol defined in WP2 §2.2.4.
 *
 * The four steps are always the same — only Step 4 differs by context:
 *   - "retrieval":     verify ReadApproved(address, documentHash) on-chain
 *   - "certification": verify PENDING record in DocumentRegistry
 *                      for (creatorAddress, documentHash)
 *
 * @param req       Auth request — DID, nonce, signature, documentHash, context
 * @param contracts Initialised contract clients
 */
export async function authenticateRequest(
  req:       AuthRequest,
  contracts: ContractClients
): Promise<AuthResult> {
  const { did, nonce, signature, documentHash, context } = req;

  // Step 1 — Resolve DID Document and check isFullyActive
  // WP2: "Aborts if isActive = false."
  const fullyActive = await isFullyActive(contracts, did);
  if (!fullyActive) {
    return { success: false, did, address: "", reason: "DID not active or authority removed" };
  }

  const didDoc          = await resolveDID(contracts, did);
  const activePublicKey = didDoc.activePublicKey as string;

  if (!activePublicKey || activePublicKey.length === 0) {
    return { success: false, did, address: "", reason: "No active public key registered" };
  }

  // Step 2 — Verify nonce signature against activePublicKey
  // WP2: "The requester signs it with sk_active and returns the signature.
  //       The Authority verifies the signature against activePublicKey."
  const nonceBuffer = Buffer.from(nonce, "hex");
  const sigBuffer   = Buffer.from(signature, "hex");

  if (!verifySignature(nonceBuffer, sigBuffer, activePublicKey)) {
    return { success: false, did, address: "", reason: "Invalid signature" };
  }

  // Step 3 — Consume nonce to prevent replay (T7)
  // WP2: "The nonce is marked as consumed to prevent replay."
  const entry = _nonceStore.get(did);
  if (
    !entry ||
    entry.consumed ||
    entry.nonce !== nonce ||
    Date.now() - entry.createdAt > NONCE_TTL_MS
  ) {
    return { success: false, did, address: "", reason: "Nonce expired, consumed, or invalid" };
  }
  entry.consumed = true;

  // Step 4 — On-chain binding
  // WP2: "The Authority verifies that the address resolved from DID_requester
  //       via DIDRegistry.lookup matches the address recorded in the relevant
  //       on-chain event for the specific document hash h provided by the
  //       requester alongside its DID."
  const resolvedAddress = didDoc.entityAddress as `0x${string}`;

  if (context === "retrieval") {
    // Verify ReadApproved(address, documentHash) exists on-chain
    const events = await getReadApprovedEventsFromDAC(
      contracts,
      documentHash,
      resolvedAddress
    );
    if (!events || events.length === 0) {
      return {
        success: false,
        did,
        address: resolvedAddress,
        reason: `No ReadApproved event found for (${resolvedAddress}, ${documentHash})`,
      };
    }

  } else {
    // context === "certification"
    // Verify PENDING record exists for (creatorAddress, documentHash)
    let record: any;
    try {
      record = await contracts.documentRegistry.read.getRecord([documentHash]);
    } catch {
      return {
        success: false,
        did,
        address: resolvedAddress,
        reason: `No record found for document ${documentHash}`,
      };
    }

    if (record.status !== 0) {
      return {
        success: false,
        did,
        address: resolvedAddress,
        reason: `Document ${documentHash} is not in PENDING status`,
      };
    }

    const creatorDoc = await resolveDID(contracts, record.creatorDID);
    if (creatorDoc.entityAddress.toLowerCase() !== resolvedAddress.toLowerCase()) {
      return {
        success: false,
        did,
        address: resolvedAddress,
        reason: `Address mismatch: resolved ${resolvedAddress} but creator is ${creatorDoc.entityAddress}`,
      };
    }
  }

  return { success: true, did, address: resolvedAddress };
}
import { existsSync, readFileSync, writeFileSync } from "fs";
import { mkdirSync } from "fs";
import { initContracts } from "./contracts.js";
import { generateRSAKeyPair } from "./crypto.js";
import { createHeliaNode } from "./ipfs.js";
import { startServer } from "./server.js";

// ── Environment variables ─────────────────────────────────────────────────────

const RPC_URL          = process.env.RPC_URL          ?? "http://ganache:8545";
const ADDRESSES_PATH   = process.env.ADDRESSES_PATH   ?? "/shared/addresses.json";
const KEYS_DIR         = process.env.KEYS_DIR         ?? "/data/keys";
const IPFS_STORAGE     = process.env.IPFS_STORAGE     ?? "/data/ipfs";
const PORT             = parseInt(process.env.PORT    ?? "3000");
const AUTHORITY_DID    = process.env.AUTHORITY_DID    ?? "";
const AUTHORITY_ADDR   = process.env.AUTHORITY_ADDR   ?? "";
const ETH_PRIVATE_KEY  = process.env.ETH_PRIVATE_KEY  ?? "";

// Authority URLs for forced read aggregation
// Format: "0xADDR1=http://authority-a:3001,0xADDR2=http://authority-b:3002"
const AUTHORITY_URLS_ENV = process.env.AUTHORITY_URLS ?? "";

if (!AUTHORITY_DID || !AUTHORITY_ADDR || !ETH_PRIVATE_KEY) {
  console.error("[Index] Missing required environment variables: AUTHORITY_DID, AUTHORITY_ADDR, ETH_PRIVATE_KEY");
  process.exit(1);
}

// ── Key management ────────────────────────────────────────────────────────────

/**
 * Load or generate RSA keypair for this authority node.
 * On first startup, generate a fresh RSA-4096 keypair and persist it.
 * On subsequent startups, load the existing keypair from disk.
 *
 * The public key must be registered on-chain in the DIDDocument.
 * The private key never leaves this node.
 */
function loadOrGenerateKeys(): { privateKeyPem: string; publicKeyPem: string } {
  const privateKeyPath = `${KEYS_DIR}/private.pem`;
  const publicKeyPath  = `${KEYS_DIR}/public.pem`;

  if (existsSync(privateKeyPath) && existsSync(publicKeyPath)) {
    console.log("[Index] Loading existing RSA keypair from disk...");
    return {
      privateKeyPem: readFileSync(privateKeyPath, "utf-8"),
      publicKeyPem:  readFileSync(publicKeyPath,  "utf-8"),
    };
  }

  console.log("[Index] Generating new RSA-4096 keypair...");
  mkdirSync(KEYS_DIR, { recursive: true });
  const { privateKey, publicKey } = generateRSAKeyPair();
  writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
  writeFileSync(publicKeyPath,  publicKey);
  console.log(`[Index] Keypair saved to ${KEYS_DIR}`);

  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

// ── Authority URLs parsing ────────────────────────────────────────────────────

/**
 * Parse AUTHORITY_URLS env variable into a Map<address, url>.
 * Format: "0xADDR1=http://authority-a:3001,0xADDR2=http://authority-b:3002"
 */
function parseAuthorityUrls(): Map<`0x${string}`, string> {
  const map = new Map<`0x${string}`, string>();
  if (!AUTHORITY_URLS_ENV) return map;

  for (const entry of AUTHORITY_URLS_ENV.split(",")) {
    const [addr, url] = entry.split("=");
    if (addr && url) {
      map.set(addr.trim() as `0x${string}`, url.trim());
    }
  }
  return map;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`[Index] Starting authority node: ${AUTHORITY_DID}`);
  console.log(`[Index] Address: ${AUTHORITY_ADDR}`);
  console.log(`[Index] RPC: ${RPC_URL}`);

  // Step 1 — Load or generate RSA keypair
  const { privateKeyPem, publicKeyPem } = loadOrGenerateKeys();
  console.log("[Index] RSA keypair ready");

  // Step 2 — Wait for addresses.json to be available
  // The deployer container writes this file after deployment
  let attempts = 0;
  while (!existsSync(ADDRESSES_PATH) && attempts < 30) {
    console.log(`[Index] Waiting for ${ADDRESSES_PATH}...`);
    await new Promise(r => setTimeout(r, 2000));
    attempts++;
  }

  if (!existsSync(ADDRESSES_PATH)) {
    console.error(`[Index] ${ADDRESSES_PATH} not found after 60s — aborting`);
    process.exit(1);
  }
  console.log(`[Index] Addresses loaded from ${ADDRESSES_PATH}`);

  // Step 3 — Init contract clients
  const contracts = initContracts(RPC_URL, ETH_PRIVATE_KEY, ADDRESSES_PATH);
  console.log("[Index] Contract clients initialized");

  // Step 4 — Start Helia IPFS node
  mkdirSync(IPFS_STORAGE, { recursive: true });
  const helia = await createHeliaNode(IPFS_STORAGE);
  console.log("[Index] Helia IPFS node started");

  // Step 5 — Parse authority URLs for forced read aggregation
  const authorityUrls = parseAuthorityUrls();
  console.log(`[Index] Authority URLs configured: ${authorityUrls.size} entries`);

  // Step 6 — Start Express server
  startServer({
    port:             PORT,
    contracts,
    helia,
    authorityAddress: AUTHORITY_ADDR as `0x${string}`,
    authorityDID:     AUTHORITY_DID,
    privateKeyPem,
    publicKeyPem,
    authorityUrls,
  });

  console.log(`[Index] Authority node ${AUTHORITY_DID} ready on port ${PORT}`);
}

main().catch(err => {
  console.error("[Index] Fatal error:", err);
  process.exit(1);
});
import { generateKeyPairSync } from "crypto";
import { existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";

const keysDir   = process.env.KEYS_DIR   ?? "/data/user-keys";
const sharedDir = process.env.SHARED_DIR ?? "/shared";

mkdirSync(keysDir,   { recursive: true });
mkdirSync(sharedDir, { recursive: true });

const privateKeyPath = `${keysDir}/private.pem`;
const publicKeyPath  = `${keysDir}/public.pem`;
const sharedPubPath  = `${sharedDir}/user-public.pem`;

if (!existsSync(privateKeyPath)) {
  console.log("Generating RSA-2048 keypair for user...");
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
  writeFileSync(publicKeyPath,  publicKey);
  console.log(`Keypair saved to ${keysDir}`);
} else {
  console.log("User keys already exist — skipping.");
}

// Always write public key to shared volume for deployer
const publicKey = readFileSync(publicKeyPath, "utf-8");
writeFileSync(sharedPubPath, publicKey);
console.log(`Public key written to ${sharedPubPath}`);
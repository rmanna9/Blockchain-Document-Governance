const { generateKeyPairSync } = require("crypto");
const fs = require("fs");

const keysDir  = process.env.KEYS_DIR  ?? "/data/keys";
const sharedDir = process.env.SHARED_DIR ?? "/shared";
const name     = process.env.AUTHORITY_NAME ?? "authority";

fs.mkdirSync(keysDir,   { recursive: true });
fs.mkdirSync(sharedDir, { recursive: true });

const privateKeyPath = `${keysDir}/private.pem`;
const publicKeyPath  = `${keysDir}/public.pem`;
const sharedKeyPath  = `${sharedDir}/pk-${name}.pem`;

if (!fs.existsSync(privateKeyPath)) {
  console.log(`Generating RSA-4096 keypair for ${name}...`);
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(publicKeyPath,  publicKey);
  console.log(`Keypair saved to ${keysDir}`);
} else {
  console.log(`Keys already exist for ${name} — loading...`);
}

const publicKey = fs.readFileSync(publicKeyPath, "utf-8");
fs.writeFileSync(sharedKeyPath, publicKey);
console.log(`Public key written to ${sharedKeyPath}`);
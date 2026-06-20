<h1 align="center">Blockchain Document Governance</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Solidity-0.8.28-363636?style=flat-square&logo=solidity&logoColor=white" />
  <img src="https://img.shields.io/badge/Hardhat-3.x-yellow?style=flat-square&logo=ethereum&logoColor=white" />
  <img src="https://img.shields.io/badge/TypeScript-6.0-3178C6?style=flat-square&logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/IPFS-Helia-65C2CB?style=flat-square&logo=ipfs&logoColor=white" />
  <img src="https://img.shields.io/badge/License-ISC-blue?style=flat-square" />
</p>

<p align="center">
  A decentralized document governance system built on Ethereum-compatible smart contracts, with decentralized identity (DID), IPFS-based archival via Helia, threshold key sharing (Shamir's Secret Sharing), and an off-chain oracle workflow — designed as part of the <strong>WP2</strong> research specification.
</p>

<p align="center">
  <a href="docs/report.pdf"><strong>📄 Read the Full Project Report</strong></a>
</p>

---

## Overview

This system enables a consortium of authorities to **certify, revoke, and audit documents** on-chain, while keeping document content off-chain on IPFS. Access control is enforced cryptographically through RSA encryption and threshold key sharing, so no single authority can reconstruct a document key alone.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Off-chain Layer                          │
│                                                                 │
│   CLI (cli.ts)  ──►  Oracle Simulator  ──►  Helia IPFS Node    │
│       │               (oracle-sim.ts)        (helia-node.ts)   │
│       │                                                         │
│       └──►  Crypto Module (crypto.ts)                          │
│              RSA · AES-256-GCM · Shamir SSS                    │
└────────────────────────┬────────────────────────────────────────┘
                         │  ethers / viem
┌────────────────────────▼────────────────────────────────────────┐
│                     On-chain Layer (EVM)                        │
│                                                                 │
│  DIDRegistry · DocumentRegistry · DocumentAccessControl         │
│  KeyShareRegistry · GovernanceContract · AuditLog               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

- **Decentralized Identity (DID)** — authorities register and manage DIDs on-chain via `DIDRegistry`
- **Document Certification & Revocation** — `DocumentRegistry` stores IPFS CIDs and lifecycle events on-chain
- **Threshold Access Control** — `KeyShareRegistry` stores RSA-encrypted Shamir shares; a quorum of authorities is required to reconstruct the document encryption key
- **Governance** — `GovernanceContract` coordinates multi-authority proposals and voting
- **Audit Trail** — every significant action is logged immutably via `AuditLog`
- **IPFS Archival** — document content is stored on IPFS through an in-process Helia node (MemoryBlockstore)
- **Oracle Workflow** — off-chain oracle (`oracle-sim.ts`) bridges real-world verification events to on-chain state

---

## Smart Contracts

| Contract | Responsibility |
|---|---|
| `DIDRegistry` | Register and resolve Decentralized Identifiers for consortium authorities |
| `DocumentRegistry` | Certify/revoke documents; store IPFS CIDs; emit `DocumentCertified`, `DocumentRevoked`, `CIDStored` |
| `DocumentAccessControl` | Manage per-document read permissions; emit `ReadApproved` |
| `KeyShareRegistry` | Store RSA-encrypted Shamir key shares per authority; emit `SharesStored` |
| `GovernanceContract` | Multi-authority proposal and voting logic |
| `AuditLog` | Append-only log of governance and document lifecycle events |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Smart Contracts | Solidity 0.8.28 |
| Development Framework | Hardhat 3.x |
| On-chain Interaction | [viem](https://viem.sh/) |
| Language | TypeScript 6 + ESM |
| IPFS | [Helia](https://github.com/ipfs/helia) (in-process, MemoryBlockstore) |
| Cryptography | Node.js `crypto` — RSA-OAEP, AES-256-GCM |
| Key Sharing | [shamirs-secret-sharing](https://github.com/amper5and/secrets.js) |
| Local Chain | Hardhat Network / Ganache — `localhost:8545`, chainId `1337` |

---

## Project Structure

```
├── contracts/                  # Solidity smart contracts
│   ├── DIDRegistry.sol
│   ├── DocumentRegistry.sol
│   ├── DocumentAccessControl.sol
│   ├── KeyShareRegistry.sol
│   ├── GovernanceContract.sol
│   └── AuditLog.sol
├── scripts/
│   ├── cli.ts                  # Interactive CLI — main entry point
│   ├── deploy.ts               # Contract deployment script
│   ├── crypto.ts               # RSA / AES / Shamir helpers
│   └── oracle-sim.ts           # Off-chain oracle simulator
├── ipfs/
│   └── helia-node.ts           # Helia in-process IPFS node
├── shared/
│   ├── addresses.json          # Deployed contract addresses
│   └── authority-{a,b,c}-{private,public}.pem  # Authority RSA keys
├── test/                       # Hardhat integration tests (viem)
└── hardhat.config.ts
```

---

## Getting Started

### Prerequisites

- Node.js ≥ 20
- A running local EVM node (Hardhat Network or Ganache) on `localhost:8545`

### Install dependencies

```bash
npm install
```

### Compile contracts

```bash
npx hardhat compile
```

### Run tests

```bash
npx hardhat test
```

### Deploy system on Ganache Desktop

Before running the deployment, create a Ganache workspace with the following settings:

| Setting | Value |
|---|---|
| **Port** | `8545` |
| **Network ID** | `1337` |
| **Mnemonic** | `test test test test test test test test test test test junk` |

Then deploy:

```bash
npx hardhat run scripts/deploy.ts --network ganache
```

### Run the CLI

```bash
npx tsx scripts/cli.ts
```

The interactive menu guides you through the full document lifecycle: register DIDs, certify documents, upload to IPFS, manage key shares, request access, and trigger oracle workflows.
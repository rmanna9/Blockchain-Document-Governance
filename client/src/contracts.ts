import { createPublicClient, createWalletClient, http, getContract, keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { hardhat } from "viem/chains";
import { readFileSync } from "fs";

import DIDRegistryABI         from "../../artifacts/contracts/DIDRegistry.sol/DIDRegistry.json" with { type: "json" };
import DocumentRegistryABI    from "../../artifacts/contracts/DocumentRegistry.sol/DocumentRegistry.json" with { type: "json" };
import DocumentAccessControlABI from "../../artifacts/contracts/DocumentAccessControl.sol/DocumentAccessControl.json" with { type: "json" };
import KeyShareRegistryABI    from "../../artifacts/contracts/KeyShareRegistry.sol/KeyShareRegistry.json" with { type: "json" };
import GovernanceContractABI  from "../../artifacts/contracts/GovernanceContract.sol/GovernanceContract.json" with { type: "json" };
import AuditLogABI            from "../../artifacts/contracts/AuditLog.sol/AuditLog.json" with { type: "json" };

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ContractAddresses {
  auditLog:           `0x${string}`;
  didRegistry:        `0x${string}`;
  governanceContract: `0x${string}`;
  documentRegistry:   `0x${string}`;
  accessControl:      `0x${string}`;
  keyShareRegistry:   `0x${string}`;
}

export interface ClientContracts {
  publicClient:    ReturnType<typeof createPublicClient>;
  walletClient:    ReturnType<typeof createWalletClient>;
  addresses:       ContractAddresses;
  didRegistry:     ReturnType<typeof getContract>;
  documentRegistry: ReturnType<typeof getContract>;
  accessControl:   ReturnType<typeof getContract>;
  governance:      ReturnType<typeof getContract>;
  keyShareRegistry: ReturnType<typeof getContract>;
}

// ── Initialisation ────────────────────────────────────────────────────────────

export function initClientContracts(
  rpcUrl:        string,
  privateKeyHex: string,
  addressesPath: string
): ClientContracts {
  const addresses = JSON.parse(readFileSync(addressesPath, "utf-8")) as ContractAddresses;

  const chain   = { ...hardhat, rpcUrls: { default: { http: [rpcUrl] }, public: { http: [rpcUrl] } } };
  const account = privateKeyToAccount(`0x${privateKeyHex}` as `0x${string}`);

  const publicClient = createPublicClient({ chain, transport: http(rpcUrl) });
  const walletClient = createWalletClient({ chain, transport: http(rpcUrl), account });

  return {
    publicClient,
    walletClient,
    addresses,
    didRegistry: getContract({
      address: addresses.didRegistry,
      abi:     DIDRegistryABI.abi,
      client:  { public: publicClient, wallet: walletClient },
    }),
    documentRegistry: getContract({
      address: addresses.documentRegistry,
      abi:     DocumentRegistryABI.abi,
      client:  { public: publicClient, wallet: walletClient },
    }),
    accessControl: getContract({
      address: addresses.accessControl,
      abi:     DocumentAccessControlABI.abi,
      client:  { public: publicClient, wallet: walletClient },
    }),
    governance: getContract({
      address: addresses.governanceContract,
      abi:     GovernanceContractABI.abi,
      client:  { public: publicClient, wallet: walletClient },
    }),
    keyShareRegistry: getContract({
      address: addresses.keyShareRegistry,
      abi:     KeyShareRegistryABI.abi,
      client:  { public: publicClient, wallet: walletClient },
    }),
  };
}

// ── DocumentRegistry ──────────────────────────────────────────────────────────

/**
 * Phase 1 of certification workflow.
 * WP2: "The User computes h_new = H(document) and invokes
 *       DocumentRegistry.requestCertification(h_new, h_ref, ownerDID)."
 */
export async function requestCertification(
  contracts:    ClientContracts,
  documentHash: `0x${string}`,
  previousHash: `0x${string}`,
  ownerDID:     string = ""
): Promise<`0x${string}`> {
  return contracts.documentRegistry.write.requestCertification([
    documentHash,
    previousHash,
    ownerDID,
  ]) as Promise<`0x${string}`>;
}

export async function getRecord(
  contracts:    ClientContracts,
  documentHash: `0x${string}`
) {
  return contracts.documentRegistry.read.getRecord([documentHash]) as Promise<any>;
}

export async function getDocumentStatus(
  contracts:    ClientContracts,
  documentHash: `0x${string}`
): Promise<number> {
  return contracts.documentRegistry.read.getStatus([documentHash]) as Promise<number>;
}

// ── DocumentAccessControl ─────────────────────────────────────────────────────

/**
 * Phase 1 of retrieval workflow.
 * WP2: "The User invokes DocumentAccessControl.checkPermission(h, canRead)
 *       to verify on-chain that it holds a valid read permission.
 *       DocumentAccessControl emits ReadApproved(user_address, h, timestamp)."
 */
export async function checkAndApproveRead(
  contracts:    ClientContracts,
  documentHash: `0x${string}`
): Promise<`0x${string}`> {
  return contracts.accessControl.write.checkAndApproveRead([
    documentHash,
  ]) as Promise<`0x${string}`>;
}

export async function hasPermission(
  contracts:    ClientContracts,
  holderDID:    string,
  documentHash: `0x${string}`,
  actionType:   number
): Promise<boolean> {
  return contracts.accessControl.read.hasPermission([
    holderDID,
    documentHash,
    actionType,
  ]) as Promise<boolean>;
}

/**
 * Delegate canRead or canUpdate to another user.
 * WP2 §Delegation Workflow.
 */
export async function delegate(
  contracts:       ClientContracts,
  delegateeDID:    string,
  documentHash:    `0x${string}`,
  actionType:      number,
  canDelegate:     boolean,
  delegableRead:   boolean,
  delegableUpdate: boolean,
  expiresAt:       bigint = 0n
): Promise<`0x${string}`> {
  return contracts.accessControl.write.delegate([
    delegateeDID,
    documentHash,
    actionType,
    canDelegate,
    delegableRead,
    delegableUpdate,
    expiresAt,
  ]) as Promise<`0x${string}`>;
}

// ── DIDRegistry ───────────────────────────────────────────────────────────────

export async function resolveDID(
  contracts: ClientContracts,
  did:       string
) {
  return contracts.didRegistry.read.resolve([did]) as Promise<any>;
}

export async function getActivePublicKey(
  contracts: ClientContracts,
  did:       string
): Promise<string> {
  return contracts.didRegistry.read.getActivePublicKey([did]) as Promise<string>;
}

// ── GovernanceContract ────────────────────────────────────────────────────────

export async function getAuthorities(
  contracts: ClientContracts
): Promise<`0x${string}`[]> {
  return contracts.governance.read.getAuthorities([]) as Promise<`0x${string}`[]>;
}
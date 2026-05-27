import { createHelia } from "helia";
import { unixfs } from "@helia/unixfs";
import { FsBlockstore } from "blockstore-fs";
import { FsDatastore } from "datastore-fs";
import type { Helia } from "@helia/interface";
import type { UnixFS } from "@helia/unixfs";
import { CID } from "multiformats/cid";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface HeliaNode {
  helia:  Helia;
  fs:     UnixFS;
}

// ── Node creation ─────────────────────────────────────────────────────────────

/**
 * Create and start a Helia IPFS node with persistent local storage.
 * Each authority node runs its own Helia instance that acts as both
 * an upload gateway and a pinning service for documents it has certified.
 *
 * WP2 §System Architecture:
 * "Each authority runs a full IPFS node that acts as a pinning service
 *  for the documents it has certified."
 *
 * @param storagePath  Local directory for block and datastore persistence.
 *                     Each authority node uses a dedicated volume in Docker.
 */
export async function createHeliaNode(storagePath: string): Promise<HeliaNode> {
  const blockstore = new FsBlockstore(`${storagePath}/blocks`);
  const datastore  = new FsDatastore(`${storagePath}/data`);

  const helia = await createHelia({ blockstore, datastore });
  const fs    = unixfs(helia);

  return { helia, fs };
}

// ── Upload ────────────────────────────────────────────────────────────────────

/**
 * Upload encrypted document ciphertext to IPFS and pin it locally.
 * WP2 §Archival Phase 2:
 * "Authority A uploads the ciphertext c to IPFS through its own node
 *  and pins it locally, ensuring persistent availability."
 *
 * @param node     Helia node instance
 * @param content  Serialized EncryptedDocument Buffer
 *                 Layout: [iv (12)] [authTag (16)] [ciphertext]
 * @returns        CID string — permanent off-chain address of the archived document
 */
export async function uploadFile(node: HeliaNode, content: Buffer): Promise<string> {
  const cid = await node.fs.addBytes(content);
  await pinFile(node, cid.toString());
  return cid.toString();
}

// ── Download ──────────────────────────────────────────────────────────────────

/**
 * Download a file from IPFS by CID.
 * WP2 §Retrieval Phase 3:
 * "The authority finds the ciphertext associated to the CID
 *  on its own IPFS node."
 *
 * @param node  Helia node instance
 * @param cid   CID string from DocumentRegistry.getCID(hash)
 * @returns     File content as Buffer
 */
export async function downloadFile(node: HeliaNode, cid: string): Promise<Buffer> {
  const chunks: Uint8Array[] = [];

  for await (const chunk of node.fs.cat(CID.parse(cid))) {
    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

// ── Pin / Unpin ───────────────────────────────────────────────────────────────

/**
 * Pin a CID to the local IPFS node to ensure persistent availability.
 * Called automatically by uploadFile after each archival.
 *
 * @param node  Helia node instance
 * @param cid   CID string to pin
 */
export async function pinFile(node: HeliaNode, cid: string): Promise<void> {
  await node.helia.pins.add(CID.parse(cid));
}

/**
 * Unpin a CID from the local IPFS node.
 * WP2 §Revocation Phase 4:
 * "Authority A's pinning service, acting as an outbound oracle on the
 *  REVOKED event, unpins the ciphertext from its local IPFS node.
 *  Once unpinned, the ciphertext is no longer served by the authority's
 *  IPFS gateway."
 *
 * @param node  Helia node instance
 * @param cid   CID string to unpin
 */
export async function unpinFile(node: HeliaNode, cid: string): Promise<void> {
  await node.helia.pins.rm(CID.parse(cid));
}

// ── Stop ──────────────────────────────────────────────────────────────────────

/**
 * Gracefully stop the Helia node.
 * Called on process exit to flush pending writes.
 */
export async function stopHeliaNode(node: HeliaNode): Promise<void> {
  await node.helia.stop();
}
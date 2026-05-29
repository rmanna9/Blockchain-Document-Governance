import { createHelia } from "helia";
import { unixfs } from "@helia/unixfs";
import { MemoryBlockstore } from "blockstore-core";
import { MemoryDatastore } from "datastore-core";
import { CID } from "multiformats/cid";

type HeliaNode  = Awaited<ReturnType<typeof createHelia>>;
type UnixFSNode = ReturnType<typeof unixfs>;

let _helia: HeliaNode  | null = null;
let _fs:    UnixFSNode | null = null;

const _pinned = new Set<string>();

export async function getNode(): Promise<{ helia: HeliaNode; fs: UnixFSNode }> {
  if (_helia && _fs) return { helia: _helia, fs: _fs };
  _helia = await createHelia({
    blockstore: new MemoryBlockstore(),
    datastore:  new MemoryDatastore(),
    start: false,
  });
  _fs = unixfs(_helia);
  return { helia: _helia, fs: _fs };
}

export async function stopNode(): Promise<void> {
  if (_helia) { await _helia.stop(); _helia = null; _fs = null; }
}

export async function addFile(content: Uint8Array): Promise<string> {
  const { fs } = await getNode();
  return (await fs.addBytes(content)).toString();
}

export async function getFile(cidStr: string): Promise<Uint8Array> {
  const { fs } = await getNode();
  const chunks: Uint8Array[] = [];
  for await (const c of fs.cat(CID.parse(cidStr))) chunks.push(c);
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total); let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

export function pin(cid: string):      void    { _pinned.add(cid); }
export function unpin(cid: string):    void    { _pinned.delete(cid); }
export function isPinned(cid: string): boolean { return _pinned.has(cid); }
export function listPinned():          string[] { return [..._pinned]; }

// A file too large to hold whole, written a block at a time and read back a
// part at a time (Phase 3 L5c: the activity log's background downloads,
// partner decision 31). Deployed, a container on Azure's blob service, as the
// API's managed identity: Put Block for each block, the service checking its
// bytes against their MD5; Put Block List to make the file of them, over any
// file of that name (a month built again after a stop is the same requests);
// Get Blob with a range to read a part. In development and test, a local
// folder standing in for it, a file made whole only once it is committed.
//
// A token is asked once and kept for a few minutes (blobServiceCaller), so a
// file of a thousand blocks asks the identity endpoint a handful of times.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import type { OutboundFetch } from '../outbound/index.ts';
import { type AzureBlobSettings, blobErrorCode, blobServiceCaller, BlobStoreFailed, checkedBlobName } from './azure.ts';

/** A committed file's own facts, kept with it. */
export interface BlockFileFacts {
  readonly contentType: string;
  /** The whole file's SHA-256, in hex. */
  readonly sha256: string;
}

export interface BlockStore {
  /** Writes block `index` (from 0) of `name`, over one of that index not yet committed. */
  putBlock(name: string, index: number, bytes: Buffer): Promise<void>;
  /** Makes `name` the file of its blocks 0 to `blocks` - 1, in order, over any file of that name. */
  commit(name: string, blocks: number, facts: BlockFileFacts): Promise<void>;
  /** Up to `length` bytes of `name` from `offset`: fewer only at its end. */
  read(name: string, offset: number, length: number): Promise<Buffer>;
}

/** What a failure names: this store. */
const STORE = 'download store';

/** How long one call may take: a block is a few MB. */
const CALL_TIMEOUT_MS = 60_000;

/** The most blocks a file may have: Azure's limit. */
const MOST_BLOCKS = 50_000;

function checkedRange(offset: number, length: number): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1) {
    throw new RangeError('A part is read from a whole offset, at least one byte');
  }
}

function checkedBlocks(index: number): void {
  if (!Number.isSafeInteger(index) || index < 0 || index >= MOST_BLOCKS) {
    throw new RangeError(`A file has blocks 0 to ${String(MOST_BLOCKS - 1)}`);
  }
}

/** A block's ID, the same length for every block of a file, as Azure asks. */
const blockId = (index: number): string => Buffer.from(`block-${String(index).padStart(6, '0')}`).toString('base64');

/** The block list Put Block List takes: every block, in order, as written last. */
const blockList = (blocks: number): string =>
  `<?xml version="1.0" encoding="utf-8"?><BlockList>${Array.from(
    { length: blocks },
    (_, index) => `<Latest>${blockId(index)}</Latest>`,
  ).join('')}</BlockList>`;

export function azureBlockStore({
  settings,
  fetch,
  now,
}: {
  readonly settings: AzureBlobSettings;
  readonly fetch: OutboundFetch;
  /** The clock a kept token is timed by. */
  readonly now?: () => number;
}): BlockStore {
  const send = blobServiceCaller({
    settings,
    fetch,
    store: STORE,
    timeoutMs: CALL_TIMEOUT_MS,
    ...(now === undefined ? {} : { now }),
  });

  /** One call to the blob service, refused unless it answers `expected`. */
  const call = async (
    name: string,
    query: string,
    expected: number,
    request: Parameters<typeof send>[1],
  ): Promise<Response> => {
    const response = await send(`/${checkedBlobName(name)}${query}`, request);
    if (response.status === expected) return response;
    await response.body?.cancel();
    throw new BlobStoreFailed(
      STORE,
      `the blob service answered ${String(response.status)} (${blobErrorCode(response)})`,
    );
  };

  return {
    async putBlock(name, index, bytes) {
      checkedBlocks(index);
      const done = await call(name, `?comp=block&blockid=${encodeURIComponent(blockId(index))}`, 201, {
        method: 'PUT',
        headers: { 'content-md5': createHash('md5').update(bytes).digest('base64') },
        body: bytes,
      });
      await done.body?.cancel();
    },

    async commit(name, blocks, { contentType, sha256 }) {
      checkedBlocks(blocks - 1);
      const done = await call(name, '?comp=blocklist', 201, {
        method: 'PUT',
        headers: {
          'content-type': 'application/xml',
          'x-ms-blob-content-type': contentType,
          'x-ms-meta-sha256': sha256,
        },
        body: blockList(blocks),
      });
      await done.body?.cancel();
    },

    async read(name, offset, length) {
      checkedRange(offset, length);
      const part = await call(name, '', 206, {
        method: 'GET',
        headers: { 'x-ms-range': `bytes=${String(offset)}-${String(offset + length - 1)}` },
      });
      const bytes = Buffer.from(await part.arrayBuffer());
      if (bytes.length > length) throw new BlobStoreFailed(STORE, 'the blob service answered more than was asked');
      return bytes;
    },
  };
}

/** A file the folder store writes, and a folder it makes: the process's own alone. */
const OWNER_ONLY = 0o600;
const OWNER_ONLY_FOLDER = 0o700;

/** The local folder standing in for the container (development and test alone). */
export function folderBlockStore(directory: string): BlockStore {
  const pathOf = (name: string) => join(directory, checkedBlobName(name));
  const blocksOf = (name: string) => `${pathOf(name)}.blocks`;

  return {
    async putBlock(name, index, bytes) {
      checkedBlocks(index);
      await mkdir(blocksOf(name), { recursive: true, mode: OWNER_ONLY_FOLDER });
      await writeFile(join(blocksOf(name), String(index)), bytes, { mode: OWNER_ONLY });
    },

    async commit(name, blocks, { sha256 }) {
      checkedBlocks(blocks - 1);
      const parts: Buffer[] = [];
      for (let index = 0; index < blocks; index += 1) parts.push(await readFile(join(blocksOf(name), String(index))));
      const whole = Buffer.concat(parts);
      if (createHash('sha256').update(whole).digest('hex') !== sha256) {
        throw new BlobStoreFailed(STORE, "the file's blocks are not the file named");
      }
      const path = pathOf(name);
      const made = `${path}.${randomUUID()}.part`;
      await mkdir(dirname(path), { recursive: true, mode: OWNER_ONLY_FOLDER });
      await writeFile(made, whole, { flag: 'wx', mode: OWNER_ONLY });
      await rename(made, path);
      // Its blocks go with it, as Azure drops a blob's uncommitted blocks once it is committed.
      await rm(blocksOf(name), { recursive: true, force: true });
    },

    async read(name, offset, length) {
      checkedRange(offset, length);
      // Read whole: a development or test file is small.
      return (await readFile(pathOf(name))).subarray(offset, offset + length);
    },
  };
}

// The write-once store (4D2e E, PL-58): files once written never changed, where
// the chains' anchors are kept apart from the database. Deployed, a container on
// Azure's blob service, as the workload's managed identity: one Put Blob, whole,
// never over a blob there already (`If-None-Match: *`), the service checking the
// bytes against their MD5; List Blobs by a name's start; Get Blob. The container's
// immutability and a role that can only add keep it so, whatever this code does.
// In development and test, a local folder standing in for it, a second write of
// a name refused the same way, and a file made whole before its name appears.
//
// Nothing here is called in production until the durable anchors arrive (E5).
import { createHash, randomUUID } from 'node:crypto';
import { link, mkdir, open, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';

import type { OutboundFetch } from '../outbound/index.ts';
import {
  type AzureBlobSettings,
  blobAlreadyThere,
  blobErrorCode,
  blobServiceCaller,
  BlobStoreFailed,
  checkedBlobName,
  isBlobName,
} from './azure.ts';

/** What a failure names: this store. */
const STORE = 'write-once store';

/** How long one call may take: a snapshot of every chain's anchor is a few MB. */
const CALL_TIMEOUT_MS = 30_000;

/** The most names one page of a list may ask: Azure's limit. */
const MOST_LISTED = 5000;

/** A start of a name to list: as a name's characters, never `..`. */
const NAME_START = /^(?!.*\.\.)[A-Za-z0-9._/-]{1,200}$/;

/** A list's continuation, as Azure gives it: opaque, of these characters alone. */
const MARKER = /^[A-Za-z0-9+/=!*_.~-]{1,1024}$/;

/** A name already holds a file, and write-once means it stays: the caller's to decide what that says. */
export class OverwriteRefused extends Error {
  constructor() {
    super('The write-once store refused the write: a file of that name is there already');
    this.name = 'OverwriteRefused';
  }
}

/** One page of a list, in name order. */
export interface WriteOncePage {
  readonly names: readonly string[];
  /** Files listed under names this store would never write, left out and counted: someone else's work. */
  readonly foreign: number;
  /** What to give the next call to go on; none at the end. */
  readonly next: string | undefined;
}

export interface WriteOnceStore {
  /** Writes `name` whole, once. Throws OverwriteRefused if it is there already, whatever its bytes. */
  put(name: string, bytes: Buffer): Promise<void>;
  /** The names starting with `start`, at most `most` of them, in name order, from `after` (a page's `next`). */
  list(start: string, most: number, after?: string): Promise<WriteOncePage>;
  /** The whole of `name`. Throws BlobStoreFailed if there is none. */
  get(name: string): Promise<Buffer>;
  /**
   * `name` if it holds at most `mostBytes`, never downloading more than one byte past that: `missing` if there is no such
   * file, `too-large` if it holds more, `unreadable` if it is there and can't be read as plain bytes. For files anyone with
   * the add token could make huge, or put beyond a plain read (PL-65): never a failure of the store for that alone.
   */
  getAtMost(name: string, mostBytes: number): Promise<Buffer | 'missing' | 'too-large' | 'unreadable'>;
}

/** A body read only as far as `mostBytes`: past it, the rest is never fetched, and it is `too-large`. */
async function bodyAtMost(response: Response, mostBytes: number): Promise<Buffer | 'too-large'> {
  if (response.body === null) return Buffer.alloc(0);
  // Node's own types leave the chunks untyped: fetch's bodies are bytes.
  const reader = response.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (let read = await reader.read(); !read.done; read = await reader.read()) {
    size += read.value.length;
    if (size > mostBytes) {
      await reader.cancel();
      return 'too-large';
    }
    chunks.push(read.value);
  }
  return Buffer.concat(chunks);
}

/**
 * Azure's refusals to read a blob that whoever added it chose: under their own encryption key, or put in the archive
 * tier. The blob is there and nobody can read it with a plain GET: the file's fault, not the store's.
 */
const UNREADABLE_BLOB = new Set(['BlobUsesCustomerSpecifiedEncryption', 'BlobArchived', 'BlobBeingRehydrated']);

/** A read stopped by its own deadline or a stop: the store's failure, never the file's. */
const stoppedByTime = (error: unknown): boolean =>
  error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError');

/** A blob's whole size, from a ranged answer's `Content-Range: bytes <from>-<to>/<size>`. */
const sizeInRange = (response: Response): number | undefined => {
  const size = /^bytes \d+-\d+\/(\d{1,15})$/.exec(response.headers.get('content-range') ?? '')?.[1];
  return size === undefined ? undefined : Number(size);
};

/**
 * What a ranged read's answer comes to before any of its body: missing, empty, too large, unreadable or a failure; or
 * nothing, and its body is the file's bytes to read.
 */
function answerOtherThanBytes(
  response: Response,
  mostBytes: number,
): Buffer | 'missing' | 'too-large' | 'unreadable' | 'failed' | undefined {
  const code = blobErrorCode(response);
  if (response.status === 404) return code === 'BlobNotFound' ? 'missing' : 'failed';
  if (response.status === 409) return UNREADABLE_BLOB.has(code) ? 'unreadable' : 'failed';
  // An empty blob has no first byte to give.
  if (response.status === 416) return Buffer.alloc(0);
  if (response.status !== 200 && response.status !== 206) return 'failed';
  // A blob stored with an encoding fetch would undo is no plain bytes, and its undoing can fail mid-read.
  const encoding = response.headers.get('content-encoding');
  if (encoding !== null && encoding.trim().toLowerCase() !== 'identity') return 'unreadable';
  if (response.status === 200) return undefined;
  const size = sizeInRange(response);
  if (size === undefined) return 'failed';
  return size > mostBytes ? 'too-large' : undefined;
}

function checkedListing(start: string, most: number): void {
  if (!NAME_START.test(start)) throw new RangeError('A list starts from plain path characters');
  if (!Number.isSafeInteger(most) || most < 1 || most > MOST_LISTED) {
    throw new RangeError(`A list asks 1 to ${String(MOST_LISTED)} names`);
  }
}

/**
 * The names in a List Blobs answer, in its order. Azure's XML is read for these
 * two elements alone. An answer that isn't a whole list is a failure, never an
 * empty store: a caller would take that for "no anchors".
 */
function pageIn(xml: string): WriteOncePage {
  if (!/<EnumerationResults[\s>]/.test(xml) || !xml.includes('</EnumerationResults>')) {
    throw new BlobStoreFailed(STORE, 'the blob service answered a list with something that is not a whole list');
  }
  const listed = [...xml.matchAll(/<Blob>\s*<Name>([^<]*)<\/Name>/g)].map((match) => match[1] ?? '');
  const names = listed.filter(isBlobName);
  const marker = /<NextMarker>([^<]*)<\/NextMarker>/.exec(xml)?.[1] ?? '';
  if (marker !== '' && !MARKER.test(marker)) {
    throw new BlobStoreFailed(STORE, 'the blob service answered a list with a continuation of another form');
  }
  return { names, foreign: listed.length - names.length, next: marker === '' ? undefined : marker };
}

export function azureWriteOnceStore({
  settings,
  fetch,
  now,
}: {
  readonly settings: AzureBlobSettings;
  readonly fetch: OutboundFetch;
  /** The clock a kept token is timed by. */
  readonly now?: () => number;
}): WriteOnceStore {
  const call = blobServiceCaller({
    settings,
    fetch,
    store: STORE,
    timeoutMs: CALL_TIMEOUT_MS,
    ...(now === undefined ? {} : { now }),
  });

  /** An answer other than `expected` as the failure it is: nothing of it read but its status and code. */
  const failed = async (response: Response): Promise<BlobStoreFailed> => {
    await response.body?.cancel();
    return new BlobStoreFailed(
      STORE,
      `the blob service answered ${String(response.status)} (${blobErrorCode(response)})`,
    );
  };

  return {
    async put(name, bytes) {
      const response = await call(`/${checkedBlobName(name)}`, {
        method: 'PUT',
        headers: {
          'x-ms-blob-type': 'BlockBlob',
          'if-none-match': '*',
          'content-type': 'application/octet-stream',
          'content-md5': createHash('md5').update(bytes).digest('base64'),
          'x-ms-meta-sha256': createHash('sha256').update(bytes).digest('hex'),
        },
        body: bytes,
      });
      if (response.status === 201) {
        await response.body?.cancel();
        return;
      }
      if (blobAlreadyThere(response)) {
        await response.body?.cancel();
        throw new OverwriteRefused();
      }
      throw await failed(response);
    },

    async list(start, most, after) {
      checkedListing(start, most);
      const query = new URLSearchParams({
        restype: 'container',
        comp: 'list',
        prefix: start,
        maxresults: String(most),
        ...(after === undefined ? {} : { marker: after }),
      });
      const response = await call(`?${query.toString()}`, { method: 'GET', headers: {} });
      if (response.status !== 200) throw await failed(response);
      return pageIn(await response.text());
    },

    async get(name) {
      const response = await call(`/${checkedBlobName(name)}`, { method: 'GET', headers: {} });
      if (response.status !== 200) throw await failed(response);
      return Buffer.from(await response.arrayBuffer());
    },

    async getAtMost(name, mostBytes) {
      // One byte past the most asked, so a file of exactly that much is told from a larger one.
      const response = await call(`/${checkedBlobName(name)}`, {
        method: 'GET',
        headers: { 'x-ms-range': `bytes=0-${String(mostBytes)}`, 'accept-encoding': 'identity' },
      });
      const answer = answerOtherThanBytes(response, mostBytes);
      if (answer === 'failed') throw await failed(response);
      if (answer !== undefined) {
        await response.body?.cancel();
        return answer;
      }
      try {
        return await bodyAtMost(response, mostBytes);
      } catch (error) {
        if (stoppedByTime(error)) throw error;
        return 'unreadable';
      }
    },
  };
}

/** A file the folder store writes, and a folder it makes: the process's own alone. */
const OWNER_ONLY = 0o600;
const OWNER_ONLY_FOLDER = 0o700;

/** A file being written, not yet under its name. */
const PART = /\.[0-9a-f-]{36}\.part$/;

const hasCode = (error: unknown, code: string): boolean =>
  typeof error === 'object' && error !== null && 'code' in error && error.code === code;

/** The local folder standing in for the container (development and test alone). */
export function folderWriteOnceStore(directory: string): WriteOnceStore {
  const pathOf = (name: string) => join(directory, checkedBlobName(name));

  /** Every file's name, as the store names it; none in a folder not made yet. */
  const allNames = async (): Promise<readonly string[]> => {
    try {
      const entries = await readdir(directory, { recursive: true, withFileTypes: true });
      return entries
        .filter((entry) => entry.isFile())
        .map((entry) => relative(directory, join(entry.parentPath, entry.name)).split(sep).join('/'))
        .filter((name) => !PART.test(name));
    } catch (error) {
      if (hasCode(error, 'ENOENT')) return [];
      throw error;
    }
  };

  return {
    async put(name, bytes) {
      const path = pathOf(name);
      const made = `${path}.${randomUUID()}.part`;
      await mkdir(dirname(path), { recursive: true, mode: OWNER_ONLY_FOLDER });
      try {
        await writeFile(made, bytes, { flag: 'wx', mode: OWNER_ONLY });
        // A hard link fails if the name is taken, where a rename would write over it.
        await link(made, path);
      } catch (error) {
        if (hasCode(error, 'EEXIST')) throw new OverwriteRefused();
        throw error;
      } finally {
        await rm(made, { force: true });
      }
    },

    async list(start, most, after) {
      checkedListing(start, most);
      const names = (await allNames())
        .filter((name) => name.startsWith(start) && (after === undefined || name > after))
        .toSorted();
      // A foreign name takes its place on a page, as Azure's `maxresults` counts it.
      const page = names.slice(0, most);
      const own = page.filter(isBlobName);
      return { names: own, foreign: page.length - own.length, next: names.length > most ? page.at(-1) : undefined };
    },

    async get(name) {
      try {
        return await readFile(pathOf(name));
      } catch (error) {
        if (hasCode(error, 'ENOENT')) throw new BlobStoreFailed(STORE, 'no file of that name');
        throw error;
      }
    },

    async getAtMost(name, mostBytes) {
      let file: Awaited<ReturnType<typeof open>>;
      try {
        file = await open(pathOf(name), 'r');
      } catch (error) {
        if (hasCode(error, 'ENOENT')) return 'missing';
        throw error;
      }
      try {
        // Sized on the file opened, so it can't change between the look and the read.
        const about = await file.stat();
        // A folder where a file would be is no file of that name: it opens for reading on Windows and Linux alike.
        if (about.isDirectory()) return 'missing';
        if (about.size > mostBytes) return 'too-large';
        return await file.readFile();
      } finally {
        await file.close();
      }
    },
  };
}

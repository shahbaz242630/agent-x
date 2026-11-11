// The sharded anchors' store (4D2e PL-65, PR2): each chain's lines in one of 256 shards, so the store can be read a
// shard at a time (PR3 onwards) rather than whole. A chain's shard is the first byte of the SHA-256 of its name: a raw
// UUIDv7 prefix would crowd the newest organisations into one shard. The database computes the same (PR4); a golden test
// holds the two to the same vectors.
//
// Each shard has one folder, `e<epoch>/shards/<hh>/`, its snapshots and deltas side by side, named as the old files are
// (when, counted down, then an ID) with `-s` or `-d` after, so one list a shard finds both, newest first. Each file ends
// with a version 2 closing line, which signs the SHA-256 of every byte before it as well as its name, epoch and count of
// lines: a sound file costs one signature check, not one a line. Its lines keep their own signatures, so a file whose
// closing line fails is read a line at a time, as the old files are.
//
// Each write also leaves a signed list of the shard files it is about to write, `e<epoch>/shards/changes/<when>-<id>`,
// written before them: after its first read a process lists that one folder each run, back to the last it read, and
// fetches what is named there, never 256 folders (a list of the whole `shards/` prefix would page through every file
// written since the epoch began). A file named and not there yet is looked for again for an hour.
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { isCount, openedSmallFile, parsedJson } from './rebase.ts';

/** How many shards there are: one byte of a hash. */
export const SHARDS = 256;

/** The shard a chain's lines go in, by its name as the anchors give it (`platform`, `organisation:<id>`). */
export const shardOf = (chain: string): number => createHash('sha256').update(chain, 'utf8').digest().readUInt8(0);

/** A shard as its folder names it: two hex digits. */
export const shardHex = (shard: number): string => shard.toString(16).padStart(2, '0');

export const shardsFolder = (epoch: number): string => `e${String(epoch)}/shards/`;

export const shardFolder = (epoch: number, shard: number): string => `${shardsFolder(epoch)}${shardHex(shard)}/`;

/** A file's name after its shard's folder: when, counted down, an ID, then whether a snapshot or a delta. */
export const SHARD_FILE = /^\d{13}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[sd]$/;

/** What a version 2 closing line signs: which file, in which epoch, of how many lines, and the hash of them all. */
export const closingV2Message = (name: string, epoch: number, lines: number, body: string): Message => [
  'audit-anchor-file-v2',
  name,
  String(epoch),
  String(lines),
  body,
];

/** The bytes before a closing line, hashed as they are made or read: each line and its end. */
export interface BodyHash {
  add(line: string): void;
  readonly lines: number;
  digest(): string;
}

export function bodyHash(): BodyHash {
  const hash = createHash('sha256');
  let lines = 0;
  return {
    add(line) {
      hash.update(line, 'utf8');
      hash.update('\n');
      lines += 1;
    },
    get lines() {
      return lines;
    },
    digest: () => hash.digest('hex'),
  };
}

/** Where the lists of shard files written are: one folder for every shard, listed each run. */
export const changesFolder = (epoch: number): string => `${shardsFolder(epoch)}changes/`;

/** A list's name after its folder: when, counted down, then an ID. */
export const CHANGES_FILE = /^\d{13}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A shard file as a list names it, after `shards/`: its shard, then its name in the shard's folder. */
export const LISTED_FILE =
  /^([0-9a-f]{2})\/(\d{13}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[sd])$/;

/** A list of 256 files' names is about 15 KB opened: anything past this is none. */
export const MOST_CHANGES_BYTES = 32_768;

const changesMessage = (name: string, epoch: number, files: readonly string[]): Message => [
  'audit-anchor-changes',
  name,
  String(epoch),
  ...files,
];

/** A list of the shard files a write is about to make, signed with the `audit-anchor` key for its own name. */
export function changesFile(keys: KeyProvider, name: string, epoch: number, files: readonly string[]): Buffer {
  const { signature, keyVersion } = keys.sign('audit-anchor', changesMessage(name, epoch, files));
  const line = JSON.stringify({ k: 'changes', name, epoch, files, kv: keyVersion, sig: signature.toString('base64') });
  return gzipSync(`${line}\n`);
}

/** The files a list names, if it is one signed for its own name and epoch; or nothing. */
export async function readChangesFile(
  keys: KeyProvider,
  { bytes, name, epoch }: { readonly bytes: Buffer; readonly name: string; readonly epoch: number },
): Promise<readonly string[] | undefined> {
  const text = await openedSmallFile(bytes, MOST_CHANGES_BYTES);
  const lines = text?.endsWith('\n') === true ? text.slice(0, -1).split('\n') : [];
  const said = lines.length === 1 ? parsedJson(lines[0] ?? '') : undefined;
  if (typeof said !== 'object' || said === null) return undefined;
  const { k, files, kv, sig } = said as Record<string, unknown>;
  if (k !== 'changes' || !Array.isArray(files) || !isCount(kv) || typeof sig !== 'string') return undefined;
  const named = files.filter((file): file is string => typeof file === 'string' && LISTED_FILE.test(file));
  if (named.length !== files.length) return undefined;
  try {
    return keys.verifySignature('audit-anchor', kv, changesMessage(name, epoch, named), Buffer.from(sig, 'base64'))
      ? named
      : undefined;
  } catch (error) {
    if (error instanceof KeyError) return undefined;
    throw error;
  }
}

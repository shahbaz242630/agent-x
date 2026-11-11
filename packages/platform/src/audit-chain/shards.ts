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
import { createHash } from 'node:crypto';

import type { Message } from '../keys/message.ts';

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

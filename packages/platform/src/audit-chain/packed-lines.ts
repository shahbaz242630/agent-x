// The anchor log's lines in memory, packed (PL-65): one fixed record a line in buffers outside the JS heap, in place of
// an object with two buffers and a date, about 885 bytes a line held. What a line says, and the order a table gives its
// chains in, are the same as a Map of the lines would give: a chain set again keeps its place, one deleted and set again
// goes last. A line is a new frozen copy each time it is read, so code that must know a line moved can't go by identity:
// each line carries a stamp instead, the anchor log's count at the moment it came in, kept with it from table to table,
// as the same object was before (anchor-log.ts). A line that doesn't fit a record (a hash or signature of another
// length, a place past 64 bits, a field more) is kept as it came, so nothing it says is ever lost.
import type { Anchor, Progress } from './anchor.ts';

/** How many records a buffer holds: small, so a table that holds a few lines costs little. */
const RECORDS_A_CHUNK = 1024;

/** Where each field sits in a record. Counts and times as doubles: exact for every safe integer and every date. */
const SEQ = 0;
const AT = 8;
const MAC_KEY_VERSION = 16;
const KEY_VERSION = 24;
const STAMP = 32;
const HASH = 40;
const HASH_BYTES = 32;
const SIGNATURE = HASH + HASH_BYTES;
const SIGNATURE_BYTES = 64;
const MARK = SIGNATURE + SIGNATURE_BYTES;
const BEGAN = MARK + 1;
/** A record's size: 137 bytes, and 145 with a pass's start. */
const RECORD_BYTES = BEGAN;
const PLACE_RECORD_BYTES = BEGAN + 8;

const SEQ_LIMIT = 2n ** 64n;

/** A line kept as it came, with what a record would hold beside it. */
interface Whole<T> {
  readonly line: T;
  readonly stamp: number;
  readonly marked: boolean;
}

type Entry<T> = number | Whole<T>;

/** A line and its stamp. */
export interface Stamped<T> {
  readonly line: T;
  readonly stamp: number;
}

/** The lines a table held when it was taken, as they were then, whatever the table does after, until released. */
export interface Taken<T> {
  readonly size: number;
  lines(): Generator<Stamped<T>>;
  /** Each chain taken and the stamp its line had: no copies made. */
  stamps(): Generator<readonly [string, number]>;
  /** Lets the table reuse what the lines taken were in. Once is enough; again does nothing. */
  release(): void;
}

/** One line a chain, as a Map of the lines would hold them. */
export interface PackedLines<T extends Anchor> {
  readonly size: number;
  /** How many records are in use: one a line that fits, and those a file taken may still read, until released. */
  readonly records: number;
  has(chain: string): boolean;
  get(chain: string): T | undefined;
  stampOf(chain: string): number | undefined;
  /** Whether the line was set marked: the anchor log's mark for an anchor that is a rebase's. */
  marked(chain: string): boolean;
  set(line: T, stamp: number, marked?: boolean): void;
  delete(chain: string): void;
  keys(): MapIterator<string>;
  held(): Generator<Stamped<T>>;
  /** The lines `keep` says yes to, held as they are now until released: what a file is made from. Its line, when asked. */
  take(keep: (chain: string, line: () => T) => boolean): Taken<T>;
}

/** Whether a line fits a record: every field its own length, and nothing beside them. */
const packs = (line: Anchor, places: boolean): boolean =>
  typeof line.seq === 'bigint' &&
  line.seq >= 0n &&
  line.seq < SEQ_LIMIT &&
  Buffer.isBuffer(line.hash) &&
  line.hash.length === HASH_BYTES &&
  Buffer.isBuffer(line.signature) &&
  line.signature.length === SIGNATURE_BYTES &&
  line.at instanceof Date &&
  typeof line.macKeyVersion === 'number' &&
  typeof line.keyVersion === 'number' &&
  (!places || (line as Progress).began instanceof Date) &&
  Object.keys(line).length === (places ? 8 : 7);

/** A table of lines; `places` for a pass's places reached, whose lines say when their pass began. */
export function packedLines<T extends Anchor>(places: boolean): PackedLines<T> {
  const size = places ? PLACE_RECORD_BYTES : RECORD_BYTES;
  const index = new Map<string, Entry<T>>();
  const chunks: Buffer[] = [];
  let used = 0;
  const free: number[] = [];
  // While anything is taken, a record is never written over or reused: what it held goes on being read from it.
  let taken = 0;
  let retired: number[] = [];

  const where = (slot: number): readonly [Buffer, number] => {
    const chunk = chunks[Math.floor(slot / RECORDS_A_CHUNK)];
    // Only a slot `allocated` gave is ever asked for, so there is always a buffer there.
    if (chunk === undefined) throw new RangeError('no record at that slot');
    return [chunk, (slot % RECORDS_A_CHUNK) * size];
  };

  const allocated = (): number => {
    const reused = free.pop();
    if (reused !== undefined) return reused;
    if (used === chunks.length * RECORDS_A_CHUNK) chunks.push(Buffer.alloc(RECORDS_A_CHUNK * size));
    used += 1;
    return used - 1;
  };

  const letGo = (slot: number): void => {
    (taken > 0 ? retired : free).push(slot);
  };

  const write = (slot: number, line: T, stamp: number, marked: boolean): void => {
    const [chunk, at] = where(slot);
    chunk.writeBigUInt64LE(line.seq, at + SEQ);
    chunk.writeDoubleLE(line.at.getTime(), at + AT);
    chunk.writeDoubleLE(line.macKeyVersion, at + MAC_KEY_VERSION);
    chunk.writeDoubleLE(line.keyVersion, at + KEY_VERSION);
    chunk.writeDoubleLE(stamp, at + STAMP);
    line.hash.copy(chunk, at + HASH);
    line.signature.copy(chunk, at + SIGNATURE);
    chunk[at + MARK] = marked ? 1 : 0;
    if (places) chunk.writeDoubleLE((line as unknown as Progress).began.getTime(), at + BEGAN);
  };

  const lineOf = (chain: string, entry: Entry<T>): T => {
    if (typeof entry !== 'number') return entry.line;
    const [chunk, at] = where(entry);
    const line = {
      chain,
      seq: chunk.readBigUInt64LE(at + SEQ),
      hash: Buffer.from(chunk.subarray(at + HASH, at + HASH + HASH_BYTES)),
      macKeyVersion: chunk.readDoubleLE(at + MAC_KEY_VERSION),
      at: new Date(chunk.readDoubleLE(at + AT)),
      keyVersion: chunk.readDoubleLE(at + KEY_VERSION),
      signature: Buffer.from(chunk.subarray(at + SIGNATURE, at + SIGNATURE + SIGNATURE_BYTES)),
    };
    return Object.freeze(places ? { ...line, began: new Date(chunk.readDoubleLE(at + BEGAN)) } : line) as T;
  };

  const stampIn = (entry: Entry<T>): number => {
    if (typeof entry !== 'number') return entry.stamp;
    const [chunk, at] = where(entry);
    return chunk.readDoubleLE(at + STAMP);
  };

  const take = (keep: (chain: string, line: () => T) => boolean): Taken<T> => {
    // Two flat arrays, a reference each a line, not a pair each: a snapshot takes every chain.
    const chains: string[] = [];
    const entries: Entry<T>[] = [];
    for (const [chain, entry] of index) {
      if (keep(chain, () => lineOf(chain, entry))) {
        chains.push(chain);
        entries.push(entry);
      }
    }
    // The two arrays are the same length, so a chain is always there for an entry.
    const each = function* <R>(made: (chain: string, entry: Entry<T>) => R): Generator<R> {
      for (const [at, entry] of entries.entries()) yield made(chains[at] ?? '', entry);
    };
    taken += 1;
    let open = true;
    return Object.freeze({
      size: entries.length,
      lines: () => each((chain, entry) => ({ line: lineOf(chain, entry), stamp: stampIn(entry) })),
      stamps: () => each((chain, entry) => [chain, stampIn(entry)] as const),
      release() {
        if (!open) return;
        open = false;
        taken -= 1;
        if (taken > 0) return;
        for (const slot of retired) free.push(slot);
        retired = [];
      },
    });
  };

  return Object.freeze({
    get size() {
      return index.size;
    },
    get records() {
      return used - free.length;
    },
    has: (chain: string) => index.has(chain),
    get(chain: string) {
      const entry = index.get(chain);
      return entry === undefined ? undefined : lineOf(chain, entry);
    },
    stampOf(chain: string) {
      const entry = index.get(chain);
      return entry === undefined ? undefined : stampIn(entry);
    },
    marked(chain: string) {
      const entry = index.get(chain);
      if (entry === undefined) return false;
      if (typeof entry !== 'number') return entry.marked;
      const [chunk, at] = where(entry);
      return chunk[at + MARK] === 1;
    },
    set(line: T, stamp: number, marked = false) {
      const entry = index.get(line.chain);
      if (!packs(line, places)) {
        if (typeof entry === 'number') letGo(entry);
        index.set(line.chain, { line, stamp, marked });
        return;
      }
      // Written over in place only while nothing taken may still read it.
      const slot = typeof entry === 'number' && taken === 0 ? entry : allocated();
      if (typeof entry === 'number' && slot !== entry) letGo(entry);
      write(slot, line, stamp, marked);
      index.set(line.chain, slot);
    },
    delete(chain: string) {
      const entry = index.get(chain);
      if (typeof entry === 'number') letGo(entry);
      index.delete(chain);
    },
    keys: () => index.keys(),
    *held() {
      for (const [chain, entry] of index) yield { line: lineOf(chain, entry), stamp: stampIn(entry) };
    },
    take,
  });
}

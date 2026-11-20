// The signed states' digest kept apart from the database (AT13, R-15): what state-digest.ts holds in memory, written to
// the anchors' write-once store beside the anchors, where someone with the database's keys can't reach it, and read back
// at a start the way the anchors are. Tx A and every decision read it from memory, with no trip.
//
// Files, gzipped lines, each closed by a line signed with the `audit-anchor` key for the file's own name, its epoch, how
// many lines it holds and the hash of every byte before it, under its own label, so no anchor file can pass for one:
//   e<epoch>/digests/deltas/<inverted-ms>-<id>     what the walks found, at each write the anchors make
//   e<epoch>/digests/snapshots/<inverted-ms>-<id>  every chain's digest, hourly, where something moved
// A line is one chain's objects, at most MOST_ENTRIES_A_LINE of them: `{"c":chain,"t":when,"e":entries}`, the entries
// packed (state-digest.ts) as base64. Every fact a line holds is a place the chain's own walk read, sealed by the app's
// MAC key, so it stays true however often or late it is read: a read merges them, the higher place winning, in any order.
// So a delta is always written for what moved, and a snapshot is only a quicker start, never the one copy of a fact.
//
// A start reads the newest sound snapshot, then every delta named since it, less five minutes for the clocks. A file
// whose closing line fails is spoiled: the alarm, and nothing in it counts. A snapshot spoiled is passed over for the one
// before it, at most a day's worth; with none sound past that, every delta is read instead: slower, and nothing lost.
// Until a start's read has ended whole, every chain is unknown. Each later read takes the deltas named since the last.
// A name dated past the clock is the alarm and passed over, as the anchors' are.
//
// A rebase (rebase.ts, E11) blesses a chain wound back: its old facts may no longer hold, so a line dated before the
// chain's newest rebase is passed over, and a table holding a fact from before it is set aside whole when next asked.
// The digest learns of rebases from the anchors' log, which reads them first.
//
// What it knows of a chain is said only while the anchors' log holds that chain's shard (PL-65 PR3): a shard let go may
// hold a rebase not yet read again. Tx A waits for the anchor then anyway (`anchor_pending`).
//
// What it can hold is bounded (`mostBytes`): past it, it keeps nothing more and says so, and every chain reads as unknown
// to Tx A, so payments wait (`digest_pending`) rather than go on a digest that may miss a fact. The anchors' log counts
// what is held here against its own budget too (`alsoHeld`), and lets its shards go to make room.
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip, createGzip } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import type { Logger } from '../observability/index.ts';
import type { WriteOnceStore } from '../storage/write-once.ts';
import { type Chain, chainName } from './chain.ts';
import { isCount, timeIn } from './rebase.ts';
import { bodyHash } from './shards.ts';
import {
  ChainDigest,
  fingerprintOf,
  packEntries,
  placeOf,
  type SignedSeen,
  subjectKey,
  unpackEntries,
} from './state-digest.ts';

/** What a decision reads of the digest: the newest signed place it knows for an object, and whether it is whole. */
export interface StateDigest {
  /** The newest signed place known for the object on the chain; nothing where it knows none, or can't say now. */
  latest(chain: Chain, type: string, id: string): bigint | undefined;
  /** Whether the digest stands for the chain: the store read whole, and nothing left out for memory. */
  known(chain: Chain): boolean;
}

/** The digest, kept: what the anchor check records into it and how it is read and written. */
export interface DigestLog extends StateDigest {
  /** What a walk found under the anchor signed `at`: each object's newest signed place. */
  record(chain: Chain, seen: SignedSeen, at: Date): void;
  /** Reads what the store holds that this process has not. Never throws; one at a time, a second call joins the first. */
  read(): Promise<void>;
  /** Writes what moved, and hourly the whole. Never throws; one at a time, a second call joins the first. */
  flush(): Promise<void>;
  state(): 'unread' | 'read';
  /** What the digest holds, in bytes, against what it may. */
  memoryHeld(): {
    readonly bytes: number;
    readonly mostBytes: number;
    readonly chains: number;
    readonly objects: number;
  };
}

/** What the digest asks of the anchors' log: the rebases it read, and which shards it holds. */
export interface DigestAnchors {
  rebasedAfter(chain: Chain, at: Date): boolean;
  holds(chain: Chain): boolean;
}

/** The most objects on one line: 32 KB of entries, 44 KB of base64. */
const MOST_ENTRIES_A_LINE = 2048;

/** A line past this is no line of ours. */
const MOST_LINE_BYTES = 64 * 1024;

/** How often the whole is written, where something moved. */
const SNAPSHOT_EVERY_MS = 60 * 60_000;

/** What a file's name counts down from, so the newest lists first, as the anchors' files. */
const LAST_MS = 9_999_999_999_999;

/** A file's name after its folder. */
const FILE = /^\d{13}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** How far past this process's clock a name may be dated, as the anchors' log allows. */
const MOST_AHEAD_MS = 5 * 60_000;

/** How far before the newest file read a later read looks again: a file named earlier may land later. */
const LAG_MS = MOST_AHEAD_MS;

/** How many spoiled snapshots a start goes back past: a day's at one an hour. */
const MOST_SPOILED_SNAPSHOTS = 24;

/** How many names a list asks. */
const NAMES_A_PAGE = 100;

/** How near what is held may come to what it may before that is said. */
const NEAR_MEMORY = 0.5;

/** What a chain's table costs beside its slots: its name and the map's entry. */
const CHAIN_BYTES = 200;

const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;

type Kind = 'deltas' | 'snapshots';

/** What a file's closing line signs: its own label, so an anchor file's closing line can't close one of these. */
const closingMessage = (name: string, epoch: number, lines: number, body: string): Message => [
  'audit-digest-file',
  name,
  String(epoch),
  String(lines),
  body,
];

const countedDown = (ms: number): string => String(LAST_MS - ms).padStart(13, '0');
const timeOfName = (countdown: string): number => LAST_MS - Number(countdown);

/** A file's lines, as gunzip gives them, never the whole as one string. */
async function* linesIn(bytes: Buffer): AsyncGenerator<string> {
  const opening = createGunzip();
  opening.end(bytes);
  let rest: Buffer = Buffer.alloc(0);
  for await (const chunk of opening as AsyncIterable<Buffer>) {
    const joined = rest.length > 0 ? Buffer.concat([rest, chunk]) : chunk;
    let from = 0;
    for (let end = joined.indexOf(10, from); end >= 0; end = joined.indexOf(10, from)) {
      yield joined.toString('utf8', from, end);
      from = end + 1;
    }
    rest = joined.subarray(from);
    if (rest.length > MOST_LINE_BYTES) throw new RangeError('a line longer than any of ours');
  }
  if (rest.length > 0) yield rest.toString('utf8');
}

/** Text gzipped as it is made: a snapshot is never one string. */
async function gzipped(text: Iterable<string>): Promise<Buffer> {
  const made: Buffer[] = [];
  await pipeline(Readable.from(text), createGzip(), async (chunks: AsyncIterable<Buffer>) => {
    for await (const chunk of chunks) made.push(chunk);
  });
  return Buffer.concat(made);
}

function parsed(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch {
    return undefined;
  }
}

/** A line of a file, read: its chain, when, and its entries. */
interface DigestLine {
  readonly chain: string;
  readonly at: Date;
  readonly entries: readonly (readonly [number, number, number])[];
}

function lineFrom(fields: unknown): DigestLine | undefined {
  if (typeof fields !== 'object' || fields === null) return undefined;
  const { c, t, e } = fields as Record<string, unknown>;
  if (typeof c !== 'string' || !CHAIN.test(c) || typeof e !== 'string') return undefined;
  const at = timeIn(t);
  const entries = unpackEntries(Buffer.from(e, 'base64'));
  if (at === undefined || entries === undefined) return undefined;
  return { chain: c, at, entries };
}

/** A file's text lines, made: one chain's entries a line, at most MOST_ENTRIES_A_LINE each. */
function* linesOf(chain: string, at: Date, entries: readonly (readonly [number, number, number])[]): Generator<string> {
  for (let from = 0; from < entries.length; from += MOST_ENTRIES_A_LINE) {
    const part = entries.slice(from, from + MOST_ENTRIES_A_LINE);
    yield JSON.stringify({ c: chain, t: at.toISOString(), e: packEntries(part, part.length).toString('base64') });
  }
}

/** The chain's object, from its name in a line. */
const chainOfName = (name: string): Chain =>
  name === 'platform' ? { kind: 'platform' } : { kind: 'organisation', orgId: name.slice('organisation:'.length) };

export function createDigestLog({
  store,
  keys,
  logger,
  now,
  epoch,
  anchors,
  alertAfterMs,
  mostBytes,
}: {
  /** Where it is kept; none in development and test with no store, where it lives in memory alone and reads as read. */
  readonly store?: WriteOnceStore | undefined;
  readonly keys: KeyProvider;
  readonly logger: Logger;
  readonly now: () => Date;
  readonly epoch: number;
  /** The anchors' log, for its rebases and its shards held; none where the anchors are in memory alone. */
  readonly anchors?: DigestAnchors | undefined;
  /** How long reads or writes may fail before that is the alert, not just a warning. */
  readonly alertAfterMs: number;
  /** What it may hold, in bytes. */
  readonly mostBytes: number;
}): DigestLog {
  const tables = new Map<string, ChainDigest>();
  // What moved since the last write, by chain: the same tables, and the earliest time a fact in each was signed.
  let pending = new Map<string, ChainDigest>();
  let state: 'unread' | 'read' = store === undefined ? 'read' : 'unread';
  let full = false;
  let nearSaid = false;
  let changedSinceSnapshot = false;
  let lastSnapshotAt: number | undefined;
  // The newest delta read or written, by its name's time, and the names read since a look back past it.
  let deltasFrom: number | undefined;
  const namesRead = new Set<string>();
  let reading: Promise<void> | undefined;
  let flushing: Promise<void> | undefined;
  let readFailingSince: number | undefined;
  let writeFailingSince: number | undefined;
  const folder = (kind: Kind): string => `e${String(epoch)}/digests/${kind}/`;

  const alarm = (reason: string, more: Record<string, unknown>): void => {
    logger.error('audit.integrity_failed', { chain: 'store', check: 'digest_store', reason, ...more });
  };

  const tablesBytes = (of: ReadonlyMap<string, ChainDigest>): number => {
    let bytes = 0;
    for (const table of of.values()) bytes += table.bytes + CHAIN_BYTES;
    return bytes;
  };
  const heldBytes = (): number => tablesBytes(tables) + tablesBytes(pending);

  /** Past what may be held: nothing more kept, and every chain unknown to Tx A. Said once; near it, said at half. */
  const judgeMemory = (): void => {
    const bytes = heldBytes();
    if (bytes > mostBytes && !full) {
      full = true;
      logger.error('audit.state_digest_beyond_memory', { bytes, mostBytes });
    } else if (bytes > mostBytes * NEAR_MEMORY && !nearSaid) {
      nearSaid = true;
      logger.warn('audit.state_digest_near_memory', { bytes, mostBytes });
    }
  };

  /** The chain's table, set aside whole where the chain was rebased after its oldest fact. */
  const tableOf = (chain: string, of: Map<string, ChainDigest>): ChainDigest | undefined => {
    const table = of.get(chain);
    if (table !== undefined && anchors?.rebasedAfter(chainOfName(chain), new Date(table.bornAt)) === true) {
      of.delete(chain);
      return undefined;
    }
    return table;
  };

  /** Merges a fact into a table, made where the chain has none. Whether it moved. */
  const merge = (of: Map<string, ChainDigest>, chain: string, at: number, high: number, low: number, place: number) => {
    let table = tableOf(chain, of);
    if (table === undefined) {
      table = new ChainDigest(at);
      of.set(chain, table);
    }
    table.bornAt = Math.min(table.bornAt, at);
    return table.put(high, low, place);
  };

  /** A line read: passed over if dated before its chain's rebase, else merged. */
  const take = (line: DigestLine): void => {
    if (full) return;
    if (anchors?.rebasedAfter(chainOfName(line.chain), line.at) === true) return;
    const at = line.at.getTime();
    for (const [high, low, place] of line.entries) {
      if (merge(tables, line.chain, at, high, low, place)) changedSinceSnapshot = true;
    }
  };

  /** Whether the signature closes the file for its name, epoch, lines and body. A version not held is simply wrong. */
  const closes = (fields: unknown, name: string, lines: number, body: string): boolean => {
    if (typeof fields !== 'object' || fields === null) return false;
    const { k, kv, sig } = fields as Record<string, unknown>;
    if (k !== 'z' || !isCount(kv) || typeof sig !== 'string') return false;
    try {
      return keys.verifySignature(
        'audit-anchor',
        kv,
        closingMessage(name, epoch, lines, body),
        Buffer.from(sig, 'base64'),
      );
    } catch (error) {
      if (error instanceof KeyError) return false;
      throw error;
    }
  };

  /**
   * Whether a file is sound: closed for its own name, and every line before it one of ours. A pass of its own, holding a
   * line at a time, so nothing of a file is taken before that is known, and a large one is never held parsed whole.
   */
  const isSound = async (bytes: Buffer, name: string): Promise<boolean> => {
    const body = bodyHash();
    let last: string | undefined;
    try {
      for await (const text of linesIn(bytes)) {
        if (last !== undefined) {
          if (lineFrom(parsed(last)) === undefined) return false;
          body.add(last);
        }
        last = text;
      }
    } catch {
      // Not gzip, or a line longer than any of ours.
      return false;
    }
    return last !== undefined && closes(parsed(last), name, body.lines, body.digest());
  };

  /** A file taken in if it is sound: whether it was. One listed and then gone is a failure of the store's. */
  const takeFile = async (from: WriteOnceStore, name: string): Promise<boolean> => {
    const got = await from.getAtMost(name, mostBytes);
    if (got === 'missing') throw new Error('a digest file listed and then not there');
    if (typeof got === 'string' || !(await isSound(got, name))) return false;
    let last: DigestLine | undefined;
    for await (const text of linesIn(got)) {
      // Every line but the closing one, each known to read by the pass above.
      if (last !== undefined) take(last);
      last = lineFrom(parsed(text));
    }
    return true;
  };

  /** Every well-named file of a kind, newest first. A name dated past the clock is the alarm, and passed over. */
  async function* namesOf(
    from: WriteOnceStore,
    kind: Kind,
  ): AsyncGenerator<{ readonly name: string; readonly at: number }> {
    const start = folder(kind);
    let after: string | undefined;
    do {
      const page = await from.list(start, NAMES_A_PAGE, after);
      for (const name of page.names) {
        const rest = name.slice(start.length);
        if (!FILE.test(rest)) continue;
        const at = timeOfName(rest.slice(0, 13));
        if (at > now().getTime() + MOST_AHEAD_MS) {
          alarm('future', { kind, fileAt: new Date(at).toISOString() });
          continue;
        }
        yield { name, at };
      }
      after = page.next;
    } while (after !== undefined);
  }

  /**
   * The newest sound snapshot taken in, and its time: none for a store with none, or with only spoiled ones as far back
   * as a start goes. Then every delta is read instead, which loses nothing: each fact was in a delta first.
   */
  const readSnapshot = async (from: WriteOnceStore): Promise<number | undefined> => {
    let spoiled = 0;
    for await (const { name, at } of namesOf(from, 'snapshots')) {
      if (await takeFile(from, name)) return at;
      spoiled += 1;
      alarm('file', { kind: 'snapshots', fileAt: new Date(at).toISOString() });
      if (spoiled >= MOST_SPOILED_SNAPSHOTS) return undefined;
    }
    return undefined;
  };

  /** Every delta named at or after `since` (all of them, with none), not read yet, taken in. */
  const readDeltas = async (from: WriteOnceStore, since: number | undefined): Promise<void> => {
    for await (const { name, at } of namesOf(from, 'deltas')) {
      if (since !== undefined && at < since) break;
      if (namesRead.has(name)) continue;
      if (!(await takeFile(from, name))) alarm('file', { kind: 'deltas', fileAt: new Date(at).toISOString() });
      namesRead.add(name);
      deltasFrom = Math.max(deltasFrom ?? at, at);
    }
  };

  const readOnce = async (): Promise<void> => {
    if (store === undefined) return;
    try {
      if (state === 'read') {
        await readDeltas(store, deltasFrom === undefined ? undefined : deltasFrom - LAG_MS);
      } else {
        const snapshot = await readSnapshot(store);
        if (snapshot !== undefined) lastSnapshotAt = snapshot;
        await readDeltas(store, snapshot === undefined ? undefined : snapshot - LAG_MS);
        state = 'read';
      }
      // Names older than any later look back reaches need no remembering.
      const keepFrom = (deltasFrom ?? 0) - 2 * LAG_MS;
      for (const name of namesRead) {
        if (timeOfName(name.slice(folder('deltas').length, folder('deltas').length + 13)) < keepFrom) {
          namesRead.delete(name);
        }
      }
      readFailingSince = undefined;
      judgeMemory();
    } catch (error) {
      failed('read', error);
    }
  };

  /** A read or write that failed: a warning, and past `alertAfterMs` of failing, the alert. */
  const failed = (what: 'read' | 'write', error: unknown): void => {
    const at = now().getTime();
    const since = what === 'read' ? (readFailingSince ??= at) : (writeFailingSince ??= at);
    if (at - since >= alertAfterMs) logger.error('audit.state_digest_store_failing', { what, err: error });
    else logger.warn('audit.state_digest_store_failed', { what, err: error });
  };

  /** A file of the lines, closed and signed, named for `at`: made a line at a time, its closing line last. */
  const fileOf = async (kind: Kind, lines: Iterable<string>, at: number): Promise<{ name: string; bytes: Buffer }> => {
    const name = `${folder(kind)}${countedDown(at)}-${randomUUID()}`;
    function* closed(): Generator<string> {
      const body = bodyHash();
      for (const line of lines) {
        body.add(line);
        yield `${line}\n`;
      }
      const message = closingMessage(name, epoch, body.lines, body.digest());
      const { signature, keyVersion } = keys.sign('audit-anchor', message);
      yield JSON.stringify({ k: 'z', lines: body.lines, kv: keyVersion, sig: signature.toString('base64') });
    }
    return { name, bytes: await gzipped(closed()) };
  };

  /** Each table's lines, as a file holds them. */
  function* tableLines(of: ReadonlyMap<string, ChainDigest>): Generator<string> {
    for (const [chain, table] of of) yield* linesOf(chain, new Date(table.bornAt), [...table.entries()]);
  }

  const flushOnce = async (): Promise<void> => {
    if (store === undefined) return;
    const at = now().getTime();
    if (pending.size > 0) {
      const taken = pending;
      pending = new Map();
      try {
        const file = await fileOf('deltas', tableLines(taken), at);
        await store.put(file.name, file.bytes);
        namesRead.add(file.name);
        deltasFrom = Math.max(deltasFrom ?? at, at);
        writeFailingSince = undefined;
      } catch (error) {
        // Kept for the next write: its facts are as true then.
        for (const [chain, table] of taken) {
          for (const [high, low, place] of table.entries()) merge(pending, chain, table.bornAt, high, low, place);
        }
        failed('write', error);
        return;
      }
    }
    // A snapshot only after a whole read: one made from less would stand for the whole at the next start.
    const due = lastSnapshotAt === undefined || at - lastSnapshotAt >= SNAPSHOT_EVERY_MS;
    if (state !== 'read' || full || !changedSinceSnapshot || !due) return;
    try {
      const file = await fileOf('snapshots', tableLines(tables), at);
      await store.put(file.name, file.bytes);
      lastSnapshotAt = at;
      changedSinceSnapshot = false;
    } catch (error) {
      failed('write', error);
    }
  };

  return Object.freeze({
    latest(chain: Chain, type: string, id: string): bigint | undefined {
      if (anchors?.holds(chain) === false) return undefined;
      const table = tableOf(chainName(chain), tables);
      if (table === undefined) return undefined;
      const [high, low] = fingerprintOf(subjectKey(type, id));
      const place = table.get(high, low);
      return place === undefined ? undefined : BigInt(place);
    },
    known(chain: Chain): boolean {
      return state === 'read' && !full && anchors?.holds(chain) !== false;
    },
    record(chain: Chain, seen: SignedSeen, at: Date): void {
      if (full || seen.size === 0) return;
      const name = chainName(chain);
      const when = at.getTime();
      for (const [key, seq] of seen) {
        const [high, low] = fingerprintOf(key);
        const place = placeOf(seq);
        if (merge(tables, name, when, high, low, place)) {
          changedSinceSnapshot = true;
          if (store !== undefined) merge(pending, name, when, high, low, place);
        }
      }
      judgeMemory();
    },
    read(): Promise<void> {
      reading ??= readOnce().finally(() => {
        reading = undefined;
      });
      return reading;
    },
    flush(): Promise<void> {
      flushing ??= flushOnce().finally(() => {
        flushing = undefined;
      });
      return flushing;
    },
    state: () => state,
    memoryHeld() {
      let objects = 0;
      for (const table of tables.values()) objects += table.size;
      return { bytes: heldBytes(), mostBytes, chains: tables.size, objects };
    },
  });
}

// The signed states' digest kept apart from the database (AT13, R-15): what state-digest.ts holds in memory, written to
// the anchors' write-once store beside the anchors, where someone with the database's keys can't reach it, and read back
// at a start the way the anchors are. Tx A and every decision read it from memory, with no trip.
//
// Files, gzipped lines, each closed by a line signed with the `audit-anchor` key for the file's own name, its epoch, how
// many lines it holds and the hash of every byte before it, under its own label, so no anchor file can pass for one:
//   e<epoch>/digests/deltas/<inverted-ms>-<id>     what the walks found, at each write the anchors make
//   e<epoch>/digests/snapshots/<inverted-ms>-<id>  every chain's digest, hourly, where something moved
// A line is one chain's objects of one class (`p` for a payment's: below), at most MOST_ENTRIES_A_LINE of them, packed
// (state-digest.ts) as base64, dated when the walk that read them began (`t`), and the stretch of the chain that walk
// read whole (`f` to `u`, `h`, `k`). Every fact a line holds is a place the chain's own walk read, sealed by the app's
// MAC key, so it stays true however often or late it is read: a read merges them, the higher place winning, in any
// order. So a delta is always written for what moved, and a snapshot is only a quicker start, never the one copy.
//
// Coverage: a chain's digest stands for the chain only up to where the stretches its walks read join up unbroken from
// the chain's first event (`covered`). Tx A asks `covers` of the anchor it compares with: a stretch lost (a crash between
// the anchor's write and the digest's, a spoiled delta) or a rebase leaves the chain uncovered, so its hand-offs wait
// (`digest_pending`, that organisation alone) until the anchor check's catch-up walk reads on from where it is covered
// (anchor-check.ts). Every other read goes on with the facts held, which are true either way.
//
// A start reads the newest sound snapshot, then every delta named since it, less five minutes for the clocks. A file
// whose closing line fails is spoiled: the alarm, and nothing in it counts. A snapshot spoiled is passed over for the one
// before it, at most a day's worth; with none sound past that, every delta is read instead: slower, and nothing lost.
// Until a start's read has ended whole, no chain is covered. A name dated past the clock is the alarm and passed over.
//
// A rebase (rebase.ts, E11) blesses a chain wound back: its old facts may no longer hold, so a line dated before the
// chain's newest rebase is passed over, and a chain holding a fact from before it is set aside whole when next asked,
// facts and coverage, until walks read it again from its first event. The digest learns of rebases from the anchors'
// log, which reads them first. A walk's facts are dated when it began, so a walk a rebase lands during counts as before.
//
// Said only while the anchors' log holds the chain's shard (PL-65 PR3; a shard let go may hold a rebase not read again),
// and only while this process leads (`leading`): one that has lost the lease reads the store no more, so it forgets all
// it holds and reads it again whole when it leads again.
//
// What it holds is bounded (`mostBytes`), and one organisation's growth never stops another's. Past it, the largest chain
// gives way first: its payments' objects (`PAYMENT_SUBJECTS`: requests, instructions, transactions, which grow with use),
// then the whole chain, each with that organisation's alarm. A chain given way reads as before the digest, Tx A
// included (today's checks), never as a stop. How far it gave way is written with what moved and in every snapshot
// (`g`), so a restart holds it so at once, never as a chain to wait for: given way whole, it reads as before the digest;
// its payments alone, it stays covered, as a fact missing only loses protection, never raises the alarm. The anchors'
// log counts what is held here against its own budget too (`alsoHeld`), and lets its shards go to make room.
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip, createGzip } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import type { Logger } from '../observability/index.ts';
import type { WriteOnceStore } from '../storage/write-once.ts';
import { type Chain, chainName, type CheckedPoint } from './chain.ts';
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

/** A stretch of a chain a walk read whole: after `from`, up to and at `to`. */
export interface Stretch {
  readonly from: bigint;
  readonly to: CheckedPoint;
}

/** What a decision reads of the digest. */
export interface StateDigest {
  /** The newest signed place known for the object on the chain; nothing where it knows none, or can't say now. */
  latest(chain: Chain, type: string, id: string): bigint | undefined;
  /**
   * Whether Tx A may go on a chain anchored at `seq`: the digest covers it to there, or has given the chain up for memory
   * (today's checks, its alarm said). False until the store is read, and while a stretch below `seq` is missing.
   */
  covers(chain: Chain, seq: bigint): boolean;
}

/** The digest, kept: what the anchor check records into it and how it is read and written. */
export interface DigestLog extends StateDigest {
  /** What a walk that began at `began` read: each object's newest signed place, and the stretch it read whole. */
  record(chain: Chain, seen: SignedSeen, began: Date, stretch?: Stretch): void;
  /** Where the chain is covered to, for a catch-up walk to go on from: none, from its first event. */
  coverage(chain: Chain): CheckedPoint | undefined;
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
  /** What the chains' tables take, in bytes, kept as they change: no count, for the anchors' log at every line. */
  bytesHeld(): number;
}

/** What the digest asks of the anchors' log: the rebases it read, and which shards it holds. */
export interface DigestAnchors {
  rebasedAfter(chain: Chain, at: Date): boolean;
  holds(chain: Chain): boolean;
}

/**
 * The subject types that grow with use, one or more a payment: given way first under memory, as the authority a payment
 * rests on (agents, keys, mandates, members, policies, suppliers, sources, the hold) is what an attacker rolls back first.
 */
export const PAYMENT_SUBJECTS: ReadonlySet<string> = new Set([
  'spend_request',
  'instruction',
  'transaction',
  'failure_proposal',
  'supplier_remittance',
]);

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

/** How far below what it may hold giving way goes, so the next few facts don't give way again. */
const GIVE_WAY_TO = 0.9;

/** What a chain costs beside its slots: its name, coverage and the map's entry. */
const CHAIN_BYTES = 300;

/** How many stretches a chain keeps that don't join its coverage yet: a gap's far side, a few. */
const MOST_STRETCHES = 16;

/** How often a chain given way says so again. */
const SAY_EVERY_MS = 60 * 60_000;

const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SEQ = /^(?:0|[1-9]\d{0,18})$/;
const HASH = /^[0-9a-f]{64}$/;

type Kind = 'deltas' | 'snapshots';
type Entries = readonly (readonly [number, number, number])[];

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

/** A line of a file, read: its chain, when its walk began, its entries and their class, and the stretch read. */
interface DigestLine {
  readonly chain: string;
  readonly at: Date;
  readonly payments: boolean;
  readonly entries: Entries;
  readonly stretch?: Stretch | undefined;
  /** How much of the chain had given way for memory where the line was written (`g`): kept so across a restart. */
  readonly gaveWay?: 1 | 2 | undefined;
}

/** A line's stretch, none where it names none, or `undefined` read as a line not ours where one is half there. */
function stretchFrom({ f, u, h, k }: Record<string, unknown>): Stretch | 'none' | undefined {
  if (f === undefined && u === undefined && h === undefined && k === undefined) return 'none';
  if (typeof f !== 'string' || !SEQ.test(f) || typeof u !== 'string' || !SEQ.test(u)) return undefined;
  if (typeof h !== 'string' || !HASH.test(h) || !isCount(k) || BigInt(f) > BigInt(u)) return undefined;
  return { from: BigInt(f), to: { seq: BigInt(u), hash: Buffer.from(h, 'hex'), macKeyVersion: k } };
}

function lineFrom(fields: unknown): DigestLine | undefined {
  if (typeof fields !== 'object' || fields === null) return undefined;
  const said = fields as Record<string, unknown>;
  const { c, t, e, p, g } = said;
  const at = timeIn(t);
  const stretch = stretchFrom(said);
  if (typeof c !== 'string' || !CHAIN.test(c) || at === undefined || stretch === undefined) return undefined;
  if ((p !== undefined && p !== 1) || (g !== undefined && g !== 1 && g !== 2)) return undefined;
  const entries = e === undefined ? [] : typeof e === 'string' ? unpackEntries(Buffer.from(e, 'base64')) : undefined;
  if (entries === undefined || (entries.length === 0 && stretch === 'none' && g === undefined)) return undefined;
  return {
    chain: c,
    at,
    payments: p === 1,
    entries,
    ...(stretch === 'none' ? {} : { stretch }),
    ...(g === undefined ? {} : { gaveWay: g }),
  };
}

/** A line's text. */
function lineText(
  chain: string,
  at: number,
  payments: boolean,
  entries: Entries,
  stretch?: Stretch,
  gaveWay?: 1 | 2,
): string {
  return JSON.stringify({
    c: chain,
    t: new Date(at).toISOString(),
    ...(gaveWay === undefined ? {} : { g: gaveWay }),
    ...(entries.length === 0 ? {} : { e: packEntries(entries, entries.length).toString('base64') }),
    ...(payments ? { p: 1 } : {}),
    ...(stretch === undefined
      ? {}
      : {
          f: stretch.from.toString(),
          u: stretch.to.seq.toString(),
          h: stretch.to.hash.toString('hex'),
          k: stretch.to.macKeyVersion,
        }),
  });
}

/**
 * A chain's lines: how much of it gave way for memory, if any, first; each class's entries, at most MOST_ENTRIES_A_LINE a
 * line; the stretches on lines of their own.
 */
function* linesOf(
  chain: string,
  at: number,
  [kept, spent]: readonly [Entries, Entries],
  stretches: readonly Stretch[],
  gaveWay: 0 | 1 | 2 = 0,
): Generator<string> {
  if (gaveWay !== 0) yield lineText(chain, at, false, [], undefined, gaveWay);
  for (const [payments, entries] of [
    [false, kept],
    [true, spent],
  ] as const) {
    for (let from = 0; from < entries.length; from += MOST_ENTRIES_A_LINE) {
      yield lineText(chain, at, payments, entries.slice(from, from + MOST_ENTRIES_A_LINE));
    }
  }
  for (const stretch of stretches) yield lineText(chain, at, false, [], stretch);
}

/** The chain's object, from its name in a line. */
const chainOfName = (name: string): Chain =>
  name === 'platform' ? { kind: 'platform' } : { kind: 'organisation', orgId: name.slice('organisation:'.length) };

/** Whether a subject key is a payment's. */
const isPayment = (key: string): boolean => PAYMENT_SUBJECTS.has(key.slice(0, key.indexOf('\n')));

/**
 * One chain as held: its authority's and its payments' tables, when its oldest fact's walk began, where it is covered to
 * and the stretches beyond a gap; and how much of it has given way for memory (1 its payments, 2 all of it).
 */
interface ChainState {
  bornAt: number;
  readonly tables: [ChainDigest, ChainDigest];
  covered: CheckedPoint | undefined;
  readonly stretches: Map<bigint, CheckedPoint>;
  gaveWay: 0 | 1 | 2;
  saidAt?: number;
  saidWhat?: 1 | 2;
}

/** Joins a stretch to the chain's coverage where it reaches it, else keeps it for when a stretch fills the gap. */
function extend(state: ChainState, { from, to }: Stretch): boolean {
  if (from !== 0n && (state.covered === undefined || from > state.covered.seq)) {
    keepBeyond(state, from, to);
    return false;
  }
  const before = state.covered?.seq;
  let covered = farther(state.covered, to);
  for (let joined = true; joined;) {
    joined = false;
    for (const [start, end] of state.stretches) {
      if (start > covered.seq) continue;
      state.stretches.delete(start);
      covered = farther(covered, end);
      joined = true;
    }
  }
  state.covered = covered;
  return covered.seq !== before;
}

/** The farther of two places. */
const farther = (one: CheckedPoint | undefined, other: CheckedPoint): CheckedPoint =>
  one === undefined || other.seq > one.seq ? other : one;

/** A stretch beyond a gap, kept: beyond the bound the farthest is let go, as a catch-up walk joins the nearest first. */
function keepBeyond(state: ChainState, from: bigint, to: CheckedPoint): void {
  state.stretches.set(from, farther(state.stretches.get(from), to));
  if (state.stretches.size > MOST_STRETCHES) {
    state.stretches.delete([...state.stretches.keys()].reduce((one, other) => (one > other ? one : other)));
  }
}

export function createDigestLog({
  store,
  keys,
  logger,
  now,
  epoch,
  anchors,
  leading,
  alertAfterMs,
  mostBytes,
  mostFileBytes = mostBytes,
}: {
  /** Where it is kept; none in development and test with no store, where it lives in memory alone and reads as read. */
  readonly store?: WriteOnceStore | undefined;
  readonly keys: KeyProvider;
  readonly logger: Logger;
  readonly now: () => Date;
  readonly epoch: number;
  /** The anchors' log, for its rebases and its shards held; none where the anchors are in memory alone. */
  readonly anchors?: DigestAnchors | undefined;
  /** Whether this process leads the jobs now: none, always. */
  readonly leading?: (() => boolean) | undefined;
  /** How long reads or writes may fail before that is the alert, not just a warning. */
  readonly alertAfterMs: number;
  /** What it may hold, in bytes. */
  readonly mostBytes: number;
  /**
   * The most a file it fetches or writes may hold: what it may hold unless a test says. A snapshot is smaller than the
   * tables it was made from (16.5 bytes an object gzipped, against at least 21 held), so it fits; one that didn't is
   * not written, and a start reads the deltas instead.
   */
  readonly mostFileBytes?: number;
}): DigestLog {
  const chains = new Map<string, ChainState>();
  // What moved since the last write, by chain, in the same shape: given way to nothing, written then dropped.
  let pending = new Map<string, ChainState>();
  // Each chain's stretches since the last write, in order.
  let pendingStretches = new Map<string, Stretch[]>();
  let state: 'unread' | 'read' = store === undefined ? 'read' : 'unread';
  // What the chains' tables take, kept as they change (the anchors' log asks it at every line it stages).
  let heldBytes = 0;
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

  const tablesBytes = (state: ChainState): number => state.tables[0].bytes + state.tables[1].bytes;

  /** A fresh chain, counted. */
  const newChain = (bornAt: number, counted: boolean): ChainState => {
    const made: ChainState = {
      bornAt,
      tables: [new ChainDigest(bornAt), new ChainDigest(bornAt)],
      covered: undefined,
      stretches: new Map(),
      gaveWay: 0,
    };
    if (counted) heldBytes += tablesBytes(made) + CHAIN_BYTES;
    return made;
  };

  /** A chain set aside, uncounted. */
  const dropped = (name: string): void => {
    const held = chains.get(name);
    if (held === undefined) return;
    heldBytes -= tablesBytes(held) + CHAIN_BYTES;
    chains.delete(name);
  };

  /** All held forgotten: a process that no longer leads, which reads the store again whole when it does. */
  const forget = (): void => {
    chains.clear();
    heldBytes = 0;
    namesRead.clear();
    deltasFrom = undefined;
    lastSnapshotAt = undefined;
    changedSinceSnapshot = false;
    if (store !== undefined) state = 'unread';
  };

  /** Whether this process may say anything: it leads, or nothing says otherwise. Forgets all held when it doesn't. */
  const speaks = (): boolean => {
    if (leading === undefined || leading()) return true;
    if (chains.size > 0 || state === 'read') forget();
    return false;
  };

  /** The chain held, set aside whole where it was rebased after its oldest fact. */
  const chainOf = (name: string): ChainState | undefined => {
    const held = chains.get(name);
    if (held !== undefined && anchors?.rebasedAfter(chainOfName(name), new Date(held.bornAt)) === true) {
      dropped(name);
      return undefined;
    }
    return held;
  };

  /** The chain held, made where there is none, dated by the oldest walk that put a fact in it. */
  const heldChain = (name: string, at: number): ChainState => {
    let held = chainOf(name);
    if (held === undefined) {
      held = newChain(at, true);
      chains.set(name, held);
    }
    held.bornAt = Math.min(held.bornAt, at);
    return held;
  };

  /** A fact into a chain's table of its class, counted. Whether it moved. */
  const putInto = (held: ChainState, payment: boolean, high: number, low: number, place: number): boolean => {
    if (held.gaveWay === 2 || (payment && held.gaveWay === 1)) return false;
    const table = held.tables[payment ? 1 : 0];
    const before = table.bytes;
    const moved = table.put(high, low, place);
    heldBytes += table.bytes - before;
    return moved;
  };

  /** The organisation's line, for a chain that gave way. */
  const sayGaveWay = (name: string, held: ChainState): void => {
    const at = now().getTime();
    if (held.saidWhat === held.gaveWay && held.saidAt !== undefined && at - held.saidAt < SAY_EVERY_MS) return;
    held.saidAt = at;
    held.saidWhat = held.gaveWay === 2 ? 2 : 1;
    const log = name.startsWith('organisation:') ? logger.child({ orgId: name.slice('organisation:'.length) }) : logger;
    log.error('audit.state_digest_chain_gave_way', {
      what: held.gaveWay === 1 ? 'payments' : 'chain',
      bytes: heldBytes,
      mostBytes,
    });
  };

  /**
   * Past what may be held, the largest chain gives way, its payments first, then all of it, until under GIVE_WAY_TO of
   * it: so one organisation's growth costs it alone. Said at half, once.
   */
  const judgeMemory = (): void => {
    if (heldBytes > mostBytes * NEAR_MEMORY && !nearSaid) {
      nearSaid = true;
      logger.warn('audit.state_digest_near_memory', { bytes: heldBytes, mostBytes });
    }
    while (heldBytes > mostBytes) {
      const largest = largestStanding();
      if (largest === undefined) return;
      giveWay(...largest);
      if (heldBytes <= mostBytes * GIVE_WAY_TO) return;
    }
  };

  /** The largest chain not wholly given way yet. */
  const largestStanding = (): [string, ChainState] | undefined => {
    let largest: [string, ChainState] | undefined;
    for (const entry of chains) {
      if (entry[1].gaveWay < 2 && (largest === undefined || tablesBytes(entry[1]) > tablesBytes(largest[1]))) {
        largest = entry;
      }
    }
    return largest;
  };

  /** The chain gives way: its payments' table, or with none or those gone already, all of it. Said. */
  const giveWay = (name: string, held: ChainState): void => {
    dropTo(held, held.gaveWay === 0 && held.tables[1].size > 0 ? 1 : 2);
    // Written with what moved, so a restart holds the chain as given way at once, never as a chain to walk again.
    if (store !== undefined) pendingChain(name, now().getTime()).gaveWay = held.gaveWay;
    sayGaveWay(name, held);
  };

  /** The chain held as given way this far: its payments' table let go, or both. */
  const dropTo = (held: ChainState, level: 1 | 2): void => {
    for (const index of level === 1 ? ([1] as const) : ([0, 1] as const)) {
      heldBytes -= held.tables[index].bytes;
      held.tables[index] = new ChainDigest(held.bornAt, 1);
      heldBytes += held.tables[index].bytes;
    }
    held.gaveWay = level;
  };

  /** A line read: passed over if dated before its chain's rebase, else merged. */
  const take = (line: DigestLine): void => {
    if (anchors?.rebasedAfter(chainOfName(line.chain), line.at) === true) return;
    const at = line.at.getTime();
    const held = heldChain(line.chain, at);
    // Given way where it was written: so here at once, its alarm said again.
    if (line.gaveWay !== undefined && line.gaveWay > held.gaveWay) {
      dropTo(held, line.gaveWay);
      sayGaveWay(line.chain, held);
    }
    for (const [high, low, place] of line.entries) {
      if (putInto(held, line.payments, high, low, place)) changedSinceSnapshot = true;
    }
    if (line.stretch !== undefined && extend(held, line.stretch)) changedSinceSnapshot = true;
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
    const got = await from.getAtMost(name, mostFileBytes);
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
    if (store === undefined || !speaks()) return;
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
    if (what === 'read') readFailingSince ??= at;
    else writeFailingSince ??= at;
    const since = (what === 'read' ? readFailingSince : writeFailingSince) ?? at;
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

  /** What moved, as a delta's lines: each chain's facts, then the stretches its walks read. */
  function* deltaLines(
    facts: ReadonlyMap<string, ChainState>,
    stretches: ReadonlyMap<string, readonly Stretch[]>,
  ): Generator<string> {
    for (const name of new Set([...facts.keys(), ...stretches.keys()])) {
      const held = facts.get(name);
      const entries = [
        held === undefined ? [] : [...held.tables[0].entries()],
        held === undefined ? [] : [...held.tables[1].entries()],
      ] as const;
      // Every chain with a stretch has its pending entry too (record makes one), dated by its walk.
      yield* linesOf(name, held?.bornAt ?? now().getTime(), entries, stretches.get(name) ?? [], held?.gaveWay);
    }
  }

  /**
   * The whole, as a snapshot's lines: a chain that gave way any part of itself is written with no coverage, so the next
   * start reads it again from its first event; one wholly given way, not at all.
   */
  function* snapshotLines(): Generator<string> {
    for (const [name, held] of chains) {
      // A chain given way is written as such: its payments given way keep their coverage (a fact missing only loses
      // protection, never raises the alarm); one given way whole needs none, as it reads as before the digest.
      const coverage =
        held.gaveWay < 2 && held.covered !== undefined ? [{ from: 0n, to: held.covered }] : ([] as Stretch[]);
      const tables = [[...held.tables[0].entries()], [...held.tables[1].entries()]] as const;
      yield* linesOf(name, held.bornAt, tables, coverage, held.gaveWay);
    }
  }

  const flushOnce = async (): Promise<void> => {
    if (store === undefined) return;
    const at = now().getTime();
    if ((pending.size > 0 || pendingStretches.size > 0) && !(await deltaWritten(store, at))) return;
    // A snapshot only after a whole read: one made from less would stand for the whole at the next start.
    const due = lastSnapshotAt === undefined || at - lastSnapshotAt >= SNAPSHOT_EVERY_MS;
    if (state === 'read' && changedSinceSnapshot && due) await snapshotWritten(store, at);
  };

  /** What moved, written as a delta: whether it was. One that failed is kept for the next, its facts as true then. */
  const deltaWritten = async (into: WriteOnceStore, at: number): Promise<boolean> => {
    const [facts, stretches] = [pending, pendingStretches];
    pending = new Map();
    pendingStretches = new Map();
    try {
      const file = await fileOf('deltas', deltaLines(facts, stretches), at);
      await into.put(file.name, file.bytes);
      namesRead.add(file.name);
      deltasFrom = Math.max(deltasFrom ?? at, at);
      writeFailingSince = undefined;
      return true;
    } catch (error) {
      for (const [name, held] of facts) {
        const kept = pendingChain(name, held.bornAt);
        if (held.gaveWay > kept.gaveWay) kept.gaveWay = held.gaveWay;
        for (const index of [0, 1] as const) {
          for (const [high, low, place] of held.tables[index].entries()) kept.tables[index].put(high, low, place);
        }
      }
      for (const [name, walked] of stretches) {
        pendingStretches.set(name, [...walked, ...(pendingStretches.get(name) ?? [])]);
      }
      failed('write', error);
      return false;
    }
  };

  /** The whole, written as a snapshot, never past what a start fetches. */
  const snapshotWritten = async (into: WriteOnceStore, at: number): Promise<void> => {
    try {
      const file = await fileOf('snapshots', snapshotLines(), at);
      lastSnapshotAt = at;
      // Never past what a start fetches: the deltas hold every fact, so a start reads them instead, slower.
      if (file.bytes.length > mostFileBytes) {
        logger.error('audit.state_digest_snapshot_too_large', { bytes: file.bytes.length, mostBytes: mostFileBytes });
        return;
      }
      await into.put(file.name, file.bytes);
      changedSinceSnapshot = false;
    } catch (error) {
      failed('write', error);
    }
  };

  /** A walk's facts into the chain, and those that moved into what waits to be written. */
  const recordFacts = (name: string, held: ChainState, seen: SignedSeen, at: number): void => {
    for (const [key, seq] of seen) {
      const [high, low] = fingerprintOf(key);
      const place = placeOf(seq);
      const payment = isPayment(key);
      if (!putInto(held, payment, high, low, place)) continue;
      changedSinceSnapshot = true;
      if (store !== undefined) pendingChain(name, at).tables[payment ? 1 : 0].put(high, low, place);
    }
  };

  /**
   * A walk's stretch into the chain's coverage, and into what waits to be written: never for a chain given way any part
   * of itself, which holds less than the stretch would claim.
   */
  const recordStretch = (name: string, held: ChainState, stretch: Stretch, at: number): void => {
    if (extend(held, stretch)) changedSinceSnapshot = true;
    if (store === undefined || held.gaveWay === 2) return;
    pendingChain(name, at);
    pendingStretches.set(name, [...(pendingStretches.get(name) ?? []), stretch]);
  };

  /** The chain's facts waiting to be written, made where there are none. */
  const pendingChain = (name: string, at: number): ChainState => {
    let held = pending.get(name);
    if (held === undefined) {
      held = newChain(at, false);
      pending.set(name, held);
    }
    held.bornAt = Math.min(held.bornAt, at);
    return held;
  };

  return Object.freeze({
    latest(chain: Chain, type: string, id: string): bigint | undefined {
      if (!speaks() || anchors?.holds(chain) === false) return undefined;
      const held = chainOf(chainName(chain));
      if (held === undefined) return undefined;
      const [high, low] = fingerprintOf(subjectKey(type, id));
      const place = held.tables[PAYMENT_SUBJECTS.has(type) ? 1 : 0].get(high, low);
      return place === undefined ? undefined : BigInt(place);
    },
    covers(chain: Chain, seq: bigint): boolean {
      if (!speaks() || state !== 'read' || anchors?.holds(chain) === false) return false;
      if (seq === 0n) return true;
      const held = chainOf(chainName(chain));
      if (held?.gaveWay === 2) return true;
      return held?.covered !== undefined && held.covered.seq >= seq;
    },
    coverage(chain: Chain): CheckedPoint | undefined {
      if (!speaks()) return undefined;
      return chainOf(chainName(chain))?.covered;
    },
    record(chain: Chain, seen: SignedSeen, began: Date, stretch?: Stretch): void {
      if (!speaks()) return;
      const name = chainName(chain);
      const at = began.getTime();
      // Dated before the chain's newest rebase: it read the chain as it was, which nothing goes on from.
      if (anchors?.rebasedAfter(chain, began) === true) return;
      const held = heldChain(name, at);
      recordFacts(name, held, seen, at);
      if (stretch !== undefined) recordStretch(name, held, stretch, at);
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
    bytesHeld: () => heldBytes,
    memoryHeld() {
      let objects = 0;
      for (const held of chains.values()) objects += held.tables[0].size + held.tables[1].size;
      return { bytes: heldBytes, mostBytes, chains: chains.size, objects };
    },
  });
}

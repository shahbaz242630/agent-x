// Recording to a chain and checking it, the same way for every chain. Each
// module owns its chain's tables (ADR-004 §4), so it gives the steps here a
// store over them: the SQL stays in the module, and the order of the steps,
// the refusals and the check, which the reviews tested hardest, are written
// once. Every call of a store runs in the caller's transaction.
//
// A store that breaks its contract must not pass a tampered chain or fork a
// good one. Where the steps can check a duty, they do: the check reads until
// it reaches the head rather than trusting page sizes, and refuses a batch
// that couldn't come from the SQL asked for (ChainStoreError); the head moves
// only if it is still the one read under the lock. The duties they can't
// check are on each method below, and a store's tests must prove them.

import { UUID } from '../db/patterns.ts';
import type { KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import {
  type AnchorPoint,
  type Chain,
  CHAIN_START,
  type ChainHead,
  type ChainLink,
  type ChainProblem,
  type ChainReport,
  type ChainWalker,
  type CheckedPoint,
  createChainVerifier,
  createChainWalker,
  entryIsSealed,
  GENESIS_HASH,
  genesisHead,
  headIsSealed,
  sealNext,
  type StoredEntry,
} from './chain.ts';

/** An event as sealed, for the store to write beside its own fields. */
export interface SealedEvent extends ChainLink {
  readonly seq: bigint;
  readonly id: string;
  readonly recordedAt: Date;
}

/** The head read under the lock, and the database's clock read in the same statement once the lock was held. */
export interface LockedHead {
  readonly head: ChainHead | undefined;
  readonly now: Date;
}

/** What recording needs from a chain's tables. */
export interface ChainWriter {
  /**
   * Locks the head (`FOR NO KEY UPDATE`) and reads it: nothing if the chain
   * hasn't started, a head of undefined if its row can't be read. The lock is
   * held to the end of the transaction, so recordings queue on it. In the same
   * statement, once the lock is held, the database's clock to the millisecond
   * (4D2d P2: one trip, not two).
   */
  lockHead(): Promise<LockedHead | undefined>;
  /**
   * Inserts the first head, doing nothing if another transaction just did (it
   * then waits for that one to end). The head's table needs a key that allows
   * one head per chain, or two racing first events would each insert one.
   */
  start(head: ChainHead): Promise<void>;
  /**
   * In **one statement**, moves the head to `head`, but only if it is still
   * `previous` and no event is stored past it, and then, only if it moved,
   * stores the event (exactly the sealed ID and time, and the fields its
   * content was made from). Says whether it did: a refused event leaves nothing
   * behind, even for a caller that goes on to commit. The check for events past
   * the head is here, not in lockHead: this statement starts once the lock is
   * held, so it sees every event committed before (4D2d P2, the partner S157).
   */
  append(event: SealedEvent, head: ChainHead, previous: ChainHead): Promise<boolean>;
}

/** What recording events together needs (appendEvents): `append`'s duties, for all of them in one statement. */
export interface ChainBatchWriter extends Pick<ChainWriter, 'lockHead' | 'start'> {
  /** As `append`: all of the events stored and the head moved from `previous` to `head`, or nothing at all. */
  appendAll(events: readonly SealedEvent[], head: ChainHead, previous: ChainHead): Promise<boolean>;
}

/** An event to add: its ID, drawn once the head is locked and found clean, and what it says. */
interface EventToAppend {
  readonly nextId: () => string;
  readonly content: Message;
}

/** What checking needs from a chain's tables. */
export interface ChainReader {
  /**
   * The head (`none` if there is no head row, `unreadable` if it can't be
   * read, or there is more than one) and how many events are stored, read in
   * **one statement**, so both come from the same moment: read apart, an event
   * added between them could hide a forged one.
   */
  state(): Promise<{ readonly head: ChainHead | 'none' | 'unreadable'; readonly stored: bigint }>;
  /**
   * Up to `limit` events numbered after `after` and at most `upTo`, in number
   * order: each as the chain checks it, or undefined if its row can't be read
   * (sealedFields reads the seal's columns, `whole_ms` among them). Never
   * throws for a bad row.
   */
  events(after: bigint, upTo: bigint, limit: number): Promise<readonly (StoredEntry | undefined)[]>;
}

/** A check's answer when it found a problem. */
type ChainRefusal = Extract<ChainReport, { ok: false }>;

/** A chain's edges (ChainEdgeReader.edges), all read in one statement, so all from one moment. */
export interface ChainEdges {
  /** As ChainReader.state's head. */
  readonly head: ChainHead | 'none' | 'unreadable';
  /** The lowest and highest numbers stored, null with no event stored. */
  readonly lowest: bigint | null;
  readonly highest: bigint | null;
  /** The hash stored on the event numbered as the head is; undefined if there is none. */
  readonly headEventHash: Buffer | undefined;
  /** The event at the number asked, whole; undefined if there is none or its row can't be read. */
  readonly anchored: StoredEntry | undefined;
}

/** What checking from an anchor needs: nothing that reads a whole chain. */
export interface ChainEdgeReader extends Pick<ChainReader, 'events'> {
  /** The chain's edges and the event numbered `anchored`, in **one statement**, on indexes alone. Never throws for a bad row. */
  edges(anchored: bigint): Promise<ChainEdges>;
  /** How many events are stored numbered after `after` and at most `upTo`. */
  countBetween(after: bigint, upTo: bigint): Promise<bigint>;
}

/**
 * How a check made in steps stands: it has checked up to `seq`, and is going to
 * `to` (`seq === to` when it has got there), or the first problem it found.
 */
export type ChainStep = (Extract<ChainReport, { ok: true }> & { readonly to: bigint }) | ChainRefusal;

/** A store broke its contract in a way the steps can see: a bug in the store, not a tampered chain. */
export class ChainStoreError extends Error {
  constructor(message: string) {
    super(`The audit chain's store broke its contract: ${message}`);
    this.name = 'ChainStoreError';
  }
}

/**
 * The chain fails its check at the head, or holds events past it: tampered
 * with, or sealed with a key version this process doesn't hold (a new key made
 * current before it was installed everywhere). Nothing more is added to it
 * until someone has looked into it.
 */
export class ChainBroken extends Error {
  readonly chain: Chain;

  constructor(chain: Chain) {
    super(
      `The ${chain.kind === 'platform' ? "platform's" : "organisation's"} audit chain fails its check at the head (tampered with, or sealed with a key version this process doesn't hold), so no event can be added to it`,
    );
    this.name = 'ChainBroken';
    this.chain = chain;
  }
}

/** How many events the check reads at a time. */
const BATCH = 500;

/** The most events one check from an anchor walks (ADR-012 §2, 4D2e E): the anchor moves on, and the next run goes on from it. */
const MOST_EVENTS_A_STEP = 100_000;

/**
 * Adds an event to the chain, in the caller's transaction. Takes the head's
 * lock, which comes last of all the transaction's locks (ADR-006 §6): two
 * transactions recording at once queue on it, so each event takes the next
 * place. Refuses (ChainBroken) a head that fails its check, and one with
 * events past it (found by the write itself, which then writes nothing):
 * someone removed or wound it back, and a new event would carry on the
 * tampered chain. With the head locked no one else can be adding one through
 * the app, so any found came from outside it. The ID is drawn once the lock is held,
 * so IDs rise with the numbers, and written in lower case, as Postgres returns
 * a uuid, so the stored row hashes the same.
 */
export async function appendEvent(
  keys: KeyProvider,
  chain: Chain,
  writer: ChainWriter,
  event: EventToAppend,
): Promise<SealedEvent> {
  const [stored] = await appendEvents(
    keys,
    chain,
    {
      lockHead: () => writer.lockHead(),
      start: (head) => writer.start(head),
      appendAll: ([sealed], head, previous) =>
        sealed === undefined ? Promise.resolve(false) : writer.append(sealed, head, previous),
    },
    [event],
  );
  if (stored === undefined) throw new ChainBroken(chain);
  return stored;
}

/**
 * appendEvent for events that belong together (4D2d P13): the head locked
 * once, the events chained one after another, all written and the head moved
 * once, in one statement, under one reading of the clock (partner S163). Each is
 * sealed and checked afterwards exactly as one recorded alone. In the order
 * given.
 */
export async function appendEvents(
  keys: KeyProvider,
  chain: Chain,
  writer: ChainBatchWriter,
  events: readonly EventToAppend[],
): Promise<readonly SealedEvent[]> {
  if (events.length === 0) throw new RangeError('At least one event is appended');
  let locked = await writer.lockHead();
  if (locked === undefined) {
    await writer.start(genesisHead(keys, chain));
    locked = await writer.lockHead();
  }
  if (locked?.head === undefined || !headIsSealed(keys, chain, locked.head)) throw new ChainBroken(chain);
  const { head: previous, now } = locked;
  let head = previous;
  const stored = events.map(({ nextId, content }): SealedEvent => {
    const id = nextId().toLowerCase();
    if (!UUID.test(id)) throw new RangeError('The ID generator gave an ID that is not a UUID');
    // The clock was read once the lock was held, so the times never fall as the events' numbers rise.
    const entry = { seq: head.seq + 1n, id, recordedAt: now, content };
    const sealed = sealNext(keys, chain, head, entry);
    head = sealed.head;
    return Object.freeze({ seq: entry.seq, id, recordedAt: entry.recordedAt, ...sealed.link });
  });
  // The head moves only from the one read under the lock, and only with no event past it:
  // a store that didn't lock can't fork the chain, nor carry on one wound back.
  if (!(await writer.appendAll(stored, head, previous))) throw new ChainBroken(chain);
  return stored;
}

/** Events with no usable head: the head row was removed, or can't be read. */
const NO_HEAD: ChainRefusal = Object.freeze({ ok: false, problem: Object.freeze({ reason: 'head', seq: 0n }) });

/** The report on a chain with no head row, given how many events are stored and the last anchor. */
function headlessReport(stored: bigint, anchor: AnchorPoint | undefined): ChainReport {
  // A chain that was never started is empty, unless it had been anchored; events with no head mean the head was removed.
  if (stored !== 0n) return NO_HEAD;
  return anchor !== undefined && anchor.seq > 0n
    ? { ok: false, problem: { reason: 'anchor', seq: anchor.seq } }
    : { ok: true, ...CHAIN_START };
}

/** The next batch of events after `after`, up to `upTo`: a store giving more than were asked for is failing. */
async function readBatch(
  reader: Pick<ChainReader, 'events'>,
  after: bigint,
  upTo: bigint,
  size: number,
): Promise<readonly (StoredEntry | undefined)[]> {
  const batch = await reader.events(after, upTo, size);
  if (batch.length > size)
    throw new ChainStoreError(`it gave ${batch.length} events where at most ${size} were asked for`);
  return batch;
}

/**
 * Gives `walker` every event after `after` up to `upTo`: any problem found, or
 * nothing once the store has none left. Reads until `upTo` is reached; every
 * batch that isn't empty moves `after` on, and an empty one ends the reading.
 */
async function walkEvents(
  reader: Pick<ChainReader, 'events'>,
  walker: Pick<ChainWalker, 'check' | 'unreadable'>,
  from: bigint,
  upTo: bigint,
  size: number = BATCH,
): Promise<ChainProblem | undefined> {
  let after = from;
  while (after < upTo) {
    const batch = await readBatch(reader, after, upTo, size);
    if (batch.length === 0) break;
    for (const entry of batch) {
      if (entry === undefined) return walker.unreadable();
      if (entry.seq > upTo) throw new ChainStoreError('it gave an event past the place it was asked to read up to');
      const problem = walker.check(entry);
      if (problem !== undefined) return problem;
      after = entry.seq;
    }
  }
  return undefined;
}

/**
 * Checks the whole chain up to its head (SEC-EVD-02), and, given the last
 * anchor, that the chain still holds it (ADR-012 §2, SEC-DB-11). The head and
 * the count come from one moment; events added while the check runs are past
 * the head, so they aren't read, and raise no false alarm.
 */
export async function verifyChain(
  keys: KeyProvider,
  chain: Chain,
  reader: ChainReader,
  anchor: AnchorPoint | undefined,
): Promise<ChainReport> {
  const { head, stored } = await reader.state();
  if (head === 'none') return headlessReport(stored, anchor);
  if (head === 'unreadable') return NO_HEAD;

  const verifier = createChainVerifier(keys, chain, { head, stored, anchor });
  const problem = await walkEvents(reader, verifier, 0n, head.seq);
  return problem === undefined ? verifier.finish() : { ok: false, problem };
}

const refused = (reason: ChainProblem['reason'], seq: bigint): ChainRefusal => ({
  ok: false,
  problem: { reason, seq },
});

/**
 * What the head and the stored numbers show without reading the events
 * between: the head is sealed, it is at the last event, whose hash it holds,
 * nothing lies past it or below 1, and it isn't behind `from`.
 */
function edgeProblem(
  keys: KeyProvider,
  chain: Chain,
  { lowest, highest, headEventHash }: ChainEdges,
  head: ChainHead,
  from: CheckedPoint,
): ChainProblem | undefined {
  const atHead = { reason: 'head', seq: head.seq } as const;
  if (!headIsSealed(keys, chain, head)) return atHead;
  // No event at all is the one case where nothing need sit at the head: a chain with its first event to come.
  const nothingStored = head.seq === 0n && highest === null;
  if (!nothingStored && highest !== head.seq) return atHead;
  if (lowest !== null && lowest < 1n) return atHead;
  // After the checks above, so a head behind the anchor with events left past it reads as those events do in verifyChain.
  if (head.seq < from.seq) return { reason: 'anchor', seq: from.seq };
  if (lowest !== null && lowest > 1n) return { reason: 'gap', seq: 1n };
  return nothingStored || headEventHash?.equals(head.hash) === true ? undefined : atHead;
}

/**
 * Whether the chain still holds the place it is checked from: the event there
 * whole, sealed, with the hash and the MAC key's version `from` was signed with.
 * The version is what keeps "an old key can't add events after a rotation" true
 * from an anchor: an event sealed again under an older key isn't the one anchored.
 */
function holdsPoint(keys: KeyProvider, chain: Chain, from: CheckedPoint, anchored: StoredEntry | undefined): boolean {
  if (from.seq === 0n) return from.hash.equals(GENESIS_HASH) && from.macKeyVersion === 0;
  return (
    anchored !== undefined &&
    entryIsSealed(keys, chain, anchored) &&
    anchored.hash.equals(from.hash) &&
    anchored.macKeyVersion === from.macKeyVersion
  );
}

/** Walks from a checked place to `upTo`, which it must reach: a store with no event left short of it has a gap there. */
async function walkTo(
  keys: KeyProvider,
  chain: Chain,
  reader: Pick<ChainReader, 'events'>,
  from: CheckedPoint,
  upTo: bigint,
  size?: number,
): Promise<ChainReport> {
  const walker = createChainWalker(keys, chain, from);
  const problem = await walkEvents(reader, walker, from.seq, upTo, size);
  if (problem !== undefined) return { ok: false, problem };
  const reached = walker.reached();
  return reached.ok && reached.seq !== upTo ? refused('gap', reached.seq + 1n) : reached;
}

function checkedMost(most: number): number {
  if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('A step checks a whole number of events, from 1');
  return most;
}

/**
 * Checks a chain from its last anchor (4D2e E): the edges in one read, then only
 * the events past the anchor, at most `most` of them. Takes a chain that hasn't
 * moved in one read. What it can't see is an event edited or deleted below the
 * anchor: passStep and countStep are for those. verifyChain stays whole, for
 * clearing a hold and for the restore check. A report short of the head (`seq`
 * below `to`) is good as far as it went, and the anchor can move on to it.
 */
export async function verifyFromAnchor(
  keys: KeyProvider,
  chain: Chain,
  reader: ChainEdgeReader,
  from: CheckedPoint,
  most: number = MOST_EVENTS_A_STEP,
): Promise<ChainStep> {
  checkedMost(most);
  const edges = await reader.edges(from.seq);
  const { head } = edges;
  if (head === 'none') {
    const report = headlessReport(edges.highest === null ? 0n : 1n, from);
    return report.ok ? { ...report, to: 0n } : report;
  }
  if (head === 'unreadable') return NO_HEAD;
  const problem = edgeProblem(keys, chain, edges, head, from);
  if (problem !== undefined) return { ok: false, problem };
  if (!holdsPoint(keys, chain, from, edges.anchored)) return refused('anchor', from.seq);

  const upTo = head.seq < from.seq + BigInt(most) ? head.seq : from.seq + BigInt(most);
  const report = await walkTo(keys, chain, reader, from, upTo);
  if (!report.ok) return report;
  // The events read after the edges must end at the hash the head holds: the edges alone only compare the stored row.
  if (report.seq === head.seq && !report.hash.equals(head.hash)) return refused('head', head.seq);
  return { ...report, to: head.seq };
}

/**
 * One step of a full pass over a chain's old events (4D2e E): the next `most`
 * events after `cursor`, up to `target`, the place the pass set out for, and
 * there the hash and the MAC key's version must be the ones the anchor signed.
 * Reads no head: the check from the anchor sees to that.
 */
export async function passStep(
  keys: KeyProvider,
  chain: Chain,
  reader: Pick<ChainReader, 'events'>,
  cursor: CheckedPoint,
  target: CheckedPoint,
  most: number,
): Promise<ChainStep> {
  checkedMost(most);
  if (cursor.seq > target.seq) throw new RangeError('A pass never goes past where it set out for');
  const upTo = target.seq < cursor.seq + BigInt(most) ? target.seq : cursor.seq + BigInt(most);
  const report = await walkTo(keys, chain, reader, cursor, upTo, most);
  if (!report.ok) return report;
  if (
    report.seq === target.seq &&
    (!report.hash.equals(target.hash) || report.macKeyVersion !== target.macKeyVersion)
  ) {
    return refused('anchor', target.seq);
  }
  return { ...report, to: target.seq };
}

/**
 * Whether every event numbered after `after` and at most `upTo` is stored (4D2e
 * E): a deleted one, which no read of a signed state can see, shows as a count
 * short. Says where the stretch starts, as a count can't say which is gone.
 */
export async function countStep(
  reader: Pick<ChainEdgeReader, 'countBetween'>,
  after: bigint,
  upTo: bigint,
): Promise<ChainProblem | undefined> {
  if (after >= upTo) throw new RangeError('A stretch to count holds at least one event');
  const stored = await reader.countBetween(after, upTo);
  return stored === upTo - after ? undefined : { reason: 'gap', seq: after + 1n };
}

const isBytes = (value: unknown): value is Buffer => Buffer.isBuffer(value);

/**
 * A head row's fields as a head, or nothing if one is missing or of the wrong
 * type: the database owner could have changed any of them, or their types.
 */
export function headFields(row: Readonly<Record<string, unknown>>): ChainHead | undefined {
  const { seq, hash, mac, mac_key_version: macKeyVersion } = row;
  if (typeof seq !== 'bigint' || !isBytes(hash) || !isBytes(mac) || typeof macKeyVersion !== 'number') {
    return undefined;
  }
  return { seq, hash, mac, macKeyVersion };
}

/** The clock a writer's lockHead read with the head (its `now`): a time, or the store is failing. */
export function clockOf(row: Readonly<Record<string, unknown>>): Date {
  const { now } = row;
  if (!(now instanceof Date) || !Number.isFinite(now.getTime()))
    throw new ChainStoreError('it read no clock with the head');
  return now;
}

/**
 * An event row's sealed fields, or nothing if one is missing or of the wrong
 * type, or its time isn't one the app could have written: a real time (one
 * past JavaScript's range arrives as an Invalid Date, 'infinity' as a number)
 * and a whole millisecond. The reader's SQL says the last as `whole_ms`:
 * `recorded_at = pg_catalog.date_trunc('milliseconds', recorded_at)`.
 */
export function sealedFields(row: Readonly<Record<string, unknown>>): Omit<StoredEntry, 'content'> | undefined {
  const { seq, id, recorded_at: recordedAt, whole_ms: wholeMs, prev_hash: prevHash, hash, mac } = row;
  const { mac_key_version: macKeyVersion } = row;
  if (
    typeof seq !== 'bigint' ||
    typeof id !== 'string' ||
    !(recordedAt instanceof Date) ||
    !Number.isFinite(recordedAt.getTime()) ||
    wholeMs !== true ||
    !isBytes(prevHash) ||
    !isBytes(hash) ||
    !isBytes(mac) ||
    typeof macKeyVersion !== 'number'
  ) {
    return undefined;
  }
  return { seq, id, recordedAt, prevHash, hash, mac, macKeyVersion };
}

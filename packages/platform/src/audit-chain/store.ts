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

import type { KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import {
  type Chain,
  type ChainHead,
  type ChainLink,
  type ChainReport,
  createChainVerifier,
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

/** What recording needs from a chain's tables. */
export interface ChainWriter {
  /**
   * Locks the head (`FOR NO KEY UPDATE`) and reads it: nothing if the chain
   * hasn't started, a head of undefined if its row can't be read. The lock is
   * held to the end of the transaction, so recordings queue on it.
   */
  lockHead(): Promise<{ readonly head: ChainHead | undefined } | undefined>;
  /**
   * Inserts the first head, doing nothing if another transaction just did (it
   * then waits for that one to end). The head's table needs a key that allows
   * one head per chain, or two racing first events would each insert one.
   */
  start(head: ChainHead): Promise<void>;
  /** Whether an event is stored past this number. */
  hasEventsPast(seq: bigint): Promise<boolean>;
  /** The database's clock, to the millisecond, read at the moment it is asked, not the transaction's start. */
  now(): Promise<Date>;
  /**
   * Stores the event (exactly the sealed ID and time, and the fields its
   * content was made from), then moves the head to `head`, but only if it is
   * still `previous`. Says whether the head moved.
   */
  append(event: SealedEvent, head: ChainHead, previous: ChainHead): Promise<boolean>;
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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** How many events the check reads at a time. */
const BATCH = 500;

/**
 * Adds an event to the chain, in the caller's transaction. Takes the head's
 * lock, which comes last of all the transaction's locks (ADR-006 §6): two
 * transactions recording at once queue on it, so each event takes the next
 * place. Refuses (ChainBroken) a head that fails its check, and one with
 * events past it: someone removed or wound it back, and a new event would
 * carry on the tampered chain. With the head locked no one else can be adding
 * one, so any found were there before. The ID is drawn once the lock is held,
 * so IDs rise with the numbers, and written in lower case, as Postgres returns
 * a uuid, so the stored row hashes the same.
 */
export async function appendEvent(
  keys: KeyProvider,
  chain: Chain,
  writer: ChainWriter,
  event: { readonly nextId: () => string; readonly content: Message },
): Promise<SealedEvent> {
  let locked = await writer.lockHead();
  if (locked === undefined) {
    await writer.start(genesisHead(keys, chain));
    locked = await writer.lockHead();
  }
  if (
    locked?.head === undefined ||
    !headIsSealed(keys, chain, locked.head) ||
    (await writer.hasEventsPast(locked.head.seq))
  ) {
    throw new ChainBroken(chain);
  }
  const { head } = locked;
  const id = event.nextId().toLowerCase();
  if (!UUID.test(id)) throw new RangeError('The ID generator gave an ID that is not a UUID');
  // Read once the lock is held, so the times rise with the events' numbers.
  const entry = { seq: head.seq + 1n, id, recordedAt: await writer.now(), content: event.content };
  const sealed = sealNext(keys, chain, head, entry);
  const stored: SealedEvent = Object.freeze({ seq: entry.seq, id, recordedAt: entry.recordedAt, ...sealed.link });
  // The head moves only from the one read under the lock: a store that didn't lock can't fork the chain.
  if (!(await writer.append(stored, sealed.head, head))) throw new ChainBroken(chain);
  return stored;
}

/** Events with no usable head: the head row was removed, or can't be read. */
const NO_HEAD: ChainReport = Object.freeze({ ok: false, problem: Object.freeze({ reason: 'head', seq: 0n }) });

/**
 * Checks the whole chain up to its head (SEC-EVD-02). The head and the count
 * come from one moment; events added while the check runs are past the head,
 * so they aren't read, and raise no false alarm.
 */
export async function verifyChain(keys: KeyProvider, chain: Chain, reader: ChainReader): Promise<ChainReport> {
  const { head, stored } = await reader.state();
  if (head === 'none') {
    // A chain that was never started is empty; events with no head mean the head was removed.
    return stored === 0n ? { ok: true, seq: 0n, hash: GENESIS_HASH } : NO_HEAD;
  }
  if (head === 'unreadable') return NO_HEAD;

  const verifier = createChainVerifier(keys, chain, { head, stored });
  // Reads until the head is reached; every batch that isn't empty moves `after` on, and an empty one ends the reading.
  let after = 0n;
  while (after < head.seq) {
    const batch = await reader.events(after, head.seq, BATCH);
    if (batch.length === 0) break;
    if (batch.length > BATCH)
      throw new ChainStoreError(`it gave ${batch.length} events where at most ${BATCH} were asked for`);
    for (const entry of batch) {
      if (entry === undefined) return { ok: false, problem: verifier.unreadable() };
      if (entry.seq > head.seq) throw new ChainStoreError('it gave an event past the head it was asked to read up to');
      const problem = verifier.check(entry);
      if (problem !== undefined) return { ok: false, problem };
      after = entry.seq;
    }
  }
  return verifier.finish();
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

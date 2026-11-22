// The witness log (TR-1): every chain head a copy of the app commits, written outside the database where someone with
// the database's keys can't reach it, and read back by every copy. The digest (digest-log.ts) holds a chain only to the
// heads its own copy saw or its walks covered; a stop written on one web copy was never seen by the jobs copy, so the
// owner cutting the chain back below it (rows deleted, an earlier sealed head put back) left every seal true there.
// Each copy now notes the head of every chain write it commits (audit-trail.ts, platform-chain.ts: afterCommit), and
// every copy reads the others', so a cut below any head a copy wrote is the chain cut back, wherever it is read.
//
// Files in the witness store (a write-once container beside the anchors'), gzipped lines `{c, s, h, t}` (a chain, a
// head's place and hash, when it was noted), each closed by a line signed for the file's own name, its epoch, how many
// lines it holds and the hash of every byte before it (signed-files.ts), under labels of their own:
//   e<epoch>/heads/<inverted-ms>-<id>      any copy of the API, signed with the `audit-anchor` key
//   e<epoch>/operator/<inverted-ms>-<id>   the operator's command, signed with its own `operator-signing` key, which
//                                         is all it holds (the anchors' key is the API's alone)
//   e<epoch>/snapshots/<inverted-ms>-<id>  hourly, every head held, in a container of its own (`snapshots`) that only
//                                         the jobs copy leading writes
// A file is taken only under the key its folder allows: a web copy holds the anchors' key, so a snapshot it could sign
// would let it leave out a real head; snapshots are read from their own container alone, which no web copy can add to,
// and a heads file can say only what was written, never what wasn't. A spoiled file is the alarm, and counts nothing.
// A name dated past the clock is the alarm and passed over. A line dated past its own file's name (past the clocks'
// spread) spoils the file, as no honest copy writes one: each names its file after its lines were noted. So a head is
// never dated past a few minutes from when its file landed, and a rebase after that sets it aside (TR-3: a web copy's
// key could otherwise date heads in 2099, which no rebase would ever set aside).
//
// Writing (group commit): a `now` head (a stop, an approval, every class but the decision path's: witness-class.ts) is
// written at once, at most one Put in flight a process, each taking every head waiting, `now` ones first (TR-11: a stop
// never queues behind a backlog of decisions, which still fill what a file has left); `now` resolves once a Put holding
// it succeeded. A `soon` head (an agent's decision) waits for the next flush, every few seconds while any waits, and at
// a stop. A Put that fails is tried again, backing off; a `now` waiter gives up after `waitMs` (`WitnessUnconfirmed`,
// the request answered 503), but its head stays queued, and every later wait for that chain on this process waits for
// it too: nothing that chain does here is told it succeeded before the head is outside the database. A Put not answered
// within PUT_WITHIN_MS failed (its heads go again in a file named afresh), well inside the readers' look back, so a file
// can't land past it. A head this process wrote already (a replay noting its kept head again) is not queued again.
//
// Reading: a coalesced `refresh` (a caller waits for the next that starts after its call) lists each heads folder
// newest-first to what it read already, less five minutes for the clocks and late writes; a start reads the newest sound
// snapshot first (passing over at most a day's spoiled ones), then every heads file since, less the same; with no sound
// snapshot, a day of heads files back (a head older than that above its chain's anchor means the anchor check has been
// stalled a day, its own alarm).
//
// Clocks (TR-12): a name carries its writer's clock, and readers look back only minutes, so a copy whose clock ran slow
// would name its files behind every look back (never read), and one running fast past every name a reader takes. So
// every time this log names or dates goes by the store's: each Put and list sets an offset from the service's `Date` on
// its answer (Azure's, over TLS), the first file waiting on a list for it: none within a minute of it (an honest clock
// dates as it always did), else set late, never early (a head dated early could fall before a rebase it came after). An honest copy with a wrong clock lands in
// every reader's next pass, however far off. More than the clocks' spread off is said (`audit.witness_clock_skew`, the
// alarm `clock_skew`): this copy's offset, or a file read whose name is that far from when the store says it landed
// (its Creation-Time), a copy the store's time didn't set. A line is never dated past its own file's name.
//
// Held: every head read or noted (`pending`, a list per chain, never only the highest: a stale copy's head on a cut
// branch must not bury the honest one below it), set aside by a rebase dated after it. Let go only once confirmed on the
// chain (`prune`): the anchor check's walk passed through it (never one it wasn't asked, nor one at or below where it
// began), or its probe read the same event at its place. A copy that never checks a chain (a web copy, `dropsAtAnchor`)
// lets go those at or below the chain's anchor instead, which the jobs copy made only after confirming every head it
// had read. So a head landing late at or below an anchor stays held on the jobs copy until its probe judges it: never
// dropped unseen, and a fork there is the alarm. Two heads at one place with different hashes prove a fork without a
// read: the alarm at once. Bounded: past what may be held, the organisation chain holding most lets its lowest heads go
// first, loudly (the platform's only where no organisation's is held), and that chain reads as `beyondMemory` (its
// hand-offs wait, the anchor check holds its anchor). Each head let go leaves a fingerprint (its place and its hash's
// first 16 bytes, a fifth of a head), which the next walk is held to as to a head (`fingerprints`: a place holding
// another event is a fork, the alarm and the hold); once a walk held to them all runs from below the lowest to at or past
// the highest, the chain is beyond memory no more (`walkedPast`: TR-3, a spike may slow a chain, never stop it for good).
// Fingerprints past their own share drop the chain holding most of them, loudly, back to a rebase alone. Both are kept in
// the snapshot, so a restart holds them too.
//
// Released (TR-3): heads the leader's probe found on the chain between anchor runs leave the list (`release`) as compact
// entries of the same form, never let go outright: a probe reads the hashes at their places in one statement with no
// link between them, and the owner can put rows back beside a cut branch for just that statement. Every later walk is
// held to them as to fingerprints (a place holding another event is a fork, the alarm and the hold), and a walk from the
// anchor that passes them, linked event by event, lets them go (walkedPast). A head noted again at a released place is
// the same one, or a fork, as with a held head. They take the fingerprints' share; past it, a head stays held. With
// them each chain keeps the anchors (place and whole hash) its compact heads went above (`baseBelow`), in the snapshot
// too: a walk confirming one that ended at or below a later anchor starts from there, not from the chain's first event.
//
// One held set (TR-9): every read and walk that may let money move or a read stand (Tx A's walks, the hand-off's gate,
// the digest's reads, the anchor check's walk) is held to `heldTo`, the heads held and the compact ones together. A
// released head left only the anchor check holding it, so a stop released on a fooled probe, its cut branch put back,
// was paid before the next anchor run raised the alarm. Kept as released rather than held whole until a linked walk
// passes it, as release exists to keep a busy chain's memory flat between anchor runs.
import type { KeyProvider } from '../keys/key-provider.ts';
import type { Logger } from '../observability/index.ts';
import type { WriteOnceStore } from '../storage/write-once.ts';
import { type Chain, chainName } from './chain.ts';
import { COMPACT_HASH_BYTES } from './digest-log.ts';
import { timeIn } from './rebase.ts';
import { bodyLines, fileName, type FileKind, isSoundFile, namesIn, signedFile, timeOfName } from './signed-files.ts';

/**
 * A head a copy wrote, as witnessed: its place, its event's hash, and when it was noted, by the store's clock as its
 * writer kept it (TR-12: the clock file names go by, never to be set against this process's own).
 */
export interface WitnessedHead {
  readonly seq: bigint;
  readonly hash: Buffer;
  readonly at: number;
}

/** How soon a head goes out: before anyone is told the write succeeded, or with the next flush. */
export type WitnessClass = 'now' | 'soon';

/** A `now` head not written within the wait: the write is committed, but not yet confirmed outside the database. */
export class WitnessUnconfirmed extends Error {
  constructor() {
    super('The chain head was saved but not yet confirmed outside the database; retry');
    this.name = 'WitnessUnconfirmed';
  }
}

/** What the chains' writers and reads ask of the witness log (core's audit-trail.ts and platform-chain.ts). */
export interface ChainWitness {
  /** A committed write's head, to go out now or with the next flush. Never throws, never waits. */
  note(chain: Chain, head: { readonly seq: bigint; readonly hash: Buffer }, klass: WitnessClass): void;
  /** Resolves once every `now` head noted so far for these chains is written; WitnessUnconfirmed past the wait. */
  settled(chains: readonly Chain[]): Promise<void>;
  /**
   * Every witnessed head above the chain's latest anchor, the highest first; at most `most` where given (a decision's
   * read asks only the highest few, so its cost stays flat however busy the chain is between anchors).
   */
  pending(chain: Chain, most?: number): readonly WitnessedHead[];
}

/** What the witness log asks of the anchors' log: the rebases it read, and each chain's latest anchor. */
export interface WitnessAnchors {
  rebasedAfter(chain: Chain, at: Date): boolean;
  /** The chain's latest anchor: its place, and its whole hash where the log keeps it (TR-3: baseBelow). */
  latest(chain: Chain): { readonly seq: bigint; readonly hash?: Buffer } | undefined;
}

export interface WitnessLog extends ChainWitness {
  /**
   * heldTo, each head's time (compact ones' too) on this process's own clock (TR-12): for setting against a time it took
   * itself (the digest's accepts), where heldTo's are the store's clock, as file names go.
   */
  witnessed(chain: Chain, most?: number): readonly WitnessedHead[];
  /** note(chain, head, 'now') and a wait for it (settled): for a writer outside the API's requests, the operator's. */
  now(chain: Chain, head: { readonly seq: bigint; readonly hash: Buffer }): Promise<void>;
  /** note(chain, head, 'soon'). */
  soon(chain: Chain, head: { readonly seq: bigint; readonly hash: Buffer }): void;
  /** Writes every head waiting, and hourly the snapshot where this copy leads. Never throws. */
  flush(): Promise<void>;
  /**
   * Every head noted here written, `soon` ones too: for a process about to end (the operator's command), which reports
   * success only once they are outside the database. WitnessUnconfirmed past the wait, the heads still queued.
   */
  drained(): Promise<void>;
  /**
   * Reads what the store holds that this process has not: the next refresh that starts after this call. The chains
   * that gained a head from another copy, none where the read failed. Never throws.
   */
  refresh(): Promise<readonly Chain[]>;
  /**
   * refresh, answering whether that very read ended whole (TR-1 F.6: the hand-off's gate sends nothing on a read that
   * began after its commit and failed). Never throws.
   */
  refreshWhole(): Promise<boolean>;
  /**
   * Whether this process's heads go out: no heads Put failing since the last one that went, and no `now` head waiting
   * past the wait (TR-1, plan §1.4 #2: hand-offs wait while the store takes no writes, rather than commit and be held).
   */
  writesSound(): boolean;
  /**
   * When the last refresh that ended whole began, none before one has: by this process's own clock (the `now` it was
   * given), as its callers compare it with theirs (TR-12: never the store's clock, which names the files).
   */
  freshAt(): Date | undefined;
  /** Those heads let go: each confirmed on the chain (the anchor check's walk passed through it, or its probe read it). */
  prune(chain: Chain, heads: readonly { readonly seq: bigint; readonly hash: Buffer }[]): void;
  /**
   * Whether a head of the chain was let go for memory: its hand-offs wait, and it is anchored no more, until a walk held
   * to every head still held passes the heads let go (walkedPast) or a rebase.
   */
  beyondMemory(chain: Chain): boolean;
  /**
   * A walk that held, from `from` (exclusive) to `to`, held to every head still held and the compact heads in `asked`,
   * told (TR-3): where it was held to every fingerprint, began below the lowest and reached the highest, the chain is
   * beyond memory no more; each released head it was held to and passed is let go. Whether it is still beyond memory.
   */
  walkedPast(
    chain: Chain,
    from: bigint,
    to: bigint,
    asked: readonly { readonly seq: bigint; readonly hash: Buffer }[],
  ): boolean;
  /**
   * The compact heads a walk of the chain is held to as to heads (TR-3), each its place and its hash's first 16 bytes (a
   * place holding another event is a fork): the fingerprints of those it let go for memory (none once those went too: a
   * rebase alone sets it aside then), and the heads released on a probe's finding.
   */
  fingerprints(chain: Chain): readonly { readonly seq: bigint; readonly hash: Buffer }[];
  /**
   * Everything a read or walk of the chain is held to (TR-9, the header): every head still held (pending) and every
   * compact head (fingerprints), the highest first, at most `most` where given. A compact head's hash is its first
   * COMPACT_HASH_BYTES alone, compared as such (hashHolds): a place holding another event is a fork, never a pass.
   */
  heldTo(chain: Chain, most?: number): readonly WitnessedHead[];
  /**
   * Those heads out of the list as released (TR-3, the header): a probe found them on the chain, which no link proves, so
   * every walk stays held to them (fingerprints) until one from the anchor passes them (walkedPast). Only those above
   * the chain's anchor, where the anchors' log holds it now (its base); none with no anchor known. Past the compact
   * heads' share, the rest stay held.
   */
  release(chain: Chain, heads: readonly { readonly seq: bigint; readonly hash: Buffer }[]): void;
  /**
   * The highest anchor (its place and whole hash) the chain's compact heads went above, at or below `seq` (TR-3): where
   * a walk confirming those at or below the anchor starts, its first link checked from it. None kept, none.
   */
  baseBelow(chain: Chain, seq: bigint): { readonly seq: bigint; readonly hash: Buffer } | undefined;
  /** The organisation chains holding more than one head, the most first, at most `most`: probed between anchor runs. */
  crowded(most: number): readonly Chain[];
  /** The anchors' log this one goes by, once it is made: none until then, and no head is set aside or let go by it. */
  useAnchors(anchors: WitnessAnchors): void;
  state(): 'unread' | 'read';
}

/** Who writes this copy's heads, and so where and under which key. */
export type WitnessSigner = 'app' | 'operator';

const HEADS_FILE: FileKind = { label: 'audit-witness-file', purpose: 'audit-anchor' };
const OPERATOR_FILE: FileKind = { label: 'audit-witness-file', purpose: 'operator-signing' };
const SNAPSHOT_FILE: FileKind = { label: 'audit-witness-snapshot', purpose: 'audit-anchor' };

/** How long a `now` waiter waits for its Put: past it, WitnessUnconfirmed, the head still queued. */
const WAIT_MS = 5_000;

/** How far past this process's clock a name may be dated, as the anchors' log allows. */
const MOST_AHEAD_MS = 5 * 60_000;

/** How far before the newest file read a later read looks again: a file named earlier may land later. */
const LAG_MS = MOST_AHEAD_MS;

/** How finely Azure's Date tells the store's time: whole seconds, rounded down. */
const DATE_STEP_MS = 1000;

/** How near the store's Date a clock is left as it stands (TR-12): an NTP-synced one always, so it dates as before. */
const RIGHT_ENOUGH_MS = 60_000;

/** The most names a list call asks of the heads' folders: Azure's most, one call where a hundred names took one each. */
const LIST_PAGE = 5000;

/** How far back a start with no sound snapshot reads heads files: a day, far past any anchor's turn. */
const NO_SNAPSHOT_READ_BACK_MS = 24 * 60 * 60_000;

/** How many spoiled snapshots a start goes back past: a day's at one an hour. */
const MOST_SPOILED_SNAPSHOTS = 24;

/** How often the leader writes a snapshot. */
const SNAPSHOT_EVERY_MS = 60 * 60_000;

/**
 * How many heads let go since the last snapshot write the next before the hour (after SNAPSHOT_AT_MOST_MS): a restart
 * starts from the snapshot, and every head confirmed and let go since would come back to be confirmed again.
 */
const PRUNED_FOR_A_SNAPSHOT = 1_000;

/**
 * The least time between snapshots written early for heads let go: busy chains let a thousand go a minute, and every
 * snapshot is kept for years in the write-once store.
 */
const SNAPSHOT_AT_MOST_MS = 15 * 60_000;

/**
 * How long a Put may take before it failed, its heads going again in a file named afresh: well inside LAG_MS, so a
 * file never lands past what a later read looks back over (one landing late anyway only repeats heads sent again).
 */
const PUT_WITHIN_MS = 60_000;

/** How many heads this process wrote it remembers, so a replay's head isn't queued again. */
const MOST_WRITTEN_REMEMBERED = 10_000;

/** The most lines one heads file carries: more wait for the next Put. */
const MOST_LINES_A_FILE = 10_000;

/** The lines of a file kept for `soon` heads where any wait, however many `now` heads do (TR-11): a tenth. */
const SOON_RESERVED = MOST_LINES_A_FILE / 10;

/** The most a heads file or snapshot may hold to be fetched. */
const MOST_FILE_BYTES = 64 * 1024 * 1024;

/**
 * What one head held takes on the heap: its object (a bigint place, a time), its 32-byte hash's Buffer and the list's
 * entry. Measured on Node 24 at 234 bytes (200,000 heads held as note() keeps them, after a full collection).
 */
export const WITNESS_HEAD_BYTES = 240;

/**
 * What one compact head (a fingerprint, or a head released) takes: a 32-byte packed record (its place, its hash's first
 * 16 bytes, when it was noted), with half again for the list's growth.
 */
const WITNESS_FINGERPRINT_BYTES = 48;

/** A compact head's packed record: its place, its hash's part, and when noted. */
const PRINT_RECORD = 32;
const PRINT_PREFIX = COMPACT_HASH_BYTES;
const PRINT_AT = 24;
const PREFIX = /^[0-9a-f]{32}$/;

/** A compact head: its place, its hash's first PRINT_PREFIX bytes, and when it was noted. */
interface Compact {
  readonly seq: bigint;
  readonly hash: Buffer;
  readonly at: number;
}

/** A chain's compact heads, packed. */
interface Packed {
  bytes: Buffer;
  count: number;
}

/** A compact head added to a pack, which grows by half again when full. */
function packIn(pack: Packed | undefined, { seq, hash, at }: Compact): Packed {
  const kept = pack ?? { bytes: Buffer.alloc(PRINT_RECORD * 4), count: 0 };
  if ((kept.count + 1) * PRINT_RECORD > kept.bytes.length) {
    const grown = Buffer.alloc(Math.ceil((kept.bytes.length * 1.5) / PRINT_RECORD) * PRINT_RECORD);
    kept.bytes.copy(grown);
    kept.bytes = grown;
  }
  const from = kept.count * PRINT_RECORD;
  kept.bytes.writeBigUInt64BE(seq, from);
  hash.copy(kept.bytes, from + 8, 0, PRINT_PREFIX);
  kept.bytes.writeDoubleBE(at, from + PRINT_AT);
  kept.count += 1;
  return kept;
}

/** A pack's compact heads. */
function unpacked(pack: Packed | undefined): Compact[] {
  if (pack === undefined) return [];
  return Array.from({ length: pack.count }, (_, index) => {
    const from = index * PRINT_RECORD;
    return {
      seq: pack.bytes.readBigUInt64BE(from),
      hash: Buffer.from(pack.bytes.subarray(from + 8, from + 8 + PRINT_PREFIX)),
      at: pack.bytes.readDoubleBE(from + PRINT_AT),
    };
  });
}

/** Whether a compact head is a given head's, or one a walk was held to: its place and its hash's first bytes. */
const sameCompact = (compact: Compact, { seq, hash }: { readonly seq: bigint; readonly hash: Buffer }): boolean =>
  compact.seq === seq && hash.subarray(0, PRINT_PREFIX).equals(compact.hash);

/** A failed Put's first wait before the next try, doubling to RETRY_MOST_MS. */
const RETRY_FIRST_MS = 100;
const RETRY_MOST_MS = 5_000;

/** How often a chain past memory says so again. */
const SAY_EVERY_MS = 60_000;

const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SEQ = /^[1-9]\d{0,18}$/;
const HASH = /^[0-9a-f]{64}$/;

/** What a chain let go for memory: the highest and lowest heads, and when the last went (a rebase after sets it aside). */
interface LostMark {
  readonly seq: bigint;
  readonly low: bigint;
  readonly at: number;
}

/** A line of a heads file or snapshot: one chain's head, or (a snapshot's) the heads it let go for memory. */
type HeadLine =
  | { readonly chain: string; readonly head: WitnessedHead }
  | { readonly chain: string; readonly lost: LostMark }
  | { readonly chain: string; readonly print: Compact }
  | { readonly chain: string; readonly released: Compact }
  | { readonly chain: string; readonly base: Compact };

/**
 * A line as its file of `fileAt` gives it: none where it isn't one, or is dated past the file's name beyond the clocks'
 * spread (no honest copy writes one: the header). Its time never past the name's, so a rebase after the file sets it aside.
 */
function lineFrom(fields: unknown, fileAt: number): HeadLine | undefined {
  if (typeof fields !== 'object' || fields === null) return undefined;
  const { c, s, h, t, l, f, x, r, b, a, ...rest } = fields as Record<string, unknown>;
  const dated = timeIn(t)?.getTime();
  if (Object.keys(rest).length > 0 || typeof c !== 'string' || !CHAIN.test(c) || dated === undefined) return undefined;
  if (dated > fileAt + MOST_AHEAD_MS) return undefined;
  const at = Math.min(dated, fileAt);
  if (b !== undefined || a !== undefined) return baseLine(c, { s, h, l, f, x, r }, b, a, at);
  if (s === undefined && h === undefined) return lostLine(c, l, f, at);
  if (l !== undefined || f !== undefined || typeof s !== 'string' || !SEQ.test(s)) return undefined;
  const seq = BigInt(s);
  if (h !== undefined) {
    return x !== undefined || r !== undefined || typeof h !== 'string' || !HASH.test(h)
      ? undefined
      : { chain: c, head: { seq, hash: Buffer.from(h, 'hex'), at } };
  }
  // A fingerprint of a head let go, or a head released: its place and its hash's first bytes (a snapshot's alone).
  if (typeof x === 'string' && PREFIX.test(x) && r === undefined) {
    return { chain: c, print: { seq, hash: Buffer.from(x, 'hex'), at } };
  }
  return typeof r === 'string' && PREFIX.test(r) && x === undefined
    ? { chain: c, released: { seq, hash: Buffer.from(r, 'hex'), at } }
    : undefined;
}

/** A snapshot's anchor its chain's compact heads went above (`b` its place, `a` its whole hash), and nothing else. */
function baseLine(
  chain: string,
  others: Readonly<Record<string, unknown>>,
  b: unknown,
  a: unknown,
  at: number,
): HeadLine | undefined {
  if (Object.values(others).some((one) => one !== undefined)) return undefined;
  if (typeof b !== 'string' || !SEQ.test(b) || typeof a !== 'string' || !HASH.test(a)) return undefined;
  return { chain, base: { seq: BigInt(b), hash: Buffer.from(a, 'hex'), at } };
}

/** A snapshot's line for an anchor a chain's compact heads went above. */
const baseText = (chain: string, { seq, hash, at }: Compact): string =>
  JSON.stringify({ c: chain, b: seq.toString(), a: hash.toString('hex'), t: new Date(at).toISOString() });

/** A snapshot's mark of heads let go for memory: the lowest where it says it, else none known (a rebase alone then). */
function lostLine(chain: string, l: unknown, f: unknown, at: number): HeadLine | undefined {
  if (typeof l !== 'string' || !SEQ.test(l)) return undefined;
  const low = typeof f === 'string' && SEQ.test(f) && BigInt(f) <= BigInt(l) ? BigInt(f) : 0n;
  return f !== undefined && low === 0n ? undefined : { chain, lost: { seq: BigInt(l), low, at } };
}

/** A snapshot's line for a chain's heads let go for memory. */
const lostText = (chain: string, { seq, low, at }: LostMark): string =>
  JSON.stringify({
    c: chain,
    l: seq.toString(),
    ...(low > 0n ? { f: low.toString() } : {}),
    t: new Date(at).toISOString(),
  });

/** A snapshot's line for a compact head: a fingerprint (`x`) or a head released (`r`), dated as it was noted. */
const compactText = (chain: string, field: 'x' | 'r', { seq, hash, at }: Compact): string =>
  JSON.stringify({ c: chain, s: seq.toString(), [field]: hash.toString('hex'), t: new Date(at).toISOString() });

/**
 * A line's time held to its file's (TR-12): a head noted before this copy first heard the store's time, by a clock
 * running fast, would otherwise be dated past the file it goes in, which spoils it.
 */
const datedBy = <T extends { readonly at: number }>(one: T, fileAt: number): T =>
  one.at > fileAt ? { ...one, at: fileAt } : one;

const lineText = (chain: string, { seq, hash, at }: WitnessedHead): string =>
  JSON.stringify({ c: chain, s: seq.toString(), h: hash.toString('hex'), t: new Date(at).toISOString() });

/** The first place in a list held highest first whose head is below `seq`: its length where none is. */
function firstBelow(list: readonly WitnessedHead[], seq: bigint): number {
  let low = 0;
  let high = list.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if ((list[middle]?.seq ?? 0n) < seq) high = middle;
    else low = middle + 1;
  }
  return low;
}

/** The chain's object, from its name. */
const chainOfName = (name: string): Chain =>
  name === 'platform' ? { kind: 'platform' } : { kind: 'organisation', orgId: name.slice('organisation:'.length) };

/** A chain's name as the witness keeps it: an organisation's ID in lower case, as the chains' writers name it. */
const nameOf = (chain: Chain): string =>
  chainName(chain.kind === 'platform' ? chain : { kind: 'organisation', orgId: chain.orgId.toLowerCase() });

/** What one refresh read: the chains that gained a head, and whether it ended whole. */
interface Refreshed {
  readonly chains: readonly Chain[];
  readonly whole: boolean;
}

/** A head noted here, waiting for its Put. */
interface Queued {
  readonly chain: string;
  /** Its time re-dated by the store's clock once that is first known, where noted before (TR-12). */
  readonly head: { readonly seq: bigint; readonly hash: Buffer; at: number };
  readonly klass: WitnessClass;
  readonly confirmed: Promise<void>;
  readonly done: () => void;
}

export function createWitnessLog({
  store,
  snapshots,
  keys,
  logger,
  now: localNow,
  epoch,
  signer = 'app',
  writes,
  alertAfterMs,
  mostBytes,
  waitMs = WAIT_MS,
  dropsAtAnchor = false,
}: {
  /** Where every copy adds its heads and reads the others'. */
  readonly store: WriteOnceStore;
  /** Where the leader's snapshots are kept, apart (only it may add there); none, a start reads a day of heads files. */
  readonly snapshots?: WriteOnceStore | undefined;
  readonly keys: KeyProvider;
  readonly logger: Logger;
  readonly now: () => Date;
  readonly epoch: number;
  /** Who writes this copy's heads: the API's copies (the default), or the operator's command. */
  readonly signer?: WitnessSigner;
  /** Whether this copy writes the snapshots: it leads the jobs. None, never. */
  readonly writes?: (() => boolean) | undefined;
  /** How long reads or writes may fail before that is the alert, not just a warning. */
  readonly alertAfterMs: number;
  /** What it may hold, in bytes: heads past it are let go, loudly. */
  readonly mostBytes: number;
  /** How long a `now` waiter waits for its Put. */
  readonly waitMs?: number;
  /**
   * Whether heads at or below the chain's anchor are let go as such: a copy that never checks a chain (a web copy). The
   * copy that anchors (jobs) lets a head go only once it confirmed it (`prune`), as an anchor of its own is no proof.
   */
  readonly dropsAtAnchor?: boolean;
}): WitnessLog {
  const folder = (kind: 'heads' | 'operator' | 'snapshots'): string => `e${String(epoch)}/${kind}/`;
  const ownFolder = signer === 'operator' ? folder('operator') : folder('heads');
  const ownKind = signer === 'operator' ? OPERATOR_FILE : HEADS_FILE;
  // A tenth of the heads' share for the fingerprints of those let go (the header).
  const mostHeads = Math.max(1, Math.floor((mostBytes * 10) / 11 / WITNESS_HEAD_BYTES));
  const mostPrints = Math.floor(mostBytes / 11 / WITNESS_FINGERPRINT_BYTES);
  let anchors: WitnessAnchors | undefined;

  // Every head held, by chain, and how many in all.
  const held = new Map<string, WitnessedHead[]>();
  let heldCount = 0;
  // What a chain let go for memory (a rebase after, or a walk past it, sets it aside), and when that was last said.
  const lost = new Map<string, LostMark>();
  // Each chain's fingerprints of the heads it let go, packed, and how many in all.
  const prints = new Map<string, Packed>();
  // Each chain's heads released on a probe's finding, packed: held to by every walk until one passes them.
  const released = new Map<string, Packed>();
  // Compact heads of both kinds, in all.
  let printCount = 0;
  // Each chain's anchors its compact heads went above (place, whole hash, when kept): where a confirming walk starts.
  const bases = new Map<string, Compact[]>();
  let lostSaidAt: number | undefined;

  // Heads waiting for their Put, and each chain's `now` heads not yet written.
  let queue: Queued[] = [];
  // The heads of the Put in flight, out of the queue (redate reaches them too).
  let inFlight: readonly Queued[] = [];
  const unconfirmed = new Map<string, Set<Queued>>();
  let writing: Promise<void> | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let failedWrites = 0;
  let lastFailedAt = 0;
  let writeFailingSince: number | undefined;
  // A heads Put failed and none has gone since (a snapshot's failure is not one: it holds no head back).
  let headsPutFailing = false;
  // The heads this process wrote, latest last, at most MOST_WRITTEN_REMEMBERED: a replay's isn't queued again.
  const writtenHere = new Set<string>();

  let state: 'unread' | 'read' = 'unread';
  let freshAt: Date | undefined;
  let refreshing: Promise<Refreshed> | undefined;
  let refreshNext: Promise<Refreshed> | undefined;
  let readFailingSince: number | undefined;
  // The newest heads file a whole pass read, by its name's time, when the last whole pass began, and the names read
  // since a look back past them. Moved on only by a pass that ended whole, never by this copy's own writes: a pass cut
  // short newest-first would otherwise pass over the older files it never reached.
  let headsFrom: number | undefined;
  let wholeFrom: number | undefined;
  const namesRead = new Set<string>();
  let lastSnapshotAt: number | undefined;
  let changedSinceSnapshot = false;
  let prunedSinceSnapshot = 0;

  const alarm = (reason: string, more: Record<string, unknown>): void => {
    logger.error('audit.integrity_failed', { chain: 'store', check: 'witness_store', reason, ...more });
  };

  // This copy's clock as the store's (TR-12): how far the store's Date was from the local clock on its latest answer,
  // whether one was asked yet, and when a clock far off was last said.
  let offset = 0;
  let clockAsked = false;
  let offsetKnown = false;
  let skewSaidAt: number | undefined;
  /** Every time this log names or dates: the local clock set by the store's (the header). */
  const nowMs = (): number => localNow().getTime() + offset;
  const now = (): Date => new Date(nowMs());

  /** A clock more than the clocks' spread off the store's, said and the alarm, at most once a SAY_EVERY_MS. */
  const skewed = (fields: Record<string, unknown>): void => {
    const said = now().getTime();
    if (skewSaidAt !== undefined && said - skewSaidAt < SAY_EVERY_MS) return;
    skewSaidAt = said;
    logger.error('audit.witness_clock_skew', fields);
    alarm('clock_skew', fields);
  };

  /**
   * The store's Date on the answer to a call sent at `sent` (this clock), where it gives one: this copy's clock set by
   * it, and said if far off. Within RIGHT_ENOUGH_MS of it, left as it stands: an honest clock dates as before TR-12.
   */
  const heard = (sent: number): void => {
    const at = store.serverTime?.();
    if (at === undefined) return;
    // Else set late, never early (a head dated early could fall before a rebase it came after): the store stamped its
    // Date after the call left, at a true time below at + DATE_STEP_MS (whole seconds, rounded down), so the true
    // offset at `sent` is below at + DATE_STEP_MS - sent; this one is never less, and later by at most the trip and 1 s.
    offset = Math.abs(localNow().getTime() - at) <= RIGHT_ENOUGH_MS ? 0 : at + DATE_STEP_MS - sent;
    clockAsked = true;
    if (!offsetKnown) {
      offsetKnown = true;
      redate();
    }
    if (Math.abs(offset) > MOST_AHEAD_MS) skewed({ offsetMs: offset });
  };

  /**
   * Every head waiting, each noted before the store's time was first known, dated as noted by the store's clock now it
   * is (TR-12): so a Put failing after, or a snapshot, never carries the local clock's time.
   */
  const redate = (): void => {
    for (const { head } of [...queue, ...inFlight]) head.at += offset;
  };

  /**
   * The store's time asked where it gives one and none was heard yet: before this copy's first file, so even that one is
   * named by it, and before its first read, so the snapshots' names are judged by it too (TR-12). Throws as a list does.
   */
  const askClock = async (): Promise<void> => {
    if (clockAsked || store.serverTime === undefined) return;
    await timed.list(ownFolder, 1);
    clockAsked = true;
  };

  /** The heads' store, each Put and list setting this copy's clock by the store's answer. */
  const timed: WriteOnceStore = {
    async put(name, bytes) {
      const sent = localNow().getTime();
      await store.put(name, bytes);
      heard(sent);
    },
    async list(start, most, after) {
      const sent = localNow().getTime();
      const page = await store.list(start, most, after);
      heard(sent);
      return page;
    },
    get: (name) => store.get(name),
    getAtMost: (name, most) => store.getAtMost(name, most),
  };

  /** A failed read or write: a warning, and past `alertAfterMs` of failing, the alert. */
  const failed = (what: 'read' | 'write', error: unknown): void => {
    const at = now().getTime();
    if (what === 'read') readFailingSince ??= at;
    else writeFailingSince ??= at;
    const since = (what === 'read' ? readFailingSince : writeFailingSince) ?? at;
    const lasting = at - since >= alertAfterMs;
    if (what === 'read') {
      if (lasting) logger.error('audit.witness_read_failing', { err: error });
      else logger.warn('audit.witness_read_failed', { err: error });
    } else if (lasting) logger.error('audit.witness_write_failing', { err: error });
    else logger.warn('audit.witness_write_failed', { err: error });
  };

  /** The chain's latest anchor's place, as the anchors' log says it: none, nothing is let go by it. */
  const anchoredAt = (name: string): bigint | undefined => anchors?.latest(chainOfName(name))?.seq;

  /** Whether a head is still held: not dated before a rebase of the chain; where `dropsAtAnchor`, above its anchor. */
  const stands = (name: string, head: WitnessedHead): boolean => {
    const anchored = dropsAtAnchor ? anchoredAt(name) : undefined;
    if (anchored !== undefined && head.seq <= anchored) return false;
    return anchors?.rebasedAfter(chainOfName(name), new Date(head.at)) !== true;
  };

  /** The fork alarm: two heads witnessed at one place with different hashes, no read needed. */
  const forked = (name: string, seq: bigint): void => {
    const platform = name === 'platform';
    const log = platform ? logger : logger.child({ orgId: name.slice('organisation:'.length) });
    log.error('audit.integrity_failed', {
      chain: platform ? 'platform' : 'organisation',
      check: 'witness',
      reason: 'fork',
      seq: seq.toString(),
    });
  };

  /** The chain to give way: the organisation's holding most; the platform's only where no organisation's is held. */
  const largestHeld = (): [string, WitnessedHead[]] | undefined => {
    let largest: [string, WitnessedHead[]] | undefined;
    for (const entry of held) {
      if (entry[0] !== 'platform' && (largest === undefined || entry[1].length > largest[1].length)) largest = entry;
    }
    const platform = held.get('platform');
    return largest ?? (platform === undefined ? undefined : ['platform', platform]);
  };

  /** Past what may be held, the chain chosen (largestHeld) lets its lowest head go: said, and the chain marked. */
  const giveWay = (): void => {
    while (heldCount > mostHeads) {
      const largest = largestHeld();
      if (largest === undefined) return;
      const [name, list] = largest;
      // Its lowest above its anchor, which the next walk from the anchor passes (walkedPast); one at or below it (a
      // late head, waiting to be confirmed) only where none is above.
      const anchored = anchoredAt(name);
      const above = anchored === undefined ? -1 : list.findLastIndex(({ seq }) => seq > anchored);
      const [lowest] = list.splice(above < 0 ? list.length - 1 : above, 1);
      heldCount -= 1;
      if (list.length === 0) held.delete(name);
      const at = now().getTime();
      if (lowest !== undefined) {
        lostOne(name, lowest.seq, at);
        keepBase(name);
        printOne(name, { seq: lowest.seq, hash: lowest.hash, at });
      }
      if (lostSaidAt === undefined || at - lostSaidAt >= SAY_EVERY_MS) {
        lostSaidAt = at;
        logger.error('audit.witness_beyond_memory', { heads: heldCount, mostHeads, chain: name });
      }
    }
  };

  /** A fingerprint of a head let go kept, unless the chain's were let go already; past their share, some let go. */
  const printOne = (name: string, head: Compact): void => {
    // A mark with no lowest known: its fingerprints went, and only a rebase sets it aside.
    if (lost.get(name)?.low === 0n) return;
    prints.set(name, packIn(prints.get(name), head));
    printCount += 1;
    changedSinceSnapshot = true;
    while (printCount > mostPrints && prints.size > 0) unprint();
  };

  /** The chain holding most fingerprints (an organisation's before the platform's) lets them all go: a rebase alone now. */
  const unprint = (): void => {
    const organisations = [...prints].filter(([name]) => name !== 'platform');
    const pool = organisations.length > 0 ? organisations : [...prints];
    let chosen: (typeof pool)[number] | undefined;
    for (const entry of pool) if (chosen === undefined || entry[1].count > chosen[1].count) chosen = entry;
    if (chosen === undefined) return;
    const [most] = chosen;
    dropPrints(most);
    const mark = lost.get(most);
    if (mark !== undefined) lost.set(most, { ...mark, low: 0n });
    logger.error('audit.witness_beyond_memory', { heads: heldCount, mostHeads, chain: most, fingerprints: false });
  };

  /** A chain's fingerprints let go. */
  const dropPrints = (name: string): void => {
    printCount -= prints.get(name)?.count ?? 0;
    prints.delete(name);
    tidyBases(name);
  };

  /**
   * The chain's latest anchor kept as one its compact heads went above, where the anchors' log gives it whole: its place,
   * or none where the log holds none for the chain now (never anchored, or its shard let go: PL-65).
   */
  const keepBase = (name: string): bigint | undefined => {
    const anchor = anchors?.latest(chainOfName(name));
    if (anchor?.hash === undefined) return undefined;
    const kept = bases.get(name) ?? [];
    if (!kept.some(({ seq, hash }) => seq === anchor.seq && hash.equals(anchor.hash ?? hash))) {
      bases.set(name, [...kept, { seq: anchor.seq, hash: Buffer.from(anchor.hash), at: now().getTime() }]);
      changedSinceSnapshot = true;
    }
    return anchor.seq;
  };

  /** A chain's bases let go once it holds no compact head. */
  const tidyBases = (name: string): void => {
    if (!prints.has(name) && !released.has(name)) bases.delete(name);
  };

  /** A chain's bases that still stand: those kept before a rebase of it let go. */
  const basesOf = (name: string): Compact[] => {
    const list = bases.get(name) ?? [];
    const kept = list.filter(({ at }) => anchors?.rebasedAfter(chainOfName(name), new Date(at)) !== true);
    if (kept.length !== list.length) bases.set(name, kept);
    return kept;
  };

  /** A chain's fingerprints, each its place and its hash's first bytes. */
  const printsOf = (name: string): Compact[] => unpacked(prints.get(name));

  /** A chain's released heads, as given: counted. */
  const setReleased = (name: string, list: readonly Compact[]): void => {
    printCount += list.length - (released.get(name)?.count ?? 0);
    let pack: Packed | undefined;
    for (const one of list) pack = packIn(pack, one);
    if (pack === undefined) released.delete(name);
    else released.set(name, pack);
    tidyBases(name);
    changedSinceSnapshot = true;
  };

  /**
   * A chain's released heads that still stand: those dated before a rebase of it let go, and where `dropsAtAnchor` (a
   * web copy, which never walks the chain to let them go), those at or below its anchor, as `stands` lets heads go.
   */
  const releasedOf = (name: string): Compact[] => {
    const list = unpacked(released.get(name));
    const anchored = dropsAtAnchor ? anchoredAt(name) : undefined;
    const kept = list.filter(
      ({ seq, at }) =>
        (anchored === undefined || seq > anchored) && anchors?.rebasedAfter(chainOfName(name), new Date(at)) !== true,
    );
    if (kept.length !== list.length) setReleased(name, kept);
    return kept;
  };

  /** A head let go for memory, into the chain's mark: its highest and lowest, and now. */
  const lostOne = (name: string, seq: bigint, at: number): void => {
    const mark = lost.get(name);
    lost.set(name, {
      seq: mark === undefined || seq > mark.seq ? seq : mark.seq,
      low: mark === undefined || seq < mark.low ? seq : mark.low,
      at,
    });
  };

  /** A head into the chain's list, the highest first, once each: whether it was new. */
  const keep = (name: string, head: WitnessedHead): boolean => {
    if (!stands(name, head)) return false;
    const list = held.get(name) ?? [];
    // Those at its place, found by halving (a busy chain holds many heads, highest first): the same, or a fork.
    const place = firstBelow(list, head.seq);
    const there = list.slice(firstBelow(list, head.seq + 1n), place);
    if (there.some(({ hash }) => hash.equals(head.hash))) return false;
    // Released at its place: the same head again (as good as held), or a fork.
    const releasedThere = released.has(name) ? releasedOf(name).filter(({ seq }) => seq === head.seq) : [];
    if (releasedThere.some((one) => sameCompact(one, head))) return false;
    if (releasedThere.length > 0 || there.some((one) => stands(name, one))) forked(name, head.seq);
    list.splice(place, 0, head);
    held.set(name, list);
    heldCount += 1;
    changedSinceSnapshot = true;
    giveWay();
    return true;
  };

  /** The chain's heads that still stand, those that don't let go. */
  const standing = (name: string, most = Number.POSITIVE_INFINITY): readonly WitnessedHead[] => {
    const list = held.get(name);
    if (list === undefined) return [];
    // Highest first: those at or below the anchor are the list's tail, let go from its end (a web copy's alone).
    const anchored = dropsAtAnchor ? anchoredAt(name) : undefined;
    let end = list.length;
    while (anchored !== undefined && end > 0 && (list[end - 1]?.seq ?? 0n) <= anchored) end -= 1;
    if (end < list.length) setList(name, list.slice(0, end));
    const kept: WitnessedHead[] = [];
    for (const head of held.get(name) ?? []) {
      if (kept.length >= most) break;
      if (!stands(name, head)) return dropRebased(name).slice(0, most);
      kept.push(head);
    }
    return kept;
  };

  /** Whether the chain let a head go for memory since its last rebase: set aside only by a rebase after it. */
  const beyond = (name: string): boolean => {
    const mark = lost.get(name);
    if (mark === undefined) return false;
    if (anchors?.rebasedAfter(chainOfName(name), new Date(mark.at)) !== true) return true;
    lost.delete(name);
    dropPrints(name);
    return false;
  };

  /** A chain's compact heads a walk is held to: its fingerprints while it is beyond memory, and its released heads. */
  const compactOf = (name: string): Compact[] => [...(beyond(name) ? printsOf(name) : []), ...releasedOf(name)];

  /** The chain's list as given, counted. */
  const setList = (name: string, list: WitnessedHead[]): void => {
    heldCount += list.length - (held.get(name)?.length ?? 0);
    if (list.length === 0) held.delete(name);
    else held.set(name, list);
  };

  /** The chain's heads a rebase set aside, let go (rare: a sanctioned restore): what stands. */
  const dropRebased = (name: string): readonly WitnessedHead[] => {
    const kept = (held.get(name) ?? []).filter((head) => stands(name, head));
    setList(name, kept);
    return kept;
  };

  // ---- writing ----

  /** The key a head this process wrote is remembered by. */
  const writtenKey = (name: string, { seq, hash }: { readonly seq: bigint; readonly hash: Buffer }): string =>
    `${name}|${seq.toString()}|${hash.toString('hex')}`;

  /** A head written, remembered, the oldest forgotten past MOST_WRITTEN_REMEMBERED. */
  const remember = (name: string, head: WitnessedHead): void => {
    const key = writtenKey(name, head);
    writtenHere.delete(key);
    writtenHere.add(key);
    for (const oldest of writtenHere) {
      if (writtenHere.size <= MOST_WRITTEN_REMEMBERED) break;
      writtenHere.delete(oldest);
    }
  };

  /** A Put, failed where it isn't answered within PUT_WITHIN_MS (the header). */
  const putWithin = async (name: string, bytes: Buffer): Promise<void> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        reject(new Error(`the witness store didn't answer a Put within ${String(PUT_WITHIN_MS)} ms`));
      }, PUT_WITHIN_MS);
      timer.unref();
    });
    try {
      await Promise.race([timed.put(name, bytes), late]);
    } finally {
      clearTimeout(timer);
    }
  };

  /**
   * The next file's heads, taken from the queue (TR-11): every `now` head first, so a stop never waits behind a backlog
   * of decisions, then `soon` ones to fill it; past a file's worth of `now` heads, SOON_RESERVED lines still go to `soon`
   * ones, so neither class waits for good.
   */
  const nextFile = (): Queued[] => {
    const nowHeads: Queued[] = [];
    const soonHeads: Queued[] = [];
    for (const queued of queue) (queued.klass === 'now' ? nowHeads : soonHeads).push(queued);
    const nowTaken = nowHeads.slice(0, MOST_LINES_A_FILE - Math.min(soonHeads.length, SOON_RESERVED));
    const taking = [...nowTaken, ...soonHeads.slice(0, MOST_LINES_A_FILE - nowTaken.length)];
    const taken = new Set(taking);
    queue = queue.filter((queued) => !taken.has(queued));
    return taking;
  };

  /** The next file's worth written: whether it was. Taken back into the queue where it wasn't. */
  const writeOnce = async (): Promise<boolean> => {
    let taking: Queued[] = [];
    try {
      // The store's time first, so heads noted before it are re-dated while still in the queue.
      await askClock();
      taking = nextFile();
      inFlight = taking;
      const at = now().getTime();
      const name = fileName(ownFolder, at);
      const bytes = await signedFile(
        keys,
        ownKind,
        name,
        epoch,
        taking.map(({ chain, head }) => lineText(chain, datedBy(head, at))),
      );
      await putWithin(name, bytes);
      namesRead.add(name);
      for (const queued of taking) {
        remember(queued.chain, queued.head);
        unconfirmed.get(queued.chain)?.delete(queued);
        if (unconfirmed.get(queued.chain)?.size === 0) unconfirmed.delete(queued.chain);
        queued.done();
      }
      writeFailingSince = undefined;
      headsPutFailing = false;
      failedWrites = 0;
      return true;
    } catch (error) {
      queue = [...taking, ...queue];
      headsPutFailing = true;
      failedWrites += 1;
      lastFailedAt = now().getTime();
      failed('write', error);
      return false;
    } finally {
      inFlight = [];
    }
  };

  const nowWaiting = (): boolean => queue.some(({ klass }) => klass === 'now');

  /** A `soon` head waited for as a `now` one: counted among its chain's unconfirmed. */
  const promoted = (queued: Queued): Queued => {
    const now: Queued = { ...queued, klass: 'now' };
    const waiting = unconfirmed.get(queued.chain) ?? new Set<Queued>();
    waiting.add(now);
    unconfirmed.set(queued.chain, waiting);
    return now;
  };

  /**
   * Writes what waits, one Put at a time, each taking all it can: `all`, every head; else only while a `now` head
   * waits. A Put that fails is tried again after a wait that doubles, while a `now` head waits.
   */
  const write = (all: boolean): Promise<void> => {
    const next = (writing ?? Promise.resolve()).then(async () => {
      while (queue.length > 0 && (all || nowWaiting())) {
        if (!(await writeOnce())) {
          retryLater();
          return;
        }
      }
    });
    const tracked = next.finally(() => {
      if (writing === tracked) writing = undefined;
    });
    writing = tracked;
    return next;
  };

  /** A `now` head that failed to go out, tried again after a wait. */
  const retryLater = (): void => {
    if (retryTimer !== undefined || !nowWaiting()) return;
    const waitFor = Math.min(RETRY_MOST_MS, RETRY_FIRST_MS * 2 ** Math.min(failedWrites - 1, 16));
    retryTimer = setTimeout(() => {
      retryTimer = undefined;
      void write(false);
    }, waitFor);
    retryTimer.unref();
  };

  const note = (chain: Chain, { seq, hash }: { readonly seq: bigint; readonly hash: Buffer }, klass: WitnessClass) => {
    if (seq < 1n) return;
    const name = nameOf(chain);
    // Written by this process already (a replay's kept head): outside the database, nothing to wait for.
    if (writtenHere.has(writtenKey(name, { seq, hash }))) return;
    // Kept as given, its time set once its file is named where the store's time wasn't known yet.
    const head: { readonly seq: bigint; readonly hash: Buffer; at: number } = {
      seq,
      hash: Buffer.from(hash),
      at: nowMs(),
    };
    keep(name, head);
    let done = (): void => undefined;
    const confirmed = new Promise<void>((resolve) => {
      done = resolve;
    });
    const queued: Queued = { chain: name, head, klass, confirmed, done };
    queue.push(queued);
    if (klass !== 'now') return;
    const waiting = unconfirmed.get(name) ?? new Set<Queued>();
    waiting.add(queued);
    unconfirmed.set(name, waiting);
    if (retryTimer === undefined) void write(false);
  };

  const settled = (chains: readonly Chain[]): Promise<void> => {
    const waiting = chains.flatMap((chain) => [...(unconfirmed.get(nameOf(chain)) ?? [])]);
    if (waiting.length === 0) return Promise.resolve();
    // A new waiter tries at once rather than waiting out a backed-off retry, at most one try per RETRY_FIRST_MS.
    if (retryTimer !== undefined && now().getTime() - lastFailedAt >= RETRY_FIRST_MS) {
      clearTimeout(retryTimer);
      retryTimer = undefined;
      void write(false);
    }
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        logger.warn('audit.witness_unconfirmed', { heads: waiting.length, waitMs });
        reject(new WitnessUnconfirmed());
      }, waitMs);
      timer.unref();
      void Promise.all(waiting.map(({ confirmed }) => confirmed)).then(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  };

  // ---- reading ----

  /** A heads file or snapshot taken in if it is sound under its kind's key: the chains it gave a new head, or false. */
  const takeFile = async (
    from: WriteOnceStore,
    { name, at }: { readonly name: string; readonly at: number },
    kind: FileKind,
    gained: Set<string>,
  ): Promise<boolean> => {
    const got = await from.getAtMost(name, MOST_FILE_BYTES);
    if (got === 'missing') throw new Error('a witness file listed and then not there');
    if (
      typeof got === 'string' ||
      !(await isSoundFile(keys, kind, got, name, epoch, (f) => lineFrom(f, at) !== undefined))
    ) {
      return false;
    }
    // A snapshot's released heads gathered by chain, each chain's packed once at the end.
    const releasedRead = new Map<string, Compact[]>();
    for await (const fields of bodyLines(got)) {
      const line = lineFrom(fields, at);
      if (line === undefined) continue;
      if ('head' in line) {
        if (keep(line.chain, line.head)) gained.add(line.chain);
      } else if (kind === SNAPSHOT_FILE) {
        snapshotLine(line, releasedRead);
      }
    }
    for (const [name, list] of releasedRead) setReleased(name, [...unpacked(released.get(name)), ...list]);
    return true;
  };

  /**
   * A snapshot's line other than a head: a mark of heads let go, a fingerprint, a head released (gathered into
   * `releasedRead`), or an anchor compact heads went above. A heads file says only what was written, so these come from
   * a snapshot alone.
   */
  const snapshotLine = (
    line: Exclude<HeadLine, { readonly head: WitnessedHead }>,
    releasedRead: Map<string, Compact[]>,
  ): void => {
    if ('lost' in line) lostRead(line.chain, line.lost);
    else if ('print' in line) printOne(line.chain, line.print);
    else if ('base' in line) bases.set(line.chain, [...(bases.get(line.chain) ?? []), line.base]);
    else releasedRead.set(line.chain, [...(releasedRead.get(line.chain) ?? []), line.released]);
  };

  /** Every well-named file of a folder, newest first; a name dated past the clock the alarm, passed over. */
  const namesOf = (from: WriteOnceStore, at: string) =>
    namesIn(
      from,
      at,
      () => now().getTime() + MOST_AHEAD_MS,
      (fileAt) => {
        alarm('future', { folder: at, fileAt: new Date(fileAt).toISOString() });
      },
      LIST_PAGE,
    );

  /**
   * A file read whose name is further than the clocks' spread from when the store says it landed (TR-12): a copy naming
   * files by a clock the store's time didn't set (an older build, or one whose store gave no time), said.
   */
  const judgeLanding = (
    at: string,
    { at: fileAt, created }: { readonly at: number; readonly created: number | undefined },
  ): void => {
    if (created === undefined || Math.abs(fileAt - created) <= MOST_AHEAD_MS) return;
    skewed({
      folder: at,
      fileAt: new Date(fileAt).toISOString(),
      landedAt: new Date(created).toISOString(),
      skewMs: fileAt - created,
    });
  };

  /** The newest sound snapshot taken in, and its time; none with no snapshots' store, or none sound a day back. */
  const readSnapshot = async (gained: Set<string>): Promise<number | undefined> => {
    if (snapshots === undefined) return undefined;
    let spoiled = 0;
    for await (const file of namesOf(snapshots, folder('snapshots'))) {
      const { at } = file;
      if (await takeFile(snapshots, file, SNAPSHOT_FILE, gained)) return at;
      spoiled += 1;
      alarm('spoiled', { folder: 'snapshots', fileAt: new Date(at).toISOString() });
      if (spoiled >= MOST_SPOILED_SNAPSHOTS) return undefined;
    }
    return undefined;
  };

  /** A snapshot's mark of heads let go for memory, kept as the higher of what is held and what it says. */
  const lostRead = (name: string, mark: LostMark): void => {
    const held = lost.get(name);
    if (held === undefined) {
      lost.set(name, mark);
      return;
    }
    // The wider of the two, so a walk past it covers both.
    lost.set(name, {
      seq: held.seq > mark.seq ? held.seq : mark.seq,
      low: held.low < mark.low ? held.low : mark.low,
      at: Math.max(held.at, mark.at),
    });
  };

  /**
   * Every heads file of both folders named at or after `since`, not read yet, each under its own folder's key: the
   * newest name read, for the next pass to look back from once this one has ended whole.
   */
  const readHeads = async (since: number, gained: Set<string>): Promise<number | undefined> => {
    let newest: number | undefined;
    for (const [at, kind] of [
      [folder('heads'), HEADS_FILE],
      [folder('operator'), OPERATOR_FILE],
    ] as const) {
      for await (const file of namesOf(timed, at)) {
        if (file.at < since) break;
        if (namesRead.has(file.name)) continue;
        if (!(await takeFile(store, file, kind, gained))) {
          alarm('spoiled', { folder: at, fileAt: new Date(file.at).toISOString() });
        }
        judgeLanding(at, file);
        namesRead.add(file.name);
        newest = Math.max(newest ?? file.at, file.at);
      }
    }
    return newest;
  };

  const refreshOnce = async (): Promise<Refreshed> => {
    // When it began by this process's clock, as freshAt gives it; `began`, by the store's, as file names go.
    const beganHere = localNow();
    const gained = new Set<string>();
    try {
      await askClock();
      const began = now();
      let newest: number | undefined;
      if (state === 'read') {
        // From the older of the newest file the last whole pass read and when it began, so nothing it didn't reach is
        // passed over, less the lag for a file named earlier that landed later.
        const from = Math.min(headsFrom ?? began.getTime(), wholeFrom ?? began.getTime());
        newest = await readHeads(from - LAG_MS, gained);
      } else {
        const snapshot = await readSnapshot(gained);
        if (snapshot !== undefined) lastSnapshotAt = snapshot;
        newest = await readHeads(
          snapshot === undefined ? began.getTime() - NO_SNAPSHOT_READ_BACK_MS : snapshot - LAG_MS,
          gained,
        );
        state = 'read';
      }
      // Ended whole: only now does the next pass look back from here.
      if (newest !== undefined) headsFrom = Math.max(headsFrom ?? newest, newest);
      wholeFrom = began.getTime();
      // Names older than any later look back reaches need no remembering.
      const keepFrom = Math.min(headsFrom ?? 0, wholeFrom) - 2 * LAG_MS;
      for (const name of namesRead) {
        const countdown = name.slice(name.lastIndexOf('/') + 1, name.lastIndexOf('/') + 14);
        if (timeOfName(countdown) < keepFrom) namesRead.delete(name);
      }
      readFailingSince = undefined;
      freshAt = beganHere;
      return { chains: [...gained].map(chainOfName), whole: true };
    } catch (error) {
      failed('read', error);
      return { chains: [], whole: false };
    }
  };

  /** A refresh begun, kept as the one under way until it ends. */
  const startRefresh = (): Promise<Refreshed> => {
    const run: Promise<Refreshed> = refreshOnce().finally(() => {
      if (refreshing === run) refreshing = undefined;
    });
    refreshing = run;
    return run;
  };

  /** Each refresh's chains, as refresh answers them: one promise a refresh. */
  const chainsOf = new WeakMap<Promise<Refreshed>, Promise<readonly Chain[]>>();

  /** The next refresh that starts after this call. */
  const nextRefresh = (): Promise<Refreshed> => {
    if (refreshing === undefined) return startRefresh();
    // The one under way may have begun before this call: the next, shared by every caller meanwhile.
    refreshNext ??= refreshing.then(() => {
      refreshNext = undefined;
      return startRefresh();
    });
    return refreshNext;
  };

  /** Every head held, and what was let go for memory or released, as the lines of a snapshot named at `at`. */
  const snapshotLines = (at: number): string[] => {
    const lines: string[] = [];
    for (const name of held.keys()) {
      for (const head of standing(name)) lines.push(lineText(name, datedBy(head, at)));
    }
    // What was let go for memory, so a start from it still holds those chains as missing heads (never quietly).
    for (const [name, mark] of lost) {
      if (!beyond(name)) continue;
      lines.push(lostText(name, datedBy(mark, at)));
      for (const print of printsOf(name)) lines.push(compactText(name, 'x', datedBy(print, at)));
    }
    for (const name of [...released.keys()]) {
      for (const one of releasedOf(name)) lines.push(compactText(name, 'r', datedBy(one, at)));
    }
    for (const name of [...bases.keys()]) {
      for (const base of basesOf(name)) lines.push(baseText(name, datedBy(base, at)));
    }
    return lines;
  };

  /** The whole held, as a snapshot, where this copy leads, hourly and only after a whole read. */
  const snapshotOnce = async (): Promise<void> => {
    if (snapshots === undefined || writes?.() !== true || state !== 'read' || !changedSinceSnapshot) return;
    const at = now().getTime();
    const since = lastSnapshotAt === undefined ? Infinity : at - lastSnapshotAt;
    const early = prunedSinceSnapshot >= PRUNED_FOR_A_SNAPSHOT && since >= SNAPSHOT_AT_MOST_MS;
    if (since < SNAPSHOT_EVERY_MS && !early) return;
    try {
      const name = fileName(folder('snapshots'), at);
      await snapshots.put(name, await signedFile(keys, SNAPSHOT_FILE, name, epoch, snapshotLines(at)));
      lastSnapshotAt = at;
      changedSinceSnapshot = false;
      prunedSinceSnapshot = 0;
    } catch (error) {
      failed('write', error);
    }
  };

  /** heldTo (the interface): the heads held and the compact ones, the highest first, at most `most`. */
  const heldTo = (chain: Chain, most = Number.POSITIVE_INFINITY): readonly WitnessedHead[] => {
    const name = nameOf(chain);
    const heads = standing(name, most);
    // Most chains hold no compact head: their pending heads as they are, no merge.
    const compact = compactOf(name);
    if (compact.length === 0) return heads;
    return [...heads, ...compact].toSorted((one, other) => (one.seq > other.seq ? -1 : 1)).slice(0, most);
  };

  return Object.freeze({
    note,
    settled,
    now(chain: Chain, head: { readonly seq: bigint; readonly hash: Buffer }): Promise<void> {
      note(chain, head, 'now');
      return settled([chain]);
    },
    soon(chain: Chain, head: { readonly seq: bigint; readonly hash: Buffer }): void {
      note(chain, head, 'soon');
    },
    pending(chain: Chain, most?: number): readonly WitnessedHead[] {
      return standing(nameOf(chain), most);
    },
    witnessed(chain: Chain, most?: number): readonly WitnessedHead[] {
      return heldTo(chain, most).map((head) => ({ ...head, at: head.at - offset }));
    },
    async flush(): Promise<void> {
      await write(true);
      await snapshotOnce();
    },
    async drained(): Promise<void> {
      // Every head waiting made a `now` one, so a failed Put is tried again, backing off, within the wait.
      queue = queue.map((queued) => (queued.klass === 'now' ? queued : promoted(queued)));
      await write(true);
      await settled([...unconfirmed.keys()].map(chainOfName));
    },
    refresh(): Promise<readonly Chain[]> {
      // One promise a refresh, shared by every caller of it, as before refreshWhole.
      const run = nextRefresh();
      const chains = chainsOf.get(run) ?? run.then(({ chains: gained }) => gained);
      chainsOf.set(run, chains);
      return chains;
    },
    async refreshWhole(): Promise<boolean> {
      return (await nextRefresh()).whole;
    },
    freshAt: () => freshAt,
    writesSound(): boolean {
      if (headsPutFailing) return false;
      const waitedSince = now().getTime() - waitMs;
      for (const waiting of unconfirmed.values()) {
        for (const { head } of waiting) if (head.at <= waitedSince) return false;
      }
      return true;
    },
    prune(chain: Chain, heads: readonly { readonly seq: bigint; readonly hash: Buffer }[]): void {
      const name = nameOf(chain);
      const list = held.get(name);
      if (list === undefined || heads.length === 0) return;
      // By key, so a probe letting most of a busy chain's heads go stays one pass over each list.
      const going = new Set(heads.map((one) => writtenKey(name, one)));
      const kept = list.filter((one) => !going.has(writtenKey(name, one)));
      // Counted towards the next snapshot, so a restart doesn't confirm them all over again.
      prunedSinceSnapshot += list.length - kept.length;
      if (kept.length !== list.length) changedSinceSnapshot = true;
      setList(name, kept);
    },
    beyondMemory: (chain: Chain): boolean => beyond(nameOf(chain)),
    walkedPast(
      chain: Chain,
      from: bigint,
      to: bigint,
      asked: readonly { readonly seq: bigint; readonly hash: Buffer }[],
    ): boolean {
      const name = nameOf(chain);
      const mark = lost.get(name);
      // Held to every fingerprint, from below the lowest let go to at or past the highest: each place it held was walked
      // and holds the event it did. None known (a mark's lowest 0: its fingerprints went) is below every start: never.
      const wasAsked = (compact: Compact): boolean => asked.some((one) => sameCompact(compact, one));
      if (mark !== undefined && printsOf(name).every(wasAsked) && from < mark.low && to >= mark.seq) {
        lost.delete(name);
        dropPrints(name);
        changedSinceSnapshot = true;
      }
      // Released heads it was held to and passed, linked from the anchor: on the chain, let go.
      const list = releasedOf(name);
      const passed = list.filter((one) => one.seq > from && one.seq <= to && wasAsked(one));
      if (passed.length > 0)
        setReleased(
          name,
          list.filter((one) => !passed.includes(one)),
        );
      return beyond(name);
    },
    fingerprints(chain: Chain): readonly { readonly seq: bigint; readonly hash: Buffer }[] {
      return compactOf(nameOf(chain)).map(({ seq, hash }) => ({ seq, hash }));
    },
    heldTo,
    baseBelow(chain: Chain, seq: bigint): { readonly seq: bigint; readonly hash: Buffer } | undefined {
      let best: Compact | undefined;
      for (const base of basesOf(nameOf(chain)))
        if (base.seq <= seq && (best === undefined || base.seq > best.seq)) best = base;
      return best === undefined ? undefined : { seq: best.seq, hash: best.hash };
    },
    release(chain: Chain, heads: readonly { readonly seq: bigint; readonly hash: Buffer }[]): void {
      const name = nameOf(chain);
      const list = held.get(name);
      if (list === undefined || heads.length === 0) return;
      // Only above an anchor the log holds whole, kept as their base: with none known, nothing is released.
      const anchored = keepBase(name);
      if (anchored === undefined) return;
      const going = new Set(heads.map((one) => writtenKey(name, one)));
      const room = Math.max(0, mostPrints - printCount);
      const leaving = list.filter((one) => one.seq > anchored && going.has(writtenKey(name, one))).slice(0, room);
      if (leaving.length === 0) return;
      setReleased(name, [...releasedOf(name), ...leaving.map(({ seq, hash, at }) => ({ seq, hash, at }))]);
      setList(
        name,
        list.filter((one) => !leaving.includes(one)),
      );
    },
    crowded(most: number): readonly Chain[] {
      return [...held]
        .filter(([name, list]) => name !== 'platform' && list.length > 1)
        .toSorted((one, other) => other[1].length - one[1].length)
        .slice(0, most)
        .map(([name]) => chainOfName(name));
    },
    useAnchors(given: WitnessAnchors): void {
      anchors = given;
    },
    state: () => state,
  });
}

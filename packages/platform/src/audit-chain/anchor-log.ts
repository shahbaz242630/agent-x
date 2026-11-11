// The chains' anchors kept apart from the database (4D2e E, PL-58): every anchor
// the check signs goes to the write-once store, where someone with the database's
// keys can't reach it, so a chain wound back shows across a restart too. Tx A
// still reads this process's memory, with no trip.
//
// Files, gzipped lines, each ending in a closing line, named so the newest lists first, under an epoch a
// sanctioned restore of the whole database moves on (AGENTX_ANCHOR_EPOCH):
//   e<epoch>/deltas/<inverted-ms>-<id>     what moved, each minute of a run and at its end
//   e<epoch>/snapshots/<inverted-ms>-<id>  every chain's anchor, hourly
// A restart reads the newest snapshot and every delta since: at the default
// interval, 2 lists and about 13 gets, or about 35 where every run goes its whole
// four minutes (anchor-check.ts). Each run then reads again whatever
// another process wrote, so a copy that takes the lease back holds what the
// one before it found. Nothing is written if nothing moved.
//
// Every line is signed with the `audit-anchor` key for its epoch, and every file ends with a
// signed closing line naming the file, its epoch and how many lines it holds, so
// an empty file or signed lines copied under a new name can't pass for one of ours.
// A line that fails is skipped and is the alarm, never a hold; so is a file with no
// closing line for its own name, though its sound lines still count, as each is
// signed and the highest place wins. A snapshot with either wrong can't stand for
// the whole, or the chains on those lines would read as new: the read goes back to
// the last with nothing wrong and every delta since, and if none is left (a key
// version gone, say), the store reads as unreadable, so nothing is anchored afresh.
// Its moves that no delta holds, as a snapshot due takes what moved in place of a
// delta, are lost with it: those chains read one run behind, and a wind-back inside
// that gap passes, with the spoiled file's alarm raised. In a delta, the chain falls
// back on the anchor before it; a chain whose first anchor that line was is anchored
// afresh, at most an hour's comparing lost, and the alarm says so. Two lines at one
// place with different hashes are the alarm too: the older is kept, and the chain's
// own check then says which it holds. A name dated past the clock is passed over and
// is the alarm, so it can't hide later files. Every chain in the store counts as
// seen, so an organisation taken off the list and the record is still missed.
//
// A chain's finished full pass is a line of its own (`k:"p"`, 4D2e E7, its time when that pass began), and so is the
// place a pass under way has reached (`k:"u"`, with when its pass began, `b`, and since when one was owed), each signed
// under its own label: the newest of each kept, written with what moved and in every snapshot, so a restart goes on with
// the chains passed longest ago, and from where a pass had got to. A place reached is dropped once a pass that began at
// or after its own has finished.
//
// Signed lines stand, and the highest place wins, so they count as they are read. A chain
// this process holds moves on at once, even if the read then fails, or the file turns out
// broken: its line is signed and higher. A check under way as that happens can't be compared
// with what landed, so it says nothing and goes again. A chain new to this process waits
// for the whole read, as a part read could look like one never anchored; and the read's marks
// move only with a whole read. What's held and what waits count against memory together.
//
// A rebase (rebase.ts, 4D2e E11) is a file of its own, under `e<epoch>/rebases/`, signed with the
// operator's `audit-rebase` key, which this process checks with the public half alone. Every read
// takes the rebases first, all of them each read, as they are few: the newest of a chain stands in
// for its anchor where that is older, and every anchor or pass place of that chain dated before it is
// passed over, here and in every file read after, so a restart can't bring the old one back. A
// snapshot leaves a chain still at its rebase out, as the rebase's own file holds it; the check then
// signs it again as its own (anchor-check.ts). One badly signed, or not a rebase file, is the alarm,
// once a process; one dated past the clock waits, the alarm each read until its time.
//
// The sharded store (PL-65 PR2, shards.ts): a process this version runs moves the store on to it at its first write after
// a whole read (`cutOver`, the API's): the signed cutover marker first (cutover.ts), then every file in the shards, each
// shard's first a snapshot. Until the record that the migration is done is there, a read takes the old files and every
// shard's alike, the highest place winning as ever: a shard with no sound snapshot of its own stands on the old files.
// The record is written once a read begun an hour past the marker has found every shard holding chains with a snapshot
// made since it last read an old file of theirs, by when every older version has seen the marker and stopped anchoring;
// from then on the old files are read no more, unless a shard's own snapshots are all spoiled back to its first file,
// when they stand under it again. A version from before the marker reads none of the store once it is there (PR0). A
// line in another shard's file is skipped, and the alarm (`misplaced`).
//
// Shards in and out of memory (PL-65 PR3): a log set to (`evicts`, the API's) lets shards go once what it holds passes
// what it can, the least recently used first, down to `EVICT_TO` of it, and only in the sharded layout, where a shard's
// own files hold all of it. Never one with lines waiting to be written or in a file unsent or being made, one pinned
// (`pin`: the anchor check while it compares a chain, so the hand-off's first anchor), the platform chain's, or one
// that stood on the old files. A shard let go is held whole or not at all: its chains say nothing
// (`latest` and the rest give nothing, so Tx A waits, `anchor_pending`), nothing of it is kept (`keep` and the rest are
// refused, said), its lines in any file read are passed over, and no file of it is written, so no snapshot of it can
// ever stand for less than the whole. `pin` reads it again as a first read does, every signature checked again, from
// its folder's own list, its rebases first; one with no sound snapshot of its own stands on the old files, as at a
// first read, and is never let go again. One that can't be read whole or held stays let go: its organisations wait,
// said, and no other's do. Its organisations still count as seen.
//
// So the API identity's token alone (add and read) can raise alarms, and can make payments
// wait after a restart: by more than a day's spoiled snapshots named newer than the last
// sound one, in the old files or in a shard, each until an operator acts. A file is never
// fetched past what this process can hold (`getAtMost`): one larger, or put beyond a plain
// read (its own encryption key, the archive tier, an encoding fetch undoes), is a spoiled
// file, the alarm, and the read goes on. It can't move an anchor back, nor stop a running
// process anchoring. Under `cutover/` and `shards/`, and with a rebase file, it can raise
// the alarm alone: only a marker signed with `audit-anchor`, at its one name, moves the
// store on, and a marker, a record or a rebase is never fetched past 4 KB, one too large
// or unreadable being none. Taking the marker's or the record's name first only makes the
// migration's write of it refused: the alarm, and the migration stops there, payments
// unaffected. Whoever also holds the `audit-anchor` signing key can write anything a file
// may hold, a marker too: nothing here guards against them; nor against whoever holds
// `audit-rebase`.
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { getHeapStatistics } from 'node:v8';
import { createGunzip, createGzip } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Logger } from '../observability/index.ts';
import { OverwriteRefused, type WriteOncePage, type WriteOnceStore } from '../storage/write-once.ts';
import type { Message } from '../keys/message.ts';
import {
  type Anchor,
  type AnchorStore,
  anchorMessage,
  passMessage,
  type PassRecord,
  type Progress,
  progressMessage,
} from './anchor.ts';
import { type Chain, chainName } from './chain.ts';
import { type PackedLines, packedLines, type Taken } from './packed-lines.ts';
import {
  cutoverFile,
  cutoverFolder,
  cutoverName,
  readCutoverFile,
  readShardsDoneFile,
  type RecordRead,
  shardsDoneFile,
  shardsDoneName,
} from './cutover.ts';
import { isCount, MOST_FILE_BYTES, type Rebase, rebaseFolder, readRebaseFile, timeIn } from './rebase.ts';
import {
  bodyHash,
  CHANGES_FILE,
  MOST_CHANGES_BYTES,
  changesFile,
  changesFolder,
  closingV2Message,
  LISTED_FILE,
  readChangesFile,
  SHARD_FILE,
  shardFolder,
  shardHex,
  shardOf,
  SHARDS,
  shardsFolder,
} from './shards.ts';

/** How often every chain's anchor is written whole, where something moved. */
const SNAPSHOT_EVERY_MS = 60 * 60_000;

/** What a file's name counts down from, so the newest lists first: 13 digits until the year 2286. */
const LAST_MS = 9_999_999_999_999;

/** A file's name after its folder: when, counted down, then an ID. Anything else in the folder isn't ours. */
const FILE = /^\d{13}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** How many names a list asks: a restart reads about a dozen deltas, and at most one snapshot unless some are spoiled. */
const SNAPSHOTS_A_PAGE = 5;
const DELTAS_A_PAGE = 100;

/**
 * How many spoiled snapshots a read goes back past, a day's at one an hour. A file spoiled by chance is one or two; a
 * key version gone spoils every one since, and the read must not walk years of them each run before saying so. A file
 * claiming a good name and a time gone by counts, as nothing else tells it from a key gone: so this many added before a
 * restart stop that restart's read, which fails closed, with the alarm for each and the store's alert.
 */
const MOST_SPOILED_SNAPSHOTS = 24;

/**
 * How far past this process's clock a file's name may be dated. Copies' clocks agree far closer than this on Azure; a
 * later name sorts first and counts as the newest, so one any later would hide what's written until its time comes.
 */
const MOST_AHEAD_MS = 5 * 60_000;

/**
 * What this process may hold of the store, a fifth of its heap, the lines held counted at `KEPT_LINE_BYTES` each (and a
 * file's opened bytes against it too: past it a file is read on only to tell a sound one, capacity, from a broken one; it
 * isn't kept). By what the process has, not by a setting the store can outgrow.
 *
 * Measured (S184, Node 24, `--max-old-space-size=768`, whose heap limit reads ~1 GB): a store of N organisations, each an
 * anchor and a finished pass, read whole by a process of its own, an hourly snapshot written and one held unsent while the
 * store is away, the heap and the buffers outside it counted together. The lines packed (packed-lines.ts): 451-515 bytes
 * an organisation held from 100k to 565k (177-241 of it heap), and 79-100 more in the anchor check's `firstSeen`
 * (anchor-check.ts), which takes every organisation in the store: about 310 bytes a line at most. Before, as objects:
 * 3,398 bytes an organisation at 100k, 996 of it heap (S183 measured the heap alone: the 2.4 KB of small buffers outside
 * it were missed, so S183's edge of ~280k would have run the container out before its refusal), and 111 in the check.
 *
 * What bounds it is not what is held but the process's resident memory at its worst, as a read's garbage fills the heap
 * before it is collected: 470 MB at 200k, 936 MB at 423k, 995 MB at 470k, about 2.1 KB an organisation, the same with a
 * snapshot unsent. So a fifth: counted at 340 a line (past the ~310 measured, and past a file line's own length, ~300 and
 * ~335 for a place reached, so a sound snapshot at the edge opens within the same budget in bytes), about 282-296k
 * organisations as the heap limit reads 960 MB-1 GB, ~650 MB resident at the edge's worst for this log and the check's
 * map, leaving the rest of the jobs process room inside the container's 1 GiB. The warning (`NEAR_MEMORY`) comes at half.
 * Moving it further is less garbage per line read, or a smaller heap beside the packed records (PR2 onwards, PL-65).
 */
const heapsFileBytes = (): number => Math.floor(getHeapStatistics().heap_size_limit / 5);

/** What a line held is counted at: about 310 measured with the check's share, rounded up past a file line's own length. */
const KEPT_LINE_BYTES = 340;

/** What a file being made holds of each line it took from a table, until its bytes are made: its chain and its record. */
const TAKEN_LINE_BYTES = 16;

/** What a file made and not yet in the store holds of each line beside its bytes: the line's stamp. */
const UNSENT_LINE_BYTES = 8;

/**
 * How near what is held may come to that before it is said, at each snapshot (hourly): half, so it is said while the
 * organisations can still double, months of growth to add memory or move to the sharded store (PL-65).
 */
const NEAR_MEMORY = 0.5;

/** How far past that a file is read: a million lines of ones signed before, in a file anyone can add, cost little to pack. */
const MOST_READ_PAST = 8;

/** A line past this is no line of ours; they are about 340 bytes. */
const MOST_LINE_BYTES = 4096;

const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SEQ = /^(?:0|[1-9]\d{0,18})$/;
const HASH = /^[0-9a-f]{64}$/;
const ORGANISATION = 'organisation:';

/**
 * Line kinds passed over in a delta or snapshot: a rebase's line, which only ever stands in a file of its own (E11), so
 * one here is no rebase and moves nothing; as before E11, it raises nothing.
 */
const LATER_KINDS: ReadonlySet<unknown> = new Set(['r']);

/** How many names a shard's list asks: its snapshot and the dozen deltas since, at a restart; a few, each run after. */
const SHARD_FILES_A_PAGE = 100;

/**
 * How long after the cutover marker the migration waits before it says it is done (PR2): every older version reads the
 * store each run, sees the marker and anchors no more, far sooner. What one wrote to the old files before that, a read
 * begun after this takes into the shards.
 */
const SETTLE_MS = 60 * 60_000;

/** What a name this process wrote, and has not yet listed past, is counted at against what it can hold. */
const WRITTEN_NAME_BYTES = 160;

/** How many names a list of the changes asks: those of another process since the last run, a few. */
const CHANGES_A_PAGE = 100;

/**
 * At a process's first read, how far back before it the lists of changes are read too, after the walk of every shard:
 * a file a list named may have landed after the walk listed its shard. Past the clocks' widest gap, and a put's time.
 */
const CHANGES_LAG_MS = MOST_AHEAD_MS;

/** How many names a list of changes holds at most: 256, about 15 KB opened, well within what a reader fetches. */
const NAMES_A_LIST = 256;

/** How many lists a write makes at most: 8, 2,048 names, past any number of shard files one write makes. */
const LISTS_A_WRITE = 8;

/** How many shards' folders a read walks again, the hourly walk spread over the runs: all 256 within the hour. */
const WALKS_A_READ = 32;

/**
 * How far below what it can hold a log lets shards go to, once past it (PR3): far enough that the next few lines read
 * don't let another go, near enough that little is read again.
 */
const EVICT_TO = 0.8;

/**
 * What an organisation seen in the store, whose shard is let go, is counted at: its chain's name, and what is last known
 * of it (its place and when it was signed, when its last pass began, when its place was owed), in a map.
 */
const SEEN_NAME_BYTES = 160;

/**
 * What is last known of a chain: its anchored place and when that anchor was signed (PR4: what the anchor check's walk
 * orders and judges lateness by), when its last pass began, and when its place reached was owed.
 */
export interface LastKnown {
  readonly seq?: bigint | undefined;
  readonly anchoredAt?: number | undefined;
  readonly passedAt?: number | undefined;
  readonly placeAt?: number | undefined;
}

/**
 * How many shards read again in an hour say the shards held are too few for the chains in use: more than every shard
 * read once over. Past it, what is read each hour is the whole store again, at about a dozen calls a shard.
 */
const CHURN_RELOADS = SHARDS;

/**
 * A chain's anchored place last known, given an anchor line of it: the highest place wins, as in `merge`, and the same
 * place signed again later (an idle chain checked since) moves its time on.
 */
export const anchoredOf = (was: LastKnown, seq: bigint, at: number): Pick<LastKnown, 'seq' | 'anchoredAt'> => {
  if (was.seq === undefined || seq > was.seq) return { seq, anchoredAt: at };
  if (seq === was.seq) return { seq, anchoredAt: Math.max(was.anchoredAt ?? at, at) };
  return { seq: was.seq, anchoredAt: was.anchoredAt };
};

/** The platform chain's shard: never let go, as more than the anchor check reads its anchor (job-list.ts). */
const PLATFORM_SHARD = shardOf('platform');

/** How many rebase files a list asks: there are a handful in an epoch. */
const REBASES_A_PAGE = 100;

/**
 * How far past this process's clock a rebase may be dated (E11 review): it is dated by the database's clock, which this
 * one keeps near, and a rebase dated ahead sets aside this process's own anchors of the chain until its time comes.
 */
const REBASE_MOST_AHEAD_MS = 20_000;

/** A rebase file's name after its folder: its ID. */
const REBASE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A line's kind: an anchor, or a finished full pass. */
type LineKind = 'a' | 'p' | 'u';

const isLineKind = (kind: unknown): kind is LineKind => kind === 'a' || kind === 'p' || kind === 'u';

type Kind = 'deltas' | 'snapshots';

/** A file that can't be one of ours, found while reading it. */
class BrokenFile extends Error {}

/** A file signed and sound, past what this process can hold. */
class BeyondMemory extends Error {
  readonly kind: Kind;
  readonly fileAt: string;

  constructor(kind: Kind, fileAt: string) {
    super('a sound file too large for this process');
    this.kind = kind;
    this.fileAt = fileAt;
  }
}

export interface AnchorLog extends AnchorStore, PassRecord {
  /** The epoch anchors kept here must be signed for. */
  readonly epoch: number;
  /**
   * Reads what the store holds that this process has not read: all of it, or
   * none of it if any call fails. Never throws: every outcome is logged. One
   * read at a time; a second call joins the first.
   */
  read(): Promise<void>;
  /**
   * Whether the store has been read whole since this process began. Until it
   * has, no chain may be anchored: a first anchor would hide a chain wound back.
   */
  state(): 'unread' | 'read' | 'unreadable';
  /** Says a read failed, or ran out of time: what `read` says of its own failures. */
  readFailed(error: unknown): void;
  /** Every organisation with a chain in the store, by ID: what has been seen. */
  organisations(): readonly string[];
  /** Writes what has moved, trying a file unsent again first. Never throws. One at a time; a second call joins the first. */
  flush(): Promise<void>;
  /** Says a write failed, or ran out of time: what `flush` says of its own failures. */
  writeFailed(error: unknown): void;
  /** When the newest file this process has read or written was named: where another process last left off. */
  lastFileAt(): Date | undefined;
  /**
   * Whether the chain's shard is held whole (PL-65 PR3): until it is, nothing of the chain is said or kept. Always, in a
   * log that never lets a shard go; whether the store is read at all is `state`.
   */
  holds(chain: Chain): boolean;
  /**
   * Holds the chain's shard, read again first if it was let go (once the store has been read whole): never let go
   * until the release given is called. Nothing, if it can't be read whole; the reason said.
   */
  pin(chain: Chain): Promise<(() => void) | undefined>;
  /**
   * What is last known of the chain, held or let go, with no read (PR3): what a caller sizing or ordering work by every
   * chain goes by, never reading a shard back for it. Nothing for a chain never seen.
   */
  lastKnown(chain: Chain): LastKnown | undefined;
  /**
   * For a walk about to read a shard back (PR4): near the budget, what waits to be written is written now, so the shards
   * it holds may go. A walk signing each chain again as it passes leaves a line waiting in every shard behind it, none of
   * which may go until written, and the next shard would find no room, its organisations waiting until the next write.
   * Nothing while writes are failing (each would wait out the store), or with room enough. Never throws.
   */
  roomToReadBack(): Promise<void>;
  /**
   * For a walk (PR4): it has gone past the chain's shard, and won't want it again this round. Such a shard goes first when
   * room is needed, the one passed last before those passed earlier: in a walk that repeats, the shard passed longest
   * ago is the one it reaches soonest, so least-recently-used would let go exactly what comes next. Used again, it is as
   * any other. Nothing in a log that holds every shard.
   */
  walkedPast(chain: Chain): void;
  /**
   * The chain's anchor where its shard is held, as `latest`, without counting the shard as used (PR4): for the run's
   * probe, which reads every held anchor in the list's order and would otherwise reorder what goes first.
   */
  heldAnchor(chain: Chain): Anchor | undefined;
  /**
   * What is held, by this log's count against what it can hold; the records its tables really use, and the bytes their
   * buffers take; and how many shards are held.
   */
  memoryHeld(): {
    readonly bytes: number;
    readonly mostBytes: number;
    readonly records: number;
    readonly allocated: number;
    readonly shards: number;
    /** Shards pinned now, and organisations known only as let go. */
    readonly pinned: number;
    readonly elsewhere: number;
  };
}

/** A file made, not yet known to be in the store. Tried again under the same name, with the same bytes. */
interface Unsent {
  readonly kind: Kind;
  /** Its shard, for a file in the sharded layout; and for a snapshot made while moving, the stamp it was taken at. */
  readonly shard?: number;
  readonly seedStamp?: number;
  readonly name: string;
  readonly bytes: Buffer;
  /** How many of its lines are anchors, finished full passes and passes' places reached, in that order. */
  readonly lines: number;
  readonly passes: number;
  readonly places: number;
  /** Each line's stamp, in the file's order, and any line its own text can't give back, by its place there. */
  readonly stamps: Float64Array;
  readonly kept: ReadonlyMap<number, Anchor | Progress>;
}

/** Which kind of line a file this process made holds at a place in it: none past its lines, at its closing line. */
const sectionOf = (file: Unsent, at: number): LineKind | undefined => {
  if (at < file.lines) return 'a';
  if (at < file.lines + file.passes) return 'p';
  return at < file.lines + file.passes + file.places ? 'u' : undefined;
};

/**
 * Whether a line's own text reads back as the same line (`signedLineOf`), every field and nothing more: so an unsent file
 * needs only its bytes to send its lines again. Every line this process holds does, signed here or read from the store;
 * anything else is kept whole beside the file.
 */
const readsBack = (line: Anchor | Progress, kind: LineKind): boolean =>
  CHAIN.test(line.chain) &&
  SEQ.test(line.seq.toString()) &&
  line.hash.length === 32 &&
  isCount(line.macKeyVersion) &&
  isCount(line.keyVersion) &&
  timeIn(line.at.toISOString()) !== undefined &&
  Object.keys(line).length === (kind === 'u' ? 8 : 7) &&
  (kind !== 'u' || (isPlace(line) && timeIn(line.began.toISOString()) !== undefined));

const tooManySpoiled = (spoiled: number): string =>
  `no snapshot with every line sound, in the ${String(spoiled)} read: is an audit-anchor key version missing?`;

const countedDown = (ms: number): string => String(LAST_MS - ms).padStart(13, '0');

/** The time a file's name counts down from, as a time a person can look for in the store's own logs. */
const whenNamed = (countdown: string): string => new Date(LAST_MS - Number(countdown)).toISOString();

const lineOf = (anchor: Anchor | Progress, k: LineKind): string =>
  JSON.stringify({
    k,
    chain: anchor.chain,
    seq: anchor.seq.toString(),
    hash: anchor.hash.toString('hex'),
    mk: anchor.macKeyVersion,
    at: anchor.at.toISOString(),
    ...('began' in anchor ? { b: anchor.began.toISOString() } : {}),
    kv: anchor.keyVersion,
    sig: anchor.signature.toString('base64'),
  });

/** Whether a line read is a pass's place, which says when its pass began. */
const isPlace = (line: Anchor | Progress): line is Progress => 'began' in line && line.began instanceof Date;

/** A parsed line of a kind, if it is one in every field, and the message its signature must cover. */
function signedLineOf(
  kind: LineKind,
  fields: Record<string, unknown>,
  epoch: number,
): { readonly line: Anchor | Progress; readonly message: Message } | undefined {
  const anchor = anchorFrom(fields);
  if (anchor === undefined) return undefined;
  if (kind === 'a') return { line: anchor, message: anchorMessage(anchor.chain, anchor, anchor.at, epoch) };
  if (kind === 'p') return { line: anchor, message: passMessage(anchor.chain, anchor, anchor.at, epoch) };
  const began = timeIn(fields.b);
  if (began === undefined) return undefined;
  return {
    line: { ...anchor, began },
    message: progressMessage(anchor.chain, anchor, anchor.at, epoch, began),
  };
}

/** The anchor a parsed line says, if it is one in every field; its signature is checked after. */
function anchorFrom(line: Record<string, unknown>): Anchor | undefined {
  const { chain, seq, hash, mk, at, kv, sig } = line;
  if (typeof chain !== 'string' || !CHAIN.test(chain)) return undefined;
  if (typeof seq !== 'string' || !SEQ.test(seq)) return undefined;
  if (typeof hash !== 'string' || !HASH.test(hash)) return undefined;
  if (!isCount(mk) || !isCount(kv) || typeof sig !== 'string') return undefined;
  const when = timeIn(at);
  if (when === undefined) return undefined;
  return {
    chain,
    seq: BigInt(seq),
    hash: Buffer.from(hash, 'hex'),
    macKeyVersion: mk,
    at: when,
    keyVersion: kv,
    signature: Buffer.from(sig, 'base64'),
  };
}

/** What a file's closing line signs: which file, in which epoch, of how many lines. */
const closingMessage = (name: string, epoch: number, lines: number): Message => [
  'audit-anchor-file',
  name,
  String(epoch),
  String(lines),
];

/** Whether the signature is the one for the message. A version this process doesn't hold is simply wrong. */
function isSigned(keys: KeyProvider, keyVersion: number, message: Message, signature: Buffer): boolean {
  try {
    return keys.verifySignature('audit-anchor', keyVersion, message, signature);
  } catch (error) {
    if (error instanceof KeyError) return false;
    throw error;
  }
}

function parsed(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch {
    // Not JSON is one more line that isn't an anchor; the caller's alarm counts it.
    return undefined;
  }
}

const kindOf = (fields: unknown): unknown =>
  typeof fields === 'object' && fields !== null && 'k' in fields ? fields.k : undefined;

/**
 * Whether a parsed line closes this file: signed for its own name, its epoch and as many lines as came before it, as
 * this read finds them. The line says them too, for someone reading the file; the signature is what's relied on.
 */
function closes(keys: KeyProvider, fields: unknown, name: string, epoch: number, lines: number): boolean {
  if (kindOf(fields) !== 'c') return false;
  const said = fields as Record<string, unknown>;
  if (!isCount(said.kv) || typeof said.sig !== 'string') return false;
  return isSigned(keys, said.kv, closingMessage(name, epoch, lines), Buffer.from(said.sig, 'base64'));
}

/**
 * A file's lines as it opens, never the whole as one string: V8 can't hold one much past 1.5 million chains' worth. Each
 * line is signed on its own and the closing line signs how many came before, so nothing needs the file whole to be checked.
 */
async function* linesIn(bytes: Buffer, opened: { bytes: number }): AsyncGenerator<string> {
  const opening = createGunzip();
  opening.end(bytes);
  let rest: Buffer = Buffer.alloc(0);
  for await (const chunk of opening as AsyncIterable<Buffer>) {
    opened.bytes += chunk.length;
    const joined = rest.length > 0 ? Buffer.concat([rest, chunk]) : chunk;
    let from = 0;
    for (let end = joined.indexOf(10, from); end >= 0; end = joined.indexOf(10, from)) {
      yield joined.toString('utf8', from, end);
      from = end + 1;
    }
    rest = joined.subarray(from);
    if (rest.length > MOST_LINE_BYTES) throw new BrokenFile('a line longer than any of ours');
  }
  if (rest.length > 0) yield rest.toString('utf8');
}

/**
 * How many of a file's lines failed, whether it closes for its own name, and whether it went past `mostBytes`: then its first
 * wrong line, or an empty one, or going on too far, is thrown. Each sound line goes to `keep` as it is read, up to that point,
 * so no file is ever held whole: each is signed on its own and counts as soon as it is found. Lines of a later piece's kinds
 * are neither sound nor failed.
 */
async function readFile(
  keys: KeyProvider,
  {
    bytes,
    name,
    epoch,
    mostBytes,
    belongs,
  }: {
    bytes: Buffer;
    name: string;
    epoch: number;
    mostBytes: number;
    /** A shard's file: whether a chain is that shard's. Its lines are trusted whole if its version 2 closing line holds. */
    belongs?: ((chain: string) => boolean) | undefined;
  },
  keep: (anchor: Anchor | Progress, kind: LineKind) => void,
) {
  const whole = belongs !== undefined && (await closesWhole(keys, { bytes, name, epoch, mostBytes }));
  const opened = { bytes: 0 };
  let bad = 0;
  let misplaced = 0;
  let body = 0;
  const judged = (fields: unknown): void => {
    body += 1;
    const kind = kindOf(fields);
    if (LATER_KINDS.has(kind)) return;
    const lineKind = isLineKind(kind) ? kind : undefined;
    const read = lineKind === undefined ? undefined : signedLineOf(lineKind, fields as Record<string, unknown>, epoch);
    if (
      lineKind === undefined ||
      read === undefined ||
      (!whole && !isSigned(keys, read.line.keyVersion, read.message, read.line.signature))
    ) {
      bad += 1;
    } else if (belongs !== undefined && !belongs(read.line.chain)) {
      // Signed, but not this shard's: a line copied in from another shard's file, which says nothing here.
      misplaced += 1;
    } else if (opened.bytes <= mostBytes) {
      keep(read.line, lineKind);
    }
  };
  let last: unknown;
  let any = false;
  for await (const line of linesIn(bytes, opened)) {
    if (opened.bytes > mostBytes && (bad + misplaced > 0 || line === '' || opened.bytes > mostBytes * MOST_READ_PAST)) {
      throw new BrokenFile('past what can be held, and not a sound file');
    }
    if (line !== '') {
      if (any) judged(last);
      last = parsed(line);
      any = true;
    }
  }
  // Only the last line can close: one anywhere else is one more line that fails.
  const closing = kindOf(last) === 'c';
  if (any && !closing) judged(last);
  const past = opened.bytes > mostBytes;
  return { bad, misplaced, past, closed: whole || (closing && closes(keys, last, name, epoch, body)) };
}

/**
 * Whether a shard's file ends in a version 2 closing line signed for its own name, its epoch, its count of lines and the
 * hash of every byte before it: then each line in it is as signed as that line, and needs no check of its own. A pass of
 * its own over the file, holding a line at a time. Anything else is no, and the file is read a line at a time, as the
 * old files are, which says what is wrong with it.
 */
async function closesWhole(
  keys: KeyProvider,
  { bytes, name, epoch, mostBytes }: { bytes: Buffer; name: string; epoch: number; mostBytes: number },
): Promise<boolean> {
  const body = bodyHash();
  const opened = { bytes: 0 };
  let last: string | undefined;
  try {
    for await (const line of linesIn(bytes, opened)) {
      if (opened.bytes > mostBytes * MOST_READ_PAST) return false;
      if (last !== undefined) body.add(last);
      last = line;
    }
  } catch {
    // Not gzip, or a line longer than any of ours: the read a line at a time says so.
    return false;
  }
  const fields = parsed(last ?? '');
  if (kindOf(fields) !== 'c') return false;
  const said = fields as Record<string, unknown>;
  if (said.v !== 2 || !isCount(said.kv) || typeof said.sig !== 'string') return false;
  const message = closingV2Message(name, epoch, body.lines, body.digest());
  return isSigned(keys, said.kv, message, Buffer.from(said.sig, 'base64'));
}

/** Gzipped lines, made a line at a time: the whole as one string has the same limit as on the way in. */
async function gzippedLines(lines: Iterable<string>): Promise<Buffer> {
  const made: Buffer[] = [];
  await pipeline(Readable.from(lines), createGzip(), async (gzipped: AsyncIterable<Buffer>) => {
    for await (const chunk of gzipped) made.push(chunk);
  });
  return Buffer.concat(made);
}

/** The anchors held durable, read and written through `store`, and in memory for Tx A. */
export function createAnchorLog({
  store,
  keys,
  logger,
  now,
  epoch,
  alertAfterMs,
  mostFileBytes = heapsFileBytes(),
  cutOver = false,
  evicts = false,
}: {
  readonly store: WriteOnceStore;
  readonly keys: KeyProvider;
  readonly logger: Logger;
  readonly now: () => Date;
  /** AGENTX_ANCHOR_EPOCH: a sanctioned restore of the whole database starts a new one. */
  readonly epoch: number;
  /** How long reads once the store is read, or writes, may fail before that is the alert, not just a warning. */
  readonly alertAfterMs: number;
  /** What this process may hold of the store, and open of one file (a fifth of its heap), unless a test says. */
  readonly mostFileBytes?: number;
  /**
   * Whether this process moves the store on to the sharded layout (PL-65 PR2) at its first write after a whole read: the
   * API's jobs, which anchor. Whatever this says, a store moved on is read and written as the shards.
   */
  readonly cutOver?: boolean;
  /**
   * Whether shards are let go past what this process can hold (PL-65 PR3): the API's, whose callers ask `holds` and
   * `pin`. The operator's tools read a chain's anchor after a read and would take nothing for none: theirs never are.
   */
  readonly evicts?: boolean;
}): AnchorLog {
  const folder = (kind: Kind): string => `e${String(epoch)}/${kind}/`;
  // Every table packed (packed-lines.ts, PL-65): each line a record, not an object. Where the same object stood in two
  // tables, as `keep` puts it in `anchors` and `pending`, the same stamp does now: a file made says what it wrote by it.
  let stamps = 0;
  const stamped = (): number => (stamps += 1);
  const anchors = packedLines<Anchor>(false);
  // What has moved since it was last written: one line a chain at most, however long the store stays away.
  const pending = packedLines<Anchor>(false);
  // Each chain's newest line of each side kind, and those not written yet, the same way.
  const sides = { p: packedLines<Anchor>(false), u: packedLines<Progress>(true) };
  const pendingSides = { p: packedLines<Anchor>(false), u: packedLines<Progress>(true) };
  // Each chain's newest rebase, the rebase files read already, and the anchors that are a rebase's, not signed here:
  // marked in `anchors`, and each copy of one `latest` gives out, so a copy kept back is still a rebase's.
  const rebases = new Map<string, Rebase>();
  const rebaseFilesRead = new Set<string>();
  // Whether a file at the marker's name that is none, another name under `cutover/`, a name under `shards/` with no
  // marker, and a file at the done record's name that is none, have been said: each the alarm once a process.
  const said = { marker: false, cutover: false, shards: false, done: false };
  // Which layout the store is in, as this process last read it (PL-65 PR2): the old files alone; moved on, the old files
  // and the shards read together; or the migration done, the shards alone. Files are never taken away, so it only moves on.
  let layout: 'old' | 'moving' | 'sharded' = 'old';
  // When the marker was signed, and whether a whole read begun `SETTLE_MS` after it has been: then the migration can end.
  let markerAt: Date | undefined;
  let settledRead = false;
  // The marker's or the record's name held by something else: said, and the migration goes no further in this process.
  let migrationStopped = false;
  // When the shards' writes last looked at how near the edge what is held is.
  let nearSaidAt: number | undefined;
  // When this process first walked every shard's folder: at its first read of the shards. After it each shard is walked
  // again hourly, a few at each read (`WALKS_A_READ`), so a file written and never listed (its writer stopped between
  // the two) is found within the hour, and no read has all 256 to do. Then: the newest list of changes it read; the lists
  // that were none, passed over without a fetch; the shard files a list named and the store did not give (looked for an
  // hour); the shard files read since each shard's last walk, which its next walk passes over; and this process's own
  // files no list it wrote names yet, by when each was named, carried into each list until one lands.
  let walkedAt: number | undefined;
  const refusedChanges = new Set<string>();
  const readSinceWalk = new Map<string, number>();
  const unlisted = new Map<string, number>();
  // Named by a list and not given by the store for an hour: by shard, the oldest such name's time, until the shard's
  // next walk, which reaches back past it.
  const lost = new Map<number, number>();
  // The newest moment a list of changes read was named at, and every list of that moment read: two made in the same
  // millisecond sort by their IDs, not by when, so one named then is passed over only if it is known.
  let changesFrom: { readonly countdown: string; readonly names: Set<string> } | undefined;
  const awaited = new Map<string, number>();
  /**
   * Each shard's marks, as the old files' `deltasFrom` and `snapshotFrom` are: the newest sound file listed, and the newest
   * sound snapshot read or written, counted down. While moving: the stamp a snapshot of its own was taken at, and the
   * stamp given when a read last took a line of it from the old files. Its snapshot stands for it once the first is later.
   */
  const shardMarks = Array.from({ length: SHARDS }, () => ({
    from: undefined as string | undefined,
    snapshotFrom: undefined as string | undefined,
    seeded: 0,
    old: 0,
    walkedAt: undefined as number | undefined,
  }));
  const seeded = (shard: number): boolean => {
    const marks = shardMarks[shard];
    return marks !== undefined && marks.seeded > marks.old;
  };
  const fromRebase = new WeakSet<Anchor>();
  // Shards in and out of memory (PR3). Which are held whole; when each was last used, by a count; how many pins each has;
  // those that stood on the old files; those a file is being made of; the shard being read again, if
  // any; each shard's read again under way; and the organisations seen in the store whose shard was let go.
  const resident = Array.from({ length: SHARDS }, () => true);
  const usedAt = new Float64Array(SHARDS);
  const pins = new Uint32Array(SHARDS);
  let uses = 0;
  const bareShards = new Set<number>();
  const making = new Set<number>();
  let loading: number | undefined;
  const loads = new Map<number, Promise<void>>();
  const seenElsewhere = new Map<string, LastKnown>();
  /** A line of an organisation whose shard is let go, as what is last known of it: the newest of each kind. */
  const elsewhere = (chain: string, kind: LineKind, { seq, at }: { seq: bigint; at: Date }): void => {
    if (!chain.startsWith(ORGANISATION)) return;
    const was = seenElsewhere.get(chain) ?? {};
    const ms = at.getTime();
    const later = (known: number | undefined): number => Math.max(known ?? ms, ms);
    if (kind === 'a') seenElsewhere.set(chain, { ...was, ...anchoredOf(was, seq, ms) });
    else if (kind === 'p') seenElsewhere.set(chain, { ...was, passedAt: later(was.passedAt) });
    else seenElsewhere.set(chain, { ...was, placeAt: later(was.placeAt) });
  };
  /** Whether a shard is held whole. */
  const isResident = (shard: number): boolean => resident[shard] === true;
  /** A chain's shard: as a table holding it keeps it, else worked out. */
  const shardOfChain = (chain: string): number =>
    anchors.shardOf(chain) ?? sides.p.shardOf(chain) ?? sides.u.shardOf(chain) ?? shardOf(chain);
  /** Whether a chain's shard is held whole, and so what is held of it says all the store does: used, if so. */
  const visible = (chain: string): boolean => {
    if (!evicts) return true;
    const shard = shardOfChain(chain);
    if (!isResident(shard)) return false;
    uses += 1;
    usedAt[shard] = uses;
    return true;
  };
  /** Whether a line of this shard read now is taken in: held; while one is read again, that one alone. */
  const takes = (shard: number): boolean => !evicts || (loading === undefined ? isResident(shard) : loading === shard);
  /** Whether a line may be kept for this chain: its shard held whole. Anything else said, and nothing kept. */
  const keepable = (chain: string, kind: LineKind): boolean => {
    if (visible(chain)) return true;
    const organisation = chain.startsWith(ORGANISATION);
    const log = organisation ? logger.child({ orgId: chain.slice(ORGANISATION.length) }) : logger;
    log.warn('audit.anchor_shard_not_held', { kind, shard: shardHex(shardOfChain(chain)) });
    return false;
  };
  /** A chain's anchor, a copy: one that is a rebase's is known to `keep` by it as such, as the one object was before. */
  const latestUnmarked = (chain: string): Anchor | undefined => {
    const anchor = anchors.get(chain);
    if (anchor !== undefined && anchors.marked(chain)) fromRebase.add(anchor);
    return anchor;
  };
  const latest = (chain: string): Anchor | undefined => (visible(chain) ? latestUnmarked(chain) : undefined);
  // How many shards a walk has gone past, and when each held was last passed, by that count (PR4): those passed go
  // first, the one passed last first, then the rest least recently used. A repeating walk wants next what it passed
  // longest ago, so this keeps what it will reach soonest.
  let walkedPasses = 0;
  const walkPassedAt = new Float64Array(SHARDS);
  /** Whether the chain's newest rebase is later than `at`: whatever was dated then is passed over. */
  const rebasedAfter = (chain: string, at: Date): boolean => {
    const rebase = rebases.get(chain);
    return rebase !== undefined && rebase.at > at;
  };
  /** How many lines this process holds, against what it can: anchors and the side lines alike. */
  const linesHeld = (): number => anchors.size + sides.p.size + sides.u.size + rebases.size;
  /** How many organisations have an anchor here: counted, not listed, as a snapshot is made. */
  const organisationsHeld = (): number => {
    let count = 0;
    for (const name of anchors.keys()) if (name.startsWith(ORGANISATION)) count += 1;
    return count;
  };
  /** A place reached by a pass no later than the chain's last finished one: nothing goes on from it. */
  const overtaken = (line: Progress): boolean => {
    const pass = sides.p.get(line.chain);
    return pass !== undefined && pass.at >= line.began;
  };
  let unsent: Unsent | undefined;
  // Lines a file being made has taken from the tables, until its bytes are made.
  let takenLines = 0;
  /**
   * What a file being made, and one unsent, hold beside the tables' own records, in bytes. The unsent file's own gzipped
   * bytes (~144 a line: random hashes barely compress) aren't counted: one file is unsent at a time, so they are bounded
   * by one snapshot, and the edge measured by resident memory (S184) includes them.
   */
  const besideLines = (): number =>
    takenLines * TAKEN_LINE_BYTES +
    (unsent?.stamps.length ?? 0) * UNSENT_LINE_BYTES +
    (written.size + awaited.size + refusedChanges.size + readSinceWalk.size + unlisted.size + lost.size) *
      WRITTEN_NAME_BYTES +
    seenElsewhere.size * SEEN_NAME_BYTES;
  /** What is held, by the budget's count, with `staging` lines a read has yet to merge. */
  const heldBytes = (staging: number): number => (linesHeld() + staging) * KEPT_LINE_BYTES + besideLines();
  /** A line this process made, read back from its own text: `readsBack` held when the file was made, so it does. */
  const readBack = (kind: LineKind, text: string): Anchor | Progress => {
    const read = signedLineOf(kind, parsed(text) as Record<string, unknown>, epoch);
    if (read === undefined) throw new BrokenFile('a line this process made does not read back');
    return read.line;
  };

  let state: 'unread' | 'read' | 'unreadable' = 'unread';
  let reading: Promise<void> | undefined;
  let flushing: Promise<void> | undefined;
  // The newest sound delta listed, by name, and the newest sound snapshot read or written, as counted down: older ones
  // have nothing new. Only sound ones move them, or a file anyone can add could hide honest ones named before it, or stop
  // snapshots being written. So a spoiled file newer than both is read again at each read, its alarm with it.
  let deltasFrom: string | undefined;
  let snapshotFrom: string | undefined;
  // Deltas this process wrote since it last listed: nothing to read in them.
  const written = new Set<string>();
  let readFailingSince: number | undefined;
  let writeFailingSince: number | undefined;

  /** The alarm, on a line naming the chain's organisation where it has one. */
  const alarm = (reason: string, more: Record<string, unknown>, chain?: string): void => {
    const log =
      chain?.startsWith(ORGANISATION) === true ? logger.child({ orgId: chain.slice(ORGANISATION.length) }) : logger;
    log.error('audit.integrity_failed', { chain: 'store', check: 'anchor_store', reason, ...more });
  };

  /**
   * Every well-named file of a kind, newest first. Anything else its caller reaches is counted in `foreign`; a read stops
   * at the first file it need not go past, so a name sorting after that is never counted, and never read. Counting them
   * all would list every file since the epoch began, a hundred thousand a year, at each restart.
   */
  async function* filesOf(kind: Kind, most: number, foreign: { count: number }): AsyncGenerator<string> {
    const start = folder(kind);
    let after: string | undefined;
    do {
      const page = await store.list(start, most, after);
      foreign.count += page.foreign;
      for (const name of page.names) {
        const rest = name.slice(start.length);
        if (!FILE.test(rest)) {
          foreign.count += 1;
        } else if (LAST_MS - Number(rest.slice(0, 13)) > now().getTime() + MOST_AHEAD_MS) {
          foreign.count += 1;
          alarm('future', { kind, fileAt: whenNamed(rest.slice(0, 13)) });
        } else {
          yield name;
        }
      }
      after = page.next;
    } while (after !== undefined);
  }

  const countdownOf = (kind: Kind, name: string): string => name.slice(folder(kind).length, folder(kind).length + 13);

  /**
   * Into `stage`, as read, what a file changes, and whether it stands for what it should: every line sound and closed for
   * its name. Anything wrong is the alarm. A failed call to the store is thrown. Never fetched past what this process can
   * hold (PL-65): a file larger, or one a plain read can't fetch, is a spoiled file, the alarm, and the read goes on. A
   * shard's file (`shard`) holds that shard's chains alone. While moving, an old file's lines say which shards' snapshots
   * no longer stand for them (`touched`).
   */
  const opened = async (
    { kind, countdown, shard, named }: { kind: Kind; countdown: string; shard?: number; named?: boolean },
    name: string,
    stage: PackedLines<Anchor>,
    touched: Set<number>,
  ): Promise<{ sound: boolean; missing?: true }> => {
    const got = await store.getAtMost(name, mostFileBytes);
    // Named by a list of changes, written before it: it may not be there yet.
    if (got === 'missing' && named === true) return { sound: false, missing: true };
    if (got === 'missing') throw new Error('a file listed and then not there');
    const fileAt = whenNamed(countdown);
    const where = { kind, fileAt, ...(shard === undefined ? {} : { shard: shardHex(shard) }) };
    if (typeof got === 'string') {
      alarm('file', { ...where, problem: got, mostBytes: mostFileBytes });
      return { sound: false };
    }
    const belongs = shard === undefined ? undefined : (chain: string) => shardOf(chain) === shard;
    const take = lineTaken(stage, kind, fileAt);
    const moving = shard === undefined && layout === 'moving';
    let file: Awaited<ReturnType<typeof readFile>>;
    try {
      file = await readFile(keys, { bytes: got, name, epoch, mostBytes: mostFileBytes, belongs }, (line, lineKind) => {
        if (moving) touched.add(shardOf(line.chain));
        take(line, lineKind);
      });
    } catch (error) {
      if (error instanceof BeyondMemory) return outgrown(error, shard, stage);
      alarm('file', { ...where, err: error });
      return { sound: false };
    }
    try {
      return { sound: judgedFile(file, where) };
    } catch (error) {
      if (error instanceof BeyondMemory) return outgrown(error, shard, stage);
      throw error;
    }
  };

  /**
   * A sound shard's file, or its lines, past what can be held: that shard let go if it may be (PR3), so it waits alone,
   * and the read goes on; it is said when it is asked for again. Otherwise the read is past what can be held, as before.
   */
  const outgrown = (error: BeyondMemory, shard: number | undefined, stage: PackedLines<Anchor>): { sound: false } => {
    if (shard === undefined || !evicts || layout !== 'sharded' || !evictable(shard, waitingShards())) throw error;
    purged(new Set([shard]), stage);
    logger.info('audit.anchor_shards_evicted', { shards: 1, outgrown: shardHex(shard), mostBytes: mostFileBytes });
    return { sound: false };
  };

  /** What takes a file's lines in as each is read: dated before its chain's rebase, the chain as it was, passed over. */
  const lineTaken =
    (stage: PackedLines<Anchor>, kind: Kind, fileAt: string) =>
    (line: Anchor | Progress, lineKind: LineKind): void => {
      // A shard let go is held whole or not at all: its lines are passed over, its read again takes them all (PR3).
      const shard = shardOf(line.chain);
      if (!takes(shard)) {
        if (!isResident(shard)) elsewhere(line.chain, lineKind, line);
        return;
      }
      // Read back whole: held again, so no longer counted as known elsewhere as well.
      if (loading === shard) seenElsewhere.delete(line.chain);
      // Each line read a new one, as each was a new object: stamped as it comes in.
      if (lineKind === 'a') {
        if (!rebasedAfter(line.chain, line.at)) staged(stage, line, stamped(), kind, fileAt);
      } else if (isPlace(line)) {
        if (!rebasedAfter(line.chain, line.began)) placeLine(stage, line, stamped(), kind, fileAt);
      } else passLine(stage, line, stamped(), kind, fileAt);
    };

  /** Whether a file read stands for what it should; anything wrong the alarm. Sound but past what can be held, thrown. */
  const judgedFile = (
    { bad, misplaced, closed, past }: Awaited<ReturnType<typeof readFile>>,
    where: { kind: Kind; fileAt: string },
  ): boolean => {
    if (past) {
      if (bad + misplaced === 0 && closed) throw new BeyondMemory(where.kind, where.fileAt);
      alarm('file', where);
      return false;
    }
    if (bad > 0) alarm('signature', { ...where, lines: bad });
    if (misplaced > 0) alarm('misplaced', { ...where, lines: misplaced });
    if (!closed) alarm('unclosed', where);
    return bad + misplaced === 0 && closed;
  };

  /** Highest place wins. The same place with another hash is the alarm, and the older stays: the chain then says which it holds. */
  const merge = (into: PackedLines<Anchor>, line: Anchor, stamp: number): void => {
    const held = into.get(line.chain);
    if (held === undefined || line.seq > held.seq) {
      into.set(line, stamp);
      return;
    }
    if (line.seq !== held.seq) return;
    if (line.hash.equals(held.hash)) {
      // The same place signed again later: an idle chain checked since (anchor-check.ts).
      if (line.at > held.at) into.set(line, stamp);
    } else {
      alarm('fork', { seq: line.seq }, line.chain);
      if (line.at < held.at) into.set(line, stamp);
    }
  };

  /**
   * A line as it is read, by `merge`'s rules. On a chain held it goes straight there, so a read of every chain moved costs
   * nothing more, and a line behind or the same costs nothing. Another hash at the place held, like a chain new to this
   * process, waits for the whole read. What's held and what waits count together against what this process can hold, or a
   * read could end it, past anything a catch can see.
   */
  const staged = (stage: PackedLines<Anchor>, line: Anchor, stamp: number, kind: Kind, fileAt: string): void => {
    const held = anchors.get(line.chain);
    if (held !== undefined && (line.seq !== held.seq || line.hash.equals(held.hash))) {
      merge(anchors, line, stamp);
      return;
    }
    merge(stage, line, stamp);
    pastMemory(stage, kind, fileAt);
  };

  /** Whether what's held, what this read staged and what a file being made or unsent holds are past what this process can hold. */
  const pastMemory = (stage: PackedLines<Anchor>, kind: Kind, fileAt: string): void => {
    if (heldBytes(stage.size) <= mostFileBytes) return;
    letGo(stage);
    if (heldBytes(stage.size) > mostFileBytes) throw new BeyondMemory(kind, fileAt);
  };

  /** The shards with a line waiting to be written. */
  const waitingShards = (): Set<number> => shardsIn(waitingTables, () => true, new Set<number>());

  /** Whether a shard may be let go now: held, in the sharded layout, and none of what keeps one in (PR3). */
  const evictable = (shard: number, waiting: ReadonlySet<number>): boolean =>
    isResident(shard) &&
    pins[shard] === 0 &&
    shard !== PLATFORM_SHARD &&
    !bareShards.has(shard) &&
    !making.has(shard) &&
    unsent?.shard !== shard &&
    !waiting.has(shard);

  /**
   * Past what this process can hold, in the sharded layout of a log that evicts: shards let go, the least recently used
   * first, until what is held is under `EVICT_TO` of it, or none is left that may go. `stage`, a read's lines yet to be
   * merged, counts and goes with its shard.
   */
  const letGo = (stage: PackedLines<Anchor> | undefined, past = mostFileBytes): void => {
    if (!evicts || layout !== 'sharded' || heldBytes(stage?.size ?? 0) <= past) return;
    const waiting = waitingShards();
    const tables = stage === undefined ? heldTables : [...heldTables, stage];
    const counts = new Float64Array(SHARDS);
    for (const table of tables) {
      for (const chain of table.keys()) {
        // Every chain a table holds has its shard: one without would be counted nowhere and purged with none.
        const shard = table.shardOf(chain);
        if (shard !== undefined) counts[shard] = (counts[shard] ?? 0) + 1;
      }
    }
    const victims = new Set<number>();
    let bytes = heldBytes(stage?.size ?? 0);
    const byUse = Array.from({ length: SHARDS }, (_, shard) => shard)
      .filter((shard) => (counts[shard] ?? 0) > 0 && evictable(shard, waiting))
      .toSorted(
        (one, other) =>
          (walkPassedAt[other] ?? 0) - (walkPassedAt[one] ?? 0) || (usedAt[one] ?? 0) - (usedAt[other] ?? 0),
      );
    for (const shard of byUse) {
      if (bytes <= mostFileBytes * EVICT_TO) break;
      victims.add(shard);
      bytes -= (counts[shard] ?? 0) * KEPT_LINE_BYTES;
    }
    if (victims.size === 0) return;
    purged(victims, stage);
    logger.info('audit.anchor_shards_evicted', {
      shards: victims.size,
      held: SHARDS - resident.filter((held) => !held).length,
      bytes: heldBytes(stage?.size ?? 0),
      mostBytes: mostFileBytes,
    });
  };

  /**
   * Shards let go: every line of theirs out of every table, and every name of theirs this process would pass over as
   * read, so reading one again reads every file of it. Its organisations still count as seen.
   */
  const purged = (shards: ReadonlySet<number>, stage: PackedLines<Anchor> | undefined): void => {
    for (const table of stage === undefined ? heldTables : [...heldTables, stage]) {
      const kind: LineKind = table === sides.p ? 'p' : table === sides.u ? 'u' : 'a';
      for (const chain of table.keys()) {
        if (!shards.has(table.shardOf(chain) ?? -1)) continue;
        const line = table.get(chain);
        if (line !== undefined) elsewhere(chain, kind, line);
        table.delete(chain);
      }
    }
    for (const shard of shards) {
      resident[shard] = false;
      walkPassedAt[shard] = 0;
    }
    const folders = [...shards].map((shard) => shardFolder(epoch, shard));
    const ofThem = (name: string): boolean => folders.some((folderName) => name.startsWith(folderName));
    for (const name of written) if (ofThem(name)) written.delete(name);
    for (const name of readSinceWalk.keys()) if (ofThem(name)) readSinceWalk.delete(name);
  };

  /** A finished pass as it is read: the latest begun kept, at once, as it moves nothing a check compares with. */
  const passLine = (stage: PackedLines<Anchor>, line: Anchor, stamp: number, kind: Kind, fileAt: string): void => {
    const kept = sides.p.get(line.chain);
    if (kept !== undefined && kept.at >= line.at) return;
    sides.p.set(line, stamp);
    pastMemory(stage, kind, fileAt);
  };

  /** A place reached as it is read: the latest pass's, and of that pass the furthest, kept at once. */
  const placeLine = (stage: PackedLines<Anchor>, line: Progress, stamp: number, kind: Kind, fileAt: string): void => {
    const kept = sides.u.get(line.chain);
    if (
      kept !== undefined &&
      (kept.began > line.began || (kept.began.getTime() === line.began.getTime() && kept.seq >= line.seq))
    )
      return;
    sides.u.set(line, stamp);
    pastMemory(stage, kind, fileAt);
  };

  /**
   * The snapshots not read yet, newest first, back to the first with nothing wrong: `base`, the one deltas count from.
   * Thrown if none is left to stand for the whole, as with a failed call: what's in memory already does, once there is any.
   */
  const newerSnapshots = async (
    foreign: { count: number },
    stage: PackedLines<Anchor>,
    touched: Set<number>,
    // The newest sound snapshot read: none, when one shard is read again whole (PR3).
    from: string | undefined,
  ) => {
    let spoiled = 0;
    for await (const name of filesOf('snapshots', SNAPSHOTS_A_PAGE, foreign)) {
      const countdown = countdownOf('snapshots', name);
      if (from !== undefined && countdown >= from) break;
      if (spoiled > MOST_SPOILED_SNAPSHOTS) throw new Error(tooManySpoiled(spoiled));
      const file = await opened({ kind: 'snapshots', countdown }, name, stage, touched);
      if (file.sound) return { base: countdown, sound: countdown };
      spoiled += 1;
    }
    if (spoiled > 0 && from === undefined) throw new Error(tooManySpoiled(spoiled));
    return { base: from, sound: undefined };
  };

  /**
   * Every delta this process didn't write, newer than the last it listed or, with
   * none yet, than the snapshot: one of the same millisecond may hold more than it.
   */
  const newerDeltas = async (
    snapshot: string | undefined,
    foreign: { count: number },
    stage: PackedLines<Anchor>,
    { touched, again }: { touched: Set<number>; again: boolean },
  ) => {
    let newest: string | undefined;
    let files = 0;
    // Read again for one shard (PR3): back to the snapshot whatever was read before, this process's own deltas too.
    const from = again ? undefined : deltasFrom;
    for await (const name of filesOf('deltas', DELTAS_A_PAGE, foreign)) {
      const old = from === undefined ? snapshot !== undefined && countdownOf('deltas', name) > snapshot : name >= from;
      if (old) break;
      if (!again && written.delete(name)) {
        newest ??= name;
        continue;
      }
      files += 1;
      const file = await opened({ kind: 'deltas', countdown: countdownOf('deltas', name) }, name, stage, touched);
      if (file.sound) newest ??= name;
    }
    return { newest, files };
  };

  const readFailed = (error: unknown): void => {
    if (state === 'read') {
      const at = now().getTime();
      readFailingSince ??= at;
      logger.warn('audit.anchor_store_read_failed', { err: error });
      // Payments go on from memory, but the next restart would make every organisation's wait: someone should know first.
      if (at - readFailingSince >= alertAfterMs) {
        logger.error('audit.anchor_store_read_failing', { forMs: at - readFailingSince });
      }
      return;
    }
    state = 'unreadable';
    logger.error('audit.anchor_store_unreadable', { err: error });
  };

  /**
   * A rebase taken in: the chain's newest, so it stands in for an anchor older than it, and a place a pass reached
   * before it goes, or the next resume would find the chain moved and raise the alarm. Said on a line of its own.
   */
  const rebased = (rebase: Rebase): void => {
    const before = rebases.get(rebase.chain);
    if (before !== undefined && before.at >= rebase.at) return;
    rebases.set(rebase.chain, rebase);
    const held = anchors.get(rebase.chain);
    const moved = held === undefined || held.at < rebase.at;
    // A shard let go takes its rebases in first when it is read again (PR3).
    if (moved && takes(shardOf(rebase.chain))) rebaseAnchored(rebase);
    else if (moved) elsewhere(rebase.chain, 'a', rebase);
    const waiting = pending.get(rebase.chain);
    if (waiting !== undefined && waiting.at < rebase.at) pending.delete(rebase.chain);
    for (const places of [sides.u, pendingSides.u]) {
      const place = places.get(rebase.chain);
      if (place !== undefined && place.began < rebase.at) places.delete(rebase.chain);
    }
    const organisation = rebase.chain.startsWith(ORGANISATION);
    const log = organisation ? logger.child({ orgId: rebase.chain.slice(ORGANISATION.length) }) : logger;
    log.warn('audit.rebased', {
      chain: organisation ? 'organisation' : 'platform',
      rebaseId: rebase.id,
      seq: rebase.seq,
      anchorSeq: held?.seq ?? null,
      moved,
      reason: rebase.reason,
      at: rebase.at.toISOString(),
    });
  };

  /** A rebase's anchor as the chain's, marked as a rebase's: it isn't signed with this key. */
  const rebaseAnchored = ({ chain, seq, hash, macKeyVersion, at, keyVersion, signature }: Rebase): void => {
    anchors.set({ chain, seq, hash, macKeyVersion, at, keyVersion, signature }, stamped(), true);
  };

  /** One rebase file: taken in, or the alarm; one dated ahead of the clock is read again next time. */
  const rebaseRead = async (name: string): Promise<void> => {
    // Never more than a rebase's size fetched: one made huge, or put beyond a plain read, is no rebase, and must not stop
    // every read.
    const bytes = await store.getAtMost(name, MOST_FILE_BYTES);
    if (bytes === 'missing') throw new Error('a rebase file listed and then not there');
    const read = typeof bytes === 'string' ? { problem: 'file' } : await readRebaseFile(keys, { bytes, name, epoch });
    if ('problem' in read) {
      rebaseFilesRead.add(name);
      alarm('rebase', { problem: read.problem, file: name });
      return;
    }
    if (read.rebase.at.getTime() > now().getTime() + REBASE_MOST_AHEAD_MS) {
      alarm('rebase', { problem: 'future', file: name, rebaseAt: read.rebase.at.toISOString() }, read.rebase.chain);
      return;
    }
    rebaseFilesRead.add(name);
    rebased(read.rebase);
  };

  /**
   * Every rebase file not read yet, each taken in as it is read: a chain's rebase is signed alone, so it stands whether
   * the rest of the read does or not. A failed call to the store is thrown, as the read's own.
   */
  const readRebases = async (foreign: { count: number }): Promise<void> => {
    const start = rebaseFolder(epoch);
    let after: string | undefined;
    do {
      const page = await store.list(start, REBASES_A_PAGE, after);
      foreign.count += page.foreign;
      for (const name of page.names) {
        if (!REBASE_ID.test(name.slice(start.length))) foreign.count += 1;
        else if (!rebaseFilesRead.has(name)) await rebaseRead(name);
      }
      after = page.next;
    } while (after !== undefined);
  };

  /** Whether a page holds any name but `except`: one of its own, one it would never write, or more to come. */
  const holdsOther = (page: WriteOncePage, except?: string): boolean =>
    page.names.some((name) => name !== except) || page.foreign > 0 || page.next !== undefined;

  /** A record at its one name, never fetched past a record's size: signed for it, or why not; nothing, if none is there. */
  const recordAt = async (
    name: string,
    read: (holding: KeyProvider, file: { bytes: Buffer; name: string; epoch: number }) => Promise<RecordRead>,
  ): Promise<RecordRead | undefined> => {
    const got = await store.getAtMost(name, MOST_FILE_BYTES);
    if (got === 'missing') return undefined;
    return typeof got === 'string' ? { problem: 'file' } : read(keys, { bytes: got, name, epoch });
  };

  /** A record read at its name: when it was signed, if it is one; anything else there the alarm, once a process. */
  const signedAt = async (
    name: string,
    read: Parameters<typeof recordAt>[1],
    which: 'marker' | 'done',
  ): Promise<Date | undefined> => {
    const got = await recordAt(name, read);
    if (got === undefined || 'marker' in got) return got?.at;
    if (!said[which]) alarm('cutover', { problem: got.problem, file: name });
    said[which] = true;
    return undefined;
  };

  /** Whether a folder's first page holds any name but `except`: its foreign names counted either way. */
  const foreignPage = async (
    folderName: string,
    most: number,
    foreign: { count: number },
    except?: string,
  ): Promise<boolean> => {
    const page = await store.list(folderName, most);
    foreign.count += page.foreign;
    return holdsOther(page, except);
  };

  /**
   * Which layout the store is in, asked at every read until the migration is done (PL-65): a marker signed for this epoch
   * at its one name moves it on, and after it the record that the migration is done, to the shards alone. Anything else
   * at either name, any other name under `cutover/`, and any name under `shards/` with no marker is the alarm, once a
   * process each, and moves nothing: the read goes on as before.
   */
  const layoutRead = async (foreign: { count: number }): Promise<void> => {
    const marker = cutoverName(epoch);
    if (layout === 'old') {
      markerAt = await signedAt(marker, readCutoverFile, 'marker');
      if (markerAt !== undefined) layout = 'moving';
    }
    if (layout === 'moving' && (await signedAt(shardsDoneName(epoch), readShardsDoneFile, 'done')) !== undefined) {
      layout = 'sharded';
    }
    if (!said.cutover && (await foreignPage(cutoverFolder(epoch), 2, foreign, marker))) {
      said.cutover = true;
      alarm('cutover', { problem: 'name' });
    }
    if (layout === 'old' && !said.shards && (await foreignPage(shardsFolder(epoch), 1, foreign))) {
      said.shards = true;
      alarm('shards', {});
    }
  };

  /**
   * One shard's walk, newest first: at a process's first read of the shards, back to its newest sound snapshot (and any
   * file of the same moment), past at most a day's spoiled ones; hourly after, back to `floor`, a little before the last
   * walk began, whatever lies between. Between walks, the lists of changes say what is new. What it
   * found, kept only once the whole read is: the newest sound file and snapshot, and whether it reached the shard's first
   * file with no sound snapshot (`bare`), so the old files must stand under it.
   */
  const shardWalk = (floor: string | undefined) => {
    const walk = {
      newest: undefined as string | undefined,
      snapshot: undefined as string | undefined,
      base: undefined as string | undefined,
      spoiled: 0,
      files: 0,
      read: [] as string[],
    };
    return {
      /** Whether the walk stops before this file: everything older is held already. */
      past: (countdown: string): boolean =>
        floor === undefined ? walk.base !== undefined && countdown > walk.base : countdown > floor,
      /** Whether this file, a snapshot, is one the first walk looks back past for a sound one. */
      first: (kind: Kind): boolean => floor === undefined && walk.base === undefined && kind === 'snapshots',
      /** A file of this process's own, or one read: sound, it moves the marks. */
      met(name: string, countdown: string, kind: Kind, sound: boolean, first: boolean): void {
        if (!sound) {
          if (first) walk.spoiled += 1;
          return;
        }
        walk.newest ??= name;
        if (kind === 'snapshots') walk.snapshot ??= countdown;
        if (first) walk.base = countdown;
      },
      walk,
      found: () => ({
        read: walk.read,
        newest: walk.newest,
        snapshot: walk.snapshot,
        bare: floor === undefined && walk.base === undefined && walk.files > 0,
      }),
    };
  };

  /** One shard's files not read yet, newest first, snapshots and deltas together, as the old files are read. */
  const readShard = async (
    shard: number,
    foreign: { count: number },
    stage: PackedLines<Anchor>,
    touched: Set<number>,
    floor: string | undefined,
  ) => {
    const start = shardFolder(epoch, shard);
    const walking = shardWalk(floor);
    let after: string | undefined;
    do {
      const page = await store.list(start, SHARD_FILES_A_PAGE, after);
      foreign.count += page.foreign;
      for (const name of page.names) {
        // Let go part way, or never held: read again whole, when asked for.
        if (!takes(shard)) return walking.found();
        const reading = { shard, name, rest: name.slice(start.length), walking, stage, touched, foreign };
        if (await shardFileRead(reading)) return walking.found();
      }
      after = page.next;
    } while (after !== undefined);
    return walking.found();
  };

  /** One name listed in a shard's folder: read, passed over, or where the walk stops (true). */
  const shardFileRead = async ({
    shard,
    name,
    rest,
    walking,
    stage,
    touched,
    foreign,
  }: {
    shard: number;
    name: string;
    rest: string;
    walking: ReturnType<typeof shardWalk>;
    stage: PackedLines<Anchor>;
    touched: Set<number>;
    foreign: { count: number };
  }): Promise<boolean> => {
    const countdown = rest.slice(0, 13);
    const kind: Kind = rest.endsWith('-s') ? 'snapshots' : 'deltas';
    if (!ourShardFile(shard, rest, kind, foreign)) return false;
    if (walking.past(countdown)) return true;
    // Read since the shard's last walk, through a list or by it: nothing new in it.
    if (written.delete(name) || readSinceWalk.has(name)) {
      // A snapshot of its own stands for the shard as this process held it: the walk need go back no further.
      walking.met(name, countdown, kind, true, walking.first(kind));
      return false;
    }
    const first = walking.first(kind);
    if (first && walking.walk.spoiled > MOST_SPOILED_SNAPSHOTS) throw new Error(tooManySpoiled(walking.walk.spoiled));
    walking.walk.files += 1;
    const file = await opened({ kind, countdown, shard }, name, stage, touched);
    walking.walk.read.push(name);
    walking.met(name, countdown, kind, file.sound, first);
    return false;
  };

  /** Whether a name in a shard's folder is one this log would write, and not dated past the clock: else counted, never read. */
  const ourShardFile = (shard: number, rest: string, kind: Kind, foreign: { count: number }): boolean => {
    if (!SHARD_FILE.test(rest)) {
      foreign.count += 1;
      return false;
    }
    const countdown = rest.slice(0, 13);
    if (LAST_MS - Number(countdown) <= now().getTime() + MOST_AHEAD_MS) return true;
    foreign.count += 1;
    alarm('future', { kind, shard: shardHex(shard), fileAt: whenNamed(countdown) });
    return false;
  };

  /** Every shard's files not read yet, one shard at a time. */
  const readShards = async (
    foreign: { count: number },
    stage: PackedLines<Anchor>,
    touched: Set<number>,
    walks: readonly { readonly shard: number; readonly floor: string | undefined }[],
  ) => {
    const found = [];
    for (const { shard, floor } of walks) {
      found.push({ shard, ...(await readShard(shard, foreign, stage, touched, floor)) });
    }
    return found;
  };

  /**
   * The shards this read walks: every one at a process's first read of the shards; after, those not walked for an hour,
   * the longest first, `WALKS_A_READ` at most. Each back to a little before its last walk began, or before the oldest
   * name of this process's own still in no list, or one a list named that the store did not give, if older: a file named
   * then may land long after.
   */
  const walksDue = (began: number) => {
    if (walkedAt === undefined) return Array.from({ length: SHARDS }, (_, shard) => ({ shard, floor: undefined }));
    let oldest = began;
    for (const at of unlisted.values()) oldest = Math.min(oldest, at);
    return shardMarks
      .map((marks, shard) => ({ shard, at: marks.walkedAt ?? walkedAt ?? began }))
      .filter(({ at }) => began - at >= SNAPSHOT_EVERY_MS)
      .toSorted((one, other) => one.at - other.at)
      .slice(0, WALKS_A_READ)
      .map(({ shard, at }) => ({
        shard,
        floor: countedDown(Math.min(at, oldest, lost.get(shard) ?? at) - CHANGES_LAG_MS),
      }));
  };

  /** The old files not read yet: the snapshots back to a sound one, and every delta since. */
  const readOld = async (
    foreign: { count: number },
    stage: PackedLines<Anchor>,
    touched: Set<number>,
    again = false,
  ) => {
    const snapshots = await newerSnapshots(foreign, stage, touched, again ? undefined : snapshotFrom);
    const deltas = await newerDeltas(snapshots.base, foreign, stage, { touched, again });
    return { snapshots, deltas };
  };

  /** What a read of the lists of changes found. */
  interface Changes {
    newest: { readonly countdown: string; readonly names: Set<string> } | undefined;
    readonly missing: Map<string, number>;
    readonly gotten: string[];
    /** Named and never given for an hour: no longer looked for, but not read either, so a walk still fetches it. */
    readonly givenUp: string[];
    readonly snapshots: [number, string][];
  }

  /**
   * The lists of changes not read yet, newest first, and every shard file each names (PL-65 PR2): one list call a run,
   * where a walk of every shard's folder would be 256. At the first read, after the walk, only those made in the last
   * few minutes, whose files may have landed after the walk listed their shard. A list names only files that landed; one
   * the store doesn't give is looked for again at each read, for an hour.
   */
  const readChanges = async (
    foreign: { count: number },
    stage: PackedLines<Anchor>,
    touched: Set<number>,
    began: number,
  ): Promise<Changes> => {
    const seen: Changes = { newest: undefined, missing: new Map(), gotten: [], givenUp: [], snapshots: [] };
    for (const [name, at] of awaited) {
      // Of a shard let go: looked for once it is held again, its own walk meanwhile reading whatever has landed.
      if (!takes(shardOfName(name))) continue;
      if (now().getTime() - at > SNAPSHOT_EVERY_MS) seen.givenUp.push(name);
      else await namedFileRead(name, at, { stage, touched, seen });
    }
    const start = changesFolder(epoch);
    const first = walkedAt === undefined;
    let after: string | undefined;
    do {
      const page = await store.list(start, CHANGES_A_PAGE, after);
      foreign.count += page.foreign;
      for (const name of page.names) {
        if (await changesListed(name, name.slice(start.length), { first, began, foreign, stage, touched, seen })) {
          return seen;
        }
      }
      after = page.next;
    } while (after !== undefined);
    return seen;
  };

  /** One name in the folder of changes: read, passed over, or where the read stops (true). */
  const changesListed = async (
    name: string,
    rest: string,
    {
      first,
      began,
      foreign,
      ...reading
    }: {
      first: boolean;
      began: number;
      foreign: { count: number };
      stage: PackedLines<Anchor>;
      touched: Set<number>;
      seen: Changes;
    },
  ): Promise<boolean> => {
    if (!CHANGES_FILE.test(rest)) {
      foreign.count += 1;
      return false;
    }
    const at = LAST_MS - Number(rest.slice(0, 13));
    if (at > now().getTime() + MOST_AHEAD_MS) {
      foreign.count += 1;
      alarm('future', { kind: 'changes', fileAt: whenNamed(rest.slice(0, 13)) });
      return false;
    }
    const countdown = rest.slice(0, 13);
    const known = changesKnown(name, countdown);
    if (known !== 'new') return known === 'older';
    const own = written.delete(name);
    // At the first read, one older than the last few minutes named only files the walk has read.
    if (first && at < began - CHANGES_LAG_MS) return true;
    if (refusedChanges.has(name)) return false;
    // Only a list that is one, or this process's own, moves the mark: a file anyone can add must hide nothing after it.
    if (!own && !(await changesFileRead(name, at, reading))) {
      refusedChanges.add(name);
      return false;
    }
    reading.seen.newest ??= { countdown, names: new Set() };
    if (reading.seen.newest.countdown === countdown) reading.seen.newest.names.add(name);
    return false;
  };

  /** Whether a list of changes is older than the last read, of its moment and read already, or new. */
  const changesKnown = (name: string, countdown: string): 'older' | 'known' | 'new' => {
    if (changesFrom === undefined || countdown < changesFrom.countdown) return 'new';
    if (countdown > changesFrom.countdown) return 'older';
    return changesFrom.names.has(name) ? 'known' : 'new';
  };

  /** A list of changes not of this process's: every file it names read; or the alarm, once, and false. */
  const changesFileRead = async (
    name: string,
    at: number,
    reading: { stage: PackedLines<Anchor>; touched: Set<number>; seen: Changes },
  ): Promise<boolean> => {
    const got = await store.getAtMost(name, MOST_CHANGES_BYTES);
    if (got === 'missing') throw new Error('a file listed and then not there');
    const files = typeof got === 'string' ? undefined : await readChangesFile(keys, { bytes: got, name, epoch });
    if (files === undefined) {
      alarm('changes', { file: name, ...(typeof got === 'string' ? { problem: got } : {}) });
      return false;
    }
    for (const file of files) await namedFileRead(`${shardsFolder(epoch)}${file}`, at, reading);
    return true;
  };

  /** A shard file a list of changes named: read, or, if the store doesn't give it, looked for again next read. */
  const namedFileRead = async (
    name: string,
    at: number,
    { stage, touched, seen }: { stage: PackedLines<Anchor>; touched: Set<number>; seen: Changes },
  ): Promise<void> => {
    const [, hex = '', rest = ''] = LISTED_FILE.exec(name.slice(shardsFolder(epoch).length)) ?? [];
    const shard = Number.parseInt(hex, 16);
    // Of a shard let go: its read again lists its folder, and finds the file there.
    if (!takes(shard)) return;
    const kind: Kind = rest.endsWith('-s') ? 'snapshots' : 'deltas';
    const countdown = rest.slice(0, 13);
    const file = await opened({ kind, countdown, shard, named: true }, name, stage, touched);
    if (file.missing === true) {
      seen.missing.set(name, at);
      return;
    }
    seen.gotten.push(name);
    if (file.sound && kind === 'snapshots') seen.snapshots.push([shard, countdown]);
  };

  /** The shard of a shard file's whole name. */
  const shardOfName = (name: string): number =>
    Number.parseInt(name.slice(shardsFolder(epoch).length, shardsFolder(epoch).length + 2), 16);

  /** A read of the lists of changes, kept only once the whole read is. */
  const changesRead = ({ newest, missing, gotten, givenUp, snapshots }: Changes, floor: string): void => {
    // Not of a shard let go part way: its read again must read them.
    for (const name of gotten) if (takes(shardOfName(name))) readSinceWalk.set(name, 0);
    if (newest !== undefined && newest.countdown === changesFrom?.countdown) {
      for (const name of newest.names) changesFrom.names.add(name);
    } else if (newest !== undefined) changesFrom = newest;
    // At the first read with no list since the walk's few minutes: from there on.
    else changesFrom ??= { countdown: floor, names: new Set() };
    const from = changesFrom.countdown;
    for (const name of refusedChanges)
      if (name.slice(changesFolder(epoch).length, -37) > from) refusedChanges.delete(name);
    for (const name of [...gotten, ...givenUp]) awaited.delete(name);
    for (const name of givenUp) {
      const shard = shardOfName(name);
      const at = LAST_MS - Number(name.slice(shardsFolder(epoch).length + 3, shardsFolder(epoch).length + 16));
      lost.set(shard, Math.min(at, lost.get(shard) ?? at));
    }
    for (const [name, at] of missing) awaited.set(name, at);
    for (const [shard, countdown] of snapshots) snapshotMet(shard, countdown);
  };

  /** A sound snapshot of a shard read: its newest counts when the next is due. */
  const snapshotMet = (shard: number, countdown: string): void => {
    const marks = shardMarks[shard];
    if (marks !== undefined && (marks.snapshotFrom === undefined || countdown < marks.snapshotFrom))
      marks.snapshotFrom = countdown;
  };

  /** A walk kept: its own shard files named before it began are met or older than any walk goes back to. */
  const walked = (began: number, shards: Awaited<ReturnType<typeof readShards>>): void => {
    if (shards.length === 0) return;
    // The first walk takes every shard at once: each is then counted as walked a little earlier, by its place across
    // the hour, so their next walks fall due spread over the hour, about 21 a 5-minute run, not all 256 together.
    const first = walkedAt === undefined;
    walkedAt ??= began;
    const walkedNow = new Set(shards.map(({ shard }) => shard));
    for (const shard of walkedNow) {
      const marks = shardMarks[shard];
      if (marks !== undefined)
        marks.walkedAt = first ? began - Math.floor((shard * SNAPSHOT_EVERY_MS) / SHARDS) : began;
    }
    // What the next walk of each won't reach back to, or will pass over as read: let go.
    const before = countedDown(began - CHANGES_LAG_MS);
    const start = shardsFolder(epoch).length;
    const ofWalked = (name: string): boolean =>
      SHARD_FILE.test(name.slice(start + 3)) && walkedNow.has(Number.parseInt(name.slice(start, start + 2), 16));
    for (const name of written) if (ofWalked(name) && name.slice(start + 3, start + 16) > before) written.delete(name);
    for (const name of readSinceWalk.keys()) if (ofWalked(name)) readSinceWalk.delete(name);
    for (const shard of walkedNow) lost.delete(shard);
  };

  /** A read's marks, kept only once the whole read is: the newest sound file and snapshot of each shard. */
  const shardsRead = (found: Awaited<ReturnType<typeof readShards>>): void => {
    for (const { shard, newest, snapshot, read, bare } of found) {
      // A shard let go part way: what its walk read is gone, so is read again (PR3).
      if (!takes(shard)) continue;
      // Stood on the old files, the migration done: never let go, as its own files alone can't give it back.
      if (bare && layout === 'sharded') bareShards.add(shard);
      for (const name of read) readSinceWalk.set(name, shard);
      const marks = shardMarks[shard];
      if (marks === undefined) continue;
      if (newest !== undefined) marks.from = newest;
      if (snapshot !== undefined && (marks.snapshotFrom === undefined || snapshot < marks.snapshotFrom))
        marks.snapshotFrom = snapshot;
    }
  };

  /**
   * Every file not read yet: the rebases first, so every line read after is judged against them; then the shards once
   * the store has moved on, and the old files while moving, or once moved only under a shard whose own snapshots are
   * all spoiled. Merged in only once every call is answered: a part read could look like a chain never anchored.
   */
  const readWhole = async (began: number, touched: Set<number>): Promise<void> => {
    const foreign = { count: 0 };
    await layoutRead(foreign);
    const stage = packedLines<Anchor>(false);
    await readRebases(foreign);
    const shards = layout === 'old' ? [] : await readShards(foreign, stage, touched, walksDue(began));
    const changes = layout === 'old' ? undefined : await readChanges(foreign, stage, touched, began);
    const bare = shards.some((found) => found.bare);
    const old = layout === 'sharded' && !bare ? undefined : await readOld(foreign, stage, touched);
    for (const { line, stamp } of stage.held()) merge(anchors, line, stamp);
    if (old?.snapshots.sound !== undefined) snapshotFrom = old.snapshots.sound;
    if (old?.deltas.newest !== undefined) deltasFrom = old.deltas.newest;
    marksKept({ began, shards, changes });
    if (foreign.count > 0) logger.warn('audit.anchor_store_foreign', { files: foreign.count });
    if (state === 'read') return;
    logger.info('audit.anchors_read', {
      epoch,
      chains: anchors.size,
      snapshot: old?.snapshots.sound !== undefined,
      deltas: old?.deltas.files ?? 0,
      ...(layout === 'old' ? {} : { layout, shardSnapshots: shards.filter((found) => found.snapshot).length }),
    });
  };

  /** The shards' marks a whole read moves, kept only once it is whole. */
  const marksKept = ({
    began,
    shards,
    changes,
  }: {
    began: number;
    shards: Awaited<ReturnType<typeof readShards>>;
    changes: Changes | undefined;
  }): void => {
    shardsRead(shards);
    // The walks first: a name given up in this read, after its shard's walk, is left for that shard's next walk.
    walked(began, shards);
    if (changes !== undefined) changesRead(changes, countedDown(began - CHANGES_LAG_MS));
    if (layout === 'moving' && markerAt !== undefined && began - markerAt.getTime() >= SETTLE_MS) settledRead = true;
  };

  const catchUp = async (): Promise<void> => {
    const began = now().getTime();
    // Shards an old file's line was read for while moving: their snapshots stand for them no longer.
    const touched = new Set<number>();
    try {
      await readWhole(began, touched);
      readFailingSince = undefined;
      state = 'read';
    } catch (error) {
      if (!(error instanceof BeyondMemory)) {
        readFailed(error);
        return;
      }
      // Fails closed all the same: anchors it can't hold can't be compared, so payments wait, for the true reason.
      logger.error('audit.anchor_store_beyond_memory', {
        kind: error.kind,
        fileAt: error.fileAt,
        mostBytes: mostFileBytes,
        // What the floor is made of (PR4): every organisation seen in a shard let go is still counted, about 160 bytes
        // each, so past enough of them no shard has room to be read back.
        elsewhere: seenElsewhere.size,
        elsewhereBytes: seenElsewhere.size * SEEN_NAME_BYTES,
        heldBytes: heldBytes(0),
      });
      if (state !== 'read') state = 'unreadable';
    } finally {
      // Read whole or not, what it took from the old files is held now, and no snapshot taken before stands for it.
      if (touched.size > 0) {
        const stamp = stamped();
        for (const shard of touched) {
          const marks = shardMarks[shard];
          if (marks !== undefined) marks.old = stamp;
        }
      }
      // What keeps added since, or a read past what can be held with shards pinned, let go now if it may be.
      letGo(undefined);
      strained();
    }
  };

  // Reads and shards' reads again, one at a time: each walks the marks and tables the other moves. While one runs, a
  // shard is let go only by it, as it counts what it has yet to merge.
  let turns: Promise<unknown> = Promise.resolve();
  let running = 0;
  const inTurn = (work: () => Promise<void>): Promise<void> => {
    const run = turns.then(async () => {
      running += 1;
      try {
        await work();
      } finally {
        running -= 1;
      }
    });
    turns = run;
    return run;
  };

  /**
   * A shard let go, read again as a first read reads it (PR3): its rebases first, then its folder listed back to its
   * newest sound snapshot past at most a day's spoiled ones, every line's signature or its file's closing line checked
   * again, a line of another shard the alarm. Its lines go in only once all are read, and only then is it held, so a
   * part read never says a chain was never anchored. One with no sound snapshot of its own stands on the old files, as
   * at a first read, read whole for it alone. One that can't be read, or can't be held beside what is pinned and
   * waiting, stays let go, said, and is tried again when next asked for.
   */
  const shardLoaded = async (shard: number): Promise<void> => {
    if (isResident(shard)) return;
    const began = now().getTime();
    const stage = packedLines<Anchor>(false);
    const foreign = { count: 0 };
    loading = shard;
    try {
      for (const rebase of rebases.values()) {
        if (shardOf(rebase.chain) !== shard) continue;
        rebaseAnchored(rebase);
        seenElsewhere.delete(rebase.chain);
      }
      const found = { shard, ...(await readShard(shard, foreign, stage, new Set<number>(), undefined)) };
      // No sound snapshot of its own: it stands on the old files, as at a first read, read whole for it alone. Never
      // let go again, as that is a read of the whole old store.
      if (found.bare) {
        await readOld(foreign, stage, new Set<number>(), true);
        bareShards.add(shard);
      }
      for (const { line, stamp } of stage.held()) merge(anchors, line, stamp);
      resident[shard] = true;
      uses += 1;
      usedAt[shard] = uses;
      shardsRead([found]);
      walked(began, [found]);
      reloads += 1;
      logger.info('audit.anchor_shard_loaded', { shard: shardHex(shard), files: found.read.length });
    } catch (error) {
      purged(new Set([shard]), stage);
      const reason = error instanceof BeyondMemory ? 'memory' : 'store';
      logger.error('audit.anchor_shard_unreadable', {
        shard: shardHex(shard),
        reason,
        ...(reason === 'store' ? { err: error } : { mostBytes: mostFileBytes }),
      });
    } finally {
      loading = undefined;
      if (foreign.count > 0) logger.warn('audit.anchor_store_foreign', { files: foreign.count });
    }
  };

  /** Whether the shard is held, read again first if it was let go and the store has been read whole. */
  const held = async (shard: number): Promise<boolean> => {
    if (isResident(shard)) return true;
    if (state !== 'read') return false;
    let load = loads.get(shard);
    if (load === undefined) {
      load = inTurn(() => shardLoaded(shard)).finally(() => loads.delete(shard));
      loads.set(shard, load);
    }
    await load;
    return isResident(shard);
  };

  /** See `roomToReadBack` on AnchorLog. */
  const roomToReadBack = async (): Promise<void> => {
    if (!evicts || layout !== 'sharded' || writeFailingSince !== undefined) return;
    if (heldBytes(0) <= mostFileBytes * EVICT_TO || waitingShards().size === 0) return;
    await flushed();
  };

  /** Past what can be held with no read under way to count its own: shards let go now. */
  const trimmed = (): void => {
    if (running === 0) letGo(undefined);
    strained();
  };

  // Within the hour begun at `strainFrom`: shards read again, and whether what is held stayed past the budget after
  // letting go all it could (pinned shards and lines waiting).
  let strainFrom: number | undefined;
  let reloads = 0;
  let pastBudget = false;

  /**
   * In a log that lets shards go, said at most hourly, each a warning: held past the budget with nothing more that may
   * go, or more shards read again than there are. Never the error a log that holds every shard says past half.
   */
  const strained = (): void => {
    if (!evicts || layout !== 'sharded') return;
    const at = now().getTime();
    const bytes = heldBytes(0);
    if (bytes > mostFileBytes) pastBudget = true;
    strainFrom ??= at;
    if (at - strainFrom < SNAPSHOT_EVERY_MS) return;
    if (pastBudget) {
      logger.warn('audit.anchor_shards_past_budget', {
        bytes,
        mostBytes: mostFileBytes,
        pinned: pins.filter((count) => count > 0).length,
        waiting: waitingShards().size,
      });
    }
    if (reloads > CHURN_RELOADS) logger.warn('audit.anchor_shards_churning', { reloads, withinMs: at - strainFrom });
    strainFrom = at;
    reloads = 0;
    pastBudget = false;
  };

  const writeFailed = (error: unknown): void => {
    const at = now().getTime();
    writeFailingSince ??= at;
    logger.warn('audit.anchor_store_write_failed', { err: error });
    if (at - writeFailingSince >= alertAfterMs) {
      logger.error('audit.anchor_store_unwritable', { forMs: at - writeFailingSince });
    }
  };

  /**
   * A file's lines back from its own bytes, each with the stamp it had when the file was made, into tables of their own:
   * only for a name another holds, so an unsent file keeps no copy of its lines however long the store stays away.
   */
  const restored = async (file: Unsent) => {
    const back = { a: packedLines<Anchor>(false), p: packedLines<Anchor>(false), u: packedLines<Progress>(true) };
    let at = 0;
    for await (const text of linesIn(file.bytes, { bytes: 0 })) {
      const kind = sectionOf(file, at);
      // The closing line, and nothing past it in a file this process made.
      if (kind === undefined) break;
      const line = file.kept.get(at) ?? readBack(kind, text);
      const stamp = file.stamps.at(at) ?? 0;
      // A section's lines are of its kind: a place reached in its own.
      if (kind === 'u') back.u.set(line as Progress, stamp);
      else back[kind].set(line, stamp);
      at += 1;
    }
    return back;
  };

  /** Lines back into what waits to be written, unless a later line of the chain is waiting already: with their stamps. */
  const waitAgain = <T extends Anchor>(into: PackedLines<T>, lines: PackedLines<T>): void => {
    for (const { line, stamp } of lines.held()) if (!into.has(line.chain)) into.set(line, stamp);
  };

  /** A name taken by other bytes (the alarm raised already): the file's lines go again under a new name. */
  const overwritten = (back: Awaited<ReturnType<typeof restored>>): void => {
    waitAgain(pending, back.a);
    waitAgain(pendingSides.p, back.p);
    waitAgain(pendingSides.u, back.u);
    unsent = undefined;
  };

  /** Where a file of this process's is, for its alarms: its kind, and its shard if it has one. */
  const whereOf = (file: Unsent): Record<string, unknown> => ({
    kind: file.kind,
    ...(file.shard === undefined ? {} : { shard: shardHex(file.shard) }),
  });

  /** What a shard's file name counts down from: the same place in every shard's folder. */
  const shardCountdown = (name: string): string => {
    const at = shardFolder(epoch, 0).length;
    return name.slice(at, at + 13);
  };

  /** What this flush wrote into the shards, said once at its end: a line a file would be up to 256 lines a minute. */
  const wrote = { files: 0, snapshots: 0, lines: 0, sides: 0 };

  /**
   * A file in the store: nothing to read in a delta of ours, and a snapshot is the newest. In a shard, neither kind is read
   * back, and a snapshot taken while moving stands for its shard from the stamp it was taken at.
   */
  const stored = (file: Unsent): void => {
    unsent = undefined;
    const marks = file.shard === undefined ? undefined : shardMarks[file.shard];
    if (marks === undefined) {
      if (file.kind === 'deltas') written.add(file.name);
      else snapshotFrom = countdownOf('snapshots', file.name);
      logger.info('audit.anchors_written', { kind: file.kind, lines: file.lines, sides: file.passes + file.places });
      return;
    }
    // Met again only by a walk, which then passes it over; one older than every walk is let go after it.
    written.add(file.name);
    unlisted.set(file.name, LAST_MS - Number(shardCountdown(file.name)));
    if (file.kind === 'snapshots') {
      marks.snapshotFrom = shardCountdown(file.name);
      marks.seeded = Math.max(marks.seeded, file.seedStamp ?? 0);
      wrote.snapshots += 1;
    }
    wrote.files += 1;
    wrote.lines += file.lines;
    wrote.sides += file.passes + file.places;
  };

  /**
   * Into the store, or thrown. A name taken already holds this file if an answer was lost; if it holds anything else, that
   * is the alarm. Only then are the file's lines read back from its bytes: a lost answer reads nothing back (at the edge
   * that would be the whole file, uncounted), and a read-back that throws can't stop a file that did land. A line kept
   * while the name was fetched is later than the file's, and `waitAgain` lets it win. What holds the name is never fetched
   * past this file's own size: anything larger, or beyond a plain read, is other bytes.
   */
  const send = async (file: Unsent): Promise<void> => {
    try {
      await store.put(file.name, file.bytes);
    } catch (error) {
      if (!(error instanceof OverwriteRefused)) throw error;
      const held = await store.getAtMost(file.name, file.bytes.length);
      if (held === 'missing') throw new Error('a name refused as taken, and then not there', { cause: error });
      if (typeof held === 'string' || !held.equals(file.bytes)) {
        // The alarm first: a read-back that throws must not hide the overwrite behind a write failure.
        alarm('overwrite', whereOf(file));
        overwritten(await restored(file));
        return;
      }
    }
    stored(file);
  };

  /** Only what a file holds stops waiting: a line kept while it was made has a stamp of its own, and still waits. */
  const settled = <T extends Anchor>(waiting: PackedLines<T>, lines: Taken<T>): void => {
    for (const [chain, stamp] of lines.stamps()) if (waiting.stampOf(chain) === stamp) waiting.delete(chain);
  };

  /**
   * The next file's lines, as they are now: every chain's anchor when a snapshot is due, what moved otherwise; of one
   * shard's chains alone, for a shard's file.
   */
  const taken = (kind: Kind, shard: number | undefined) => {
    const ours = (_chain: string, _line: unknown, at: number): boolean => shard === undefined || at === shard;
    // A chain still at its rebase is left to the rebase's own file: its anchor isn't signed with this key.
    const lines =
      kind === 'snapshots'
        ? anchors.take((chain, line, at) => ours(chain, line, at) && !anchors.marked(chain))
        : pending.take(ours);
    const from = kind === 'snapshots' ? sides : pendingSides;
    const passes = from.p.take(ours);
    const places = from.u.take((chain, line, at) => ours(chain, line, at) && (kind === 'deltas' || !overtaken(line())));
    return { lines, passes, places };
  };

  /**
   * The next file to write: every chain's anchor when a snapshot is due, what moved otherwise. What it takes from the
   * tables is let go as soon as its bytes are made (PL-65 review): an unsent file holds its bytes, a stamp a line and any
   * line its own text can't give back, never the tables' records, so a store away for hours costs nothing more. A shard's
   * file is named in its folder and closes with a version 2 line, over the hash of every line before it.
   */
  const madeFile = async ({ kind, shard }: { kind: Kind; shard?: number }): Promise<Unsent> => {
    // Never a file of a shard let go: a snapshot of it would stand for less than the whole (PR3). Nothing waits in one.
    if (shard !== undefined && evicts && !isResident(shard)) throw new Error('a file of a shard not held');
    const at = now().getTime();
    // Taken before the lines are: an old file's line read after it leaves the shard's snapshot standing for less.
    const seedStamp = shard !== undefined && kind === 'snapshots' && layout === 'moving' ? stamped() : undefined;
    const { lines, passes, places } = taken(kind, shard);
    const count = lines.size + passes.size + places.size;
    takenLines += count;
    try {
      const name =
        shard === undefined
          ? `${folder(kind)}${countedDown(at)}-${randomUUID()}`
          : `${shardFolder(epoch, shard)}${countedDown(at)}-${randomUUID()}-${kind.slice(0, 1)}`;
      const body = bodyHash();
      const closing = (): string => {
        if (shard === undefined) {
          const { signature, keyVersion } = keys.sign('audit-anchor', closingMessage(name, epoch, count));
          return JSON.stringify({
            k: 'c',
            name,
            epoch,
            lines: count,
            kv: keyVersion,
            sig: signature.toString('base64'),
          });
        }
        const hash = body.digest();
        const { signature, keyVersion } = keys.sign('audit-anchor', closingV2Message(name, epoch, count, hash));
        return JSON.stringify({
          k: 'c',
          v: 2,
          name,
          epoch,
          lines: count,
          body: hash,
          kv: keyVersion,
          sig: signature.toString('base64'),
        });
      };
      const stamps = new Float64Array(count);
      const kept = new Map<number, Anchor | Progress>();
      let made = 0;
      const sections = [
        ['a', lines],
        ['p', passes],
        ['u', places],
      ] as const;
      const bytes = await gzippedLines(
        (function* lined() {
          for (const [lineKind, from] of sections) {
            for (const { line, stamp } of from.lines()) {
              stamps[made] = stamp;
              if (!readsBack(line, lineKind)) kept.set(made, line);
              made += 1;
              const text = lineOf(line, lineKind);
              body.add(text);
              yield `${text}\n`;
            }
          }
          yield `${closing()}\n`;
        })(),
      );
      if (shard === undefined) nearMemory(kind);
      // Only what this file holds: `keep` may have run while it was made.
      settled(pending, lines);
      settled(pendingSides.p, passes);
      settled(pendingSides.u, places);
      return {
        kind,
        ...(shard === undefined ? {} : { shard }),
        ...(seedStamp === undefined ? {} : { seedStamp }),
        name,
        bytes,
        lines: lines.size,
        passes: passes.size,
        places: places.size,
        stamps,
        kept,
      };
    } finally {
      lines.release();
      passes.release();
      places.release();
      takenLines -= count;
    }
  };

  /**
   * In the budget's own count, so it is said long before a read of this many would be refused; with each snapshot, so
   * hourly, not each minute's delta; in the shards, once a flush that made any.
   */
  const nearMemory = (kind: Kind): void => {
    // Past half is how a log that lets shards go runs: said instead when it can't get under, or reads too much again.
    if (evicts && layout === 'sharded') return;
    const held = linesHeld();
    if (kind === 'snapshots' && held * KEPT_LINE_BYTES > mostFileBytes * NEAR_MEMORY) {
      logger.error('audit.anchor_store_near_memory', {
        kind,
        bytes: held * KEPT_LINE_BYTES,
        mostBytes: mostFileBytes,
        organisations: organisationsHeld(),
        // Where a read is refused, each organisation an anchor and a finished pass: two lines.
        edgeOrganisations: Math.floor(mostFileBytes / KEPT_LINE_BYTES / 2),
      });
    }
  };

  /** Whether the old files' snapshot is due: none yet, or an hour since the last. */
  const oldKind = (): Kind => {
    const lastSnapshot = snapshotFrom === undefined ? undefined : LAST_MS - Number(snapshotFrom);
    return lastSnapshot === undefined || now().getTime() - lastSnapshot >= SNAPSHOT_EVERY_MS ? 'snapshots' : 'deltas';
  };

  /** Whether a shard's snapshot is due: none yet, an hour since its last, or, while moving, none standing for it. */
  const shardKind = (shard: number): Kind => {
    const from = shardMarks[shard]?.snapshotFrom;
    if (from === undefined || now().getTime() - (LAST_MS - Number(from)) >= SNAPSHOT_EVERY_MS) return 'snapshots';
    return layout === 'moving' && !seeded(shard) ? 'snapshots' : 'deltas';
  };

  /** The tables of every chain held, and of what waits to be written: a shard needs a file for a chain of either. */
  const heldTables = [anchors, sides.p, sides.u] as const;
  const waitingTables = [pending, pendingSides.p, pendingSides.u] as const;

  /** Each shard holding a chain of these tables that `wanted` says yes to: one pass, by the shard each line keeps. */
  const shardsIn = (tables: typeof heldTables, wanted: (shard: number) => boolean, into: Set<number>): Set<number> => {
    for (const table of tables) {
      for (const chain of table.keys()) {
        const shard = table.shardOf(chain);
        if (shard !== undefined && wanted(shard)) into.add(shard);
      }
    }
    return into;
  };

  /** The shards a flush writes a file for: those with lines waiting and, while moving, those whose snapshot no longer stands. */
  const shardsDue = (): number[] => {
    const due = shardsIn(waitingTables, () => true, new Set<number>());
    if (layout === 'moving') shardsIn(heldTables, (shard) => !seeded(shard), due);
    return [...due].toSorted((one, other) => one - other);
  };

  /**
   * The list of the shard files this process wrote and no list of its names yet, after them, so no name is known before
   * its file is there to be taken first. A list that fails, or whose name is taken (the alarm), leaves them for the next
   * write's list; a process stopped first leaves them to the hourly walk.
   */
  const changesWritten = async (): Promise<void> => {
    // At most a list's worth a list, so a reader's bound always holds it, however many were carried.
    // At most a few lists a write, the rest carried to the next: a write never loops on its own.
    for (let lists = 0; unlisted.size > 0 && lists < LISTS_A_WRITE; lists += 1) {
      const names = [...unlisted.keys()].slice(0, NAMES_A_LIST);
      const name = `${changesFolder(epoch)}${countedDown(now().getTime())}-${randomUUID()}`;
      const files = names.map((file) => file.slice(shardsFolder(epoch).length));
      try {
        await store.put(name, changesFile(keys, name, epoch, files));
      } catch (error) {
        if (!(error instanceof OverwriteRefused)) throw error;
        // A random name taken: only by someone else. The files are there; the next write lists them again.
        alarm('overwrite', { kind: 'changes' });
        return;
      }
      written.add(name);
      for (const file of names) unlisted.delete(file);
    }
  };

  /**
   * An unsent shard file, then every shard's file due, one at a time, so one file at most is ever unsent; then the list
   * of those that landed. What was written said once.
   */
  const shardFilesDue = async (): Promise<void> => {
    Object.assign(wrote, { files: 0, snapshots: 0, lines: 0, sides: 0 });
    try {
      if (unsent !== undefined) await send(unsent);
      for (const shard of shardsDue()) {
        // Held in until its file is in the store, or unsent: what it takes stops waiting before it is unsent.
        making.add(shard);
        try {
          unsent = await madeFile({ kind: shardKind(shard), shard });
          await send(unsent);
        } finally {
          making.delete(shard);
        }
      }
    } finally {
      await changesWritten();
      if (wrote.files > 0) logger.info('audit.anchors_written', { kind: 'shards', ...wrote });
      // Shards' snapshots fall due at their own times: said at most hourly, as the old files' one snapshot was.
      const at = now().getTime();
      if (wrote.snapshots > 0 && (nearSaidAt === undefined || at - nearSaidAt >= SNAPSHOT_EVERY_MS)) {
        nearSaidAt = at;
        nearMemory('snapshots');
      }
    }
  };

  /**
   * A record written at its one name, or found there already, signed: when it was signed. Anything else at the name is
   * the alarm, once a process as when a read finds it (`which`), and the migration goes no further in this process.
   */
  const recordWritten = async (
    file: { readonly name: string; readonly bytes: Buffer },
    at: Date,
    read: Parameters<typeof recordAt>[1],
    which: 'marker' | 'done',
  ): Promise<Date | undefined> => {
    try {
      await store.put(file.name, file.bytes);
      return at;
    } catch (error) {
      if (!(error instanceof OverwriteRefused)) throw error;
      const there = await recordAt(file.name, read);
      if (there === undefined) throw new Error('a name refused as taken, and then not there', { cause: error });
      if ('marker' in there) return there.at;
      migrationStopped = true;
      if (!said[which]) alarm('cutover', { problem: there.problem, file: file.name });
      said[which] = true;
      return undefined;
    }
  };

  /** Whether the migration's first step is due: this process is set to take it, and has read the old store whole. */
  const cutOverDue = (): boolean => cutOver && layout === 'old' && state === 'read' && !migrationStopped;

  /** The migration's first step: the marker. */
  const cutOverNow = async (): Promise<void> => {
    const at = now();
    const signed = await recordWritten(cutoverFile(keys, { epoch, at }), at, readCutoverFile, 'marker');
    if (signed === undefined) return;
    layout = 'moving';
    markerAt = signed;
    logger.info('audit.anchor_store_cutover', { epoch, file: cutoverName(epoch), at: signed.toISOString() });
  };

  /**
   * The migration's last step: the record that it is done, once a read begun an hour past the marker has been, and every
   * shard holding chains has a snapshot standing for it, with nothing unsent. From then on the old files are read no more.
   */
  const doneDue = async (): Promise<void> => {
    // No read in flight either: an old file's line it takes in may not be in any shard's snapshot yet.
    if (layout !== 'moving' || !settledRead || unsent !== undefined || migrationStopped || reading !== undefined)
      return;
    if (shardsIn(heldTables, (shard) => !seeded(shard), new Set<number>()).size > 0) return;
    const at = now();
    const done = await recordWritten(shardsDoneFile(keys, { epoch, at }), at, readShardsDoneFile, 'done');
    if (done === undefined) return;
    layout = 'sharded';
    logger.info('audit.anchor_store_sharded', { epoch, file: shardsDoneName(epoch) });
  };

  const writeDue = async (): Promise<void> => {
    try {
      // An old file unsent goes as before; a shard's goes with the next list of changes.
      if (unsent?.shard === undefined && unsent !== undefined) await send(unsent);
      // Only when due: an await here would let `keep` run before the next file takes what waits.
      if (unsent === undefined && cutOverDue()) await cutOverNow();
      if (layout !== 'old') {
        await shardFilesDue();
        await doneDue();
      } else if (unsent === undefined && pending.size + pendingSides.p.size + pendingSides.u.size > 0) {
        unsent = await madeFile({ kind: oldKind() });
        await send(unsent);
      }
      writeFailingSince = undefined;
    } catch (error) {
      writeFailed(error);
    } finally {
      // What was written waits no more, so its shard may go: and near the budget, down to `EVICT_TO` now (PR4), so the
      // next read back, a hand-off's among them, finds room at once rather than failing on shards that were waiting.
      trimmed();
      if (running === 0) letGo(undefined, mostFileBytes * EVICT_TO);
    }
  };

  /** What has moved, written: one write at a time, a second call joining the first. Never throws. */
  const flushed = (): Promise<void> => {
    flushing ??= writeDue().finally(() => {
      flushing = undefined;
    });
    return flushing;
  };

  return Object.freeze({
    epoch,
    latest: (chain: Chain) => latest(chainName(chain)),
    keep(anchor: Anchor) {
      // Signed before the chain's rebase, by a check that began on the chain as it was: nothing to keep.
      if (rebasedAfter(anchor.chain, anchor.at)) return;
      // Its shard let go: compared with nothing, so never kept, nor a snapshot made of the shard without the rest.
      if (!keepable(anchor.chain, 'a')) return;
      // The check reads the anchor again first; this holds should a caller not, as a wound-back head must never replace it.
      const held = anchors.get(anchor.chain);
      if (
        held !== undefined &&
        (anchor.seq < held.seq || (anchor.seq === held.seq && !anchor.hash.equals(held.hash)))
      ) {
        alarm('behind', { seq: anchor.seq, anchorSeq: held.seq }, anchor.chain);
        return;
      }
      // One stamp in both, as one object was: a snapshot made of the anchors then says it wrote what waits.
      const stamp = stamped();
      anchors.set(anchor, stamp, fromRebase.has(anchor));
      pending.set(anchor, stamp);
    },
    lastPass(chain: Chain) {
      const name = chainName(chain);
      return visible(name) ? sides.p.get(name) : undefined;
    },
    keepPass(line: Anchor) {
      if (!keepable(line.chain, 'p')) return;
      const stamp = stamped();
      sides.p.set(line, stamp);
      pendingSides.p.set(line, stamp);
      // Finished: its place reached goes on to nothing, and is no longer written.
      sides.u.delete(line.chain);
      pendingSides.u.delete(line.chain);
    },
    lastProgress(chain: Chain) {
      const name = chainName(chain);
      const line = visible(name) ? sides.u.get(name) : undefined;
      return line === undefined || overtaken(line) ? undefined : line;
    },
    keepProgress(line: Progress) {
      // A pass that began before the chain's rebase read the chain as it was: its place goes nowhere.
      if (rebasedAfter(line.chain, line.began)) return;
      if (!keepable(line.chain, 'u')) return;
      const stamp = stamped();
      sides.u.set(line, stamp);
      pendingSides.u.set(line, stamp);
    },
    rebasedAfter: (chain: Chain, at: Date) => rebasedAfter(chainName(chain), at),
    lastFileAt() {
      const countdowns = [deltasFrom === undefined ? undefined : countdownOf('deltas', deltasFrom), snapshotFrom];
      for (const marks of shardMarks) {
        countdowns.push(marks.from === undefined ? undefined : shardCountdown(marks.from), marks.snapshotFrom);
      }
      const times = countdowns
        .filter((countdown) => countdown !== undefined)
        .map((countdown) => LAST_MS - Number(countdown));
      return times.length === 0 ? undefined : new Date(Math.max(...times));
    },
    read(): Promise<void> {
      reading ??= inTurn(catchUp).finally(() => {
        reading = undefined;
      });
      return reading;
    },
    state: () => state,
    readFailed,
    organisations() {
      // And those of shards let go, seen all the same: an organisation off the list is still missed (PR3).
      const held = [...anchors.keys()].filter((name) => name.startsWith(ORGANISATION));
      const away = [...seenElsewhere]
        .filter(([name, known]) => known.seq !== undefined && !anchors.has(name))
        .map(([name]) => name);
      return [...held, ...away].map((name) => name.slice(ORGANISATION.length));
    },
    holds: (chain: Chain) => !evicts || isResident(shardOfChain(chainName(chain))),
    lastKnown(chain: Chain) {
      const name = chainName(chain);
      // Held: what is held, its shard's place in the queue to go untouched. Let go: what was last seen of it.
      if (!evicts || isResident(shardOfChain(name))) {
        const anchor = anchors.get(name);
        const known = {
          seq: anchor?.seq,
          anchoredAt: anchor?.at.getTime(),
          passedAt: sides.p.get(name)?.at.getTime(),
          placeAt: sides.u.get(name)?.at.getTime(),
        };
        return Object.values(known).every((value) => value === undefined) ? undefined : known;
      }
      return seenElsewhere.get(name);
    },
    async pin(chain: Chain) {
      const shard = shardOfChain(chainName(chain));
      // Counted at once, before any wait: a read meanwhile can't let it go.
      pins[shard] = (pins[shard] ?? 0) + 1;
      let open = true;
      const release = (): void => {
        if (!open) return;
        open = false;
        pins[shard] = (pins[shard] ?? 1) - 1;
        trimmed();
      };
      if (!evicts || (await held(shard))) {
        uses += 1;
        usedAt[shard] = uses;
        return release;
      }
      release();
      return undefined;
    },
    memoryHeld() {
      const tables = [anchors, sides.p, sides.u, pending, pendingSides.p, pendingSides.u];
      return {
        bytes: heldBytes(0),
        mostBytes: mostFileBytes,
        records: tables.reduce((sum, table) => sum + table.records, 0),
        allocated: tables.reduce((sum, table) => sum + table.allocatedBytes, 0),
        shards: resident.filter(Boolean).length,
        pinned: pins.filter((count) => count > 0).length,
        elsewhere: seenElsewhere.size,
      };
    },
    flush: flushed,
    roomToReadBack,
    walkedPast(chain: Chain) {
      if (!evicts) return;
      const shard = shardOfChain(chainName(chain));
      if (!isResident(shard)) return;
      // Kept however it is used after, until it is let go or read back: a walk's lanes still on it use it as it leaves.
      walkedPasses += 1;
      walkPassedAt[shard] = walkedPasses;
    },
    heldAnchor(chain: Chain) {
      const name = chainName(chain);
      return !evicts || isResident(shardOfChain(name)) ? latestUnmarked(name) : undefined;
    },
    writeFailed,
  });
}

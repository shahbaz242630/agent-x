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
// So the API identity's token alone (add and read) can raise alarms, and can make payments
// wait after a restart: by more than a day's spoiled snapshots named newer than the last
// sound one, or by a file under `deltas/` or `snapshots/` too large to fetch within a read's
// deadline, or put beyond a plain read (its own encryption key, the archive tier, an encoding
// fetch undoes): those two folders are still fetched whole and unguarded, from before PL-65,
// not closed here (a PR2 item), each until an operator acts. It can't move an anchor back,
// nor stop a running process anchoring. Under `cutover/` and `shards/`, and with a rebase
// file, it can raise the alarm alone: only a marker signed with `audit-anchor`, at its one
// name, says the store has moved on (PL-65), and a marker or rebase is never fetched past
// 4 KB, one too large or unreadable being no marker or rebase. Taking the
// marker's name first only makes the migration's write of it refused, which stops the
// migration loudly before any shard, payments unaffected. Whoever also holds the
// `audit-anchor` signing key can write anything a file may hold, a marker too, which makes
// payments wait for good: nothing here guards against them; nor against whoever holds
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
import { cutoverFolder, cutoverName, readCutoverFile } from './cutover.ts';
import { isCount, MOST_FILE_BYTES, type Rebase, rebaseFolder, readRebaseFile, timeIn } from './rebase.ts';

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

/** The store holds a signed cutover marker for this epoch: this version must not read it. */
class MovedOn extends Error {
  readonly file: string;

  constructor(file: string) {
    super('the anchor store has moved on to a later layout');
    this.file = file;
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
}

/** A file made, not yet known to be in the store. Tried again under the same name, with the same bytes. */
interface Unsent {
  readonly kind: Kind;
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
  { bytes, name, epoch, mostBytes }: { bytes: Buffer; name: string; epoch: number; mostBytes: number },
  keep: (anchor: Anchor | Progress, kind: LineKind) => void,
) {
  const opened = { bytes: 0 };
  let bad = 0;
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
      !isSigned(keys, read.line.keyVersion, read.message, read.line.signature)
    ) {
      bad += 1;
    } else if (opened.bytes <= mostBytes) {
      keep(read.line, lineKind);
    }
  };
  let last: unknown;
  let any = false;
  for await (const line of linesIn(bytes, opened)) {
    if (opened.bytes > mostBytes && (bad > 0 || line === '' || opened.bytes > mostBytes * MOST_READ_PAST)) {
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
  return { bad, past, closed: closing && closes(keys, last, name, epoch, body) };
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
  // Whether a file at the marker's name that is none, another name under `cutover/`, and a name under `shards/` have been
  // said: each the alarm once a process.
  const said = { marker: false, cutover: false, shards: false };
  const fromRebase = new WeakSet<Anchor>();
  /** A chain's anchor, a copy: one that is a rebase's is known to `keep` by it as such, as the one object was before. */
  const latest = (chain: string): Anchor | undefined => {
    const anchor = anchors.get(chain);
    if (anchor !== undefined && anchors.marked(chain)) fromRebase.add(anchor);
    return anchor;
  };
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
  const besideLines = (): number => takenLines * TAKEN_LINE_BYTES + (unsent?.stamps.length ?? 0) * UNSENT_LINE_BYTES;
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

  /** Into `stage`, as read, what a file changes, and whether it stands for what it should: every line sound and closed for its name. Anything wrong is the alarm. A failed call to the store is thrown. */
  const opened = async (kind: Kind, name: string, stage: PackedLines<Anchor>): Promise<{ sound: boolean }> => {
    const bytes = await store.get(name);
    const fileAt = whenNamed(countdownOf(kind, name));
    let file: Awaited<ReturnType<typeof readFile>>;
    try {
      file = await readFile(keys, { bytes, name, epoch, mostBytes: mostFileBytes }, (line, lineKind) => {
        // Dated before the chain's rebase: the chain as it was, passed over.
        // Each line read a new one, as each was a new object: stamped as it comes in.
        if (lineKind === 'a') {
          if (!rebasedAfter(line.chain, line.at)) staged(stage, line, stamped(), kind, fileAt);
        } else if (isPlace(line)) {
          if (!rebasedAfter(line.chain, line.began)) placeLine(stage, line, stamped(), kind, fileAt);
        } else passLine(stage, line, stamped(), kind, fileAt);
      });
    } catch (error) {
      if (error instanceof BeyondMemory) throw error;
      alarm('file', { kind, fileAt, err: error });
      return { sound: false };
    }
    const { bad, closed, past } = file;
    if (past) {
      if (bad === 0 && closed) throw new BeyondMemory(kind, fileAt);
      alarm('file', { kind, fileAt });
      return { sound: false };
    }
    if (bad > 0) alarm('signature', { kind, fileAt, lines: bad });
    if (!closed) alarm('unclosed', { kind, fileAt });
    return { sound: bad === 0 && closed };
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
    if ((linesHeld() + stage.size) * KEPT_LINE_BYTES + besideLines() > mostFileBytes)
      throw new BeyondMemory(kind, fileAt);
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
  const newerSnapshots = async (foreign: { count: number }, stage: PackedLines<Anchor>) => {
    let spoiled = 0;
    for await (const name of filesOf('snapshots', SNAPSHOTS_A_PAGE, foreign)) {
      const countdown = countdownOf('snapshots', name);
      if (snapshotFrom !== undefined && countdown >= snapshotFrom) break;
      if (spoiled > MOST_SPOILED_SNAPSHOTS) throw new Error(tooManySpoiled(spoiled));
      const file = await opened('snapshots', name, stage);
      if (file.sound) return { base: countdown, sound: countdown };
      spoiled += 1;
    }
    if (spoiled > 0 && snapshotFrom === undefined) throw new Error(tooManySpoiled(spoiled));
    return { base: snapshotFrom, sound: undefined };
  };

  /**
   * Every delta this process didn't write, newer than the last it listed or, with
   * none yet, than the snapshot: one of the same millisecond may hold more than it.
   */
  const newerDeltas = async (snapshot: string | undefined, foreign: { count: number }, stage: PackedLines<Anchor>) => {
    let newest: string | undefined;
    let files = 0;
    for await (const name of filesOf('deltas', DELTAS_A_PAGE, foreign)) {
      const old =
        deltasFrom === undefined
          ? snapshot !== undefined && countdownOf('deltas', name) > snapshot
          : name >= deltasFrom;
      if (old) break;
      if (written.delete(name)) {
        newest ??= name;
        continue;
      }
      files += 1;
      const file = await opened('deltas', name, stage);
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
    if (moved) {
      const { chain, seq, hash, macKeyVersion, at, keyVersion, signature } = rebase;
      anchors.set({ chain, seq, hash, macKeyVersion, at, keyVersion, signature }, stamped(), true);
    }
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

  /**
   * Thrown if the store holds a signed cutover marker for this epoch, at its one name, asked at every read as a rollback may
   * come at any time; never more than a marker's size fetched. Anything else there, any other name under `cutover/`, and any
   * name under `shards/` is the alarm, once a process each, and moves nothing: the read goes on with today's files.
   */
  const refuseMovedOn = async (foreign: { count: number }): Promise<void> => {
    const name = cutoverName(epoch);
    const got = await store.getAtMost(name, MOST_FILE_BYTES);
    if (got !== 'missing') {
      const read =
        typeof got === 'string' ? { problem: 'file' } : await readCutoverFile(keys, { bytes: got, name, epoch });
      if ('marker' in read) throw new MovedOn(name);
      if (!said.marker) alarm('cutover', { problem: read.problem, file: name });
      said.marker = true;
    }
    if (!said.cutover) {
      const page = await store.list(cutoverFolder(epoch), 2);
      foreign.count += page.foreign;
      if (holdsOther(page, name)) {
        said.cutover = true;
        alarm('cutover', { problem: 'name' });
      }
    }
    if (!said.shards) {
      const page = await store.list(`e${String(epoch)}/shards/`, 1);
      foreign.count += page.foreign;
      if (holdsOther(page)) {
        said.shards = true;
        alarm('shards', {});
      }
    }
  };

  const catchUp = async (): Promise<void> => {
    try {
      const foreign = { count: 0 };
      await refuseMovedOn(foreign);
      const stage = packedLines<Anchor>(false);
      // First, so every line read after is judged against them.
      await readRebases(foreign);
      const snapshots = await newerSnapshots(foreign, stage);
      const deltas = await newerDeltas(snapshots.base, foreign, stage);
      // Only now, with every call answered: a part read could look like a chain never anchored, or settle a fork.
      for (const { line, stamp } of stage.held()) merge(anchors, line, stamp);
      if (snapshots.sound !== undefined) snapshotFrom = snapshots.sound;
      if (deltas.newest !== undefined) deltasFrom = deltas.newest;
      if (foreign.count > 0) logger.warn('audit.anchor_store_foreign', { files: foreign.count });
      if (state !== 'read') {
        logger.info('audit.anchors_read', {
          epoch,
          chains: anchors.size,
          snapshot: snapshots.sound !== undefined,
          deltas: deltas.files,
        });
      }
      readFailingSince = undefined;
      state = 'read';
    } catch (error) {
      if (error instanceof MovedOn) {
        // Unreadable even after a whole read: what this process holds may be older than the later layout's anchors, so
        // it anchors nothing more, and after a start payments wait. Files are never taken away, so it stays so.
        logger.error('audit.anchor_store_moved_on', { epoch, file: error.file });
        state = 'unreadable';
        return;
      }
      if (!(error instanceof BeyondMemory)) {
        readFailed(error);
        return;
      }
      // Fails closed all the same: anchors it can't hold can't be compared, so payments wait, for the true reason.
      logger.error('audit.anchor_store_beyond_memory', {
        kind: error.kind,
        fileAt: error.fileAt,
        mostBytes: mostFileBytes,
      });
      if (state !== 'read') state = 'unreadable';
    }
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

  /** A file in the store: nothing to read in a delta of ours, and a snapshot is the newest. */
  const stored = (file: Unsent): void => {
    unsent = undefined;
    if (file.kind === 'deltas') written.add(file.name);
    else snapshotFrom = countdownOf('snapshots', file.name);
    logger.info('audit.anchors_written', { kind: file.kind, lines: file.lines, sides: file.passes + file.places });
  };

  /**
   * Into the store, or thrown. A name taken already holds this file if an answer was lost; if it holds anything else, that
   * is the alarm. Only then are the file's lines read back from its bytes: a lost answer reads nothing back (at the edge
   * that would be the whole file, uncounted), and a read-back that throws can't stop a file that did land. A line kept
   * while the name was fetched is later than the file's, and `waitAgain` lets it win.
   */
  const send = async (file: Unsent): Promise<void> => {
    try {
      await store.put(file.name, file.bytes);
    } catch (error) {
      if (!(error instanceof OverwriteRefused)) throw error;
      const held = await store.get(file.name);
      if (!held.equals(file.bytes)) {
        // The alarm first: a read-back that throws must not hide the overwrite behind a write failure.
        alarm('overwrite', { kind: file.kind });
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

  /** The next file's lines, as they are now: every chain's anchor when a snapshot is due, what moved otherwise. */
  const taken = (kind: Kind) => {
    const all = (): boolean => true;
    // A chain still at its rebase is left to the rebase's own file: its anchor isn't signed with this key.
    const lines = kind === 'snapshots' ? anchors.take((chain) => !anchors.marked(chain)) : pending.take(all);
    const from = kind === 'snapshots' ? sides : pendingSides;
    const passes = from.p.take(all);
    const places = from.u.take((_chain, line) => kind === 'deltas' || !overtaken(line()));
    return { lines, passes, places };
  };

  /**
   * The next file to write: every chain's anchor when a snapshot is due, what moved otherwise. What it takes from the
   * tables is let go as soon as its bytes are made (PL-65 review): an unsent file holds its bytes, a stamp a line and any
   * line its own text can't give back, never the tables' records, so a store away for hours costs nothing more.
   */
  const madeFile = async (): Promise<Unsent> => {
    const at = now().getTime();
    const lastSnapshot = snapshotFrom === undefined ? undefined : LAST_MS - Number(snapshotFrom);
    const kind: Kind = lastSnapshot === undefined || at - lastSnapshot >= SNAPSHOT_EVERY_MS ? 'snapshots' : 'deltas';
    const { lines, passes, places } = taken(kind);
    const count = lines.size + passes.size + places.size;
    takenLines += count;
    try {
      const name = `${folder(kind)}${countedDown(at)}-${randomUUID()}`;
      const { signature, keyVersion } = keys.sign('audit-anchor', closingMessage(name, epoch, count));
      const closing = JSON.stringify({
        k: 'c',
        name,
        epoch,
        lines: count,
        kv: keyVersion,
        sig: signature.toString('base64'),
      });
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
              yield `${lineOf(line, lineKind)}\n`;
            }
          }
          yield `${closing}\n`;
        })(),
      );
      nearMemory(kind);
      // Only what this file holds: `keep` may have run while it was made.
      settled(pending, lines);
      settled(pendingSides.p, passes);
      settled(pendingSides.u, places);
      return { kind, name, bytes, lines: lines.size, passes: passes.size, places: places.size, stamps, kept };
    } finally {
      lines.release();
      passes.release();
      places.release();
      takenLines -= count;
    }
  };

  /**
   * In the budget's own count, so it is said long before a read of this many would be refused; with each snapshot, so
   * hourly, not each minute's delta.
   */
  const nearMemory = (kind: Kind): void => {
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

  const writeDue = async (): Promise<void> => {
    try {
      if (unsent !== undefined) await send(unsent);
      if (unsent === undefined && pending.size + pendingSides.p.size + pendingSides.u.size > 0) {
        unsent = await madeFile();
        await send(unsent);
      }
      writeFailingSince = undefined;
    } catch (error) {
      writeFailed(error);
    }
  };

  return Object.freeze({
    epoch,
    latest: (chain: Chain) => latest(chainName(chain)),
    keep(anchor: Anchor) {
      // Signed before the chain's rebase, by a check that began on the chain as it was: nothing to keep.
      if (rebasedAfter(anchor.chain, anchor.at)) return;
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
    lastPass: (chain: Chain) => sides.p.get(chainName(chain)),
    keepPass(line: Anchor) {
      const stamp = stamped();
      sides.p.set(line, stamp);
      pendingSides.p.set(line, stamp);
      // Finished: its place reached goes on to nothing, and is no longer written.
      sides.u.delete(line.chain);
      pendingSides.u.delete(line.chain);
    },
    lastProgress(chain: Chain) {
      const line = sides.u.get(chainName(chain));
      return line === undefined || overtaken(line) ? undefined : line;
    },
    keepProgress(line: Progress) {
      // A pass that began before the chain's rebase read the chain as it was: its place goes nowhere.
      if (rebasedAfter(line.chain, line.began)) return;
      const stamp = stamped();
      sides.u.set(line, stamp);
      pendingSides.u.set(line, stamp);
    },
    rebasedAfter: (chain: Chain, at: Date) => rebasedAfter(chainName(chain), at),
    lastFileAt() {
      const times = [deltasFrom === undefined ? undefined : countdownOf('deltas', deltasFrom), snapshotFrom]
        .filter((countdown) => countdown !== undefined)
        .map((countdown) => LAST_MS - Number(countdown));
      return times.length === 0 ? undefined : new Date(Math.max(...times));
    },
    read(): Promise<void> {
      reading ??= catchUp().finally(() => {
        reading = undefined;
      });
      return reading;
    },
    state: () => state,
    readFailed,
    organisations: () =>
      [...anchors.keys()]
        .filter((name) => name.startsWith(ORGANISATION))
        .map((name) => name.slice(ORGANISATION.length)),
    flush(): Promise<void> {
      flushing ??= writeDue().finally(() => {
        flushing = undefined;
      });
      return flushing;
    },
    writeFailed,
  });
}

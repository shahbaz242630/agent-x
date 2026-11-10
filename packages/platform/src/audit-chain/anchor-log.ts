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
// So the API identity's token alone (add and read) can raise alarms and, with enough
// spoiled files before a restart, make payments wait, but can't move an anchor back.
// Whoever also holds the `audit-anchor` signing key can write anything a file may
// hold: nothing here guards against them; nor against whoever holds `audit-rebase`.
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { getHeapStatistics } from 'node:v8';
import { createGunzip, createGzip } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Logger } from '../observability/index.ts';
import { OverwriteRefused, type WriteOnceStore } from '../storage/write-once.ts';
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
import { isCount, type Rebase, rebaseFolder, readRebaseFile, timeIn } from './rebase.ts';

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
 * What this process may hold of the store, a third of its heap, the lines held counted at `KEPT_LINE_BYTES` each (and a
 * file's opened bytes against it too: past it a file is read on only to tell a sound one, capacity, from a broken one; it
 * isn't kept). By what the process has, not by a setting the store can outgrow.
 *
 * Measured (S183, Node 24, `--max-old-space-size=768`, whose heap limit reads 960 MB): a store of N organisations, each an
 * anchor and a finished pass, read whole and an hourly snapshot written. Held: 995-1,031 bytes an organisation in this log
 * at 100k-450k (840 at 20k, as the maps grow in steps), and 104-111 more in the anchor check's `seen` and `firstSeen`
 * (anchor-check.ts), which take every organisation in the store. The heap's high point, garbage and what a restart's read
 * stages with it, was 1.15 to 1.5 times what is held. 450k organisations (487 MB held, 558 MB at the high point) read and
 * wrote in that heap alone; 600k ran out of it and ended the process. So at a third, about 320 MB held at the edge (about
 * 280k organisations), under ~480 MB at the high point, leaving ~480 MB for the rest of the API, the check's notes on its
 * first 100k organisations (~88 MB) among them: the refusal comes, clean and alarmed (`audit.anchor_store_beyond_memory`),
 * well before the heap could run out. A fifth at 340 bytes a line, before, came to much the same edge only because it
 * counted each organisation at under two thirds of its cost and left out the check's maps.
 */
const heapsFileBytes = (): number => Math.floor(getHeapStatistics().heap_size_limit / 3);

/** What a line held costs, the anchor check's share of its organisation with it: (1,031 + 111) / 2 at most, rounded up. */
const KEPT_LINE_BYTES = 600;

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

/**
 * Folders under an epoch that only a later layout of the store writes: the sharded store's shards and its signed cutover
 * marker (4D2e PL-65). This reader can't read them, so any file there means the store has moved on past it: a rollback to
 * this version would read only the old files, older than what the shards hold, and could anchor afresh a chain wound back.
 */
const LATER_LAYOUT = ['shards', 'cutover'] as const;

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

/** The store holds a later layout's files: this version must not read it. */
class MovedOn extends Error {
  readonly folder: string;

  constructor(folder: string) {
    super('the anchor store has moved on to a later layout');
    this.folder = folder;
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
  readonly lines: readonly Anchor[];
  /** The lines kept beside the anchors: finished full passes, and passes' places reached. */
  readonly passes: readonly Anchor[];
  readonly places: readonly Progress[];
}

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
  /** What of a file this process can take into memory (a fifth of its heap) unless a test says. */
  readonly mostFileBytes?: number;
}): AnchorLog {
  const folder = (kind: Kind): string => `e${String(epoch)}/${kind}/`;
  const anchors = new Map<string, Anchor>();
  // What has moved since it was last written: one line a chain at most, however long the store stays away.
  const pending = new Map<string, Anchor>();
  // Each chain's newest line of each side kind, and those not written yet, the same way.
  const sides = { p: new Map<string, Anchor>(), u: new Map<string, Progress>() };
  const pendingSides = { p: new Map<string, Anchor>(), u: new Map<string, Progress>() };
  // Each chain's newest rebase, the rebase files read already, and the anchors that are a rebase's, not signed here.
  const rebases = new Map<string, Rebase>();
  const rebaseFilesRead = new Set<string>();
  const fromRebase = new WeakSet<Anchor>();
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
  const opened = async (kind: Kind, name: string, stage: Map<string, Anchor>): Promise<{ sound: boolean }> => {
    const bytes = await store.get(name);
    const fileAt = whenNamed(countdownOf(kind, name));
    let file: Awaited<ReturnType<typeof readFile>>;
    try {
      file = await readFile(keys, { bytes, name, epoch, mostBytes: mostFileBytes }, (line, lineKind) => {
        // Dated before the chain's rebase: the chain as it was, passed over.
        if (lineKind === 'a') {
          if (!rebasedAfter(line.chain, line.at)) staged(stage, line, kind, fileAt);
        } else if (isPlace(line)) {
          if (!rebasedAfter(line.chain, line.began)) placeLine(stage, line, kind, fileAt);
        } else passLine(stage, line, kind, fileAt);
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
  const merge = (into: Map<string, Anchor>, line: Anchor): void => {
    const held = into.get(line.chain);
    if (held === undefined || line.seq > held.seq) {
      into.set(line.chain, line);
      return;
    }
    if (line.seq !== held.seq) return;
    if (line.hash.equals(held.hash)) {
      // The same place signed again later: an idle chain checked since (anchor-check.ts).
      if (line.at > held.at) into.set(line.chain, line);
    } else {
      alarm('fork', { seq: line.seq }, line.chain);
      if (line.at < held.at) into.set(line.chain, line);
    }
  };

  /**
   * A line as it is read, by `merge`'s rules. On a chain held it goes straight there, so a read of every chain moved costs
   * nothing more, and a line behind or the same costs nothing. Another hash at the place held, like a chain new to this
   * process, waits for the whole read. What's held and what waits count together against what this process can hold, or a
   * read could end it, past anything a catch can see.
   */
  const staged = (stage: Map<string, Anchor>, line: Anchor, kind: Kind, fileAt: string): void => {
    const held = anchors.get(line.chain);
    if (held !== undefined && (line.seq !== held.seq || line.hash.equals(held.hash))) {
      merge(anchors, line);
      return;
    }
    merge(stage, line);
    if ((linesHeld() + stage.size) * KEPT_LINE_BYTES > mostFileBytes) throw new BeyondMemory(kind, fileAt);
  };

  /** Whether what's held and what this read staged are past what this process can hold. */
  const pastMemory = (stage: Map<string, Anchor>, kind: Kind, fileAt: string): void => {
    if ((linesHeld() + stage.size) * KEPT_LINE_BYTES > mostFileBytes) throw new BeyondMemory(kind, fileAt);
  };

  /** A finished pass as it is read: the latest begun kept, at once, as it moves nothing a check compares with. */
  const passLine = (stage: Map<string, Anchor>, line: Anchor, kind: Kind, fileAt: string): void => {
    const kept = sides.p.get(line.chain);
    if (kept !== undefined && kept.at >= line.at) return;
    sides.p.set(line.chain, line);
    pastMemory(stage, kind, fileAt);
  };

  /** A place reached as it is read: the latest pass's, and of that pass the furthest, kept at once. */
  const placeLine = (stage: Map<string, Anchor>, line: Progress, kind: Kind, fileAt: string): void => {
    const kept = sides.u.get(line.chain);
    if (
      kept !== undefined &&
      (kept.began > line.began || (kept.began.getTime() === line.began.getTime() && kept.seq >= line.seq))
    )
      return;
    sides.u.set(line.chain, line);
    pastMemory(stage, kind, fileAt);
  };

  /**
   * The snapshots not read yet, newest first, back to the first with nothing wrong: `base`, the one deltas count from.
   * Thrown if none is left to stand for the whole, as with a failed call: what's in memory already does, once there is any.
   */
  const newerSnapshots = async (foreign: { count: number }, stage: Map<string, Anchor>) => {
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
  const newerDeltas = async (snapshot: string | undefined, foreign: { count: number }, stage: Map<string, Anchor>) => {
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
      const anchor: Anchor = Object.freeze({ chain, seq, hash, macKeyVersion, at, keyVersion, signature });
      fromRebase.add(anchor);
      anchors.set(chain, anchor);
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
    const read = await readRebaseFile(keys, { bytes: await store.get(name), name, epoch });
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

  /**
   * Thrown if a later layout has written anything under this epoch: one name asked of each of its folders, at every read,
   * as a rollback may come at any time. Any answer but an empty last page counts, a name this store would never write or a
   * page that goes on alike: a reader that can't tell must not read.
   */
  const refuseLaterLayout = async (): Promise<void> => {
    for (const later of LATER_LAYOUT) {
      const page = await store.list(`e${String(epoch)}/${later}/`, 1);
      if (page.names.length > 0 || page.foreign > 0 || page.next !== undefined) throw new MovedOn(later);
    }
  };

  const catchUp = async (): Promise<void> => {
    try {
      await refuseLaterLayout();
      const foreign = { count: 0 };
      const stage = new Map<string, Anchor>();
      // First, so every line read after is judged against them.
      await readRebases(foreign);
      const snapshots = await newerSnapshots(foreign, stage);
      const deltas = await newerDeltas(snapshots.base, foreign, stage);
      // Only now, with every call answered: a part read could look like a chain never anchored, or settle a fork.
      for (const line of stage.values()) merge(anchors, line);
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
        logger.error('audit.anchor_store_moved_on', { epoch, folder: error.folder });
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

  /** Lines back into what waits to be written, unless a later line of the chain is waiting already. */
  const waitAgain = <T extends Anchor>(into: Map<string, T>, lines: readonly T[]): void => {
    for (const line of lines) if (!into.has(line.chain)) into.set(line.chain, line);
  };

  /** A name taken by other bytes: the alarm, and the file's lines go again under a new name. */
  const overwritten = (file: Unsent): void => {
    alarm('overwrite', { kind: file.kind });
    waitAgain(pending, file.lines);
    waitAgain(pendingSides.p, file.passes);
    waitAgain(pendingSides.u, file.places);
    unsent = undefined;
  };

  /** A file in the store: nothing to read in a delta of ours, and a snapshot is the newest. */
  const stored = (file: Unsent): void => {
    unsent = undefined;
    if (file.kind === 'deltas') written.add(file.name);
    else snapshotFrom = countdownOf('snapshots', file.name);
    logger.info('audit.anchors_written', {
      kind: file.kind,
      lines: file.lines.length,
      sides: file.passes.length + file.places.length,
    });
  };

  /** Into the store, or thrown. A name taken already holds this file if an answer was lost; if it holds anything else, that is the alarm. */
  const send = async (file: Unsent): Promise<void> => {
    try {
      await store.put(file.name, file.bytes);
    } catch (error) {
      if (!(error instanceof OverwriteRefused)) throw error;
      if (!(await store.get(file.name)).equals(file.bytes)) {
        overwritten(file);
        return;
      }
    }
    stored(file);
  };

  /** The next file to write: every chain's anchor when a snapshot is due, what moved otherwise. */
  const madeFile = async (): Promise<Unsent> => {
    const at = now().getTime();
    const lastSnapshot = snapshotFrom === undefined ? undefined : LAST_MS - Number(snapshotFrom);
    const kind: Kind = lastSnapshot === undefined || at - lastSnapshot >= SNAPSHOT_EVERY_MS ? 'snapshots' : 'deltas';
    // A chain still at its rebase is left to the rebase's own file: its anchor isn't signed with this key.
    const lines =
      kind === 'snapshots' ? [...anchors.values()].filter((line) => !fromRebase.has(line)) : [...pending.values()];
    const from = kind === 'snapshots' ? sides : pendingSides;
    const passLines = [...from.p.values()];
    const placeLines = [...from.u.values()].filter((line) => kind === 'deltas' || !overtaken(line));
    const count = lines.length + passLines.length + placeLines.length;
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
    const bytes = await gzippedLines(
      (function* lined() {
        for (const line of lines) yield `${lineOf(line, 'a')}\n`;
        for (const line of passLines) yield `${lineOf(line, 'p')}\n`;
        for (const line of placeLines) yield `${lineOf(line, 'u')}\n`;
        yield `${closing}\n`;
      })(),
    );
    // In the budget's own count, so it is said long before a read of this many would be refused; with each snapshot, so
    // hourly, not each minute's delta.
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
    // Only what this file holds: `keep` may have run while it was made.
    for (const line of lines) if (pending.get(line.chain) === line) pending.delete(line.chain);
    for (const line of passLines) if (pendingSides.p.get(line.chain) === line) pendingSides.p.delete(line.chain);
    for (const line of placeLines) if (pendingSides.u.get(line.chain) === line) pendingSides.u.delete(line.chain);
    return { kind, name, bytes, lines, passes: passLines, places: placeLines };
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
    latest: (chain: Chain) => anchors.get(chainName(chain)),
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
      anchors.set(anchor.chain, anchor);
      pending.set(anchor.chain, anchor);
    },
    lastPass: (chain: Chain) => sides.p.get(chainName(chain)),
    keepPass(line: Anchor) {
      sides.p.set(line.chain, line);
      pendingSides.p.set(line.chain, line);
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
      sides.u.set(line.chain, line);
      pendingSides.u.set(line.chain, line);
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

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
// So the API identity's token alone (add and read) can raise alarms and, with enough
// spoiled files before a restart, make payments wait, but can't move an anchor back.
// Whoever also holds the `audit-anchor` signing key can write anything a file may
// hold: nothing here guards against them.
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { getHeapStatistics } from 'node:v8';
import { createGunzip, createGzip } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Logger } from '../observability/index.ts';
import { OverwriteRefused, type WriteOnceStore } from '../storage/write-once.ts';
import type { Message } from '../keys/message.ts';
import { type Anchor, type AnchorStore, anchorMessage } from './anchor.ts';
import { type Chain, chainName } from './chain.ts';

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
 * What of a file this process can take into memory, a fifth of its heap: an anchor held is about 2.6 times its line (885
 * bytes to 340), so that much file is about half the heap in anchors. Past it a file is read on only to tell a sound one,
 * capacity, from a broken one; it isn't kept. By what the process has, not by a setting the store can outgrow.
 */
const heapsFileBytes = (): number => Math.floor(getHeapStatistics().heap_size_limit / 5);

/** How far past that a file is read: a million lines of ones signed before, in a file anyone can add, cost little to pack. */
const MOST_READ_PAST = 8;

/** A line past this is no line of ours; they are about 340 bytes. */
const MOST_LINE_BYTES = 4096;

const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SEQ = /^(?:0|[1-9]\d{0,18})$/;
const HASH = /^[0-9a-f]{64}$/;
const ORGANISATION = 'organisation:';

/** Line kinds a later piece writes (a finished pass, a rebase), passed over here, so going back a release raises nothing. */
const LATER_KINDS: ReadonlySet<unknown> = new Set(['p', 'r']);

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

export interface AnchorLog extends AnchorStore {
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
}

/** A file made, not yet known to be in the store. Tried again under the same name, with the same bytes. */
interface Unsent {
  readonly kind: Kind;
  readonly name: string;
  readonly bytes: Buffer;
  readonly lines: readonly Anchor[];
}

const tooManySpoiled = (spoiled: number): string =>
  `no snapshot with every line sound, in the ${String(spoiled)} read: is an audit-anchor key version missing?`;

const countedDown = (ms: number): string => String(LAST_MS - ms).padStart(13, '0');

/** The time a file's name counts down from, as a time a person can look for in the store's own logs. */
const whenNamed = (countdown: string): string => new Date(LAST_MS - Number(countdown)).toISOString();

const lineOf = (anchor: Anchor): string =>
  JSON.stringify({
    k: 'a',
    chain: anchor.chain,
    seq: anchor.seq.toString(),
    hash: anchor.hash.toString('hex'),
    mk: anchor.macKeyVersion,
    at: anchor.at.toISOString(),
    kv: anchor.keyVersion,
    sig: anchor.signature.toString('base64'),
  });

const isCount = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

/** The anchor a parsed line says, if it is one in every field; its signature is checked after. */
function anchorFrom(line: Record<string, unknown>): Anchor | undefined {
  const { chain, seq, hash, mk, at, kv, sig } = line;
  if (typeof chain !== 'string' || !CHAIN.test(chain)) return undefined;
  if (typeof seq !== 'string' || !SEQ.test(seq)) return undefined;
  if (typeof hash !== 'string' || !HASH.test(hash)) return undefined;
  if (!isCount(mk) || !isCount(kv) || typeof at !== 'string' || typeof sig !== 'string') return undefined;
  const when = new Date(at);
  if (Number.isNaN(when.getTime()) || when.toISOString() !== at) return undefined;
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
 * A file's anchors, how many of its lines failed, whether it closes for its own name, and whether it went past `mostBytes`,
 * when it holds none: then its first wrong line, or an empty one, or going on too far, is thrown. Lines of a later piece's
 * kinds are neither sound nor failed.
 */
async function readFile(keys: KeyProvider, bytes: Buffer, name: string, epoch: number, mostBytes: number) {
  const opened = { bytes: 0 };
  const anchors: Anchor[] = [];
  let bad = 0;
  let body = 0;
  const judged = (fields: unknown): void => {
    body += 1;
    const kind = kindOf(fields);
    if (LATER_KINDS.has(kind)) return;
    const anchor = kind === 'a' ? anchorFrom(fields as Record<string, unknown>) : undefined;
    if (
      anchor === undefined ||
      !isSigned(keys, anchor.keyVersion, anchorMessage(anchor.chain, anchor, anchor.at, epoch), anchor.signature)
    ) {
      bad += 1;
    } else if (opened.bytes <= mostBytes) {
      anchors.push(anchor);
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
  return { anchors: past ? [] : anchors, bad, past, closed: closing && closes(keys, last, name, epoch, body) };
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

  /** A file's anchors, and whether it stands for what it should: every line sound and closed for its name. Anything wrong is the alarm. A failed call to the store is thrown. */
  const opened = async (kind: Kind, name: string): Promise<{ anchors: readonly Anchor[]; sound: boolean }> => {
    const bytes = await store.get(name);
    const fileAt = whenNamed(countdownOf(kind, name));
    let file: Awaited<ReturnType<typeof readFile>>;
    try {
      file = await readFile(keys, bytes, name, epoch, mostFileBytes);
    } catch (error) {
      alarm('file', { kind, fileAt, err: error });
      return { anchors: [], sound: false };
    }
    const { anchors: lines, bad, closed, past } = file;
    if (past) {
      if (bad === 0 && closed) throw new BeyondMemory(kind, fileAt);
      alarm('file', { kind, fileAt });
      return { anchors: [], sound: false };
    }
    if (bad > 0) alarm('signature', { kind, fileAt, lines: bad });
    if (!closed) alarm('unclosed', { kind, fileAt });
    return { anchors: lines, sound: bad === 0 && closed };
  };

  /**
   * The snapshots not read yet, newest first, back to the first with nothing wrong: `base`, the one deltas count from.
   * Thrown if none is left to stand for the whole, as with a failed call: what's in memory already does, once there is any.
   */
  const newerSnapshots = async (foreign: { count: number }) => {
    const lines: Anchor[] = [];
    let spoiled = 0;
    for await (const name of filesOf('snapshots', SNAPSHOTS_A_PAGE, foreign)) {
      const countdown = countdownOf('snapshots', name);
      if (snapshotFrom !== undefined && countdown >= snapshotFrom) break;
      if (spoiled > MOST_SPOILED_SNAPSHOTS) throw new Error(tooManySpoiled(spoiled));
      const file = await opened('snapshots', name);
      for (const line of file.anchors) lines.push(line);
      if (file.sound) return { lines, base: countdown, sound: countdown };
      spoiled += 1;
    }
    if (spoiled > 0 && snapshotFrom === undefined) throw new Error(tooManySpoiled(spoiled));
    return { lines, base: snapshotFrom, sound: undefined };
  };

  /**
   * Every delta this process didn't write, newer than the last it listed or, with
   * none yet, than the snapshot: one of the same millisecond may hold more than it.
   */
  const newerDeltas = async (snapshot: string | undefined, foreign: { count: number }) => {
    const lines: Anchor[] = [];
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
      const file = await opened('deltas', name);
      for (const line of file.anchors) lines.push(line);
      if (file.sound) newest ??= name;
    }
    return { lines, newest, files };
  };

  /** Highest place wins. The same place with another hash is the alarm, and the older stays: the chain then says which it holds. */
  const merge = (line: Anchor): void => {
    const held = anchors.get(line.chain);
    if (held === undefined || line.seq > held.seq) {
      anchors.set(line.chain, line);
      return;
    }
    if (line.seq !== held.seq) return;
    if (line.hash.equals(held.hash)) {
      // The same place signed again later: an idle chain checked since (anchor-check.ts).
      if (line.at > held.at) anchors.set(line.chain, line);
    } else {
      alarm('fork', { seq: line.seq }, line.chain);
      if (line.at < held.at) anchors.set(line.chain, line);
    }
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

  const catchUp = async (): Promise<void> => {
    try {
      const foreign = { count: 0 };
      const snapshots = await newerSnapshots(foreign);
      const deltas = await newerDeltas(snapshots.base, foreign);
      // Only now, with every call answered: a part read could look like a chain never anchored.
      for (const line of snapshots.lines) merge(line);
      for (const line of deltas.lines) merge(line);
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

  /** Into the store, or thrown. A name taken already holds this file if an answer was lost; if it holds anything else, that is the alarm. */
  const send = async (file: Unsent): Promise<void> => {
    try {
      await store.put(file.name, file.bytes);
    } catch (error) {
      if (!(error instanceof OverwriteRefused)) throw error;
      if (!(await store.get(file.name)).equals(file.bytes)) {
        alarm('overwrite', { kind: file.kind });
        // They go again under a new name, unless a later anchor of the chain is waiting already.
        for (const line of file.lines) if (!pending.has(line.chain)) pending.set(line.chain, line);
        unsent = undefined;
        return;
      }
    }
    unsent = undefined;
    if (file.kind === 'deltas') written.add(file.name);
    else {
      snapshotFrom = countdownOf('snapshots', file.name);
    }
    logger.info('audit.anchors_written', { kind: file.kind, lines: file.lines.length });
  };

  /** The next file to write: every chain's anchor when a snapshot is due, what moved otherwise. */
  const madeFile = async (): Promise<Unsent> => {
    const at = now().getTime();
    const lastSnapshot = snapshotFrom === undefined ? undefined : LAST_MS - Number(snapshotFrom);
    const kind: Kind = lastSnapshot === undefined || at - lastSnapshot >= SNAPSHOT_EVERY_MS ? 'snapshots' : 'deltas';
    const lines = kind === 'snapshots' ? [...anchors.values()] : [...pending.values()];
    const name = `${folder(kind)}${countedDown(at)}-${randomUUID()}`;
    const { signature, keyVersion } = keys.sign('audit-anchor', closingMessage(name, epoch, lines.length));
    const closing = JSON.stringify({
      k: 'c',
      name,
      epoch,
      lines: lines.length,
      kv: keyVersion,
      sig: signature.toString('base64'),
    });
    const bytes = await gzippedLines(
      (function* lined() {
        for (const line of lines) yield `${lineOf(line)}\n`;
        yield `${closing}\n`;
      })(),
    );
    // Only what this file holds: `keep` may have run while it was made.
    for (const line of lines) if (pending.get(line.chain) === line) pending.delete(line.chain);
    return { kind, name, bytes, lines };
  };

  const writeDue = async (): Promise<void> => {
    try {
      if (unsent !== undefined) await send(unsent);
      if (unsent === undefined && pending.size > 0) {
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

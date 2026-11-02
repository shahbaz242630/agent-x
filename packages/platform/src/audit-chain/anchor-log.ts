// The chains' anchors kept apart from the database (4D2e E, PL-58): every anchor
// the check signs goes to the write-once store, where someone with the database's
// keys can't reach it, so a chain wound back shows across a restart too. Tx A
// still reads this process's memory, with no trip.
//
// Files, gzipped lines, named so the newest lists first, under an epoch a
// sanctioned restore of the whole database moves on (AGENTX_ANCHOR_EPOCH):
//   e<epoch>/deltas/<inverted-ms>-<id>     what moved, at the end of a run
//   e<epoch>/snapshots/<inverted-ms>-<id>  every chain's anchor, hourly
// A restart reads the newest snapshot and every delta since: at the default
// interval, 2 lists and at most 13 gets. Each run then reads again whatever
// another process wrote, so a copy that takes the lease back holds what the
// one before it found. Nothing is written if nothing moved.
//
// Every line is signed with the `audit-anchor` key. A line that fails is skipped
// and is the alarm, never a hold. Two lines at one place with different hashes
// are the alarm too: the older is kept, and the chain's own check then says which
// it holds. Every chain in the store counts as seen, so an organisation taken off
// the list and the record is still missed. Whoever holds this store's add right
// runs as the API, with its signing key: nothing here guards against them.
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { gunzip as gunzipCallback, gzip as gzipCallback } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Logger } from '../observability/index.ts';
import { OverwriteRefused, type WriteOnceStore } from '../storage/write-once.ts';
import { type Anchor, type AnchorStore, anchorMessage } from './anchor.ts';
import { type Chain, chainName } from './chain.ts';

const gzip = promisify(gzipCallback);
const gunzip = promisify(gunzipCallback);

/** How often every chain's anchor is written whole, where something moved. */
const SNAPSHOT_EVERY_MS = 60 * 60_000;

/** What a file's name counts down from, so the newest lists first: 13 digits until the year 2286. */
const LAST_MS = 9_999_999_999_999;

/** A file's name after its folder: when, counted down, then an ID. Anything else in the folder isn't ours. */
const FILE = /^\d{13}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** How many names a list asks: a restart reads about a dozen deltas, and at most one snapshot unless some are spoiled. */
const SNAPSHOTS_A_PAGE = 5;
const DELTAS_A_PAGE = 100;

/** The most a file may open to: every line of 100,000 chains (MOST_ORGANIZATIONS) is about 30 MB. */
const MOST_FILE_BYTES = 64 * 1024 * 1024;

const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SEQ = /^(?:0|[1-9]\d{0,18})$/;
const HASH = /^[0-9a-f]{64}$/;
const ORGANISATION = 'organisation:';

/** Line kinds a later piece writes (a finished pass, a rebase), passed over here, so going back a release raises nothing. */
const LATER_KINDS: ReadonlySet<unknown> = new Set(['p', 'r']);

type Kind = 'deltas' | 'snapshots';

export interface AnchorLog extends AnchorStore {
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

/** Whether the signature is the one for the anchor. A version this process doesn't hold is simply wrong. */
function isSigned(keys: KeyProvider, anchor: Anchor): boolean {
  try {
    return keys.verifySignature(
      'audit-anchor',
      anchor.keyVersion,
      anchorMessage(anchor.chain, anchor, anchor.at),
      anchor.signature,
    );
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

/** A file's anchors, and how many of its lines failed. Lines of a later piece's kinds are neither. */
function readLines(keys: KeyProvider, text: string): { readonly anchors: Anchor[]; readonly bad: number } {
  const anchors: Anchor[] = [];
  let bad = 0;
  for (const line of text.split('\n')) {
    if (line === '') continue;
    const fields = parsed(line);
    const kind = typeof fields === 'object' && fields !== null && 'k' in fields ? fields.k : undefined;
    if (LATER_KINDS.has(kind)) continue;
    const anchor = kind === 'a' ? anchorFrom(fields as Record<string, unknown>) : undefined;
    if (anchor !== undefined && isSigned(keys, anchor)) anchors.push(anchor);
    else bad += 1;
  }
  return { anchors, bad };
}

/** The anchors held durable, read and written through `store`, and in memory for Tx A. */
export function createAnchorLog({
  store,
  keys,
  logger,
  now,
  epoch,
  unwritableAfterMs,
}: {
  readonly store: WriteOnceStore;
  readonly keys: KeyProvider;
  readonly logger: Logger;
  readonly now: () => Date;
  /** AGENTX_ANCHOR_EPOCH: a sanctioned restore of the whole database starts a new one. */
  readonly epoch: number;
  /** How long writes may fail before that is the alert, not just a warning. */
  readonly unwritableAfterMs: number;
}): AnchorLog {
  const folder = (kind: Kind): string => `e${String(epoch)}/${kind}/`;
  const anchors = new Map<string, Anchor>();
  // What has moved since it was last written: one line a chain at most, however long the store stays away.
  const pending = new Map<string, Anchor>();
  let unsent: Unsent | undefined;

  let state: 'unread' | 'read' | 'unreadable' = 'unread';
  let reading: Promise<void> | undefined;
  let flushing: Promise<void> | undefined;
  // The newest delta listed, by name, and the newest snapshot read or written, as counted down: older ones have nothing new.
  let deltasFrom: string | undefined;
  let snapshotFrom: string | undefined;
  // Deltas this process wrote since it last listed: nothing to read in them.
  const written = new Set<string>();
  let failingSince: number | undefined;

  /** The alarm, on a line naming the chain's organisation where it has one. */
  const alarm = (reason: string, more: Record<string, unknown>, chain?: string): void => {
    const log =
      chain?.startsWith(ORGANISATION) === true ? logger.child({ orgId: chain.slice(ORGANISATION.length) }) : logger;
    log.error('audit.integrity_failed', { chain: 'store', check: 'anchor_store', reason, ...more });
  };

  /** Every well-named file of a kind, newest first. Anything else there is counted in `foreign`. */
  async function* filesOf(kind: Kind, most: number, foreign: { count: number }): AsyncGenerator<string> {
    const start = folder(kind);
    let after: string | undefined;
    do {
      const page = await store.list(start, most, after);
      foreign.count += page.foreign;
      for (const name of page.names) {
        if (FILE.test(name.slice(start.length))) yield name;
        else foreign.count += 1;
      }
      after = page.next;
    } while (after !== undefined);
  }

  const countdownOf = (kind: Kind, name: string): string => name.slice(folder(kind).length, folder(kind).length + 13);

  /** A file's anchors, or nothing where it won't open, which is the alarm. A failed call to the store is thrown. */
  const opened = async (kind: Kind, name: string): Promise<readonly Anchor[] | undefined> => {
    const bytes = await store.get(name);
    const fileAt = whenNamed(countdownOf(kind, name));
    let text: string;
    try {
      text = (await gunzip(bytes, { maxOutputLength: MOST_FILE_BYTES })).toString('utf8');
    } catch (error) {
      alarm('file', { kind, fileAt, err: error });
      return undefined;
    }
    const lines = readLines(keys, text);
    if (lines.bad > 0) alarm('signature', { kind, fileAt, lines: lines.bad });
    return lines.anchors;
  };

  /** The newest snapshot not read yet that opens: a spoiled one must not hide the one before it. */
  const newerSnapshot = async (foreign: { count: number }) => {
    for await (const name of filesOf('snapshots', SNAPSHOTS_A_PAGE, foreign)) {
      const countdown = countdownOf('snapshots', name);
      if (snapshotFrom !== undefined && countdown >= snapshotFrom) return undefined;
      const lines = await opened('snapshots', name);
      if (lines !== undefined) return { countdown, lines };
    }
    return undefined;
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
      newest ??= name;
      if (written.delete(name)) continue;
      files += 1;
      lines.push(...((await opened('deltas', name)) ?? []));
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
    if (line.seq === held.seq && !line.hash.equals(held.hash)) {
      alarm('fork', { seq: line.seq }, line.chain);
      if (line.at < held.at) anchors.set(line.chain, line);
    }
  };

  const readFailed = (error: unknown): void => {
    if (state === 'read') {
      logger.warn('audit.anchor_store_read_failed', { err: error });
      return;
    }
    state = 'unreadable';
    logger.error('audit.anchor_store_unreadable', { err: error });
  };

  const catchUp = async (): Promise<void> => {
    try {
      const foreign = { count: 0 };
      const snapshot = await newerSnapshot(foreign);
      const deltas = await newerDeltas(snapshot?.countdown ?? snapshotFrom, foreign);
      // Only now, with every call answered: a part read could look like a chain never anchored.
      for (const line of snapshot?.lines ?? []) merge(line);
      for (const line of deltas.lines) merge(line);
      if (snapshot !== undefined) snapshotFrom = snapshot.countdown;
      if (deltas.newest !== undefined) deltasFrom = deltas.newest;
      if (foreign.count > 0) logger.warn('audit.anchor_store_foreign', { files: foreign.count });
      if (state !== 'read') {
        logger.info('audit.anchors_read', {
          epoch,
          chains: anchors.size,
          snapshot: snapshot !== undefined,
          deltas: deltas.files,
        });
      }
      state = 'read';
    } catch (error) {
      readFailed(error);
    }
  };

  const writeFailed = (error: unknown): void => {
    const at = now().getTime();
    failingSince ??= at;
    logger.warn('audit.anchor_store_write_failed', { err: error });
    if (at - failingSince >= unwritableAfterMs) {
      logger.error('audit.anchor_store_unwritable', { forMs: at - failingSince });
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
    else snapshotFrom = countdownOf('snapshots', file.name);
    logger.info('audit.anchors_written', { kind: file.kind, lines: file.lines.length });
  };

  /** The next file to write: every chain's anchor when a snapshot is due, what moved otherwise. */
  const madeFile = async (): Promise<Unsent> => {
    const at = now().getTime();
    const lastSnapshot = snapshotFrom === undefined ? undefined : LAST_MS - Number(snapshotFrom);
    const kind: Kind = lastSnapshot === undefined || at - lastSnapshot >= SNAPSHOT_EVERY_MS ? 'snapshots' : 'deltas';
    const lines = kind === 'snapshots' ? [...anchors.values()] : [...pending.values()];
    const bytes = await gzip(`${lines.map(lineOf).join('\n')}\n`);
    // Only what this file holds: `keep` may have run while it was made.
    for (const line of lines) if (pending.get(line.chain) === line) pending.delete(line.chain);
    return { kind, name: `${folder(kind)}${countedDown(at)}-${randomUUID()}`, bytes, lines };
  };

  const writeDue = async (): Promise<void> => {
    try {
      if (unsent !== undefined) await send(unsent);
      if (unsent === undefined && pending.size > 0) {
        unsent = await madeFile();
        await send(unsent);
      }
      failingSince = undefined;
    } catch (error) {
      writeFailed(error);
    }
  };

  return Object.freeze({
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

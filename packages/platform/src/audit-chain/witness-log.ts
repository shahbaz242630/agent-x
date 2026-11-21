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
// A name dated past the clock is the alarm and passed over.
//
// Writing (group commit): a `now` head (a stop, an approval, every class but the decision path's: witness-class.ts) is
// written at once, at most one Put in flight a process, each taking every head waiting; `now` resolves once a Put holding
// it succeeded. A `soon` head (an agent's decision) waits for the next flush, every few seconds while any waits, and at
// a stop. A Put that fails is tried again, backing off; a `now` waiter gives up after `waitMs` (`WitnessUnconfirmed`,
// the request answered 503), but its head stays queued, and every later wait for that chain on this process waits for
// it too: nothing that chain does here is told it succeeded before the head is outside the database.
//
// Reading: a coalesced `refresh` (a caller waits for the next that starts after its call) lists each heads folder
// newest-first to what it read already, less five minutes for the clocks and late writes; a start reads the newest sound
// snapshot first (passing over at most a day's spoiled ones), then every heads file since, less the same; with no sound
// snapshot, a day of heads files back (a head older than that above its chain's anchor means the anchor check has been
// stalled a day, its own alarm).
//
// Held: every head read or noted above its chain's latest anchor (`pending`, a list per chain, never only the highest: a
// stale copy's head on a cut branch must not bury the honest one below it), set aside by a rebase dated after it, and
// let go at or below the chain's anchor (the anchor check refuses to anchor through a head missing on its walk, and
// prunes once it has). Bounded: past what may be held, a chain's lowest heads go first, loudly, and that chain reads as
// `beyondMemory` until anchored past them (its hand-offs wait).
import type { KeyProvider } from '../keys/key-provider.ts';
import type { Logger } from '../observability/index.ts';
import type { WriteOnceStore } from '../storage/write-once.ts';
import { type Chain, chainName } from './chain.ts';
import { timeIn } from './rebase.ts';
import { bodyLines, fileName, type FileKind, isSoundFile, namesIn, signedFile, timeOfName } from './signed-files.ts';

/** A head a copy wrote, as witnessed: its place, its event's hash, and when it was noted (the writer's clock). */
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
  latest(chain: Chain): { readonly seq: bigint } | undefined;
}

export interface WitnessLog extends ChainWitness {
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
  /** When the last refresh that ended whole began: none before one has. */
  freshAt(): Date | undefined;
  /** The chain's heads at or below `upToSeq` let go: the anchor check found each on its walk and anchored past them. */
  prune(chain: Chain, upToSeq: bigint): void;
  /** Whether a head of the chain above its anchor was let go for memory: its hand-offs wait until anchored past it. */
  beyondMemory(chain: Chain): boolean;
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

/** How far back a start with no sound snapshot reads heads files: a day, far past any anchor's turn. */
const NO_SNAPSHOT_READ_BACK_MS = 24 * 60 * 60_000;

/** How many spoiled snapshots a start goes back past: a day's at one an hour. */
const MOST_SPOILED_SNAPSHOTS = 24;

/** How often the leader writes a snapshot. */
const SNAPSHOT_EVERY_MS = 60 * 60_000;

/** The most lines one heads file carries: more wait for the next Put. */
const MOST_LINES_A_FILE = 10_000;

/** The most a heads file or snapshot may hold to be fetched. */
const MOST_FILE_BYTES = 64 * 1024 * 1024;

/** What one head held takes, generously: the list's entry, a 32-byte hash, its place and time. */
export const WITNESS_HEAD_BYTES = 64;

/** A failed Put's first wait before the next try, doubling to RETRY_MOST_MS. */
const RETRY_FIRST_MS = 100;
const RETRY_MOST_MS = 5_000;

/** How often a chain past memory says so again. */
const SAY_EVERY_MS = 60_000;

const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SEQ = /^[1-9]\d{0,18}$/;
const HASH = /^[0-9a-f]{64}$/;

/** A line of a heads file or snapshot: one chain's head. */
interface HeadLine {
  readonly chain: string;
  readonly head: WitnessedHead;
}

function lineFrom(fields: unknown): HeadLine | undefined {
  if (typeof fields !== 'object' || fields === null) return undefined;
  const { c, s, h, t, ...rest } = fields as Record<string, unknown>;
  const at = timeIn(t);
  if (Object.keys(rest).length > 0 || typeof c !== 'string' || !CHAIN.test(c) || at === undefined) return undefined;
  if (typeof s !== 'string' || !SEQ.test(s) || typeof h !== 'string' || !HASH.test(h)) return undefined;
  return { chain: c, head: { seq: BigInt(s), hash: Buffer.from(h, 'hex'), at: at.getTime() } };
}

const lineText = (chain: string, { seq, hash, at }: WitnessedHead): string =>
  JSON.stringify({ c: chain, s: seq.toString(), h: hash.toString('hex'), t: new Date(at).toISOString() });

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
  readonly head: WitnessedHead;
  readonly klass: WitnessClass;
  readonly confirmed: Promise<void>;
  readonly done: () => void;
}

export function createWitnessLog({
  store,
  snapshots,
  keys,
  logger,
  now,
  epoch,
  signer = 'app',
  writes,
  alertAfterMs,
  mostBytes,
  waitMs = WAIT_MS,
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
}): WitnessLog {
  const folder = (kind: 'heads' | 'operator' | 'snapshots'): string => `e${String(epoch)}/${kind}/`;
  const ownFolder = signer === 'operator' ? folder('operator') : folder('heads');
  const ownKind = signer === 'operator' ? OPERATOR_FILE : HEADS_FILE;
  const mostHeads = Math.max(1, Math.floor(mostBytes / WITNESS_HEAD_BYTES));
  let anchors: WitnessAnchors | undefined;

  // Every head held, by chain, and how many in all.
  const held = new Map<string, WitnessedHead[]>();
  let heldCount = 0;
  // A chain's highest head let go for memory, and when that was last said.
  const lost = new Map<string, bigint>();
  let lostSaidAt: number | undefined;

  // Heads waiting for their Put, and each chain's `now` heads not yet written.
  let queue: Queued[] = [];
  const unconfirmed = new Map<string, Set<Queued>>();
  let writing: Promise<void> | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let failedWrites = 0;
  let lastFailedAt = 0;
  let writeFailingSince: number | undefined;

  let state: 'unread' | 'read' = 'unread';
  let freshAt: Date | undefined;
  let refreshing: Promise<Refreshed> | undefined;
  let refreshNext: Promise<Refreshed> | undefined;
  let readFailingSince: number | undefined;
  // The newest heads file read or written, by its name's time, and the names read since a look back past it.
  let headsFrom: number | undefined;
  const namesRead = new Set<string>();
  let lastSnapshotAt: number | undefined;
  let changedSinceSnapshot = false;

  const alarm = (reason: string, more: Record<string, unknown>): void => {
    logger.error('audit.integrity_failed', { chain: 'store', check: 'witness_store', reason, ...more });
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

  /** Whether a head is still held: above the chain's anchor, and not dated before a rebase of the chain. */
  const stands = (name: string, head: WitnessedHead): boolean => {
    const anchored = anchoredAt(name);
    if (anchored !== undefined && head.seq <= anchored) return false;
    return anchors?.rebasedAfter(chainOfName(name), new Date(head.at)) !== true;
  };

  /** Past what may be held, the chain holding most lets its lowest head go: said, and the chain marked. */
  const giveWay = (): void => {
    while (heldCount > mostHeads) {
      let largest: [string, WitnessedHead[]] | undefined;
      for (const entry of held) if (largest === undefined || entry[1].length > largest[1].length) largest = entry;
      if (largest === undefined) return;
      const [name, list] = largest;
      const lowest = list.pop();
      heldCount -= 1;
      if (list.length === 0) held.delete(name);
      const before = lost.get(name) ?? 0n;
      if (lowest !== undefined && lowest.seq > before) lost.set(name, lowest.seq);
      const at = now().getTime();
      if (lostSaidAt === undefined || at - lostSaidAt >= SAY_EVERY_MS) {
        lostSaidAt = at;
        logger.error('audit.witness_beyond_memory', { heads: heldCount, mostHeads, chain: name });
      }
    }
  };

  /** A head into the chain's list, the highest first, once each: whether it was new. */
  const keep = (name: string, head: WitnessedHead): boolean => {
    if (!stands(name, head)) return false;
    const list = held.get(name) ?? [];
    if (list.some(({ seq, hash }) => seq === head.seq && hash.equals(head.hash))) return false;
    const place = list.findIndex(({ seq }) => seq < head.seq);
    list.splice(place < 0 ? list.length : place, 0, head);
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
    // Highest first: those at or below the anchor are the list's tail, let go from its end.
    const anchored = anchoredAt(name);
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

  /** The queue's first file's worth written: whether it was. Taken back into the queue where it wasn't. */
  const writeOnce = async (): Promise<boolean> => {
    const taking = queue.slice(0, MOST_LINES_A_FILE);
    queue = queue.slice(taking.length);
    try {
      const at = now().getTime();
      const name = fileName(ownFolder, at);
      const bytes = await signedFile(
        keys,
        ownKind,
        name,
        epoch,
        taking.map(({ chain, head }) => lineText(chain, head)),
      );
      await store.put(name, bytes);
      namesRead.add(name);
      headsFrom = Math.max(headsFrom ?? at, at);
      for (const queued of taking) {
        unconfirmed.get(queued.chain)?.delete(queued);
        if (unconfirmed.get(queued.chain)?.size === 0) unconfirmed.delete(queued.chain);
        queued.done();
      }
      writeFailingSince = undefined;
      failedWrites = 0;
      return true;
    } catch (error) {
      queue = [...taking, ...queue];
      failedWrites += 1;
      lastFailedAt = now().getTime();
      failed('write', error);
      return false;
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
    const head: WitnessedHead = { seq, hash: Buffer.from(hash), at: now().getTime() };
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
    name: string,
    kind: FileKind,
    gained: Set<string>,
  ): Promise<boolean> => {
    const got = await from.getAtMost(name, MOST_FILE_BYTES);
    if (got === 'missing') throw new Error('a witness file listed and then not there');
    if (
      typeof got === 'string' ||
      !(await isSoundFile(keys, kind, got, name, epoch, (f) => lineFrom(f) !== undefined))
    ) {
      return false;
    }
    for await (const fields of bodyLines(got)) {
      const line = lineFrom(fields);
      if (line !== undefined && keep(line.chain, line.head)) gained.add(line.chain);
    }
    return true;
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
    );

  /** The newest sound snapshot taken in, and its time; none with no snapshots' store, or none sound a day back. */
  const readSnapshot = async (gained: Set<string>): Promise<number | undefined> => {
    if (snapshots === undefined) return undefined;
    let spoiled = 0;
    for await (const { name, at } of namesOf(snapshots, folder('snapshots'))) {
      if (await takeFile(snapshots, name, SNAPSHOT_FILE, gained)) return at;
      spoiled += 1;
      alarm('spoiled', { folder: 'snapshots', fileAt: new Date(at).toISOString() });
      if (spoiled >= MOST_SPOILED_SNAPSHOTS) return undefined;
    }
    return undefined;
  };

  /** Every heads file of both folders named at or after `since`, not read yet, each under its own folder's key. */
  const readHeads = async (since: number, gained: Set<string>): Promise<void> => {
    for (const [at, kind] of [
      [folder('heads'), HEADS_FILE],
      [folder('operator'), OPERATOR_FILE],
    ] as const) {
      for await (const file of namesOf(store, at)) {
        if (file.at < since) break;
        if (namesRead.has(file.name)) continue;
        if (!(await takeFile(store, file.name, kind, gained))) {
          alarm('spoiled', { folder: at, fileAt: new Date(file.at).toISOString() });
        }
        namesRead.add(file.name);
        headsFrom = Math.max(headsFrom ?? file.at, file.at);
      }
    }
  };

  const refreshOnce = async (): Promise<Refreshed> => {
    const began = now();
    const gained = new Set<string>();
    try {
      if (state === 'read') {
        await readHeads((headsFrom ?? began.getTime()) - LAG_MS, gained);
      } else {
        const snapshot = await readSnapshot(gained);
        if (snapshot !== undefined) lastSnapshotAt = snapshot;
        await readHeads(
          snapshot === undefined ? began.getTime() - NO_SNAPSHOT_READ_BACK_MS : snapshot - LAG_MS,
          gained,
        );
        state = 'read';
      }
      // Names older than any later look back reaches need no remembering.
      const keepFrom = (headsFrom ?? 0) - 2 * LAG_MS;
      for (const name of namesRead) {
        const countdown = name.slice(name.lastIndexOf('/') + 1, name.lastIndexOf('/') + 14);
        if (timeOfName(countdown) < keepFrom) namesRead.delete(name);
      }
      readFailingSince = undefined;
      freshAt = began;
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

  /** The whole held, as a snapshot, where this copy leads, hourly and only after a whole read. */
  const snapshotOnce = async (): Promise<void> => {
    if (snapshots === undefined || writes?.() !== true || state !== 'read' || !changedSinceSnapshot) return;
    const at = now().getTime();
    if (lastSnapshotAt !== undefined && at - lastSnapshotAt < SNAPSHOT_EVERY_MS) return;
    try {
      const name = fileName(folder('snapshots'), at);
      const lines: string[] = [];
      for (const name of held.keys()) for (const head of standing(name)) lines.push(lineText(name, head));
      await snapshots.put(name, await signedFile(keys, SNAPSHOT_FILE, name, epoch, lines));
      lastSnapshotAt = at;
      changedSinceSnapshot = false;
    } catch (error) {
      failed('write', error);
    }
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
    prune(chain: Chain, upToSeq: bigint): void {
      const name = nameOf(chain);
      const list = held.get(name);
      if (list !== undefined) {
        const kept = list.filter(({ seq }) => seq > upToSeq);
        heldCount -= list.length - kept.length;
        if (kept.length === 0) held.delete(name);
        else held.set(name, kept);
      }
      if ((lost.get(name) ?? 0n) <= upToSeq) lost.delete(name);
    },
    beyondMemory(chain: Chain): boolean {
      const name = nameOf(chain);
      const seq = lost.get(name);
      if (seq === undefined) return false;
      const anchored = anchoredAt(name);
      if (anchored !== undefined && seq <= anchored) {
        lost.delete(name);
        return false;
      }
      return true;
    },
    useAnchors(given: WitnessAnchors): void {
      anchors = given;
    },
    state: () => state,
  });
}

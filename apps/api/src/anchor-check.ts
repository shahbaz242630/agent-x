// The anchor check (ADR-012 §2, SEC-DB-11): every few minutes the API checks
// each audit chain whole against its last anchor, kept in this process's
// memory and, deployed, in the write-once store (anchor-log.ts, PL-58), and
// anchors it again. A chain wound back to an earlier state, or grown again on a
// wound-back head, passes its own seals; only the anchor, held apart from the
// database, shows it.
//
// A run first reads the store, then checks, writing what moved each minute and
// at its end. A store that
// can't be read after a restart means no chain is anchored for the first time,
// every organisation's payments wait (`anchor_pending`), the seals are still
// checked and decisions go on; one that can't be written is a warning and in time
// the store's own alert, never a hold. As the API stops, or the lease goes, what
// moved is written within a few seconds; after a crash, what's kept is at most a
// minute behind, and one store write.
//
// A run is bounded (4D2e E6). Organisations' chains are checked side by side, a few
// lanes of them (AGENTX_AUDIT_ANCHOR_LANES), so one slow or locked organisation
// holds its own lane and nobody else's; one seen to be slow keeps to a single lane
// from then on (anchor-turns.ts). A run stops at four minutes, ends with its line
// whatever is under way, and the next goes on from where it stopped. So the check's
// line comes at most every 10 minutes at the default interval: 5 between runs, 4 of
// run, 1 for the last write. With lines up to 9 minutes late, the 20 minutes the
// outside's dead-man rule allows hold (D3). Every organisation's turn comes within
// seven runs' time (63 minutes at the default), and in one run wherever the lanes get
// through them all; a chain that fails is caught at its turn. Past that bound it is
// the alarm, by count, naming the first few (`unreached`). A chain whose anchor
// landed during its check goes first next run, so its alarm comes within one interval
// and one run: 9 minutes at the default.
//
// A chain that fails raises the integrity alarm (`audit.integrity_failed`; its
// SEV-1 alert rule is A2c-2) and keeps its last good anchor, so the alarm
// repeats every run until someone looks. Someone with the database's keys can
// also try to stop the check from finishing: so a database that refuses the
// check (a right, a table or a
// column gone) is the alarm too, and so is a chain left unchecked for three
// intervals. Anything else that stops a check (the database unreachable, or
// a check past its deadline) is a warning until then. Every run ends with one
// line, so a check that has stopped can be told from one with nothing to say.
// The platform chain is checked every run; each organisation's chain too,
// found from the directory's list at each run (B1d-2). The list is held to
// what the platform chain records: every organisation created there
// (`organization.created`, sealed, so one deleted breaks the platform chain's
// own check) must be listed, and so must every one this process has seen
// listed, and every one with a chain in the store. One missing is the alarm
// (`unlisted`): the app never deletes an entry, so one gone is tampering, and
// its chain would otherwise never be checked again. A list the database refuses, or one
// that isn't IDs, or too many of them, is the alarm (`list`); a list that
// can't be read otherwise is a warning until three intervals pass without one.
// An organisation whose chain fails is put on its integrity hold (B1d-3),
// naming the alarm's reason, and each run tries again a hold this process
// could not record yet: an unlisted organisation's too, since its chain is
// still reached by its ID. A chain left unchecked too long is the alarm but
// no hold: that is as often the database slow or away as anything done to
// it, and a hold on every organisation at once, each cleared only by its
// own admin, would do an attacker's work for them. People look at the alarm.
import type { Clock } from '@agentx/core/shared-kernel';
import {
  type Anchor,
  type AnchorLog,
  type AnchorPoint,
  type AnchorStore,
  type Chain,
  type ChainReport,
  ChainStoreError,
  type CheckedPoint,
  createMemoryAnchorStore,
  signAnchor,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { createTurns } from './anchor-turns.ts';
import { scheduleRuns, Stopped, withinDeadline } from './background.ts';

/** A chain the check covers, and how to check it against its last anchor, if it has one. */
export interface CheckedChain {
  readonly chain: Chain;
  readonly verify: (anchor: AnchorPoint | undefined) => Promise<ChainReport>;
}

export interface AnchorCheck {
  /**
   * Checks the platform's chain, then as many organisations' as its time allows,
   * going on from where the last run stopped, and ends at once when `signal` aborts
   * or its time is up. Never throws: every outcome is logged.
   */
  run(signal?: AbortSignal): Promise<void>;
  /**
   * One organisation's chain checked and anchored now, as a run would (its
   * alarm and hold too): for the hand-off, which compares every payment with
   * the chain's anchor and so can't wait for the next run after a restart
   * (gate H11, partner S146). With the store unreadable it makes no anchor, so
   * the payment waits. Never throws.
   */
  anchorOrganisation(orgId: string, signal?: AbortSignal): Promise<void>;
  /** Writes what has moved as the API stops, within a few seconds whatever the store does. Never throws. */
  finish(): Promise<void>;
}

/** Where the organisations' chains come from (B1d-2). */
export interface OrganisationChains {
  /** Every organisation the directory lists, by ID. */
  list(): Promise<readonly string[]>;
  /** Every organisation the platform chain records as created, by ID: each must be listed. */
  recorded(): Promise<readonly string[]>;
  /** Checks one organisation's chain against its last anchor, if it has one. */
  verify(orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport>;
  /**
   * Puts the organisation on its integrity hold for how its chain failed (the
   * alarm's reason), or, given none, tries again a hold waiting in this
   * process for it, if one is. Never throws: every outcome is logged (B1d-3).
   */
  hold(orgId: string, failure: string | undefined): Promise<void>;
}

export interface AnchorCheckOptions {
  /** The chains checked every run: the platform's. */
  readonly chains: readonly CheckedChain[];
  /** The organisations' chains, listed afresh each run. None when not given. */
  readonly organizations?: OrganisationChains;
  readonly keys: KeyProvider;
  readonly clock: Clock;
  readonly logger: Logger;
  /** How long a chain may go without a completed check before that is the alarm too, where a run reaches them all. */
  readonly staleAfterMs: number;
  /** The same for an organisation's chain while runs aren't reaching them all, and how long one may wait for its turn. Past it, the alarm. As `staleAfterMs` unless given. */
  readonly reachWithinMs?: number;
  /**
   * How long one chain's check may take. Postgres's own limits can be got round
   * by someone who owns the database, and a connection can die without a word,
   * so the app keeps its own: a check past it has not completed.
   */
  readonly deadlineMs: number;
  readonly anchors?: AnchorStore;
  /** The same anchors, where they are kept durable: read and written around each run. None in development with no store. */
  readonly durable?: AnchorLog;
  /** How long the last write may take as the API stops: the store's calls may take 30 seconds, and the stop has 25 in all. */
  readonly stopFlushMs?: number;
  /** How many organisations are checked at once. */
  readonly lanes?: number;
  /** How long a run may go on. */
  readonly runWithinMs?: number;
  /** How often a run writes what has moved so far. */
  readonly writeEveryMs?: number;
}

/** See `stopFlushMs`. */
const STOP_FLUSH_MS = 5_000;

/** See `lanes`. Each holds a connection for a check, and none across a call to the store. */
const LANES = 4;

/**
 * See `runWithinMs`. Not the interval's double: lines are up to 9 minutes late, so 10 minutes of run and 5 between would
 * read as stopped under the dead-man rule's 20 (the header).
 */
export const RUN_WITHIN_MS = 240_000;

/** See `writeEveryMs`: a crash loses at most this much, and a store gone is known this soon. */
const WRITE_EVERY_MS = 60_000;

/** How long a run's write may take: two of the store's calls at 30 seconds, a file unsent and a new one. */
const WRITE_WITHIN_MS = 60_000;

/** How many runs' time an organisation may wait for its turn. */
const RUNS_FOR_A_TURN = 7;

/** How long an organisation may wait for its turn, at this interval between runs: the answer for `reachWithinMs`. */
export const reachWithin = (intervalMs: number): number => RUNS_FOR_A_TURN * (intervalMs + RUN_WITHIN_MS);

/** How many IDs the `unreached` alarm names. The count is the whole of it; any more would be a very long line. */
const UNREACHED_NAMED = 20;

/**
 * Postgres's refusals that only a changed database gives the app's role: a
 * right taken away, a table or a column gone. The check can't be run until
 * someone puts them back, which is itself the alarm.
 */
const CHANGED_DATABASE = new Set(['42501', '42P01', '42703']);

/**
 * How many organisations a list may hold before it is read as padded. Each one
 * this process has seen holds about 885 bytes for its life (measured, S168), so
 * 100,000 is about 88 MB, which the API's 1 GiB can carry; a million would not
 * fit. Ten times the 10k accounts we plan for (4D2e); entries are never deleted.
 */
export const MOST_ORGANIZATIONS = 100_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The IDs in lower case, or nothing if any isn't a UUID given as text, or there are too many. */
function organisationIds(ids: unknown): string[] | undefined {
  if (!Array.isArray(ids) || ids.length > MOST_ORGANIZATIONS) return undefined;
  const checked: string[] = [];
  for (const id of ids as unknown[]) {
    if (typeof id !== 'string' || !UUID.test(id)) return undefined;
    checked.push(id.toLowerCase());
  }
  return checked;
}

const refusedByDatabase = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'code' in error && CHANGED_DATABASE.has(String(error.code));

/** Whether a chain's head is at or past its anchor, and at it, the same event. */
const stillHolds = (head: CheckedPoint, anchor: AnchorPoint): boolean =>
  head.seq > anchor.seq || (head.seq === anchor.seq && head.hash.equals(anchor.hash));

/** `unanchored`: checked and sound, and not anchored: the store is yet to be read, or landed during the check. */
type Outcome = 'anchored' | 'unchanged' | 'unanchored' | 'failed' | 'unchecked';

/** The in-flight key of the organisations' list, which no chain's key can be. */
const LIST = 'list';

export function createAnchorCheck({
  chains,
  organizations,
  keys,
  clock,
  logger,
  staleAfterMs,
  reachWithinMs = staleAfterMs,
  deadlineMs,
  durable,
  anchors = durable ?? createMemoryAnchorStore(),
  stopFlushMs = STOP_FLUSH_MS,
  lanes = LANES,
  runWithinMs = RUN_WITHIN_MS,
  writeEveryMs = WRITE_EVERY_MS,
}: AnchorCheckOptions): AnchorCheck {
  // From when this process began, so a check that never once completes is caught too.
  const started = clock.now().getTime();
  const lastChecked = new Map<string, number>();
  // Each organisation's alarm reason this run, until its hold is tried.
  const failures = new Map<string, string>();
  const keyOf = (chain: Chain): string => (chain.kind === 'platform' ? 'platform' : chain.orgId);
  // Chains whose check is still under way past its deadline: one each at most, so a hung database can't take every connection.
  const inFlight = new Set<string>();
  // Every organisation this process has seen listed or recorded, so one that leaves the list is noticed.
  const seen = new Set<string>();
  // When each organisation was first seen, so its stale period starts then, not when the process began.
  const firstSeen = new Map<string, number>();
  // When the list was last read whole, so a list never read is the alarm in time too.
  let listRead: number | undefined;
  /** The time a chain's stale period counts from. */
  const since = (key: string): number => lastChecked.get(key) ?? firstSeen.get(key) ?? started;
  const turns = createTurns(lanes);
  // Whether the last run left organisations waiting, so a chain's last check may rightly be longer ago than a run's.
  let spreading = false;
  let leftLastRun = false;
  /** How long this chain may go unchecked: the platform's stays short, as a run always comes to it. */
  const staleLimit = (key: string): number => (spreading && key !== 'platform' ? reachWithinMs : staleAfterMs);
  /** Whether it has gone unchecked past that. */
  const isStale = (key: string): boolean => clock.now().getTime() - since(key) >= staleLimit(key);

  /** Whether a chain's first anchor must wait: it could hide a chain wound back until the store has been read. */
  const storeUnread = (): boolean => durable !== undefined && durable.state() !== 'read';

  /** A chain's integrity alarm on its own line, its reason kept for its hold. */
  const alarmed = (chain: Chain, log: Logger, reason: string, seq?: bigint): Outcome => {
    if (chain.kind === 'organisation') failures.set(keyOf(chain), reason);
    const held = anchors.latest(chain);
    log.error('audit.integrity_failed', {
      chain: chain.kind,
      check: 'anchor',
      reason,
      ...(seq === undefined ? {} : { seq }),
      ...(held === undefined ? {} : { anchorSeq: held.seq }),
    });
    return 'failed';
  };

  /** What a completed check comes to: the alarm, nothing moved, or the chain anchored where it stands. */
  const afterCheck = (chain: Chain, log: Logger, report: ChainReport, last: Anchor | undefined): Outcome => {
    if (!report.ok) return alarmed(chain, log, report.problem.reason, report.problem.seq);
    // A store's read past its deadline, or another copy's anchor, can land during the check, and the head read before
    // it says nothing against it: an honest copy may have moved on since. The next run compares with it, the alarm a run
    // late at most, one interval and that run's length; Tx A compares with it at once, so a payment is refused meanwhile.
    if (anchors.latest(chain) !== last) return 'unanchored';
    // The check compared the anchored event already; this backs it up should a store not pass the anchor on.
    if (last !== undefined && !stillHolds(report, last)) return alarmed(chain, log, 'anchor', last.seq);
    if (last?.seq === report.seq) return 'unchanged';
    if (storeUnread()) return 'unanchored';
    const anchor = signAnchor(keys, chain, report, clock.now(), durable?.epoch);
    anchors.keep(anchor);
    log.info('audit.anchored', {
      chain: chain.kind,
      seq: report.seq,
      headHash: report.hash.toString('hex'),
      keyVersion: anchor.keyVersion,
    });
    return 'anchored';
  };

  const checkOne = async ({ chain, verify }: CheckedChain, signal: AbortSignal | undefined): Promise<Outcome> => {
    // An organisation's ID goes on the line as the logger's own field, which an event can't set.
    const log = chain.kind === 'platform' ? logger : logger.child({ orgId: chain.orgId });
    const key = keyOf(chain);
    try {
      const last = anchors.latest(chain);
      const alarm = (reason: string, seq?: bigint): Outcome => alarmed(chain, log, reason, seq);
      let report: ChainReport;
      try {
        if (inFlight.has(key)) throw new Error('the last check of this chain has not finished');
        inFlight.add(key);
        const checking = Promise.resolve().then(() => verify(last));
        // Handled here too, so a check that ends after its deadline never goes unhandled.
        void checking.then(
          () => inFlight.delete(key),
          () => inFlight.delete(key),
        );
        report = await withinDeadline(checking, deadlineMs, signal);
      } catch (error) {
        if (error instanceof Stopped) return 'unchecked';
        // A store that breaks its contract may be a hostile database too (a planted operator, a view for a table).
        if (error instanceof ChainStoreError || refusedByDatabase(error)) return alarm('store');
        log.warn('audit.anchor_check_failed', { chain: chain.kind, err: error });
        return isStale(key) ? alarm('unchecked') : 'unchecked';
      }
      lastChecked.set(key, clock.now().getTime());
      return afterCheck(chain, log, report, last);
    } catch (error) {
      // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
      log.error('audit.anchor_check_crashed', { chain: chain.kind, err: error });
      return 'unchecked';
    }
  };

  /**
   * The organisations listed and recorded, or what stopped them being read:
   * `stopped` when the run was, `refused` for a database that refuses the
   * read or answers with anything but IDs (the alarm), `failed` for anything
   * else. One read at a time: a read still under way past its deadline counts
   * as failed, so a hung database can't take a connection every run.
   */
  const listOrganizations = async (
    from: OrganisationChains,
    signal: AbortSignal | undefined,
  ): Promise<{ readonly listed: string[]; readonly recorded: string[] } | 'stopped' | 'refused' | 'failed'> => {
    const refused = (): 'refused' => {
      logger.error('audit.integrity_failed', { chain: 'organisation', check: 'anchor', reason: 'list' });
      return 'refused';
    };
    let answers: readonly [unknown, unknown];
    try {
      if (inFlight.has(LIST)) throw new Error('the last read of the list has not finished');
      inFlight.add(LIST);
      // The record first, then the list: an organisation is recorded and listed
      // in one transaction, so any recorded before the list is read is in it,
      // and one created between the two reads can't be taken for one unlisted.
      // One after the other, so the guard holds until both have ended.
      const reading = Promise.resolve()
        .then(() => from.recorded())
        .then(async (recorded): Promise<readonly [unknown, unknown]> => [await from.list(), recorded]);
      void reading.then(
        () => inFlight.delete(LIST),
        () => inFlight.delete(LIST),
      );
      answers = await withinDeadline(reading, deadlineMs, signal);
    } catch (error) {
      if (error instanceof Stopped) return 'stopped';
      if (error instanceof ChainStoreError || refusedByDatabase(error)) return refused();
      logger.warn('audit.anchor_check_failed', { chain: 'organisation', check: 'list', err: error });
      return 'failed';
    }
    const [listed, recorded] = [organisationIds(answers[0]), organisationIds(answers[1])];
    if (listed === undefined || recorded === undefined) return refused();
    listRead = clock.now().getTime();
    return { listed, recorded };
  };

  /** An organisation seen before and not reached this run: unlisted, or its chain gone unchecked too long. */
  const missed = (orgId: string, reason: 'unlisted' | 'unchecked'): Outcome => {
    if (reason === 'unchecked' && !isStale(orgId)) return 'unchecked';
    const last = anchors.latest({ kind: 'organisation', orgId });
    failures.set(orgId, reason);
    logger.child({ orgId }).error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'anchor',
      reason,
      ...(last === undefined ? {} : { anchorSeq: last.seq }),
    });
    return 'failed';
  };

  /**
   * Puts an organisation whose chain failed this run on its integrity hold,
   * or tries again a hold waiting for one that didn't (or only went
   * unchecked), within the check's deadline and one at a time for each
   * organisation, so a hold hung on the database can't take a connection
   * every run. A hold not set in time is the alarm: the hold records its own
   * outcome if it ends later.
   */
  const settle = async (from: OrganisationChains, orgId: string, signal: AbortSignal | undefined): Promise<void> => {
    const reason = failures.get(orgId);
    failures.delete(orgId);
    if (signal?.aborted === true) return;
    const failure = reason === 'unchecked' ? undefined : reason;
    const key = `hold|${orgId}`;
    try {
      if (inFlight.has(key)) throw new Error('the last hold of this organisation has not finished');
      inFlight.add(key);
      const holding = Promise.resolve().then(() => from.hold(orgId, failure));
      void holding.then(
        () => inFlight.delete(key),
        () => inFlight.delete(key),
      );
      await withinDeadline(holding, deadlineMs, signal);
    } catch (error) {
      if (error instanceof Stopped) return;
      logger
        .child({ orgId })
        .error('audit.integrity_failed', { chain: 'organisation', check: 'hold', reason: 'not_recorded', err: error });
    }
  };

  const remember = (orgId: string): void => {
    if (seen.has(orgId)) return;
    seen.add(orgId);
    firstSeen.set(orgId, clock.now().getTime());
  };

  /** A run with no list to go by: the alarm if the list has gone unread too long, and each organisation already seen counted as not checked. */
  const checkUnlisted = async (
    from: OrganisationChains,
    read: 'refused' | 'failed',
    signal: AbortSignal | undefined,
  ): Promise<Outcome[]> => {
    // A list never read for three intervals is the alarm in its own right,
    // since after a restart no organisation is known yet.
    if (read === 'failed' && clock.now().getTime() - (listRead ?? started) >= staleAfterMs) {
      logger.error('audit.integrity_failed', { chain: 'organisation', check: 'anchor', reason: 'list' });
    }
    const outcomes: Outcome[] = [];
    for (const orgId of seen) {
      outcomes.push(missed(orgId, 'unchecked'));
      await settle(from, orgId, signal);
    }
    return outcomes;
  };

  /**
   * One organisation's turn: its check, or, off the list, its alarm; then its hold. A chain reached with the run's time
   * up goes first next run, as does one whose alarm must repeat or whose comparison is owed.
   */
  const turn = async (
    from: OrganisationChains,
    orgId: string,
    listed: ReadonlySet<string>,
    signal: AbortSignal,
  ): Promise<Outcome> => {
    const began = performance.now();
    const outcome = listed.has(orgId)
      ? await checkOne(
          { chain: { kind: 'organisation', orgId }, verify: (anchor) => from.verify(orgId, anchor) },
          signal,
        )
      : missed(orgId, 'unlisted');
    await settle(from, orgId, signal);
    turns.after(orgId, {
      ms: performance.now() - began,
      again: outcome === 'failed' || outcome === 'unanchored' || (outcome === 'unchecked' && signal.aborted),
    });
    return outcome;
  };

  /**
   * Turns taken in `lanes` side by side until none is left or the run's time is up. A lane stops, too, when the check
   * holds twice its lanes in checks and holds, those past their deadline among them: each has a connection until it
   * ends, and it must not take the API's. Those left wait for the next run, which says so if it can't reach them.
   */
  const takeTurns = async (from: OrganisationChains, listed: ReadonlySet<string>, signal: AbortSignal) => {
    const outcomes: Outcome[] = [];
    const lane = async (index: number): Promise<void> => {
      while (!signal.aborted && inFlight.size < 2 * lanes) {
        const orgId = turns.next(index);
        if (orgId === undefined) return;
        outcomes.push(await turn(from, orgId, listed, signal));
      }
    };
    await Promise.all(Array.from({ length: lanes }, (_, index) => lane(index)));
    return outcomes;
  };

  const checkOrganizations = async (
    from: OrganisationChains,
    cap: AbortSignal,
    stop: AbortSignal | undefined,
  ): Promise<Outcome[]> => {
    const read = await listOrganizations(from, cap);
    if (read === 'stopped' && stop?.aborted === true) return [];
    // The run's time gone before the list was read counts against the list, or a run that always is would go unsaid.
    if (typeof read === 'string') return checkUnlisted(from, read === 'refused' ? 'refused' : 'failed', cap);
    const listed = new Set(read.listed);
    const fresh = read.listed.filter((orgId) => !seen.has(orgId));
    for (const orgId of read.recorded) remember(orgId);
    for (const orgId of fresh) remember(orgId);
    turns.begin(
      listed,
      fresh,
      [...seen].filter((orgId) => !listed.has(orgId)),
    );
    return takeTurns(from, listed, cap);
  };

  /** Organisations that have waited past the bound for a turn they haven't had: the alarm, by count, as there may be thousands. */
  const sayUnreached = (): void => {
    const late = [...turns.waiting()].filter((orgId) => clock.now().getTime() - since(orgId) >= reachWithinMs);
    if (late.length === 0) return;
    logger.error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'anchor',
      reason: 'unreached',
      organisations: late.length,
      firstFew: late.slice(0, UNREACHED_NAMED),
    });
  };

  /** What a run that ran out of time, or left organisations for the next, says it has left. */
  const sayLeft = (cap: AbortSignal): void => {
    const left = turns.left() > 0;
    // Until a whole round has gone by in one run: after the run finishing a long round come chains checked long ago.
    spreading = left || leftLastRun;
    leftLastRun = left;
    if (left || cap.aborted) {
      logger.warn('audit.anchor_check_unfinished', { left: turns.left(), lanes, withinMs: runWithinMs });
    }
    sayUnreached();
  };

  /** What the store holds that this process hasn't read, and every organisation in it as seen. Never throws. */
  const readStore = async (from: AnchorLog, signal: AbortSignal | undefined): Promise<void> => {
    try {
      await withinDeadline(from.read(), deadlineMs, signal);
    } catch (error) {
      if (error instanceof Stopped) return;
      from.readFailed(error);
    }
    for (const orgId of from.organisations()) remember(orgId);
  };

  /** What has moved so far into the store. A run stopped leaves it to `finish`. Never throws. */
  const writeStore = async (to: AnchorLog, stop: AbortSignal | undefined): Promise<void> => {
    try {
      await withinDeadline(to.flush(), Math.min(deadlineMs, WRITE_WITHIN_MS), stop);
    } catch (error) {
      if (!(error instanceof Stopped)) to.writeFailed(error);
    }
  };

  /**
   * Writes on a timer of their own while a run goes on, so what a lane has finished is kept however long another takes:
   * no lane waits for a write, and a write holds no connection. One at a time; `flush` joins any under way. Ends when told.
   */
  const writeAlong = (to: AnchorLog, stop: AbortSignal | undefined): (() => void) => {
    let timer: ReturnType<typeof setTimeout>;
    let ended = false;
    const later = (): void => {
      timer = setTimeout(() => {
        void writeStore(to, stop).then(() => {
          if (!ended) later();
        });
      }, writeEveryMs);
      timer.unref();
    };
    later();
    return () => {
      ended = true;
      clearTimeout(timer);
    };
  };

  /** Everything a run does up to its last write, each step cut off by `cap`: the run's time, or the stop. */
  const checkAll = async (cap: AbortSignal, stop: AbortSignal | undefined): Promise<Outcome[]> => {
    const outcomes: Outcome[] = [];
    for (const one of chains) {
      if (cap.aborted) break;
      outcomes.push(await checkOne(one, cap));
    }
    if (organizations !== undefined && !cap.aborted) {
      try {
        outcomes.push(...(await checkOrganizations(organizations, cap, stop)));
      } catch (error) {
        // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
        logger.error('audit.anchor_check_crashed', { chain: 'organisation', err: error });
      }
    }
    return outcomes;
  };

  return Object.freeze({
    async anchorOrganisation(orgId: string, signal?: AbortSignal): Promise<void> {
      if (organizations === undefined) return;
      // A hand-off may come before the run's first read, and joins it; once the store has failed, the run alone tries again.
      if (durable?.state() === 'unread') await readStore(durable, signal);
      if (storeUnread()) return;
      const id = orgId.toLowerCase();
      const outcome = await checkOne(
        { chain: { kind: 'organisation', orgId: id }, verify: (anchor) => organizations.verify(id, anchor) },
        signal,
      );
      if (outcome === 'failed') await settle(organizations, id, signal);
    },

    async finish(): Promise<void> {
      if (durable === undefined) return;
      try {
        // Twice: a run's write may be under way, and the first joins it.
        const writing = durable.flush().then(() => durable.flush());
        await withinDeadline(writing, stopFlushMs, undefined);
      } catch (error) {
        durable.writeFailed(error);
      }
    },

    async run(signal?: AbortSignal): Promise<void> {
      // Ended by the run's time or the stop, whichever comes first.
      const ending = new AbortController();
      const end = (): void => {
        ending.abort();
      };
      const cap = ending.signal;
      const timer = setTimeout(end, runWithinMs);
      timer.unref();
      if (signal?.aborted === true) end();
      signal?.addEventListener('abort', end, { once: true });
      if (durable !== undefined) await readStore(durable, cap);
      const endWrites = durable === undefined ? undefined : writeAlong(durable, signal);
      const outcomes = await checkAll(cap, signal);
      clearTimeout(timer);
      signal?.removeEventListener('abort', end);
      endWrites?.();
      if (signal?.aborted !== true) sayLeft(cap);
      if (durable !== undefined) {
        // A run stopped ends at once: `flush` never throws, and `finish`, where the API is stopping, joins it.
        if (signal?.aborted === true) void durable.flush();
        else await writeStore(durable, signal);
      }
      const count = (outcome: Outcome): number => outcomes.filter((each) => each === outcome).length;
      logger.info('audit.anchor_check_done', {
        chains: outcomes.length,
        anchored: count('anchored'),
        unchanged: count('unchanged'),
        unanchored: count('unanchored'),
        failed: count('failed'),
        unchecked: count('unchecked'),
        left: turns.left(),
      });
    },
  });
}

/**
 * Runs the check now and then `intervalMs` after each run ends (scheduleRuns):
 * runs never overlap, and `stop` ends a run in flight at once, waits for it,
 * then writes what moved (`finish`).
 */
export function scheduleAnchorCheck(
  check: Pick<AnchorCheck, 'run'>,
  intervalMs: number,
  finish: () => Promise<void> = () => Promise.resolve(),
): { stop(): Promise<void> } {
  const runs = scheduleRuns(check, intervalMs);
  return {
    stop: async () => {
      await runs.stop();
      await finish();
    },
  };
}

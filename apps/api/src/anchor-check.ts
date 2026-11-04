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
// A run is bounded (4D2e E6), and any number of organisations may slow the check but
// not break it or raise a false alarm. Chains are checked side by side, a few lanes of
// them (AGENTX_AUDIT_ANCHOR_LANES), so one slow or locked organisation holds its own
// lane and nobody else's; whose turn it is is anchor-turns.ts's. Checks in flight, those
// past their deadline among them, never pass the lanes, so the hand-offs' connections
// stay theirs; every trip of theirs has a limit on its answer, so a dead connection ends.
// A check past its deadline isn't thrown away: when it ends it is compared and anchored
// all the same, and if it fails then, that counts as any failure does. While it runs it is
// capacity, not the alarm, up to a ceiling of the same 63 minutes at the default: every trip of
// it has a limit, but the whole has none, so someone answering each page slowly could
// otherwise keep one chain from ever being compared. Past it, `unchecked`, no hold. A run stops at four minutes, ends with its
// line whatever is under way, and the next goes on from where it stopped. So the
// check's line comes at most every 10 minutes at the default interval: 5 between runs,
// 4 of run, 1 for the last write. With lines up to 9 minutes late, the 30 minutes the
// outside's dead-man rule allows hold (D3), and the setting refuses an interval that
// wouldn't.
//
// Wherever the lanes get through them all in a run (a run's lane-time is 16 minutes at
// the default), each chain's turn comes every run. Past that, a round spreads over
// runs. Past seven runs' time (63 minutes at the default) an organisation is late: with
// turns completing that is capacity, `audit.anchor_check_behind`, SEV-2, by count; with
// no run's turn completed for that whole time it is the alarm (`unreached`), and one
// bad run says nothing. A chain whose own check keeps failing is the alarm too. A chain
// whose anchor landed during its check goes among
// the first next run: its alarm comes within one interval and one run, 9 minutes.
//
// Any number of organisations may be listed. AGENTX_AUDIT_MOST_ORGANISATIONS only limits
// the chains this check notes that have no anchor yet in the store: every chain in the store
// is noted whatever it says, its notes small beside its anchor. Those past it take their turns
// from a cursor through the list, and `audit.anchor_check_over_size`, SEV-2, says so; their anchors are
// still held, as Tx A and their own comparison need them, the store being a log with no way
// to read one chain's. So the true limit is memory: more anchors than the heap holds take
// more hardware, and a store file past it says so (`audit.anchor_store_beyond_memory`).
//
// What that means for tamper: a chain wound back is seen at its turn, so a round's
// length, not a run's, once rounds spread. Tx A compares a payment with the last
// anchor alone (handoff.ts `chainStops`), so events past that anchor can be taken away
// unseen until the chain's next turn: up to a round, 63 minutes or more at that size,
// not 9, until E8's probe reads every head each run.
//
// After the organisations' turns, the rotation (anchor-rotation.ts, 4D2e E7): each
// organisation's daily count and walk, and the full pass's share, within what is left
// of the run, one read at a time, inside the lanes' share of the connections.
//
// A chain that fails raises the integrity alarm (`audit.integrity_failed`; its
// SEV-1 alert rule is A2c-2) and keeps its last good anchor, so the alarm
// repeats every run until someone looks. Someone with the database's keys can
// also try to stop the check from finishing: so a database that refuses the
// check (a right, a table or a
// column gone) is the alarm too, whenever it comes, and so is a check that keeps failing
// for three intervals, or one still running past the ceiling above. Anything else that
// stops a check (the database unreachable, or a check past its deadline but going on)
// is a warning until then. Every run ends with one
// line, so a check that has stopped can be told from one with nothing to say.
// The platform chain is checked every run; each organisation's chain too,
// found from the directory's list at each run (B1d-2). The list is held to
// what the platform chain records: every organisation created there
// (`organization.created`, sealed, so one deleted breaks the platform chain's
// own check) must be listed, and so must every one this process has seen
// listed, and every one with a chain in the store. One missing is the alarm
// (`unlisted`): the app never deletes an entry, so one gone is tampering, and
// its chain would otherwise never be checked again. A list the database refuses, or one
// that isn't IDs, is the alarm (`list`); a list that
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
  createMemoryPassRecord,
  signAnchor,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { createRotation, type RotatedChecks, type RotationCheck } from './anchor-rotation.ts';
import { createTurns, shuffledAfresh, startAnywhere } from './anchor-turns.ts';
import { PastDeadline, scheduleRuns, Stopped, withinDeadline } from './background.ts';

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
  /** How long an organisation may wait for its turn before it is late (see the header). As `staleAfterMs` unless given. */
  readonly reachWithinMs?: number;
  /** How many chains with no anchor in the store it keeps notes on: those past it go by a cursor (the header), never unchecked. */
  readonly mostOrganisations?: number;
  /** A round's order where there is no store to go by: a fresh shuffle unless given. */
  readonly shuffled?: (orgIds: readonly string[]) => readonly string[];
  /** Where a process starts among those past the cap: a random place unless given. */
  readonly pastCapStart?: (count: number) => number;
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
  /** The organisations' chains' reads for the rotation (4D2e E7): none, and a run has no rotation. */
  readonly rotation?: RotatedChecks;
  /** Whether this environment sleeps when unused (staging), so a full pass's lateness counts from a process's start. */
  readonly sleeps?: boolean;
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

/** How many IDs a line about many organisations names. The count is the whole of it; these are where to start looking. */
const NAMED_ON_A_LINE = 5;

/** How many organisations gone from the list a run names on a line each, with their holds' reason; the rest are a count. */
const UNLISTED_NAMED = 20;

/** How many times running a chain's check must fail, with rounds spreading, before it is that chain's own: one could be anyone's bad moment. */
const MISSES_TO_SAY = 2;

/**
 * Postgres's refusals that only a changed database gives the app's role: a
 * right taken away, a table or a column gone. The check can't be run until
 * someone puts them back, which is itself the alarm.
 */
const CHANGED_DATABASE = new Set(['42501', '42P01', '42703']);

/**
 * AGENTX_AUDIT_MOST_ORGANISATIONS's default, what memory allows: each one this process has seen holds about 885 bytes
 * for its life (measured, S168), so 100,000 is about 88 MB of the API's 1 GiB. A count past it is no alarm.
 */
export const MOST_ORGANIZATIONS = 100_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The IDs in lower case, or nothing if any isn't a UUID given as text. */
function organisationIds(ids: unknown): string[] | undefined {
  if (!Array.isArray(ids)) return undefined;
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

/** A chain's last check is still going: progress, not a failure. */
class UnderWay extends Error {}

/** `unanchored`: checked and sound, and not anchored: the store is yet to be read, or landed during the check. */
type Outcome = 'anchored' | 'unchanged' | 'unanchored' | 'failed' | 'unchecked';

/** The in-flight key of the organisations' list, which no chain's key can be. */
const LIST = 'list';

/** The in-flight key of the rotation's read: one at a time. */
const ROTATION = 'rotation';

export function createAnchorCheck({
  chains,
  organizations,
  keys,
  clock,
  logger,
  staleAfterMs,
  reachWithinMs = staleAfterMs,
  mostOrganisations = MOST_ORGANIZATIONS,
  shuffled = shuffledAfresh,
  pastCapStart = startAnywhere,
  deadlineMs,
  durable,
  anchors = durable ?? createMemoryAnchorStore(),
  stopFlushMs = STOP_FLUSH_MS,
  lanes = LANES,
  runWithinMs = RUN_WITHIN_MS,
  writeEveryMs = WRITE_EVERY_MS,
  rotation: rotatedChecks,
  sleeps = false,
}: AnchorCheckOptions): AnchorCheck {
  // From when this process began, so a check that never once completes is caught too.
  const started = clock.now().getTime();
  const lastChecked = new Map<string, number>();
  // Each organisation's alarm reason this run, until its hold is tried.
  const failures = new Map<string, string>();
  const keyOf = (chain: Chain): string => (chain.kind === 'platform' ? 'platform' : chain.orgId);
  // Checks, holds and the list's read under way, past their deadline or not: one each at most, each with a connection.
  const inFlight = new Set<string>();
  // When each chain's check under way began: past the ceiling it is no longer capacity.
  const checkBegan = new Map<string, number>();
  // Lanes waiting for room among those.
  const waitingForRoom = new Set<() => void>();
  /** One of those has ended. */
  const ended = (key: string): void => {
    inFlight.delete(key);
    checkBegan.delete(key);
    turns.ended(key);
    for (const wake of waitingForRoom) wake();
    waitingForRoom.clear();
  };
  /**
   * Work that holds a connection, one at a time under `key`, within the deadline: past it, it stays in flight until it
   * ends, so a hung database can't take a connection every run.
   */
  const tracked = <T>(key: string, busy: string, start: () => Promise<T>, signal: AbortSignal | undefined) => {
    if (inFlight.has(key)) throw new Error(busy);
    inFlight.add(key);
    const work = Promise.resolve().then(start);
    void work.then(
      () => {
        ended(key);
      },
      () => {
        ended(key);
      },
    );
    return withinDeadline(work, deadlineMs, signal);
  };
  // Every organisation this process has seen listed or recorded, so one that leaves the list is noticed.
  const seen = new Set<string>();
  // When each organisation was first seen, so its stale period starts then, not when the process began.
  const firstSeen = new Map<string, number>();
  // When the list was last read whole, so a list never read is the alarm in time too.
  let listRead: number | undefined;
  /** The time a chain's stale period counts from. */
  const since = (key: string): number => lastChecked.get(key) ?? firstSeen.get(key) ?? started;
  // Whether the last run left organisations waiting, so a chain's last check may rightly be longer ago than a run's.
  let spreading = false;
  let leftLastRun = false;
  // The organisations in use: the last list read, or with none yet, those seen.
  let inUse: readonly string[] | undefined;
  // Those past the cap, no notes kept on any, and when their round began.
  let pastCap: readonly string[] = [];
  let pastCapNow: ReadonlySet<string> = new Set();
  let pastCapSince = started;
  // When a run's turn last completed, hand-offs' apart: wedged lanes are the alarm, one bad run is not.
  let lastTurn = started;
  // Checks completed this run, and how many times running each chain's has not.
  let completed = 0;
  const misses = new Map<string, number>();
  // Organisations whose check couldn't run this run, and those of them gone too long: a line a run, not a line each, as
  // a database down is every chain at once. The first failure stands for the rest.
  let missedThisRun: string[] = [];
  let staleThisRun: string[] = [];
  // Organisations gone from the list this run: the first named, line by line, and the rest counted.
  let unlistedThisRun = 0;
  let firstMiss: unknown;
  /** Whether a chain has gone unchecked too long. With rounds spreading its turn may rightly be long ago, so a miss alone says nothing. */
  const isStale = (key: string): boolean =>
    clock.now().getTime() - since(key) >= staleAfterMs &&
    ((!spreading && !pastCapNow.has(key)) || key === 'platform' || (misses.get(key) ?? 0) >= MISSES_TO_SAY);
  /** When a chain is last known to have been checked: after a restart, as its anchor says. */
  const lastKnown = (orgId: string): number =>
    lastChecked.get(orgId) ??
    (durable === undefined ? undefined : anchors.latest({ kind: 'organisation', orgId })?.at.getTime()) ??
    since(orgId);
  /** By the store where there is one: never anchored first, then the oldest anchor. Its reads are this process's memory. */
  const oldestFirst = (orgIds: readonly string[]): readonly string[] =>
    orgIds
      .map((orgId) => ({ orgId, at: anchors.latest({ kind: 'organisation', orgId })?.at.getTime() ?? 0 }))
      .sort((one, other) => one.at - other.at)
      .map(({ orgId }) => orgId);
  const turns = createTurns(lanes, durable === undefined ? shuffled : oldestFirst, pastCapStart);

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
    if (last?.seq === report.seq) {
      // Said again in the store now and then, so its time tells a restart this chain has had its turn (anchor-turns.ts).
      if (durable !== undefined && !storeUnread() && clock.now().getTime() - last.at.getTime() >= reachWithinMs / 2) {
        anchors.keep(signAnchor(keys, chain, report, clock.now(), durable.epoch));
      }
      return 'unchanged';
    }
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

  /** A check has completed, and how it came out. */
  const compared = (
    chain: Chain,
    log: Logger,
    report: ChainReport,
    last: Anchor | undefined,
    alone: boolean,
  ): Outcome => {
    const key = keyOf(chain);
    const at = clock.now().getTime();
    if (!pastCapNow.has(key)) lastChecked.set(key, at);
    misses.delete(key);
    if (chain.kind === 'organisation' && !alone) {
      completed += 1;
      lastTurn = at;
    }
    return afterCheck(chain, log, report, last);
  };

  /** A check that ended past its deadline or the run: compared all the same, its alarm and hold as ever. Never throws. */
  const landedLate = (
    chain: Chain,
    log: Logger,
    report: ChainReport,
    last: Anchor | undefined,
    alone: boolean,
  ): void => {
    try {
      afterLate(chain, compared(chain, log, report, last, alone));
    } catch (error) {
      log.error('audit.anchor_check_crashed', { chain: chain.kind, err: error });
    }
  };

  /** What came of a check that ended past its turn: it goes again where that is owed, and its hold is tried. */
  const afterLate = (chain: Chain, outcome: Outcome): void => {
    if (chain.kind !== 'organisation' || (outcome !== 'failed' && outcome !== 'unanchored')) return;
    turns.repeat(chain.orgId);
    if (outcome === 'failed' && organizations !== undefined) void settle(organizations, chain.orgId, undefined);
  };

  /** How a check that didn't come back comes out, the same in its turn or after: the database's refusal, or a miss. */
  const failedOutcome = (chain: Chain, log: Logger, error: unknown, alone: boolean): Outcome =>
    // A store that breaks its contract may be a hostile database too (a planted operator, a view for a table).
    error instanceof ChainStoreError || refusedByDatabase(error)
      ? alarmed(chain, log, 'store')
      : missedCheck(chain, log, error, alone);

  /** A check that failed past its deadline or the run: said on its own line, as no run sums it up. Never throws. */
  const failedLate = (chain: Chain, log: Logger, error: unknown): void => {
    try {
      afterLate(chain, failedOutcome(chain, log, error, true));
    } catch (crash) {
      log.error('audit.anchor_check_crashed', { chain: chain.kind, err: crash });
    }
  };

  /**
   * A check that didn't come back, said at once on its own line where `alone`, or else in the run's one line. One that
   * failed counts towards the alarm; one still running doesn't, as every trip of it has a limit: that is capacity.
   */
  const missedCheck = (chain: Chain, log: Logger, error: unknown, alone: boolean): Outcome => {
    const key = keyOf(chain);
    const failed = !(error instanceof UnderWay || error instanceof PastDeadline);
    if (failed) misses.set(key, (misses.get(key) ?? 0) + 1);
    const stale = failed && isStale(key);
    if (alone || chain.kind === 'platform') {
      log.warn('audit.anchor_check_failed', { chain: chain.kind, err: error });
      return stale ? alarmed(chain, log, 'unchecked') : 'unchecked';
    }
    missedThisRun.push(key);
    firstMiss ??= error;
    if (!stale) return 'unchecked';
    staleThisRun.push(key);
    failures.set(key, 'unchecked');
    return 'failed';
  };

  /** The run's one line for the checks that couldn't run, its one alarm for those gone too long, and one for those gone from the list past the named. */
  const sayMissed = (): void => {
    if (unlistedThisRun > UNLISTED_NAMED) {
      logger.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'anchor',
        reason: 'unlisted',
        organisations: unlistedThisRun - UNLISTED_NAMED,
      });
    }
    if (missedThisRun.length > 0) {
      logger.warn('audit.anchor_check_failed', {
        chain: 'organisation',
        chains: missedThisRun.length,
        firstFew: missedThisRun.slice(0, NAMED_ON_A_LINE),
        err: firstMiss,
      });
    }
    if (staleThisRun.length > 0) {
      logger.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'anchor',
        reason: 'unchecked',
        organisations: staleThisRun.length,
        firstFew: staleThisRun.slice(0, NAMED_ON_A_LINE),
      });
    }
  };

  const checkOne = async (
    { chain, verify }: CheckedChain,
    signal: AbortSignal | undefined,
    alone = false,
    ran: (ms: number) => void = () => undefined,
  ): Promise<Outcome> => {
    // An organisation's ID goes on the line as the logger's own field, which an event can't set.
    const log = chain.kind === 'platform' ? logger : logger.child({ orgId: chain.orgId });
    const key = keyOf(chain);
    try {
      const last = anchors.latest(chain);
      let report: ChainReport;
      let cutOff = false;
      const began = performance.now();
      try {
        if (inFlight.has(key)) throw new UnderWay('the last check of this chain has not finished');
        inFlight.add(key);
        checkBegan.set(key, clock.now().getTime());
        const checking = Promise.resolve().then(() => verify(last));
        // Handled here too, so a check that ends after its deadline never goes unhandled.
        void checking.then(
          (ending) => {
            ended(key);
            if (cutOff) landedLate(chain, log, ending, last, alone);
          },
          (error: unknown) => {
            ended(key);
            if (cutOff) failedLate(chain, log, error);
          },
        );
        report = await withinDeadline(checking, deadlineMs, signal);
      } catch (error) {
        cutOff = true;
        if (error instanceof Stopped) return 'unchecked';
        if (error instanceof PastDeadline) ran(performance.now() - began);
        return failedOutcome(chain, log, error, alone);
      }
      ran(performance.now() - began);
      return compared(chain, log, report, last, alone);
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
      // The record first, then the list: an organisation is recorded and listed
      // in one transaction, so any recorded before the list is read is in it,
      // and one created between the two reads can't be taken for one unlisted.
      // One after the other, so the guard holds until both have ended.
      answers = await tracked(
        LIST,
        'the last read of the list has not finished',
        async (): Promise<readonly [unknown, unknown]> => {
          const recorded = await from.recorded();
          return [await from.list(), recorded];
        },
        signal,
      );
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

  /** An organisation seen before and off the list now: the alarm. */
  const unlisted = (orgId: string): Outcome => {
    const last = anchors.latest({ kind: 'organisation', orgId });
    failures.set(orgId, 'unlisted');
    unlistedThisRun += 1;
    if (unlistedThisRun > UNLISTED_NAMED) return 'failed';
    logger.child({ orgId }).error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'anchor',
      reason: 'unlisted',
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
    try {
      await tracked(
        `hold|${orgId}`,
        'the last hold of this organisation has not finished',
        () => from.hold(orgId, failure),
        signal,
      );
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
    let ranMs: number | undefined;
    const outcome = listed.has(orgId)
      ? await checkOne(
          { chain: { kind: 'organisation', orgId }, verify: (anchor) => from.verify(orgId, anchor) },
          signal,
          false,
          (ms) => {
            ranMs = ms;
          },
        )
      : unlisted(orgId);
    if (!listed.has(orgId)) turns.ended(orgId);
    await settle(from, orgId, signal);
    turns.after(orgId, {
      ms: pastCapNow.has(orgId) ? undefined : ranMs,
      again: outcome === 'failed' || outcome === 'unanchored' || (outcome === 'unchecked' && signal.aborted),
    });
    return outcome;
  };

  /** Until a check, hold or read ends, or the run does. */
  const roomOrEnd = (signal: AbortSignal): Promise<void> =>
    new Promise((resolve) => {
      waitingForRoom.add(resolve);
      signal.addEventListener(
        'abort',
        () => {
          resolve();
        },
        { once: true },
      );
    });

  /**
   * Turns taken in `lanes` side by side until none is left or the run's time is up. Nothing starts while the lanes' share
   * of the connections is in use, those past their deadline among them: it must not take the hand-offs'. Every trip these
   * make, its start and commit too, goes unanswered only so long (JOB_ANSWER_WITHIN_MS), so a dead connection ends, and with
   * it the wait.
   */
  const takeTurns = async (from: OrganisationChains, listed: ReadonlySet<string>, signal: AbortSignal) => {
    const outcomes: Outcome[] = [];
    const lane = async (): Promise<void> => {
      while (!signal.aborted && turns.left() > 0) {
        if (inFlight.size >= lanes) {
          await roomOrEnd(signal);
          continue;
        }
        const orgId = turns.next();
        // With all that's left under way's share.
        if (orgId === undefined) return;
        outcomes.push(await turn(from, orgId, listed, signal));
      }
    };
    await Promise.all(Array.from({ length: lanes }, () => lane()));
    return outcomes;
  };

  /** Whether this one, new to the check, takes a note: while the cap has room. */
  const noted = (orgId: string): boolean => {
    if (seen.has(orgId) || seen.size >= mostOrganisations) return false;
    remember(orgId);
    return true;
  };

  /** A list read whole: those noted and new as far as the cap allows, the rest by the cursor, with one line to say so. */
  const adopted = (read: { readonly listed: readonly string[]; readonly recorded: readonly string[] }) => {
    const listedNow = new Set(read.listed);
    // From the two lists alone, so one past the cap, with no note kept on it, is seen to have gone too.
    const gone = new Set(read.recorded.filter((orgId) => !listedNow.has(orgId)));
    // One recorded and off the list goes first as gone, whatever its place here.
    const fresh = read.recorded.filter((orgId) => noted(orgId));
    const past: string[] = [];
    for (const orgId of read.listed) {
      if (seen.has(orgId)) continue;
      if (noted(orgId)) fresh.push(orgId);
      else past.push(orgId);
    }
    if (past.length > 0) {
      logger.error('audit.anchor_check_over_size', {
        listed: read.listed.length,
        beyond: past.length,
        most: mostOrganisations,
      });
    }
    for (const orgId of seen) if (!listedNow.has(orgId)) gone.add(orgId);
    pastCap = past;
    pastCapNow = new Set(past);
    inUse = read.listed.filter((orgId) => !pastCapNow.has(orgId));
    return { fresh, unlisted: [...gone] };
  };

  const checkOrganizations = async (
    from: OrganisationChains,
    cap: AbortSignal,
    stop: AbortSignal | undefined,
  ): Promise<Outcome[]> => {
    const read = await listOrganizations(from, cap);
    if (read === 'stopped' && stop?.aborted === true) return [];
    // Any list not read, or a run's time gone before one was, counts against the list, and the last goes on in use.
    if (
      typeof read === 'string' &&
      read !== 'refused' &&
      clock.now().getTime() - (listRead ?? started) >= staleAfterMs
    ) {
      logger.error('audit.integrity_failed', { chain: 'organisation', check: 'anchor', reason: 'list' });
    }
    const { fresh, unlisted: gone } = typeof read === 'string' ? { fresh: [], unlisted: [] } : adopted(read);
    const listed = inUse ?? [...seen];
    turns.begin(listed, fresh, gone, pastCap);
    if (turns.pastCapStarts()) pastCapSince = clock.now().getTime();
    return takeTurns(from, new Set([...listed, ...pastCap]), cap);
  };

  /**
   * Checks still under way past the ceiling, which no longer read as capacity: the alarm, no hold, as for any chain unchecked
   * (one line for the organisations'). Slow answers could otherwise keep a chain from being compared for ever.
   */
  const sayOverCeiling = (at: number): ReadonlySet<string> => {
    const over = new Set([...checkBegan].filter(([, began]) => at - began >= reachWithinMs).map(([key]) => key));
    if (over.delete('platform')) {
      alarmed({ kind: 'platform' }, logger, 'unchecked');
      over.add('platform');
    }
    const organisations = [...over].filter((key) => key !== 'platform');
    if (organisations.length > 0) {
      logger.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'anchor',
        reason: 'unchecked',
        organisations: organisations.length,
        firstFew: organisations.slice(0, NAMED_ON_A_LINE),
      });
    }
    return over;
  };

  /**
   * Those past the bound, over all of them, by count as there may be thousands: capacity, or with no run's turn completed
   * for that whole time, the alarm. In a bad run while a turn has completed since, nothing: the next run says.
   */
  const sayLate = (): void => {
    const at = clock.now().getTime();
    const overCeiling = sayOverCeiling(at);
    const late = (inUse ?? [...seen]).filter(
      (orgId) => at - lastKnown(orgId) >= reachWithinMs && !overCeiling.has(orgId),
    );
    const pastLate = pastCap.length > 0 && at - pastCapSince >= reachWithinMs ? pastCap : [];
    // One whose own check fails has its own alarm: this is for one that goes on.
    const others = chains
      .map(({ chain }) => keyOf(chain))
      .filter((key) => !misses.has(key) && !overCeiling.has(key) && at - since(key) >= reachWithinMs);
    const named = [...others, ...late, ...pastLate.slice(0, NAMED_ON_A_LINE)];
    if (named.length === 0) return;
    const count = {
      organisations: others.length + late.length + pastLate.length,
      firstFew: named.slice(0, NAMED_ON_A_LINE),
    };
    if (completed > 0 || late.length + pastLate.length === 0) {
      logger.error('audit.anchor_check_behind', { ...count, left: turns.left(), lanes });
    } else if (at - lastTurn >= reachWithinMs) {
      logger.error('audit.integrity_failed', { chain: 'organisation', check: 'anchor', reason: 'unreached', ...count });
    }
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
    sayLate();
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

  /**
   * What has moved so far into the store. A run stopped leaves it to `finish`. Never throws. `twice`: a write is under way,
   * which this joins, and what moved since must not wait a whole interval for the next run.
   */
  const writeStore = async (to: AnchorLog, stop: AbortSignal | undefined, twice = false): Promise<void> => {
    try {
      const writing = twice ? to.flush().then(() => to.flush()) : to.flush();
      await withinDeadline(writing, Math.min(deadlineMs, WRITE_WITHIN_MS), stop);
    } catch (error) {
      if (!(error instanceof Stopped)) to.writeFailed(error);
    }
  };

  /**
   * Writes on a timer of their own while a run goes on, so what a lane has finished is kept however long another takes:
   * no lane waits for a write, and a write holds no connection. One at a time; `flush` joins any under way. Ends when told.
   */
  let writingAlong = false;
  const writeAlong = (to: AnchorLog, stop: AbortSignal | undefined): (() => void) => {
    let timer: ReturnType<typeof setTimeout>;
    let ended = false;
    const later = (): void => {
      timer = setTimeout(() => {
        writingAlong = true;
        void writeStore(to, stop).then(() => {
          writingAlong = false;
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

  /** A chain the rotation found failing: the alarm, naming which read, and its hold. */
  const rotationFailed = async (
    from: OrganisationChains,
    orgId: string,
    check: RotationCheck,
    reason: string,
    seq?: bigint,
  ): Promise<void> => {
    failures.set(orgId, reason);
    logger
      .child({ orgId })
      .error('audit.integrity_failed', { chain: 'organisation', check, reason, ...(seq === undefined ? {} : { seq }) });
    await settle(from, orgId, undefined);
  };

  /** The rotation, where it has reads: its own memory of what is due, kept across runs. */
  const rotationOf = (from: OrganisationChains | undefined) =>
    from === undefined || rotatedChecks === undefined
      ? undefined
      : createRotation({
          checks: rotatedChecks,
          anchors,
          passes: durable ?? createMemoryPassRecord(),
          keys,
          clock,
          logger,
          epoch: durable?.epoch,
          lateAfterMs: reachWithinMs,
          lastRanAt: () => durable?.lastFileAt(),
          sleeps,
          bounded: async (work, signal) => {
            // Within the lanes' share, as a turn: never a hand-off's connection.
            while (inFlight.size >= lanes && !signal.aborted) await roomOrEnd(signal);
            if (signal.aborted) throw new Stopped('the run has ended');
            return tracked(ROTATION, 'the last read of the rotation has not finished', work, signal);
          },
          failed: (orgId, check, { reason, seq }) => rotationFailed(from, orgId, check, reason, seq),
          missed: async (orgId, check, error) => {
            // A database that refuses the read is the alarm, as for any check; anything else a warning, and next run.
            if (error instanceof ChainStoreError || refusedByDatabase(error)) {
              await rotationFailed(from, orgId, check, 'store');
              return;
            }
            logger.child({ orgId }).warn('audit.anchor_check_failed', { chain: 'organisation', check, err: error });
          },
        });
  const rotation = rotationOf(organizations);

  /** Everything a run does up to its last write, each step cut off by `cap`: the run's time, or the stop. */
  const checkAll = async (cap: AbortSignal, stop: AbortSignal | undefined): Promise<Outcome[]> => {
    const outcomes: Outcome[] = [];
    for (const one of chains) {
      if (cap.aborted) break;
      outcomes.push(await checkOne(one, cap));
    }
    if (organizations !== undefined && !cap.aborted) {
      try {
        // Not spread into a call: past about 120,000, that is out of stack.
        for (const outcome of await checkOrganizations(organizations, cap, stop)) outcomes.push(outcome);
        if (inUse !== undefined) await rotation?.run([...inUse, ...pastCap], cap);
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
        true,
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
      completed = 0;
      missedThisRun = [];
      staleThisRun = [];
      unlistedThisRun = 0;
      firstMiss = undefined;
      if (durable !== undefined) await readStore(durable, cap);
      const endWrites = durable === undefined ? undefined : writeAlong(durable, signal);
      const outcomes = await checkAll(cap, signal);
      clearTimeout(timer);
      signal?.removeEventListener('abort', end);
      endWrites?.();
      sayMissed();
      if (signal?.aborted !== true) sayLeft(cap);
      if (durable !== undefined) {
        // A run stopped ends at once: `flush` never throws, and `finish`, where the API is stopping, joins it.
        if (signal?.aborted === true) void durable.flush();
        else await writeStore(durable, signal, writingAlong);
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

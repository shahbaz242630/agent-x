// The anchor check (ADR-012 §2, SEC-DB-11): every few minutes the API checks
// each audit chain whole against its last anchor, kept in this process's
// memory, and anchors it again. A chain wound back to an earlier state, or
// grown again on a wound-back head, passes its own seals; only the anchor,
// held apart from the database, shows it.
//
// A chain that fails raises the integrity alarm (`audit.integrity_failed`; its
// SEV-1 alert rule is A2c-2) and keeps its last good anchor, so the alarm
// repeats every run until someone looks. Someone with the database's keys can
// also try to stop the check from finishing, and wait for a restart to empty
// this memory: so a database that refuses the check (a right, a table or a
// column gone) is the alarm too, and so is a chain left unchecked for three
// intervals. Anything else that stops a check (the database unreachable, or
// a check past its deadline) is a warning until then. Every run ends with one
// line, so a check that has stopped can be told from one with nothing to say.
// The platform chain is checked every run; each organisation's chain too,
// found from the directory's list at each run (B1d-2). The list is held to
// what the platform chain records: every organisation created there
// (`organization.created`, sealed, so one deleted breaks the platform chain's
// own check) must be listed, and so must every one this process has seen
// listed. One missing is the alarm (`unlisted`): the app never deletes an
// entry, so one gone is tampering, and its chain would otherwise never be
// checked again, even after a restart. A list the database refuses, or one
// that isn't IDs, or too many of them, is the alarm (`list`); a list that
// can't be read otherwise is a warning until three intervals pass without one.
import type { Clock } from '@agentx/core/shared-kernel';
import {
  type AnchorPoint,
  type AnchorStore,
  type Chain,
  type ChainReport,
  ChainStoreError,
  createMemoryAnchorStore,
  signAnchor,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** A chain the check covers, and how to check it against its last anchor, if it has one. */
export interface CheckedChain {
  readonly chain: Chain;
  readonly verify: (anchor: AnchorPoint | undefined) => Promise<ChainReport>;
}

export interface AnchorCheck {
  /**
   * Checks every chain once, one after another, and ends at once when `signal`
   * aborts. Never throws: every outcome is logged.
   */
  run(signal?: AbortSignal): Promise<void>;
}

/** Where the organisations' chains come from (B1d-2). */
export interface OrganisationChains {
  /** Every organisation the directory lists, by ID. */
  list(): Promise<readonly string[]>;
  /** Every organisation the platform chain records as created, by ID: each must be listed. */
  recorded(): Promise<readonly string[]>;
  /** Checks one organisation's chain against its last anchor, if it has one. */
  verify(orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport>;
}

export interface AnchorCheckOptions {
  /** The chains checked every run: the platform's. */
  readonly chains: readonly CheckedChain[];
  /** The organisations' chains, listed afresh each run. None when not given. */
  readonly organizations?: OrganisationChains;
  readonly keys: KeyProvider;
  readonly clock: Clock;
  readonly logger: Logger;
  /** How long a chain may go without a completed check before that is the alarm too. */
  readonly staleAfterMs: number;
  /**
   * How long one chain's check may take. Postgres's own limits can be got round
   * by someone who owns the database, and a connection can die without a word,
   * so the app keeps its own: a check past it has not completed.
   */
  readonly deadlineMs: number;
  readonly anchors?: AnchorStore;
}

/**
 * Postgres's refusals that only a changed database gives the app's role: a
 * right taken away, a table or a column gone. The check can't be run until
 * someone puts them back, which is itself the alarm.
 */
const CHANGED_DATABASE = new Set(['42501', '42P01', '42703']);

/** How many organisations a list may hold before it is read as padded: each run checks them one by one. */
const MOST_ORGANIZATIONS = 10_000;

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

type Outcome = 'anchored' | 'unchanged' | 'failed' | 'unchecked';

/** The in-flight key of the organisations' list, which no chain's key can be. */
const LIST = 'list';

/** The run was stopped while a chain's check was under way. */
class Stopped extends Error {}

/** The check, or a rejection once the deadline passes or the run is stopped, whichever comes first. */
async function withinDeadline<T>(
  checking: Promise<T>,
  deadlineMs: number,
  signal: AbortSignal | undefined,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stop: (() => void) | undefined;
  const cut = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`the check did not finish within ${String(deadlineMs)} ms`));
    }, deadlineMs);
    stop = () => {
      reject(new Stopped('the check was stopped'));
    };
    signal?.addEventListener('abort', stop, { once: true });
  });
  try {
    return await Promise.race([checking, cut]);
  } finally {
    clearTimeout(timer);
    if (stop !== undefined) signal?.removeEventListener('abort', stop);
  }
}

export function createAnchorCheck({
  chains,
  organizations,
  keys,
  clock,
  logger,
  staleAfterMs,
  deadlineMs,
  anchors = createMemoryAnchorStore(),
}: AnchorCheckOptions): AnchorCheck {
  // From when this process began, so a check that never once completes is caught too.
  const started = clock.now().getTime();
  const lastChecked = new Map<string, number>();
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

  const checkOne = async ({ chain, verify }: CheckedChain, signal: AbortSignal | undefined): Promise<Outcome> => {
    // An organisation's ID goes on the line as the logger's own field, which an event can't set.
    const log = chain.kind === 'platform' ? logger : logger.child({ orgId: chain.orgId });
    const key = keyOf(chain);
    try {
      const last = anchors.latest(chain);
      const alarm = (reason: string, seq?: bigint): Outcome => {
        log.error('audit.integrity_failed', {
          chain: chain.kind,
          check: 'anchor',
          reason,
          ...(seq === undefined ? {} : { seq }),
          ...(last === undefined ? {} : { anchorSeq: last.seq }),
        });
        return 'failed';
      };
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
        return clock.now().getTime() - since(key) >= staleAfterMs ? alarm('unchecked') : 'unchecked';
      }
      lastChecked.set(key, clock.now().getTime());
      if (!report.ok) return alarm(report.problem.reason, report.problem.seq);
      // The check compared the anchored event already; this backs it up should a store not pass the anchor on.
      if (
        last !== undefined &&
        (report.seq < last.seq || (report.seq === last.seq && !report.hash.equals(last.hash)))
      ) {
        return alarm('anchor', last.seq);
      }
      if (last?.seq === report.seq) return 'unchanged';
      const anchor = signAnchor(keys, chain, { seq: report.seq, hash: report.hash }, clock.now());
      anchors.keep(anchor);
      log.info('audit.anchored', {
        chain: chain.kind,
        seq: report.seq,
        headHash: report.hash.toString('hex'),
        keyVersion: anchor.keyVersion,
      });
      return 'anchored';
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
    if (reason === 'unchecked' && clock.now().getTime() - since(orgId) < staleAfterMs) return 'unchecked';
    const last = anchors.latest({ kind: 'organisation', orgId });
    logger.child({ orgId }).error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'anchor',
      reason,
      ...(last === undefined ? {} : { anchorSeq: last.seq }),
    });
    return 'failed';
  };

  const remember = (orgId: string): void => {
    if (seen.has(orgId)) return;
    seen.add(orgId);
    firstSeen.set(orgId, clock.now().getTime());
  };

  const checkOrganizations = async (from: OrganisationChains, signal: AbortSignal | undefined): Promise<Outcome[]> => {
    const read = await listOrganizations(from, signal);
    if (read === 'stopped') return [];
    if (typeof read === 'string') {
      // No list to go by. A list never read for three intervals is the alarm
      // in its own right, since after a restart no organisation is known yet.
      if (read === 'failed' && clock.now().getTime() - (listRead ?? started) >= staleAfterMs) {
        logger.error('audit.integrity_failed', { chain: 'organisation', check: 'anchor', reason: 'list' });
      }
      // Each organisation already seen counts as not checked this run.
      return [...seen].map((orgId) => missed(orgId, 'unchecked'));
    }
    const now = new Set(read.listed);
    for (const orgId of read.recorded) remember(orgId);
    const outcomes: Outcome[] = [];
    for (const orgId of seen) if (!now.has(orgId)) outcomes.push(missed(orgId, 'unlisted'));
    for (const orgId of now) {
      if (signal?.aborted === true) break;
      remember(orgId);
      outcomes.push(
        await checkOne(
          { chain: { kind: 'organisation', orgId }, verify: (anchor) => from.verify(orgId, anchor) },
          signal,
        ),
      );
    }
    return outcomes;
  };

  return Object.freeze({
    async run(signal?: AbortSignal): Promise<void> {
      const outcomes: Outcome[] = [];
      for (const one of chains) {
        if (signal?.aborted === true) break;
        outcomes.push(await checkOne(one, signal));
      }
      if (organizations !== undefined && signal?.aborted !== true) {
        try {
          outcomes.push(...(await checkOrganizations(organizations, signal)));
        } catch (error) {
          // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
          logger.error('audit.anchor_check_crashed', { chain: 'organisation', err: error });
        }
      }
      const count = (outcome: Outcome): number => outcomes.filter((each) => each === outcome).length;
      logger.info('audit.anchor_check_done', {
        chains: outcomes.length,
        anchored: count('anchored'),
        unchanged: count('unchanged'),
        failed: count('failed'),
        unchecked: count('unchecked'),
      });
    },
  });
}

/**
 * Runs the check now and then `intervalMs` after each run ends, so runs never
 * overlap. `stop` ends a run in flight at once and waits for it to end; a
 * statement it had begun is left to the database's own limit, which closing
 * the pool waits for.
 */
export function scheduleAnchorCheck(check: AnchorCheck, intervalMs: number): { stop(): Promise<void> } {
  const stopping = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let running: Promise<void> = Promise.resolve();
  const tick = (): void => {
    running = check.run(stopping.signal).then(() => {
      if (stopping.signal.aborted) return;
      timer = setTimeout(tick, intervalMs);
      // The server keeps the process alive; the check alone shouldn't.
      timer.unref();
    });
  };
  tick();
  return Object.freeze({
    async stop(): Promise<void> {
      stopping.abort();
      clearTimeout(timer);
      await running;
    },
  });
}

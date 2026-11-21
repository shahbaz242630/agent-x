// The holdings check (ADR-012 §2: reservations and order claims checked
// against the signed decisions by a frequent scheduled reconciliation;
// SEC-DB-09; Phase 2 E1): the API's job, on a timer of its own. For each
// organisation the directory lists, it goes through every spend request a
// page at a time, each page in a transaction of its own (`checkHoldings`):
// each request the table or the log holds verified (one deleted is alarmed),
// and its reservation and claim compared with what its signed status and
// decision say they must be, and a handed-off one's with what its payment
// says (Phase 4 C3, the outcomes module's `paymentHoldsOf`). A request
// tampered with is passed over, its alarm raised, so the ones after it are
// still checked. A mismatch raises the integrity alarm (`holding`, SEV-1) and puts the organisation on hold, as any tamper sign
// does, so its hand-offs stop until an admin clears it.
//
// Where an organisation's pass has got to is kept here, in the process, as
// the hold history check keeps it: a run checks at most PAGES_A_RUN pages an
// organisation and the next run goes on from there, so a long history can't
// keep the others waiting; a restart starts it again from the beginning.
//
// Which organisations a run visits is job-list.ts's (4D2e D11; Stage D's
// decision 2, a tamper-guard trade told to the partner): every 15 minutes
// those with a mark of any job (work under way or coming, at most 1,000, due
// soonest first), and every organisation at a process's first run and at
// least an hour after the last such (the fourth run), so an idle
// organisation is checked at most an hour and four runs' time apart, never
// left out. One not passed (paused at its share, failed, or the run
// stopped) is `done` only once passed, so it is visited again next run.
//
// A run never throws: each failure is logged, naming the organisation, and
// the run goes on to the next.
import {
  type AuditTables,
  createAuditTrail,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import {
  checkMonthTotals,
  checkPayeeWindows,
  type LimitReservationsTables,
  monthTotalsCutOver,
  MOST_TOTALS_CHECKED_A_PAGE,
  MOST_WINDOWS_CHECKED_A_PAGE,
  payeeWindowsCutOver,
  totalsMissing,
  type TotalsChecked,
  type WindowsChecked,
  windowsMissing,
} from '@agentx/core/modules/limit-reservations';
import { paymentHoldsOf } from '@agentx/core/modules/outcomes';
import {
  checkHoldings,
  checkOrderSlots,
  cutOverMonthTotals,
  cutOverOrderSlots,
  cutOverPayeeWindows,
  MOST_CHECKED_A_PAGE,
  MOST_SLOTS_CHECKED_A_PAGE,
  orderSlotsCutOver,
  type SlotsChecked,
  slotsMissing,
  type SpendRequestsTables,
} from '@agentx/core/modules/spend-requests';
import type { PaymentsTables } from '@agentx/core/modules/transactions';
import { type Clock, type IdGenerator, systemClock } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often the organisations a run lists are checked against what they hold, once the last run has ended. */
export const HOLDINGS_CHECK_EVERY_MS = 15 * 60_000;

/**
 * How long after its first run a process waits before it cuts any organisation over (GM-1a): past boot.ts's stop
 * deadline (25 s), so the process before it, still running the code before GM-1a as a rollout hands the lease over,
 * has stopped, and no decision of its commits after the cutover read the requests.
 */
export const CUTOVER_HOLD_OFF_MS = 30_000;

/**
 * Waits `ms`, or less once `signal` is aborted: a stopping process never waits out the hold-off. One aborted already
 * fires no `abort` again, so it ends at once.
 */
export const waitUnlessStopped = (ms: number, signal: AbortSignal | undefined): Promise<void> =>
  new Promise<void>((resolve) => {
    if (signal?.aborted === true) {
      resolve();
      return;
    }
    const timer = setTimeout(done, ms);
    signal?.addEventListener('abort', done, { once: true });
    function done(): void {
      clearTimeout(timer);
      signal?.removeEventListener('abort', done);
      resolve();
    }
  });

/** How many pages one run checks an organisation: about 10,000 requests a run. */
const PAGES_A_RUN = 50;

export interface HoldingsCheck {
  /** Checks each listed organisation's requests, up to PAGES_A_RUN pages each, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createHoldingsCheck({
  list,
  done = () => undefined,
  database,
  keys,
  ids,
  logger,
  page = MOST_CHECKED_A_PAGE,
  pagesARun = PAGES_A_RUN,
  clock = systemClock,
  cutoverHoldOffMs = CUTOVER_HOLD_OFF_MS,
  wait = waitUnlessStopped,
}: {
  /** The time a cutover opens its totals at (GM-1a), and the hold-off it is measured by. */
  readonly clock?: Clock;
  /** CUTOVER_HOLD_OFF_MS and a timer's wait (waitUnlessStopped), but for the tests. */
  readonly cutoverHoldOffMs?: number;
  readonly wait?: (ms: number, signal: AbortSignal | undefined) => Promise<void>;
  /** The organisations to look in this run: job-list.ts's, from the marks and the directory. */
  readonly list: () => Promise<readonly string[]>;
  /** One whose pass ended this run, its requests all checked: owed no visit until listed again. */
  readonly done?: (orgId: string) => void;
  readonly database: Database<SpendRequestsTables & LimitReservationsTables & PaymentsTables & AuditTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** MOST_CHECKED_A_PAGE and PAGES_A_RUN, but for the tests. */
  readonly page?: number;
  readonly pagesARun?: number;
}): HoldingsCheck {
  /** The last request checked in each organisation's pass so far: none for one starting from the beginning. */
  const progress = new Map<string, string>();
  /** When this process's first run started, which it does once it holds the jobs' lease (job-list.ts). */
  let firstRunAt: number | undefined;
  /** Whether the hold-off has been waited out whole: once, for the month totals', payee windows' and slots' cutovers alike. */
  let heldOff = false;
  /** Waits until CUTOVER_HOLD_OFF_MS has passed since the first run started: at once after that. */
  const cutoverHeldOff = async (signal: AbortSignal | undefined): Promise<void> => {
    firstRunAt ??= clock.now().getTime();
    if (heldOff) return;
    const left = firstRunAt + cutoverHoldOffMs - clock.now().getTime();
    if (left > 0) await wait(left, signal);
    // A wait cut short by the stop signal is waited again by the next run.
    heldOff = signal?.aborted !== true;
  };
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /**
   * The organisation cut over to signed month totals, if it isn't yet (GM-1a): its own transaction, before its pages,
   * so every organisation is at a process's first run. A failure is logged and left for the next run, its decisions
   * refused busy meanwhile.
   */
  const cutOverIn = async (orgId: string, log: Logger, signal: AbortSignal | undefined): Promise<void> => {
    // Not before the process before this one can have stopped (rollout, GM-1a review): it may still commit a decision
    // or an ending made by the code before GM-1a, which keeps no total, for up to its stop deadline after the lease
    // passed here.
    // Read afresh each time: the process may be told to stop at any await.
    const stopped = (): boolean => signal?.aborted === true;
    try {
      // Most are cut over already (born so, or done): one look at the log, and no wait for them.
      const now = await withSignedStates(database, orgId, services(log), (tx, states) =>
        monthTotalsCutOver(tx, states, orgId),
      );
      // Already cut over, or the process stopping: nothing to wait for.
      if (now === 'cut_over' || stopped()) return;
      await cutoverHeldOff(signal);
      // Stopped while it waited (the process is going): left for the next run, which tries again.
      if (stopped()) return;
      const trail = createAuditTrail({ keys, ids });
      const done = await withSignedStates(database, orgId, services(log), (tx, states) =>
        cutOverMonthTotals(tx, states, orgId, {
          payments: paymentHoldsOf,
          record: (event) => trail.record(tx, orgId, event),
          at: clock.now(),
        }),
      );
      if (done.outcome === 'cut_over')
        log.info('month_totals.cut_over', { opened: done.opened, mismatched: done.mismatched });
      if (done.outcome === 'tampered') log.warn('month_totals.cutover_held', {});
    } catch (error) {
      log.error('month_totals.cutover_failed', { err: error });
    }
  };

  /**
   * The organisation cut over to signed payee windows, if it isn't yet (GM-1b), once its month totals are: its own
   * transaction, after theirs, before its pages. The same hold-off, waited once. A failure is logged and left for the
   * next run, its decisions refused busy meanwhile.
   */
  const cutOverWindowsIn = async (orgId: string, log: Logger, signal: AbortSignal | undefined): Promise<void> => {
    const stopped = (): boolean => signal?.aborted === true;
    try {
      const now = await withSignedStates(database, orgId, services(log), (tx, states) =>
        payeeWindowsCutOver(tx, states, orgId),
      );
      if (now === 'cut_over' || stopped()) return;
      await cutoverHeldOff(signal);
      if (stopped()) return;
      const trail = createAuditTrail({ keys, ids });
      const done = await withSignedStates(database, orgId, services(log), (tx, states) =>
        cutOverPayeeWindows(tx, states, orgId, {
          keys,
          payments: paymentHoldsOf,
          record: (event) => trail.record(tx, orgId, event),
          at: clock.now(),
        }),
      );
      if (done.outcome === 'cut_over')
        log.info('payee_windows.cut_over', { opened: done.opened, mismatched: done.mismatched });
      if (done.outcome === 'tampered') log.warn('payee_windows.cutover_held', {});
    } catch (error) {
      log.error('payee_windows.cutover_failed', { err: error });
    }
  };

  /**
   * The organisation cut over to signed order slots, if it isn't yet (TR-2), once its payee windows are: its own
   * transaction, after theirs, before its pages. The same hold-off, waited once. A failure is logged and left for the
   * next run, its decisions refused busy meanwhile.
   */
  const cutOverSlotsIn = async (orgId: string, log: Logger, signal: AbortSignal | undefined): Promise<void> => {
    const stopped = (): boolean => signal?.aborted === true;
    try {
      const now = await withSignedStates(database, orgId, services(log), (tx, states) =>
        orderSlotsCutOver(tx, states, orgId),
      );
      if (now === 'cut_over' || stopped()) return;
      await cutoverHeldOff(signal);
      if (stopped()) return;
      const trail = createAuditTrail({ keys, ids });
      const done = await withSignedStates(database, orgId, services(log), (tx, states) =>
        cutOverOrderSlots(tx, states, orgId, {
          keys,
          payments: paymentHoldsOf,
          record: (event) => trail.record(tx, orgId, event),
          at: clock.now(),
        }),
      );
      if (done.outcome === 'cut_over')
        log.info('order_slots.cut_over', { opened: done.opened, mismatched: done.mismatched });
      if (done.outcome === 'tampered') log.warn('order_slots.cutover_held', {});
    } catch (error) {
      log.error('order_slots.cutover_failed', { err: error });
    }
  };

  /**
   * The organisation's order slots held to their claims (TR-2), a page a transaction, after its payee windows: each
   * slot's mismatch alarmed; then any claim of the last month with no slot at all. Counts what it checked.
   */
  const checkSlotsIn = async (orgId: string, log: Logger) => {
    let after: string | null = null;
    let slots = 0;
    let mismatched = 0;
    let tampered = 0;
    do {
      const from: string | null = after;
      const checked: SlotsChecked = await withSignedStates(database, orgId, services(log), (tx, states) =>
        checkOrderSlots(tx, states, orgId, { after: from, limit: MOST_SLOTS_CHECKED_A_PAGE }),
      );
      slots += checked.slots;
      mismatched += checked.mismatched;
      tampered += checked.tampered;
      after = checked.next;
    } while (after !== null);
    const missing = await withSignedStates(database, orgId, services(log), (tx, states) =>
      slotsMissing(tx, states, orgId, clock.now()),
    );
    return { slots, slotsMismatched: mismatched, slotsTampered: tampered, slotsMissing: missing };
  };

  /**
   * The organisation's payee windows held to their reservations (GM-1b), a page a transaction, after its month
   * totals: each window's mismatch alarmed. Counts what it checked.
   */
  const checkWindowsIn = async (orgId: string, log: Logger) => {
    let after: string | null = null;
    let windows = 0;
    let mismatched = 0;
    let tampered = 0;
    do {
      const from: string | null = after;
      // Each page compared from its own time: a pass over many pages runs on as hours go by and windows let go.
      const at = clock.now();
      const checked: WindowsChecked = await withSignedStates(database, orgId, services(log), (tx, states) =>
        checkPayeeWindows(tx, states, orgId, { after: from, limit: MOST_WINDOWS_CHECKED_A_PAGE, at }),
      );
      windows += checked.windows;
      mismatched += checked.mismatched;
      tampered += checked.tampered;
      after = checked.next;
    } while (after !== null);
    const missing = await withSignedStates(database, orgId, services(log), (tx, states) =>
      windowsMissing(tx, states, orgId, clock.now()),
    );
    return { windows, windowsMismatched: mismatched, windowsTampered: tampered, windowsMissing: missing };
  };

  /**
   * The organisation's month totals held to their reservations (GM-1a), a page a transaction, once its requests'
   * pass has ended: each total's mismatch alarmed. Counts what it checked.
   */
  const checkTotalsIn = async (orgId: string, log: Logger) => {
    let after: string | null = null;
    let totals = 0;
    let mismatched = 0;
    let tampered = 0;
    do {
      const from: string | null = after;
      const checked: TotalsChecked = await withSignedStates(database, orgId, services(log), (tx, states) =>
        checkMonthTotals(tx, states, orgId, { after: from, limit: MOST_TOTALS_CHECKED_A_PAGE }),
      );
      totals += checked.totals;
      mismatched += checked.mismatched;
      tampered += checked.tampered;
      after = checked.next;
    } while (after !== null);
    const missing = await withSignedStates(database, orgId, services(log), (tx, states) =>
      totalsMissing(tx, states, orgId),
    );
    return { totals, totalsMismatched: mismatched, totalsTampered: tampered, totalsMissing: missing };
  };

  /** Checks the organisation's next pages, up to its share; false if the signal stopped it. */
  const checkIn = async (orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    if (progress.get(orgId) === undefined) {
      await cutOverIn(orgId, log, signal);
      await cutOverWindowsIn(orgId, log, signal);
      await cutOverSlotsIn(orgId, log, signal);
    }
    let requests = 0;
    let mismatched = 0;
    let tampered = 0;
    for (let pages = 0; pages < pagesARun; pages += 1) {
      if (signal?.aborted === true) return false;
      const after = progress.get(orgId) ?? null;
      try {
        const checked = await withSignedStates(database, orgId, services(log), (tx, states) =>
          checkHoldings(tx, states, keys, orgId, { after, limit: page }, paymentHoldsOf),
        );
        requests += checked.requests;
        mismatched += checked.mismatched;
        tampered += checked.tampered;
        if (checked.next === null) {
          progress.delete(orgId);
          const totals = await checkTotalsIn(orgId, log);
          const windows = await checkWindowsIn(orgId, log);
          const slots = await checkSlotsIn(orgId, log);
          done(orgId);
          log.info('holdings_check.passed', { requests, mismatched, tampered, ...totals, ...windows, ...slots });
          return true;
        }
        progress.set(orgId, checked.next);
      } catch (error) {
        log.error('holdings_check.failed', { err: error });
        return true;
      }
    }
    log.info('holdings_check.paused', { requests, mismatched, tampered });
    return true;
  };

  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        // The whole run skipped: an error, which the integrity-runs alert counts (Phase 2 E2c).
        logger.error('holdings_check.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        if (!(await checkIn(orgId, signal))) return;
      }
    },
  };
}

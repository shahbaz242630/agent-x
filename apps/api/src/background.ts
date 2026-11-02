// The API's background work (the anchor check, the retention sweep): each on a
// timer of its own, so one never holds up another, and each step bounded by
// the app's own deadline and ending at once when the API stops. Postgres's own
// limits can be got round by someone who owns the database, and a connection
// can die without a word, so the app keeps its own.
import type { Logger } from '@agentx/platform/observability';

/** How often a process takes or renews the jobs' lease, and for how long it holds. */
export const LEASE_RENEW_EVERY_MS = 20_000;
export const LEASE_TERM_MS = 60_000;

/** How long one try at the lease may go unanswered, as the schema check's read; and how soon after one fails the next. */
export const LEASE_TRY_WITHIN_MS = 10_000;
export const LEASE_RETRY_AFTER_MS = 5_000;

/** The run was stopped while a step was under way. */
export class Stopped extends Error {}

/** The step, or a rejection once the deadline passes or the run is stopped, whichever comes first. */
export async function withinDeadline<T>(
  checking: Promise<T>,
  deadlineMs: number,
  signal: AbortSignal | undefined,
): Promise<T> {
  const { promise: cut, reject: cutOff } = Promise.withResolvers<never>();
  const timer = setTimeout(() => {
    cutOff(new Error(`the check did not finish within ${String(deadlineMs)} ms`));
  }, deadlineMs);
  const stop = (): void => {
    cutOff(new Stopped('the check was stopped'));
  };
  // A signal already aborted never fires its event.
  if (signal?.aborted === true) stop();
  signal?.addEventListener('abort', stop, { once: true });
  try {
    return await Promise.race([checking, cut]);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', stop);
  }
}

/**
 * The work's result, or undefined once `ms` have passed from the signal's stop:
 * for a run whose steps can't be cut short (a bank call under way), so a stop
 * still ends within its deadline. No signal, or none stopping: as long as it takes.
 */
export async function finishedWithinStop<T>(
  work: Promise<T>,
  signal: AbortSignal | undefined,
  ms: number,
): Promise<T | undefined> {
  const { promise: gaveUp, resolve: giveUp } = Promise.withResolvers<undefined>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stop = (): void => {
    timer = setTimeout(() => {
      giveUp(undefined);
    }, ms);
  };
  if (signal?.aborted === true) stop();
  signal?.addEventListener('abort', stop, { once: true });
  try {
    return await Promise.race([work, gaveUp]);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', stop);
  }
}

/**
 * Runs the work now and then `intervalMs` after each run ends, so runs never
 * overlap. `stop` ends a run in flight at once and waits for it to end; a
 * statement it had begun is left to the database's own limit, which closing
 * the pool waits for.
 */
export function scheduleRuns(
  work: { run(signal?: AbortSignal): Promise<unknown> },
  intervalMs: number,
): { stop(): Promise<void> } {
  const stopping = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let running: Promise<void> = Promise.resolve();
  const tick = (): void => {
    running = work.run(stopping.signal).then(() => {
      if (stopping.signal.aborted) return;
      timer = setTimeout(tick, intervalMs);
      // The server keeps the process alive; background work alone shouldn't.
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

/** The lease as a process sees it: its own, on the database's clock (0068). */
export interface LeaseStore {
  /** Takes or renews it; says whether this process now has it. */
  take(beating: boolean): Promise<boolean>;
  /** Gives it up, if this process has it. */
  release(): Promise<void>;
}

/** Work with a name, as the job list passes it on. */
interface NamedWork {
  readonly name: string;
  run(signal?: AbortSignal): Promise<void>;
}

export interface Leadership {
  /** Tries for the lease once and goes on trying, each renewal saying whether `beating`. */
  start(beating: () => boolean): Promise<void>;
  /** Whether this process may run the jobs now. */
  leading(): boolean;
  /** The work, each run waiting until this process leads, and aborted through its signal if the lease goes. */
  onlyWhileLeading(work: NamedWork): NamedWork;
  /** Stops renewing and gives the lease up. Never throws. After the jobs have stopped. */
  stop(): Promise<void>;
}

/**
 * One copy of the jobs at a time (4D2e D). A process believes it leads only until
 * its last renewal's sending time plus the term: the database counted that term
 * from later, so this process has let go before another can take it. A try that
 * fails or goes unanswered within its own deadline leaves it leading until then,
 * and is tried again soon; a refusal ends it at once. One try at a time: the
 * statement has limits of its own (job-lease.ts) and the deadline cancels nothing,
 * so a try past them is a connection lost, and another would hold another. It goes
 * on trying either way, so a process that lost
 * the lease takes it back when it can. A monotonic clock by default: a wall clock
 * moved back would hold the lease longer.
 *
 * Everything the jobs do hangs on this row, the anchor check among them, and a
 * follower runs nothing that could raise an alarm. So a process that hasn't led
 * for `notLeadingAfterMs` says so as an error, once and again each time that long
 * passes: a forged or deleted row, or a database that never answers. One copy is
 * the shape we run (policy.ts's ONE_REPLICA), so a follower lasting that long isn't
 * normal.
 */
export function createLeadership({
  store,
  logger,
  notLeadingAfterMs,
  now = () => performance.now(),
  renewEveryMs = LEASE_RENEW_EVERY_MS,
  termMs = LEASE_TERM_MS,
  tryWithinMs = LEASE_TRY_WITHIN_MS,
  retryAfterMs = LEASE_RETRY_AFTER_MS,
}: {
  readonly store: LeaseStore;
  readonly logger: Logger;
  readonly notLeadingAfterMs: number;
  readonly now?: () => number;
  readonly renewEveryMs?: number;
  readonly termMs?: number;
  readonly tryWithinMs?: number;
  readonly retryAfterMs?: number;
}): Leadership {
  const stopping = new AbortController();
  let lead: AbortController | undefined;
  let endsAt = Number.NEGATIVE_INFINITY;
  let expiry: ReturnType<typeof setTimeout> | undefined;
  let renewal: ReturnType<typeof setTimeout> | undefined;
  let renewing: Promise<void> = Promise.resolve();
  let trying = false;
  let beating = (): boolean => false;
  const waiting = new Set<(held: AbortController) => void>();
  // A longer gap than any try can make between two means the process was frozen, not refused.
  const frozenAfterMs = 3 * renewEveryMs + tryWithinMs;
  let triedAt = now();
  let ledAt = triedAt;
  let saidAt = Number.NEGATIVE_INFINITY;
  let refusalSaid = false;

  const leading = (): boolean => lead !== undefined && now() < endsAt;

  const lose = (): void => {
    clearTimeout(expiry);
    if (lead === undefined) return;
    lead.abort();
    lead = undefined;
    logger.warn('jobs.lease_lost');
  };

  const refused = (): void => {
    lose();
    if (!refusalSaid) logger.info('jobs.lease_held_elsewhere');
    refusalSaid = true;
  };

  const hold = (sentAt: number): void => {
    refusalSaid = false;
    endsAt = sentAt + termMs;
    clearTimeout(expiry);
    expiry = setTimeout(lose, Math.max(0, endsAt - now()));
    expiry.unref();
    if (lead === undefined) {
      lead = new AbortController();
      logger.info('jobs.lease_taken');
    }
    for (const wake of waiting) wake(lead);
  };

  /** Whether the database answered: a refusal is an answer. */
  const renew = async (): Promise<boolean> => {
    // The last try is still out: past its deadline, said then, and its connection still held.
    if (trying) return false;
    const sentAt = now();
    trying = true;
    const taking = store.take(beating()).finally(() => {
      trying = false;
    });
    // Handled here too, so a try that fails after its deadline never goes unhandled.
    void taking.catch(() => undefined);
    try {
      if (await withinDeadline(taking, tryWithinMs, stopping.signal)) hold(sentAt);
      else refused();
      return true;
    } catch (error) {
      if (!(error instanceof Stopped)) logger.warn('jobs.lease_renew_failed', { err: error });
      return false;
    }
  };

  const sayIfLongWithout = (): void => {
    const at = now();
    if (leading() || at - triedAt > frozenAfterMs) {
      ledAt = at;
      saidAt = Number.NEGATIVE_INFINITY;
    }
    triedAt = at;
    if (at - ledAt >= notLeadingAfterMs && at - saidAt >= notLeadingAfterMs) {
      saidAt = at;
      logger.error('jobs.not_leading', { forMs: at - ledAt });
    }
  };

  const tick = (): void => {
    renewing = renew().then((answered) => {
      if (stopping.signal.aborted) return;
      sayIfLongWithout();
      renewal = setTimeout(tick, answered ? renewEveryMs : retryAfterMs);
      renewal.unref();
    });
  };

  /** This process's hold once it leads, or nothing if the signal ends the wait first. */
  const untilLeading = (signal: AbortSignal | undefined): Promise<AbortController | undefined> =>
    new Promise((resolve) => {
      if (signal?.aborted === true) {
        resolve(undefined);
        return;
      }
      if (lead !== undefined && leading()) {
        resolve(lead);
        return;
      }
      const end = (held: AbortController | undefined): void => {
        waiting.delete(wake);
        signal?.removeEventListener('abort', ended);
        resolve(held);
      };
      const wake = (held: AbortController): void => {
        end(held);
      };
      const ended = (): void => {
        end(undefined);
      };
      waiting.add(wake);
      signal?.addEventListener('abort', ended, { once: true });
    });

  return {
    start(beats) {
      beating = beats;
      tick();
      return renewing;
    },
    leading,
    onlyWhileLeading(work) {
      return {
        name: work.name,
        async run(signal) {
          const held = await untilLeading(signal);
          if (held === undefined) return;
          await work.run(signal === undefined ? held.signal : AbortSignal.any([signal, held.signal]));
        },
      };
    },
    async stop() {
      stopping.abort();
      clearTimeout(renewal);
      await renewing;
      clearTimeout(expiry);
      lead = undefined;
      try {
        await withinDeadline(store.release(), tryWithinMs, undefined);
      } catch (error) {
        logger.warn('jobs.lease_release_failed', { err: error });
      }
    },
  };
}

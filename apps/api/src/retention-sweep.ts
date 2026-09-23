// The idempotency keys' retention sweep (B1e-3, ADR-014 §3): a key is kept 30
// days from its claim, then deleted. The API sweeps when it starts and then an
// hour after each sweep ends, on a timer of its own: a long sweep (a backlog)
// must never hold up the anchor check, whose missed runs are the alarm.
// Staging's API scales to zero when idle, so each start sweeps too.
//
// Each run reads the directory's list and sweeps each organisation in its own
// withTenant (sweepExpiredKeys), a batch at a time until a batch comes back
// short. The database holds the line itself (0009's `retention` policy), so a
// sweep can only ever delete keys past their 30 days; what this adds is doing
// it. A sweep that fails for one organisation is a warning, and the rest go
// on: a key kept longer than its retention costs a little room and grants
// nothing (a retry of it is answered, as it would have been a day earlier).
// Every run ends with one line, so a sweep that has stopped can be told from
// one with nothing to delete.
import type { Logger } from '@agentx/platform/observability';

import { scheduleRuns, Stopped, withinDeadline } from './background.ts';

export interface RetentionSweepOptions {
  /** Every organisation the directory lists, by ID. */
  readonly list: () => Promise<readonly string[]>;
  /** Deletes up to `most` of the organisation's keys past their retention, and says how many. */
  readonly sweep: (orgId: string, most: number) => Promise<number>;
  readonly logger: Logger;
  /** How long one step (the list, or one batch) may take before it counts as failed. */
  readonly deadlineMs: number;
  /** How many keys one batch deletes. */
  readonly batch: number;
  /** How many batches one organisation gets in a run: the rest wait for the next. */
  readonly mostBatches: number;
}

export interface RetentionSweep {
  /** Sweeps every listed organisation once. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createRetentionSweep({
  list,
  sweep,
  logger,
  deadlineMs,
  batch,
  mostBatches,
}: RetentionSweepOptions): RetentionSweep {
  // A step still under way past its deadline: one at most, so a hung database can't take every connection.
  let inFlight = false;

  /** One step, within the deadline, never beside another still running, and never once the run is stopped. */
  const step = async <T>(doing: () => Promise<T>, signal: AbortSignal | undefined): Promise<T> => {
    if (signal?.aborted === true) throw new Stopped('the sweep was stopped');
    if (inFlight) throw new Error('the last step of the sweep has not finished');
    inFlight = true;
    const running = Promise.resolve().then(doing);
    // Handled here too, so a step that ends after its deadline never goes unhandled.
    void running.then(
      () => (inFlight = false),
      () => (inFlight = false),
    );
    return withinDeadline(running, deadlineMs, signal);
  };

  /** Sweeps one organisation: how many keys it deleted (so far, if the run stopped), or `failed` (warned). */
  const sweepOne = async (orgId: string, signal: AbortSignal | undefined): Promise<number | 'failed'> => {
    let deleted = 0;
    try {
      for (let round = 0; round < mostBatches; round += 1) {
        const swept = await step(() => sweep(orgId, batch), signal);
        deleted += swept;
        if (swept < batch) break;
      }
    } catch (error) {
      if (!(error instanceof Stopped)) {
        logger.child({ orgId }).warn('idempotency.sweep_failed', { err: error });
        return 'failed';
      }
    }
    if (deleted > 0) logger.child({ orgId }).info('idempotency.swept', { keys: deleted });
    return deleted;
  };

  return Object.freeze({
    async run(signal?: AbortSignal): Promise<void> {
      try {
        let organizations: readonly string[];
        try {
          organizations = await step(list, signal);
        } catch (error) {
          if (error instanceof Stopped) return;
          logger.warn('idempotency.sweep_failed', { check: 'list', err: error });
          return;
        }
        let keys = 0;
        let failed = 0;
        // Once stopped, each step refuses to start, so the rest go by without a query.
        for (const orgId of organizations) {
          const outcome = await sweepOne(orgId, signal);
          if (outcome === 'failed') failed += 1;
          else keys += outcome;
        }
        if (signal?.aborted === true) return;
        logger.info('idempotency.sweep_done', { organizations: organizations.length, keys, failed });
      } catch (error) {
        // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
        logger.error('idempotency.sweep_crashed', { err: error });
      }
    },
  });
}

/** Sweeps now and then `everyMs` after each sweep ends, on a timer of its own (scheduleRuns). */
export function scheduleRetentionSweep(sweep: RetentionSweep, everyMs: number): { stop(): Promise<void> } {
  return scheduleRuns(sweep, everyMs);
}

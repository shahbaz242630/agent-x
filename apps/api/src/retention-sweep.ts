// The idempotency keys' retention sweep (B1e-3, ADR-014 §3): a key is kept 30
// days from its claim, then deleted. The API runs it when it starts and then an
// hour after each run ends, on a timer of its own: a long sweep (a backlog)
// must never hold up the anchor check, whose missed runs are the alarm.
//
// Each organisation is swept once a UTC day, and at a process's first run (4D2e
// D11; job-list.ts's list, org-passes.ts), so a key goes at most about a day
// and a run past its 30. One not finished (it failed, the run was stopped, or it
// had more than its share of batches) is swept again each run, from memory,
// until it is; a restart sweeps every one anyway. The day's other runs read
// nothing but their one line.
//
// Each run sweeps each organisation it lists in its own
// withTenant (sweepExpiredKeys), a batch at a time until a batch comes back
// short. The database holds the line itself (0009's `retention` policy), so a
// sweep can only ever delete keys past their 30 days; what this adds is doing
// it. A sweep that fails for one organisation is a warning, and the rest go
// on: a key kept longer than its retention costs a little room and grants
// nothing (a retry of it is answered, as it would have been a day earlier).
// Every run ends with one line, so a sweep that has stopped can be told from
// one with nothing to delete.
//
// The same sweep deletes each organisation's own security events past their
// retention (6E1b, CO7b; 0091), under lines of its own (`lines`).
import type { Logger, ProblemEvent } from '@agentx/platform/observability';

import { scheduleRuns, Stopped, withinDeadline } from './background.ts';

/** What a sweep's lines are called, and what its count names. */
interface SweepLines {
  readonly failed: ProblemEvent;
  readonly crashed: ProblemEvent;
  readonly swept: `${string}.${string}`;
  readonly done: `${string}.${string}`;
  /** The count's field on `swept` and `done`. */
  readonly counted: string;
}

/** The idempotency keys' sweep's lines (B1e-3). */
const IDEMPOTENCY_LINES: SweepLines = {
  failed: 'idempotency.sweep_failed',
  crashed: 'idempotency.sweep_crashed',
  swept: 'idempotency.swept',
  done: 'idempotency.sweep_done',
  counted: 'keys',
};

/** The organisations' own security events' sweep's lines (6E1b). */
export const SECURITY_ORG_EVENT_LINES: SweepLines = {
  failed: 'security.org_events_sweep_failed',
  crashed: 'security.org_events_sweep_crashed',
  swept: 'security.org_events_swept',
  done: 'security.org_events_sweep_done',
  counted: 'events',
};

/** The MCP connections' token rows' sweep's lines (6E3a, 0093): each organisation's past 120 days. */
export const CONNECTION_TOKEN_LINES: SweepLines = {
  failed: 'agents.connection_tokens_sweep_failed',
  crashed: 'agents.connection_tokens_sweep_crashed',
  swept: 'agents.connection_tokens_swept',
  done: 'agents.connection_tokens_sweep_done',
  counted: 'tokens',
};

export interface RetentionSweepOptions {
  /** The organisations to sweep this run, by ID. */
  readonly list: () => Promise<readonly string[]>;
  /** One swept to its last batch this run: owed no sweep until listed again. */
  readonly done?: (orgId: string) => void;
  /** Deletes up to `most` of the organisation's keys past their retention, and says how many. */
  readonly sweep: (orgId: string, most: number) => Promise<number>;
  readonly logger: Logger;
  /** How long one step (the list, or one batch) may take before it counts as failed. */
  readonly deadlineMs: number;
  /** How many keys one batch deletes. */
  readonly batch: number;
  /** How many batches one organisation gets in a run: the rest wait for the next. */
  readonly mostBatches: number;
  /** Its lines: the idempotency keys' unless named. */
  readonly lines?: SweepLines;
}

export interface RetentionSweep {
  /** Sweeps every listed organisation once. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createRetentionSweep({
  list,
  done = () => undefined,
  sweep,
  logger,
  deadlineMs,
  batch,
  mostBatches,
  lines = IDEMPOTENCY_LINES,
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
        if (swept < batch) {
          done(orgId);
          break;
        }
      }
    } catch (error) {
      if (!(error instanceof Stopped)) {
        logger.child({ orgId }).warn(lines.failed, { err: error });
        return 'failed';
      }
    }
    if (deleted > 0) logger.child({ orgId }).info(lines.swept, { [lines.counted]: deleted });
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
          logger.warn(lines.failed, { check: 'list', err: error });
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
        logger.info(lines.done, { organizations: organizations.length, [lines.counted]: keys, failed });
      } catch (error) {
        // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
        logger.error(lines.crashed, { err: error });
      }
    },
  });
}

/** Sweeps now and then `everyMs` after each sweep ends, on a timer of its own (scheduleRuns). */
export function scheduleRetentionSweep(sweep: RetentionSweep, everyMs: number): { stop(): Promise<void> } {
  return scheduleRuns(sweep, everyMs);
}

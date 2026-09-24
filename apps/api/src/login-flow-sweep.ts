// The sign-in flows' sweep (B2-3a-2): a flow is kept until its browser comes
// back, and a browser that never does leaves it behind, so anyone could fill
// the table by starting sign-ins. The API sweeps flows past their ten
// minutes when it starts and then an hour after each sweep ends, on a timer
// of its own beside the idempotency keys' retention sweep, a batch at a time
// until a batch comes back short. A failed sweep is a warning: the next one
// takes what it left. Every run ends with one line.
import type { Logger } from '@agentx/platform/observability';

import { scheduleRuns, Stopped, withinDeadline } from './background.ts';

export interface LoginFlowSweepOptions {
  /** Deletes up to `most` flows past their ten minutes, and says how many. */
  readonly sweep: (most: number) => Promise<number>;
  readonly logger: Logger;
  /** How long one batch may take before the run counts as failed. */
  readonly deadlineMs: number;
  /** How many flows one batch deletes. */
  readonly batch: number;
  /** How many batches one run gets: the rest wait for the next. */
  readonly mostBatches: number;
}

export interface LoginFlowSweep {
  /** Sweeps once. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createLoginFlowSweep({
  sweep,
  logger,
  deadlineMs,
  batch,
  mostBatches,
}: LoginFlowSweepOptions): LoginFlowSweep {
  return Object.freeze({
    async run(signal?: AbortSignal): Promise<void> {
      let flows = 0;
      try {
        for (let round = 0; round < mostBatches; round += 1) {
          if (signal?.aborted === true) return;
          const swept = await withinDeadline(
            Promise.resolve().then(() => sweep(batch)),
            deadlineMs,
            signal,
          );
          flows += swept;
          if (swept < batch) break;
        }
      } catch (error) {
        if (error instanceof Stopped) return;
        logger.warn('identity.flow_sweep_failed', { flows, err: error });
        return;
      }
      logger.info('identity.flow_sweep_done', { flows });
    },
  });
}

/** Sweeps now and then `everyMs` after each sweep ends, on a timer of its own. */
export function scheduleLoginFlowSweep(sweep: LoginFlowSweep, everyMs: number): { stop(): Promise<void> } {
  return scheduleRuns(sweep, everyMs);
}

// The sweeps of global tables whose rows outlive their use and would
// otherwise pile up:
//
// - sign-in flows (B2-3a-2): a flow is kept until its browser comes back, and
//   a browser that never does leaves it behind, so anyone could fill the
//   table by starting sign-ins;
// - console sessions (B2-4a): a session past its idle or absolute timeout is
//   never found again, but its row stays until the person signs out, which
//   most never do;
// - security events (B2-5a): each is kept for the retention period the config
//   names, with the client's IP address, and no longer.
//
// The API sweeps each when it starts and then an hour after each sweep ends,
// each on a timer of its own beside the idempotency keys' retention sweep, a
// batch at a time until a batch comes back short. A failed sweep is a
// warning: the next one takes what it left. Every run ends with one line,
// `<rows>_sweep_done` with how many it deleted, so a sweep that has stopped
// can be told from one with nothing to do.
import type { Logger } from '@agentx/platform/observability';

import { scheduleRuns, Stopped, withinDeadline } from './background.ts';

/**
 * What a sweep deletes, as its log lines name it: `identity.flow_sweep_done`
 * and so on. The count is `deleted` for all: the logger redacts any field
 * named like `session`.
 */
export type SweptRows = 'identity.flow' | 'identity.session' | 'security.event';

export interface RowSweepOptions {
  readonly rows: SweptRows;
  /** Deletes up to `most` rows past their use, and says how many. */
  readonly sweep: (most: number) => Promise<number>;
  readonly logger: Logger;
  /** How long one batch may take before the run counts as failed. */
  readonly deadlineMs: number;
  /** How many rows one batch deletes. */
  readonly batch: number;
  /** How many batches one run gets: the rest wait for the next. */
  readonly mostBatches: number;
}

export interface RowSweep {
  /** Sweeps once. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createRowSweep({ rows, sweep, logger, deadlineMs, batch, mostBatches }: RowSweepOptions): RowSweep {
  return Object.freeze({
    async run(signal?: AbortSignal): Promise<void> {
      let deleted = 0;
      try {
        for (let round = 0; round < mostBatches; round += 1) {
          if (signal?.aborted === true) return;
          const swept = await withinDeadline(
            Promise.resolve().then(() => sweep(batch)),
            deadlineMs,
            signal,
          );
          deleted += swept;
          if (swept < batch) break;
        }
      } catch (error) {
        if (error instanceof Stopped) return;
        logger.warn(`${rows}_sweep_failed`, { deleted, err: error });
        return;
      }
      logger.info(`${rows}_sweep_done`, { deleted });
    },
  });
}

/** Sweeps now and then `everyMs` after each sweep ends, on a timer of its own. */
export function scheduleRowSweep(sweep: RowSweep, everyMs: number): { stop(): Promise<void> } {
  return scheduleRuns(sweep, everyMs);
}

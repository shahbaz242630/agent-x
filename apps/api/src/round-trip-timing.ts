// How long a trip from this API to its database takes, read through its life
// and logged (4D2d, PL-38): a decision is about 25 trips, so half a millisecond
// more a trip is over 12 ms more a decision, and on Azure the API's replica can't
// be pinned near the database (S159). Run day 4's phase 2 sat 20 ms above its
// phase 1 with nothing to say why (S165). A trip is timed from inside the API, so
// a busy API reads as a slow trip: the line carries the API's own delay beside it.
import { monitorEventLoopDelay } from 'node:perf_hooks';

import type { Logger } from '@agentx/platform/observability';

import { Stopped, withinDeadline } from './background.ts';

export const ROUND_TRIP_EVERY_MS = 15_000;
export const ROUND_TRIPS_A_RUN = 5;
// Past the pool's own 10 s wait for a connection: a busy pool alone never warns here (a load run fails on a warning).
const ROUND_TRIP_DEADLINE_MS = 15_000;
const LOOP_DELAY_RESOLUTION_MS = 10;

const tenths = (ms: number): number => Math.round(ms * 10) / 10;

export function createRoundTripTiming({
  timed,
  logger,
  deadlineMs = ROUND_TRIP_DEADLINE_MS,
}: {
  /** The run's trips, each one's time in milliseconds. */
  readonly timed: () => Promise<readonly number[]>;
  readonly logger: Logger;
  readonly deadlineMs?: number;
}): { run(signal?: AbortSignal): Promise<void> } {
  const loopDelay = monitorEventLoopDelay({ resolution: LOOP_DELAY_RESOLUTION_MS });
  loopDelay.enable();
  return Object.freeze({
    async run(signal?: AbortSignal): Promise<void> {
      try {
        const sorted = (await withinDeadline(timed(), deadlineMs, signal)).toSorted((a, b) => a - b);
        logger.info('db.round_trip', {
          trips: sorted.length,
          // The fastest is nearest the network alone; the others have the API's own business in them too.
          fastestMs: tenths(sorted[0] ?? 0),
          medianMs: tenths(sorted[Math.floor(sorted.length / 2)] ?? 0),
          slowestMs: tenths(sorted.at(-1) ?? 0),
          // Since the last line; its timer's own interval is in each reading, so taken off.
          loopDelayP99Ms: tenths(Math.max(0, loopDelay.percentile(99) / 1e6 - LOOP_DELAY_RESOLUTION_MS)),
        });
        loopDelay.reset();
      } catch (error) {
        if (error instanceof Stopped) return;
        logger.warn('db.round_trip_failed', { err: error });
      }
    },
  });
}

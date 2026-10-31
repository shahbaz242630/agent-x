// How long a trip from this API to its database takes, read through its life
// and logged (4D2d, PL-38): a decision is about 36 trips, so half a millisecond
// more a trip is 20 ms more a decision, and on Azure the API's replica can't be
// pinned near the database (S159). Run day 4's phase 2 sat 20 ms above its
// phase 1 with nothing to say why (S165).
import type { Logger } from '@agentx/platform/observability';

import { Stopped, withinDeadline } from './background.ts';

export const ROUND_TRIP_EVERY_MS = 15_000;
export const ROUND_TRIPS_A_RUN = 5;
const ROUND_TRIP_DEADLINE_MS = 5_000;

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
  return Object.freeze({
    async run(signal?: AbortSignal): Promise<void> {
      try {
        const sorted = [...(await withinDeadline(timed(), deadlineMs, signal))].sort((a, b) => a - b);
        logger.info('db.round_trip', {
          trips: sorted.length,
          // The fastest is nearest the network alone; the slowest has the API's own business in it too.
          fastestMs: tenths(sorted[0] ?? 0),
          medianMs: tenths(sorted[Math.floor(sorted.length / 2)] ?? 0),
          slowestMs: tenths(sorted.at(-1) ?? 0),
        });
      } catch (error) {
        if (error instanceof Stopped) return;
        logger.warn('db.round_trip_failed', { err: error });
      }
    },
  });
}

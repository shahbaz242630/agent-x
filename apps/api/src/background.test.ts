// The jobs' timer: runs now, and again after each run ends; stops at once.
import { describe, expect, it } from 'vitest';

import { scheduleRuns } from './background.ts';

describe('a job on a timer of its own', () => {
  it('runs now, and stopping aborts the run and ends', async () => {
    const runs: (AbortSignal | undefined)[] = [];
    const handle = scheduleRuns(
      {
        run: (signal) => {
          runs.push(signal);
          return Promise.resolve();
        },
      },
      60_000,
    );

    await handle.stop();
    expect(runs).toHaveLength(1);
    expect(runs[0]?.aborted).toBe(true);
  });

  it('runs again only after a run has ended, whatever a run gives back', async () => {
    let runs = 0;
    const { promise: ranTwice, resolve } = Promise.withResolvers<undefined>();
    const handle = scheduleRuns(
      {
        run: () => {
          runs += 1;
          if (runs === 2) resolve(undefined);
          return Promise.resolve('skipped');
        },
      },
      1,
    );
    await ranTwice;
    await handle.stop();
    expect(runs).toBeGreaterThanOrEqual(2);
  });
});

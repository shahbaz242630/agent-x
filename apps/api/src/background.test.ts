// B6-2b: background work a config may leave off: a handle that runs nothing,
// says so and stops at once; and one that runs the work, and stops it.
import { describe, expect, it } from 'vitest';

import { scheduleRunsIfAny } from './background.ts';

describe('work the config may leave off (B6-2b)', () => {
  it('runs nothing without work, says so, and stops at once', async () => {
    const handle = scheduleRunsIfAny(undefined, 60_000);

    expect(handle.running).toBe(false);
    await expect(handle.stop()).resolves.toBeUndefined();
  });

  it('runs the work now, says so, and stops it', async () => {
    const runs: (AbortSignal | undefined)[] = [];
    const handle = scheduleRunsIfAny(
      {
        run: (signal) => {
          runs.push(signal);
          return Promise.resolve();
        },
      },
      60_000,
    );

    expect(handle.running).toBe(true);
    await handle.stop();
    expect(runs).toHaveLength(1);
    expect(runs[0]?.aborted).toBe(true);
  });
});

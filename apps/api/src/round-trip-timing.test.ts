import { LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it, vi } from 'vitest';

import { createRoundTripTiming } from './round-trip-timing.ts';

function timing(timed: () => Promise<readonly number[]>, deadlineMs?: number) {
  const capture = new LogCapture();
  const job = createRoundTripTiming({
    timed,
    logger: testLogger(capture),
    ...(deadlineMs === undefined ? {} : { deadlineMs }),
  });
  return { job, lines: () => capture.lines() };
}

describe('the round trip timing', () => {
  it('logs the fastest, the middle and the slowest of a run', async () => {
    const { job, lines } = timing(() => Promise.resolve([3.26, 1.04, 2.5, 9.99, 2.01]));
    await job.run();
    expect(lines()).toEqual([
      expect.objectContaining({
        level: 'info',
        event: 'db.round_trip',
        trips: 5,
        fastestMs: 1,
        medianMs: 2.5,
        slowestMs: 10,
      }),
    ]);
  });

  it('warns when the trips fail, and throws nothing: the schedule goes on', async () => {
    const { job, lines } = timing(() => Promise.reject(new Error('no connection')));
    await expect(job.run()).resolves.toBeUndefined();
    expect(lines()).toEqual([expect.objectContaining({ level: 'warn', event: 'db.round_trip_failed' })]);
  });

  it('warns when the trips hang past the deadline', async () => {
    vi.useFakeTimers();
    try {
      const { job, lines } = timing(() => new Promise<never>(() => undefined), 100);
      const running = job.run();
      await vi.advanceTimersByTimeAsync(101);
      await running;
      expect(lines()).toEqual([expect.objectContaining({ level: 'warn', event: 'db.round_trip_failed' })]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('says nothing when stopped mid-run', async () => {
    const { job, lines } = timing(() => new Promise<never>(() => undefined));
    const stopping = new AbortController();
    const running = job.run(stopping.signal);
    stopping.abort();
    await running;
    expect(lines()).toEqual([]);
  });

  it('logs zeros, not a crash, for a run of no trips', async () => {
    const { job, lines } = timing(() => Promise.resolve([]));
    await job.run();
    expect(lines()).toEqual([expect.objectContaining({ trips: 0, fastestMs: 0, medianMs: 0, slowestMs: 0 })]);
  });
});

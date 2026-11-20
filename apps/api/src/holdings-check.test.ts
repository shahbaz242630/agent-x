// GM-1a review: the cutover's hold-off wait gives way to the job's stop signal, so a stopping process never waits it out.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CUTOVER_HOLD_OFF_MS, waitUnlessStopped } from './holdings-check.ts';

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('the hold-off wait', () => {
  it('ends when its time is up, with no signal or one never aborted', async () => {
    let ended = 0;
    void waitUnlessStopped(1_000, undefined).then(() => (ended += 1));
    void waitUnlessStopped(1_000, new AbortController().signal).then(() => (ended += 1));
    await vi.advanceTimersByTimeAsync(999);
    expect(ended).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(ended).toBe(2);
  });

  it('ends at once when the job is stopped, its timer cleared', async () => {
    const stop = new AbortController();
    let ended = false;
    void waitUnlessStopped(CUTOVER_HOLD_OFF_MS, stop.signal).then(() => (ended = true));
    await vi.advanceTimersByTimeAsync(10);
    stop.abort();
    await vi.advanceTimersByTimeAsync(0);
    expect(ended).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});

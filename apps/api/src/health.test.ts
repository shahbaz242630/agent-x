// 4D2e D: /health's check of the jobs from a process not running them.
import { describe, expect, it, vi } from 'vitest';

import { SHARED_HEARTBEAT_CACHE_MS, sharedHeartbeat } from './health.ts';

describe('the shared heartbeat', () => {
  it('reads at most once in its cache time, whatever the calls', async () => {
    let at = 0;
    const read = vi.fn(() => Promise.resolve(true));
    const { name, check } = sharedHeartbeat(
      read,
      () => false,
      () => at,
    );
    expect(name).toBe('jobs_heartbeat');
    expect(await Promise.all([check(), check()])).toEqual([true, true]);
    at = SHARED_HEARTBEAT_CACHE_MS - 1;
    await check();
    expect(read).toHaveBeenCalledTimes(1);
    at = SHARED_HEARTBEAT_CACHE_MS;
    await check();
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('keeps a failed read for the same time, so a public call never adds trips to a database in trouble', async () => {
    let at = 0;
    const read = vi.fn(() => Promise.reject(new Error('connection lost')));
    const { check } = sharedHeartbeat(
      read,
      () => false,
      () => at,
    );
    await expect(check()).rejects.toThrow('connection lost');
    await expect(check()).rejects.toThrow('connection lost');
    expect(read).toHaveBeenCalledTimes(1);
    at = SHARED_HEARTBEAT_CACHE_MS;
    await expect(check()).rejects.toThrow('connection lost');
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('makes no trip where this process leads: its own jobs say', async () => {
    const read = vi.fn(() => Promise.resolve(false));
    const { check } = sharedHeartbeat(read, () => true);
    await expect(check()).resolves.toBe(true);
    expect(read).not.toHaveBeenCalled();
  });

  it('uses a clock of its own when given none', async () => {
    const { check } = sharedHeartbeat(
      () => Promise.resolve(true),
      () => false,
    );
    await expect(check()).resolves.toBe(true);
  });
});

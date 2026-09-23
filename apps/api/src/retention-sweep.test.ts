import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createRetentionSweep, type RetentionSweepOptions, scheduleRetentionSweep } from './retention-sweep.ts';

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const DEADLINE_MS = 120_000;
const BATCH = 10;

/**
 * A sweep over `organizations`, whose batches give each organisation's counts
 * in turn (0 once they run out), with every call and line recorded.
 */
function sweeping(
  organizations: readonly string[] | (() => Promise<readonly string[]>),
  counts: Record<string, readonly (number | Error | 'hang')[]> = {},
  options: Partial<RetentionSweepOptions> = {},
) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  const calls: string[] = [];
  const turns = new Map<string, number>();
  const sweep = createRetentionSweep({
    list: typeof organizations === 'function' ? organizations : () => Promise.resolve(organizations),
    sweep: (orgId, most) => {
      calls.push(`${orgId} ${String(most)}`);
      const turn = turns.get(orgId) ?? 0;
      turns.set(orgId, turn + 1);
      const answer = counts[orgId]?.[turn] ?? 0;
      if (answer === 'hang') return new Promise<never>(() => undefined);
      return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
    },
    logger,
    deadlineMs: DEADLINE_MS,
    batch: BATCH,
    mostBatches: 5,
    ...options,
  });
  const lines = () =>
    capture
      .lines()
      .filter((line) => String(line.event).startsWith('idempotency.'))
      .map(({ level, event, orgId, keys, organizations: count, failed, check }) => ({
        level,
        event,
        ...(orgId === undefined ? {} : { orgId }),
        ...(keys === undefined ? {} : { keys }),
        ...(count === undefined ? {} : { organizations: count }),
        ...(failed === undefined ? {} : { failed }),
        ...(check === undefined ? {} : { check }),
      }));
  return { sweep, calls, lines, capture };
}

const done = (organizations: number, keys: number, failed = 0) => ({
  level: 'info',
  event: 'idempotency.sweep_done',
  organizations,
  keys,
  failed,
});

describe("the idempotency keys' retention sweep (B1e-3)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('sweeps each listed organisation a batch at a time until a batch comes back short, and says so', async () => {
    const { sweep, calls, lines } = sweeping([ORG, OTHER_ORG], { [ORG]: [BATCH, BATCH, 3], [OTHER_ORG]: [0] });
    await sweep.run();

    expect(calls).toEqual([`${ORG} 10`, `${ORG} 10`, `${ORG} 10`, `${OTHER_ORG} 10`]);
    expect(lines()).toEqual([{ level: 'info', event: 'idempotency.swept', orgId: ORG, keys: 23 }, done(2, 23)]);
  });

  it('gives an organisation at most its batches a run, leaving the rest for the next', async () => {
    const { sweep, calls, lines } = sweeping([ORG, OTHER_ORG], { [ORG]: Array<number>(9).fill(BATCH) });
    await sweep.run();

    expect(calls.filter((call) => call.startsWith(ORG))).toHaveLength(5);
    expect(lines()).toEqual([{ level: 'info', event: 'idempotency.swept', orgId: ORG, keys: 50 }, done(2, 50)]);
  });

  it('warns for an organisation whose sweep fails, keeps what it deleted before, and goes on to the next', async () => {
    const { sweep, calls, lines } = sweeping([ORG, OTHER_ORG], {
      [ORG]: [BATCH, new Error('connect ECONNREFUSED')],
      [OTHER_ORG]: [2],
    });
    await sweep.run();

    expect(calls).toEqual([`${ORG} 10`, `${ORG} 10`, `${OTHER_ORG} 10`]);
    expect(lines()).toEqual([
      { level: 'warn', event: 'idempotency.sweep_failed', orgId: ORG },
      { level: 'info', event: 'idempotency.swept', orgId: OTHER_ORG, keys: 2 },
      done(2, 2, 1),
    ]);
  });

  it('warns for a list it cannot read, sweeps nothing, and reads it again next run', async () => {
    let reads = 0;
    const { sweep, calls, lines } = sweeping(() => {
      reads += 1;
      return Promise.reject(new Error('connect ECONNREFUSED'));
    });
    await sweep.run();
    await sweep.run();

    expect(reads).toBe(2);
    expect(calls).toEqual([]);
    expect(lines()).toEqual([
      { level: 'warn', event: 'idempotency.sweep_failed', check: 'list' },
      { level: 'warn', event: 'idempotency.sweep_failed', check: 'list' },
    ]);
  });

  it('counts a batch past its deadline as failed, and never starts another step while it runs', async () => {
    vi.useFakeTimers();
    const { sweep, calls, lines, capture } = sweeping([ORG, OTHER_ORG], { [ORG]: ['hang'] });
    const running = sweep.run();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await running;

    expect(calls).toEqual([`${ORG} 10`]);
    expect(lines()).toEqual([
      { level: 'warn', event: 'idempotency.sweep_failed', orgId: ORG },
      { level: 'warn', event: 'idempotency.sweep_failed', orgId: OTHER_ORG },
      done(2, 0, 2),
    ]);
    expect(
      capture
        .lines()
        .filter((line) => line.event === 'idempotency.sweep_failed')
        .map((line) => (line.err as { message?: string } | undefined)?.message),
    ).toEqual([
      `the check did not finish within ${String(DEADLINE_MS)} ms`,
      'the last step of the sweep has not finished',
    ]);
    // The next run's list can't start either while the batch hangs.
    await sweep.run();
    expect(lines().at(-1)).toEqual({ level: 'warn', event: 'idempotency.sweep_failed', check: 'list' });
  });

  it('ends at once when stopped mid-batch: no warning, no more organisations, no closing line', async () => {
    const stopping = new AbortController();
    const { sweep, calls, lines } = sweeping(
      [ORG, OTHER_ORG],
      {},
      {
        sweep: (orgId) => {
          calls.push(orgId);
          stopping.abort();
          return new Promise<never>(() => undefined);
        },
      },
    );
    await sweep.run(stopping.signal);

    expect(calls).toEqual([ORG]);
    expect(lines()).toEqual([]);
  });

  it('ends at once when stopped while the list is read, and sweeps nothing in a run stopped before it', async () => {
    const stopping = new AbortController();
    const { sweep, calls, lines } = sweeping(() => {
      stopping.abort();
      return new Promise<never>(() => undefined);
    });
    await sweep.run(stopping.signal);
    expect(calls).toEqual([]);
    expect(lines()).toEqual([]);

    // A run stopped before it began starts no step at all: a list that would hang is never read.
    let reads = 0;
    const later = sweeping(() => {
      reads += 1;
      return new Promise<never>(() => undefined);
    });
    await later.sweep.run(AbortSignal.abort());
    expect(reads).toBe(0);
    expect(later.lines()).toEqual([]);
  });

  it('sweeps no further organisation once stopped during a batch that still ends, and closes with no line', async () => {
    const stopping = new AbortController();
    const { sweep, calls, lines } = sweeping(
      [ORG, OTHER_ORG],
      {},
      {
        sweep: (orgId) => {
          calls.push(orgId);
          stopping.abort();
          return Promise.resolve(4);
        },
      },
    );
    await sweep.run(stopping.signal);

    // The stop wins over the batch's answer: its keys are deleted, but not counted.
    expect(calls).toEqual([ORG]);
    expect(lines()).toEqual([]);
  });

  it('runs on a schedule of its own: at once, then an interval after each run ends, until stopped', async () => {
    vi.useFakeTimers();
    const { sweep, calls } = sweeping([ORG]);
    const schedule = scheduleRetentionSweep(sweep, 60_000);
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toHaveLength(2);
    await schedule.stop();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(calls).toHaveLength(2);
  });

  it('contains a run that crashes: logs it, and runs again next time', async () => {
    const { sweep, lines } = sweeping(() => Promise.resolve(null as unknown as readonly string[]));
    await sweep.run();
    await sweep.run();

    expect(lines()).toEqual([
      { level: 'error', event: 'idempotency.sweep_crashed' },
      { level: 'error', event: 'idempotency.sweep_crashed' },
    ]);
  });
});

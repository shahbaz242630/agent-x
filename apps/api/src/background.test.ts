// The jobs' timer: runs now, and again after each run ends; stops at once.
import { createLogger, type Logger, withLogContext } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { finishedWithinStop, scheduleRuns, Stopped, withinDeadline } from './background.ts';

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

  it('Stage F gives each run an ID of its own, on every line it writes through any logger, past its awaits and timers', async () => {
    const capture = new LogCapture();
    const logger: Logger = createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
      destination: capture,
    });
    const { promise: ranTwice, resolve } = Promise.withResolvers<undefined>();
    let runs = 0;
    const handle = scheduleRuns(
      {
        run: async () => {
          runs += 1;
          logger.info('job.started');
          await new Promise((settle) => setTimeout(settle, 1));
          // A job's own correlation ID for one organisation is kept beside the run's.
          logger.child({ correlationId: 'for-one-organisation' }).info('job.organisation');
          if (runs === 2) resolve(undefined);
        },
      },
      1,
    );
    await ranTwice;
    await handle.stop();
    const lines = capture.lines();
    const [first, second, third] = lines;
    expect(first).toMatchObject({ event: 'job.started', runId: expect.stringMatching(/^[0-9a-f-]{36}$/) as string });
    expect(second).toMatchObject({ runId: first?.runId, correlationId: 'for-one-organisation' });
    expect(third?.runId).not.toBe(first?.runId);
    expect(lines.every((line) => typeof line.runId === 'string')).toBe(true);
    // Outside a run, nothing of it is left.
    logger.info('job.after');
    expect(capture.lines().at(-1)).not.toHaveProperty('runId');
  });

  it('Stage F keeps two jobs under way at once apart, one woken by the other, and out of a request that started them', async () => {
    const capture = new LogCapture();
    const logger: Logger = createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
      destination: capture,
    });
    const { promise: woken, resolve: wake } = Promise.withResolvers<undefined>();
    const waits = {
      run: async () => {
        logger.info('job.began', { job: 'waits' });
        // Goes on only when the other job lets it, as a waiter let through by another's leave does.
        await woken;
        logger.info('job.went_on', { job: 'waits' });
      },
    };
    const wakes = {
      run: () => {
        logger.info('job.began', { job: 'wakes' });
        wake(undefined);
        return Promise.resolve();
      },
    };
    const handles = withLogContext({ correlationId: 'a-request' }, () => [
      scheduleRuns(waits, 60_000),
      scheduleRuns(wakes, 60_000),
    ]);
    await Promise.all(handles.map((handle) => handle.stop()));
    const lines = capture.lines();
    const runsOf = (job: string) => new Set(lines.filter((line) => line.job === job).map((line) => line.runId));
    expect(lines.map((line) => line.event).toSorted()).toEqual(['job.began', 'job.began', 'job.went_on']);
    const [ofWaits] = runsOf('waits');
    expect(runsOf('waits').size).toBe(1);
    expect(ofWaits).toEqual(expect.any(String));
    expect(runsOf('wakes').has(ofWaits)).toBe(false);
    expect(lines.every((line) => line.correlationId === undefined)).toBe(true);
  });
});

describe('a step within its deadline', () => {
  const never = () => Promise.withResolvers<undefined>().promise;

  it('stops at once for a signal already stopped, which never fires its event', async () => {
    const stopping = new AbortController();
    stopping.abort();

    await expect(withinDeadline(never(), 60_000, stopping.signal)).rejects.toThrow(Stopped);
  });

  it('stops as the signal does', async () => {
    const stopping = new AbortController();
    const step = withinDeadline(never(), 60_000, stopping.signal);

    stopping.abort();

    await expect(step).rejects.toThrow(Stopped);
  });

  it('gives its answer where nothing stops it', async () => {
    await expect(withinDeadline(Promise.resolve('done'), 60_000, undefined)).resolves.toBe('done');
  });
});

describe('a stop’s bounded wait', () => {
  const never = () => Promise.withResolvers<undefined>().promise;

  it('gives the work’s result where it finishes in time, stopped or not', async () => {
    const stopping = new AbortController();
    stopping.abort();

    await expect(finishedWithinStop(Promise.resolve('done'), undefined, 1)).resolves.toBe('done');
    await expect(finishedWithinStop(Promise.resolve('done'), stopping.signal, 60_000)).resolves.toBe('done');
  });

  it('gives up after its time from a stop already made', async () => {
    const stopping = new AbortController();
    stopping.abort();

    await expect(finishedWithinStop(never(), stopping.signal, 10)).resolves.toBeUndefined();
  });

  it('gives up after its time from the stop, not before it', async () => {
    const stopping = new AbortController();
    let ended = false;
    const waiting = finishedWithinStop(never(), stopping.signal, 10).then(() => {
      ended = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(ended).toBe(false);

    stopping.abort();
    await waiting;
    expect(ended).toBe(true);
  });

  it('waits as long as it takes with no signal at all', async () => {
    const { promise: work, resolve: finish } = Promise.withResolvers<string>();
    const waiting = finishedWithinStop(work, undefined, 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    finish('late');

    await expect(waiting).resolves.toBe('late');
  });
});

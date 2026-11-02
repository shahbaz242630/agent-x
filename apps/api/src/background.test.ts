// The jobs' timer: runs now, and again after each run ends; stops at once.
import { createLogger, type Logger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
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
});

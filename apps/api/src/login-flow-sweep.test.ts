import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createLoginFlowSweep } from './login-flow-sweep.ts';

function setUp(answers: (number | Error | 'hang')[], options: { batch?: number; mostBatches?: number } = {}) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  const asked: number[] = [];
  const sweep = createLoginFlowSweep({
    sweep: (most) => {
      asked.push(most);
      const answer = answers.shift() ?? 0;
      if (answer === 'hang') return new Promise<number>(() => undefined);
      return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
    },
    logger,
    deadlineMs: 50,
    batch: options.batch ?? 10,
    mostBatches: options.mostBatches ?? 5,
  });
  const lines = () => capture.lines().map(({ event, flows }) => ({ event, flows }));
  return { sweep, asked, lines, capture };
}

describe("the sign-in flows' sweep", () => {
  it('sweeps a batch at a time until one comes back short, then says how many', async () => {
    const { sweep, asked, lines } = setUp([10, 10, 3]);

    await sweep.run();

    expect(asked).toEqual([10, 10, 10]);
    expect(lines()).toEqual([{ event: 'identity.flow_sweep_done', flows: 23 }]);
  });

  it('says so when there was nothing to sweep', async () => {
    const { sweep, lines } = setUp([0]);

    await sweep.run();

    expect(lines()).toEqual([{ event: 'identity.flow_sweep_done', flows: 0 }]);
  });

  it('stops at its most batches a run, leaving the rest for the next', async () => {
    const { sweep, asked, lines } = setUp([10, 10, 10, 10], { mostBatches: 2 });

    await sweep.run();

    expect(asked).toHaveLength(2);
    expect(lines()).toEqual([{ event: 'identity.flow_sweep_done', flows: 20 }]);
  });

  it('warns when a batch fails, with what it swept before, and never throws', async () => {
    const { sweep, lines, capture } = setUp([10, new Error('the database is away')]);

    await expect(sweep.run()).resolves.toBeUndefined();

    expect(lines()).toEqual([{ event: 'identity.flow_sweep_failed', flows: 10 }]);
    expect(capture.lines()[0]).toMatchObject({ level: 'warn' });
  });

  it('warns when a batch outlasts its deadline', async () => {
    const { sweep, lines } = setUp(['hang']);

    await sweep.run();

    expect(lines()).toEqual([{ event: 'identity.flow_sweep_failed', flows: 0 }]);
  });

  it('ends quietly when stopped, before a batch or during one', async () => {
    const before = setUp([10]);
    const stopped = new AbortController();
    stopped.abort();
    await before.sweep.run(stopped.signal);
    expect(before.asked).toEqual([]);

    const during = setUp(['hang']);
    const stopping = new AbortController();
    const running = during.sweep.run(stopping.signal);
    stopping.abort();
    await running;
    expect(during.lines()).toEqual([]);
  });
});

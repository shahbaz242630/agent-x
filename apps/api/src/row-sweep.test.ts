import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createRowSweep, type SweptRows } from './row-sweep.ts';

function setUp(
  rows: SweptRows,
  answers: (number | Error | 'hang')[],
  options: { batch?: number; mostBatches?: number } = {},
) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  const asked: number[] = [];
  const sweep = createRowSweep({
    rows,
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
  const lines = () => capture.lines().map((line) => ({ event: line.event, count: line.deleted }));
  return { sweep, asked, lines, capture };
}

describe.each(['identity.flow', 'identity.session', 'identity.step_up_challenge', 'security.event'] as const)(
  'the %s sweep',
  (rows) => {
    it('sweeps a batch at a time until one comes back short, then says how many', async () => {
      const { sweep, asked, lines } = setUp(rows, [10, 10, 3]);

      await sweep.run();

      expect(asked).toEqual([10, 10, 10]);
      expect(lines()).toEqual([{ event: `${rows}_sweep_done`, count: 23 }]);
    });

    it('says so when there was nothing to sweep', async () => {
      const { sweep, lines } = setUp(rows, [0]);

      await sweep.run();

      expect(lines()).toEqual([{ event: `${rows}_sweep_done`, count: 0 }]);
    });

    it('stops at its most batches a run, leaving the rest for the next', async () => {
      const { sweep, asked, lines } = setUp(rows, [10, 10, 10, 10], { mostBatches: 2 });

      await sweep.run();

      expect(asked).toHaveLength(2);
      expect(lines()).toEqual([{ event: `${rows}_sweep_done`, count: 20 }]);
    });

    it('warns when a batch fails, with what it swept before, and never throws', async () => {
      const { sweep, lines, capture } = setUp(rows, [10, new Error('the database is away')]);

      await expect(sweep.run()).resolves.toBeUndefined();

      expect(lines()).toEqual([{ event: `${rows}_sweep_failed`, count: 10 }]);
      expect(capture.lines()[0]).toMatchObject({ level: 'warn' });
    });

    it('warns when a batch outlasts its deadline', async () => {
      const { sweep, lines } = setUp(rows, ['hang']);

      await sweep.run();

      expect(lines()).toEqual([{ event: `${rows}_sweep_failed`, count: 0 }]);
    });

    it('ends quietly when stopped, before a batch or during one', async () => {
      const before = setUp(rows, [10]);
      const stopped = new AbortController();
      stopped.abort();
      await before.sweep.run(stopped.signal);
      expect(before.asked).toEqual([]);

      const during = setUp(rows, ['hang']);
      const stopping = new AbortController();
      const running = during.sweep.run(stopping.signal);
      stopping.abort();
      await running;
      expect(during.lines()).toEqual([]);
    });
  },
);

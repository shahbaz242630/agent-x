// What one look at an organisation calls for. The reads are statements of their own, each at its own moment, so
// a write committing between them must never read as a miss, and a mark made while looking must never be cleared.
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { settleReadsGate } from './handoff.ts';
import { type MarkedOrganisations, movesOf, withOrgWork, withWholePasses } from './org-work.ts';

const NOW = new Date('2026-11-02T10:00:00.000Z');
const mark = (marks: string, dueAt = NOW) => ({ job: 'hand_off', due_at: dueAt, marks }) as const;
const allOthersIdle = [
  { job: 'hand_off_sweep', dueAt: null },
  { job: 'payment_check', dueAt: null },
] as const;
const due = (dueAt: Date | null) => [{ job: 'hand_off', dueAt } as const, ...allOthersIdle];
const later = (ms: number) => new Date(NOW.getTime() + ms);

describe('one look at an organisation', () => {
  it('nothing due and no mark calls for nothing', () => {
    expect(movesOf({ before: [], due: due(null), after: [] }, NOW)).toEqual([]);
  });

  it('due with a mark at the time calls for nothing', () => {
    expect(movesOf({ before: [mark('5')], due: due(NOW), after: [mark('5')] }, NOW)).toEqual([]);
  });

  it('due and no mark in either read is a real miss', () => {
    expect(movesOf({ before: [], due: due(NOW), after: [] }, NOW)).toEqual([
      { kind: 'unmarked', job: 'hand_off', dueAt: NOW },
    ]);
  });

  it('a row and its mark committing between the reads is no miss: the later read has the mark', () => {
    expect(movesOf({ before: [], due: due(NOW), after: [mark('1')] }, NOW)).toEqual([]);
  });

  it('nothing due with a mark clears it by the value read before looking, whatever came after', () => {
    expect(movesOf({ before: [mark('5')], due: due(null), after: [mark('6')] }, NOW)).toEqual([
      { kind: 'cleared', job: 'hand_off', marks: '5' },
    ]);
  });

  it('a mark made only after the first read is not cleared', () => {
    expect(movesOf({ before: [], due: due(null), after: [mark('1')] }, NOW)).toEqual([]);
  });

  it('a mark over a minute past what is due is late, by the value read before looking', () => {
    expect(movesOf({ before: [mark('5', later(60_001))], due: due(NOW), after: [mark('6')] }, NOW)).toEqual([
      { kind: 'late', job: 'hand_off', dueAt: NOW, marks: '5' },
    ]);
  });

  it('a mark a minute past, or before, what is due is left', () => {
    expect(movesOf({ before: [mark('5', later(60_000))], due: due(NOW), after: [mark('5')] }, NOW)).toEqual([]);
    expect(movesOf({ before: [mark('5', later(-600_000))], due: due(NOW), after: [mark('5')] }, NOW)).toEqual([]);
  });

  it('work due since long ago, its mark settled at a visit since: no miss, and left where the settle put it', () => {
    const rows = later(-2 * 86_400_000);
    expect(movesOf({ before: [mark('5', NOW)], due: due(rows), after: [mark('5', NOW)] }, later(3_600_000))).toEqual(
      [],
    );
  });

  it('work due since long ago, its mark not due until over a minute from now: late', () => {
    const rows = later(-86_400_000);
    expect(movesOf({ before: [mark('5', later(60_001))], due: due(rows), after: [mark('5')] }, NOW)).toEqual([
      { kind: 'late', job: 'hand_off', dueAt: rows, marks: '5' },
    ]);
    expect(movesOf({ before: [mark('5', later(60_000))], due: due(rows), after: [mark('5')] }, NOW)).toEqual([]);
  });

  it('work due an hour from now: its mark late only over a minute past that hour, not past now', () => {
    const rows = later(3_600_000);
    expect(movesOf({ before: [mark('5', later(3_660_000))], due: due(rows), after: [mark('5')] }, NOW)).toEqual([]);
    expect(movesOf({ before: [mark('5', later(3_660_001))], due: due(rows), after: [mark('5')] }, NOW)).toEqual([
      { kind: 'late', job: 'hand_off', dueAt: rows, marks: '5' },
    ]);
  });

  it("a mark for one job says nothing about another's", () => {
    const other = { job: 'payment_check', due_at: NOW, marks: '1' } as const;
    expect(movesOf({ before: [other], due: due(NOW), after: [other] }, NOW)).toEqual([
      { kind: 'unmarked', job: 'hand_off', dueAt: NOW },
      { kind: 'cleared', job: 'payment_check', marks: '1' },
    ]);
  });
});

describe("the settles' one gate", () => {
  it.each([
    [6, 1],
    [10, 1],
    [15, 3],
    [30, 8],
  ])(
    'with a pool of %i lets %i read at once: a third of the pool less the hand-off’s 2, at least 1 (one over below 9)',
    async (pool, most) => {
      const gate = settleReadsGate(pool);
      let inside = 0;
      const never = new Promise<void>(() => undefined);
      for (let n = 0; n < 10; n += 1) {
        void gate.run(`org-${String(n)}`, () => {
          inside += 1;
          return never;
        });
      }
      // Each admitted one starts on the turn it is let in: a few turns are enough for all that will.
      for (let turn = 0; turn < 5; turn += 1) await Promise.resolve();
      expect(inside).toBe(most);
    },
  );
});

/** A job's marks that list `listed` each run, and count their settlings. */
function stubMarks(listed: readonly string[]) {
  const settled: (AbortSignal | undefined)[] = [];
  const marks: MarkedOrganisations = {
    list: () => Promise.resolve(listed),
    keep: () => undefined,
    dueBy: () => undefined,
    settle: (signal) => {
      settled.push(signal);
      return Promise.resolve();
    },
  };
  return { marks, settled };
}

describe('a job on its marks (4D2e D10)', () => {
  it('says what its run said, a skip too, once its marks are settled', async () => {
    const { marks, settled } = stubMarks([]);
    const job = withOrgWork([marks], { run: () => Promise.resolve('skipped' as const) });

    await expect(job.run()).resolves.toBe('skipped');
    expect(settled).toEqual([undefined]);
  });

  it('visits every organisation besides its marks at its first run and once each whole pass, the marked first, each once', async () => {
    const clock = new FixedClock(NOW);
    const { marks } = stubMarks(['b', 'm']);
    let wholes = 0;
    const list = withWholePasses(marks, {
      job: 'factor_resets',
      logger: testLogger(),
      everyMs: 6 * 3_600_000,
      all: () => {
        wholes += 1;
        return Promise.resolve(['a', 'b', 'c']);
      },
      clock,
    });

    expect(await list()).toEqual(['b', 'm', 'a', 'c']);
    clock.advanceBy(6 * 3_600_000 - 1);
    expect(await list()).toEqual(['b', 'm']);
    clock.advanceBy(1);
    expect(await list()).toEqual(['b', 'm', 'a', 'c']);
    expect(wholes).toBe(2);
  });

  it('a whole list it cannot read fails the run, and the next run tries the whole pass again', async () => {
    const clock = new FixedClock(NOW);
    const { marks } = stubMarks(['m']);
    let fails = true;
    const list = withWholePasses(marks, {
      job: 'factor_resets',
      logger: testLogger(),
      everyMs: 3_600_000,
      all: () => (fails ? Promise.reject(new Error('no directory')) : Promise.resolve(['a'])),
      clock,
    });

    await expect(list()).rejects.toThrow('no directory');
    fails = false;
    expect(await list()).toEqual(['m', 'a']);
  });

  it('4D2e D11 marks it cannot read are said, and never hold up a whole pass that is due; with none due, the run fails', async () => {
    const clock = new FixedClock(NOW);
    const capture = new LogCapture();
    let fails = true;
    const list = withWholePasses(
      { list: () => (fails ? Promise.reject(new Error('marks unread')) : Promise.resolve(['m'])) },
      {
        job: 'holdings_check',
        everyMs: 3_600_000,
        all: () => Promise.resolve(['a', 'b']),
        logger: testLogger(capture),
        clock,
      },
    );
    const unread = () => capture.lines().filter((line) => line.event === 'org_work.marks_unread');

    expect(await list()).toEqual(['a', 'b']);
    expect(unread()).toEqual([expect.objectContaining({ level: 'error', job: 'holdings_check' })]);
    clock.advanceBy(3_600_000 - 1);
    await expect(list()).rejects.toThrow('marks unread');
    expect(unread()).toHaveLength(2);
    // The whole pass came at its time, so the next is an hour after it, not after the failure.
    clock.advanceBy(1);
    expect(await list()).toEqual(['a', 'b']);
    fails = false;
    clock.advanceBy(1);
    expect(await list()).toEqual(['m']);
  });
});

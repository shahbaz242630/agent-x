// What one look at an organisation calls for. The reads are statements of their own, each at its own moment, so
// a write committing between them must never read as a miss, and a mark made while looking must never be cleared.
import { describe, expect, it } from 'vitest';

import { settleReadsGate } from './handoff.ts';
import { movesOf } from './org-work.ts';

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
    expect(movesOf({ before: [], due: due(null), after: [] })).toEqual([]);
  });

  it('due with a mark at the time calls for nothing', () => {
    expect(movesOf({ before: [mark('5')], due: due(NOW), after: [mark('5')] })).toEqual([]);
  });

  it('due and no mark in either read is a real miss', () => {
    expect(movesOf({ before: [], due: due(NOW), after: [] })).toEqual([
      { kind: 'unmarked', job: 'hand_off', dueAt: NOW },
    ]);
  });

  it('a row and its mark committing between the reads is no miss: the later read has the mark', () => {
    expect(movesOf({ before: [], due: due(NOW), after: [mark('1')] })).toEqual([]);
  });

  it('nothing due with a mark clears it by the value read before looking, whatever came after', () => {
    expect(movesOf({ before: [mark('5')], due: due(null), after: [mark('6')] })).toEqual([
      { kind: 'cleared', job: 'hand_off', marks: '5' },
    ]);
  });

  it('a mark made only after the first read is not cleared', () => {
    expect(movesOf({ before: [], due: due(null), after: [mark('1')] })).toEqual([]);
  });

  it('a mark over a minute past what is due is late, by the value read before looking', () => {
    expect(movesOf({ before: [mark('5', later(60_001))], due: due(NOW), after: [mark('6')] })).toEqual([
      { kind: 'late', job: 'hand_off', dueAt: NOW, marks: '5' },
    ]);
  });

  it('a mark a minute past, or before, what is due is left', () => {
    expect(movesOf({ before: [mark('5', later(60_000))], due: due(NOW), after: [mark('5')] })).toEqual([]);
    expect(movesOf({ before: [mark('5', later(-600_000))], due: due(NOW), after: [mark('5')] })).toEqual([]);
  });

  it("a mark for one job says nothing about another's", () => {
    const other = { job: 'payment_check', due_at: NOW, marks: '1' } as const;
    expect(movesOf({ before: [other], due: due(NOW), after: [other] })).toEqual([
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
    'with a pool of %i lets %i read at once: a third of the pool less the hand-off’s 2, at least 1',
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

// ADR-006 §8, §10 (Phase 2 D2): a reservation's state.
import { describe, expect, it } from 'vitest';

import { RESERVATION } from './reservation.ts';

describe('a reservation’s state (D2)', () => {
  it('starts HELD, and moves only as 0040’s guard lists', () => {
    expect(RESERVATION.initial).toBe('HELD');
    expect(RESERVATION.moves.map(({ from, to }) => `${from}>${to}`)).toEqual([
      'HELD>FINALISED',
      'BLOCKED_UNKNOWN>FINALISED',
      'HELD>RELEASED',
      'BLOCKED_UNKNOWN>RELEASED',
      'HELD>BLOCKED_UNKNOWN',
    ]);
  });

  it('never moves on from FINALISED or RELEASED (a reversal restores no capacity in the MVP)', () => {
    expect(RESERVATION.moves.filter(({ from }) => from === 'FINALISED' || from === 'RELEASED')).toEqual([]);
  });
});

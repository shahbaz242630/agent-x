// PRD §4.1, ADR-006 §4 (Phase 2 B1): a mandate's status, and the defaults it
// is made with.
import { describe, expect, it } from 'vitest';

import { DEFAULT_SPLIT_WINDOW_HOURS, DEFAULT_TIME_ZONE, MANDATE, SPLIT_WINDOW_HOURS } from './mandate.ts';

describe('a mandate’s status (B1)', () => {
  it('starts PENDING_ACCEPTANCE, and moves only as 0034’s guard lists', () => {
    expect(MANDATE.initial).toBe('PENDING_ACCEPTANCE');
    expect(MANDATE.moves.map(({ from, to }) => `${from}>${to}`)).toEqual([
      'PENDING_ACCEPTANCE>ACTIVE',
      'ACTIVE>SUSPENDED',
      'SUSPENDED>ACTIVE',
      'PENDING_ACCEPTANCE>REVOKED',
      'ACTIVE>REVOKED',
      'SUSPENDED>REVOKED',
      'ACTIVE>EXPIRED',
      'SUSPENDED>EXPIRED',
    ]);
  });

  it('never comes back from REVOKED or EXPIRED', () => {
    expect(MANDATE.moves.filter(({ from }) => from === 'REVOKED' || from === 'EXPIRED')).toEqual([]);
  });
});

describe('the defaults a mandate is made with', () => {
  it('counts its months in Dubai time, and checks splits over a day', () => {
    expect(DEFAULT_TIME_ZONE).toBe('Asia/Dubai');
    expect(DEFAULT_SPLIT_WINDOW_HOURS).toBe(24);
    expect(SPLIT_WINDOW_HOURS).toEqual({ least: 1, most: 744 });
  });
});

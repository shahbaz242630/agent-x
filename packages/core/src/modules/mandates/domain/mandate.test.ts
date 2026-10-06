// PRD §4.1 (Phase 2 B1): a mandate's status.
import { describe, expect, it } from 'vitest';

import { MANDATE } from './mandate.ts';

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

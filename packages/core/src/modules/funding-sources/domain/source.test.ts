// PRD §2.3 step 5, ADR-012 §5 (D2-2): a funding source's own status, and
// when a source may fund a request.
import { describe, expect, it } from 'vitest';

import { FUNDING_SOURCE, mayFund } from './source.ts';

const NOW = new Date('2026-10-01T08:00:00Z');
const LATER = new Date(NOW.getTime() + 1);

describe('a funding source’s own status (D2-2)', () => {
  it('starts ACTIVE, is suspended and reactivated, and ends for good from either, as 0029’s guard lists', () => {
    expect(FUNDING_SOURCE.initial).toBe('ACTIVE');
    expect(FUNDING_SOURCE.moves.map(({ from, to }) => `${from}>${to}`).sort()).toEqual([
      'ACTIVE>ENDED',
      'ACTIVE>SUSPENDED',
      'SUSPENDED>ACTIVE',
      'SUSPENDED>ENDED',
    ]);
  });

  it('never leaves ENDED: a new link is a new source', () => {
    expect(FUNDING_SOURCE.moves.filter(({ from }) => from === 'ENDED')).toEqual([]);
  });
});

describe('whether a source may fund a request (PRD §2.3 step 5)', () => {
  const usable = { status: 'ACTIVE', availability: 'ACTIVE', consentExpiresAt: LATER } as const;

  it('may, when ACTIVE to Agent X and to the partner, before its consent’s expiry', () => {
    expect(mayFund(usable, NOW)).toBe(true);
  });

  it.each(['SUSPENDED', 'ENDED'] as const)('may not while Agent X holds it %s', (status) => {
    expect(mayFund({ ...usable, status }, NOW)).toBe(false);
  });

  it.each(['PENDING', 'SUSPENDED', 'UNAVAILABLE'] as const)('may not while the partner says %s', (availability) => {
    expect(mayFund({ ...usable, availability }, NOW)).toBe(false);
  });

  it('may not from the moment its consent expires', () => {
    expect(mayFund(usable, LATER)).toBe(false);
    expect(mayFund(usable, new Date(LATER.getTime() + 1))).toBe(false);
  });
});

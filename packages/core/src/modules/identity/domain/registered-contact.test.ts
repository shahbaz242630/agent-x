// B6-1a: a registered contact's machine and its cooling-off (ADR-012 §1).
import { describe, expect, it } from 'vitest';

import {
  CONTACT_COOLING_OFF_DAYS,
  contactCountsFrom,
  counts,
  MOST_CONTACTS,
  REGISTERED_CONTACT,
} from './registered-contact.ts';

describe('a registered contact (B6-1a)', () => {
  it('starts as a DRAFT, becomes ACTIVE, and is removed; never brought back', () => {
    expect(REGISTERED_CONTACT.initial).toBe('DRAFT');
    expect(REGISTERED_CONTACT.moves).toEqual([
      { from: 'DRAFT', to: 'ACTIVE' },
      { from: 'ACTIVE', to: 'REMOVED' },
    ]);
  });

  it('counts 7 days after it became ACTIVE, and not a millisecond before (SEC-OPS-06)', () => {
    expect(CONTACT_COOLING_OFF_DAYS).toBe(7);
    const activated = new Date('2026-09-27T09:00:00.123Z');
    const from = contactCountsFrom(activated);
    expect(from).toEqual(new Date('2026-10-04T09:00:00.123Z'));
    expect(counts(from, new Date('2026-10-04T09:00:00.122Z'))).toBe(false);
    expect(counts(from, from)).toBe(true);
    expect(counts(from, new Date('2026-10-05T00:00:00Z'))).toBe(true);
  });

  it('allows a short list', () => {
    expect(MOST_CONTACTS).toBe(5);
  });
});

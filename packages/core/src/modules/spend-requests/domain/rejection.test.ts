// Phase 3 B4a: a reject's reason (decision 6), kept as a note is kept for good.
import { describe, expect, it } from 'vitest';

import { REJECT_REASON_MOST, rejectReason } from './rejection.ts';

describe('rejectReason', () => {
  it('keeps a short reason composed, in any script', () => {
    expect(rejectReason('Café order not needed')).toEqual({ note: 'Café order not needed', problems: [] });
    expect(rejectReason('ليس هذا الشهر').problems).toEqual([]);
    expect(rejectReason('x'.repeat(REJECT_REASON_MOST)).problems).toEqual([]);
  });

  it('refuses one empty, too long, on two lines, or holding a phone or account number', () => {
    expect(rejectReason('').problems).toContain('the reason is 1 to 200 characters');
    expect(rejectReason('x'.repeat(REJECT_REASON_MOST + 1)).problems).toEqual(['the reason is 1 to 200 characters']);
    expect(rejectReason('one\ntwo').problems).toEqual([
      'the reason holds a control, format, invisible or unassigned character',
    ]);
    expect(rejectReason('Call 050 123 4567').problems).toEqual([
      'the reason holds a long number: leave phone and account numbers out',
    ]);
  });
});

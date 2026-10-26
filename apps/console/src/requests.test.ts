// 6B1: amounts and time left as the approvals screens say them.
import { describe, expect, it } from 'vitest';

import { amountText, isCancellable, leftText } from './requests.ts';

describe('how a request reads (6B1)', () => {
  it.each([
    [250_000, 'AED', 'AED 2,500.00'],
    [10_004, 'AED', 'AED 100.04'],
    [7, 'AED', 'AED 0.07'],
    [1_500, 'JPY', 'JPY 1,500'],
    [12_345, 'KWD', 'KWD 12.345'],
    // A code Intl doesn't take: two digits, as most currencies.
    [12_345, 'A1!', 'A1! 123.45'],
  ])('writes %i minor units of %s as %s', (minor, currency, written) => {
    expect(amountText(minor, currency)).toBe(written);
  });

  it('says the hours left, the minutes under an hour, and none once past', () => {
    const now = Date.parse('2026-10-26T06:00:00Z');
    expect(leftText('2026-10-27T04:30:00Z', now)).toEqual({ hours: 22 });
    expect(leftText('2026-10-26T06:40:30Z', now)).toEqual({ minutes: 40 });
    expect(leftText('2026-10-26T06:00:10Z', now)).toEqual({ minutes: 1 });
    expect(leftText('2026-10-26T06:00:00Z', now)).toBeNull();
  });

  it('lets a request be cancelled only before hand-off', () => {
    expect(
      ['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY'].every((status) => isCancellable(status as never)),
    ).toBe(true);
    expect(
      ['VALIDATING', 'DENIED', 'HANDED_OFF', 'EXPIRED', 'CANCELLED'].some((status) => isCancellable(status as never)),
    ).toBe(false);
  });
});

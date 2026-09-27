// SEC-OPS-04 (B6-3d): the 7 days without an admin's or approver's powers after a second factor is removed.
import { describe, expect, it } from 'vitest';

import { SECOND_FACTOR_REMOVED_EVENTS } from './idp-event.ts';
import { isRestricted, REMOVAL_RESTRICTION_DAYS, restrictedUntil } from './removal-restriction.ts';

const removedAt = new Date('2026-09-28T10:00:00.000Z');
const ms = (count: number): Date => new Date(restrictedUntil(removedAt).getTime() + count);

describe('SEC-OPS-04 the restriction after a second factor is removed', () => {
  it('lasts 7 days from the removal', () => {
    expect(REMOVAL_RESTRICTION_DAYS).toBe(7);
    expect(restrictedUntil(removedAt)).toEqual(new Date('2026-10-05T10:00:00.000Z'));
  });

  it('holds from the removal until a millisecond before its end, and not from its end', () => {
    expect(isRestricted(removedAt, removedAt)).toBe(true);
    expect(isRestricted(removedAt, ms(-1))).toBe(true);
    expect(isRestricted(removedAt, ms(0))).toBe(false);
    expect(isRestricted(removedAt, ms(1))).toBe(false);
  });

  it('never holds for a person with no removal', () => {
    expect(isRestricted(undefined, removedAt)).toBe(false);
  });

  it('counts every second factor the login service removes: an app, a code by SMS or email, a security key, a passkey, recovery codes', () => {
    expect([...SECOND_FACTOR_REMOVED_EVENTS].sort()).toEqual([
      'user.human.mfa.otp.email.removed',
      'user.human.mfa.otp.removed',
      'user.human.mfa.otp.sms.removed',
      'user.human.mfa.recoverycode.removed',
      'user.human.mfa.u2f.token.removed',
      'user.human.passwordless.token.removed',
    ]);
  });
});

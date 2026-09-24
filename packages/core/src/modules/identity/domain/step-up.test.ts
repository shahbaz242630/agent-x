import { describe, expect, it } from 'vitest';

import { AUTH_TIME_TOLERANCE_SECONDS, type ChallengeFacts, type FreshSignIn, stepUpRefusal } from './step-up.ts';

const PERSON = '0199a0f0-0000-7000-8000-000000000011';
const CHALLENGE: ChallengeFacts = { userId: PERSON, createdAt: new Date('2026-09-24T09:00:00.600Z') };
/** A security key: Zitadel's `amr` for one (S10). */
const PASSKEY = ['pwd', 'user', 'mfa'];
/** An authenticator app. */
const APP_CODE = ['pwd', 'otp', 'mfa'];

const signIn = (authTime: string, amr: readonly string[] = PASSKEY, userId = PERSON): FreshSignIn => ({
  userId,
  evidence: { authTime: new Date(authTime), amr },
});
const NO_PASSKEY = { passkeyRequired: false };
const WITH_PASSKEY = { passkeyRequired: true };

describe('ADR-003 §9 a fresh sign-in stands for its challenge', () => {
  it('takes the same person, signed in again after the challenge, with a second factor', () => {
    expect(stepUpRefusal(CHALLENGE, signIn('2026-09-24T09:00:30Z', APP_CODE), NO_PASSKEY)).toBeUndefined();
    expect(stepUpRefusal(CHALLENGE, signIn('2026-09-24T09:00:30Z', PASSKEY), WITH_PASSKEY)).toBeUndefined();
  });

  it('refuses another person, whatever else holds', () => {
    const other = signIn('2026-09-24T09:00:30Z', PASSKEY, '0199a0f0-0000-7000-8000-000000000012');
    expect(stepUpRefusal(CHALLENGE, other, NO_PASSKEY)).toBe('other_person');
  });

  it("takes the person's ID in either case", () => {
    const shouted = { ...CHALLENGE, userId: PERSON.toUpperCase() };
    expect(stepUpRefusal(shouted, signIn('2026-09-24T09:00:30Z'), NO_PASSKEY)).toBeUndefined();
  });

  describe('FX-CLOCK SEC-HA-05 an authentication from before the challenge is refused', () => {
    it.each([
      ['six seconds before the challenge', '2026-09-24T08:59:54Z', 'stale_authentication'],
      ['the session’s own sign-in, hours before', '2026-09-24T06:00:00Z', 'stale_authentication'],
      ['five seconds before, a login service clock that far behind ours', '2026-09-24T08:59:55Z', undefined],
      ["the challenge's own second, which auth_time can't tell apart", '2026-09-24T09:00:00Z', undefined],
      ['the second after', '2026-09-24T09:00:01Z', undefined],
    ])('%s', (_what, authTime, refusal) => {
      expect(stepUpRefusal(CHALLENGE, signIn(authTime), NO_PASSKEY)).toBe(refusal);
    });

    it('allows the login service clock 5 seconds behind ours, no more', () => {
      expect(AUTH_TIME_TOLERANCE_SECONDS).toBe(5);
    });

    it('refuses a time that is not a time', () => {
      expect(stepUpRefusal(CHALLENGE, signIn('not a time'), NO_PASSKEY)).toBe('stale_authentication');
    });
  });

  it.each([
    ['a password alone', ['pwd']],
    ['a password and a code, without mfa', ['pwd', 'otp']],
    ['nothing', []],
  ])('SEC-HA-06 refuses %s: no second factor', (_what, amr) => {
    expect(stepUpRefusal(CHALLENGE, signIn('2026-09-24T09:00:30Z', amr), NO_PASSKEY)).toBe('no_second_factor');
  });

  it('SEC-HA-12 refuses an authenticator app where a passkey is required, and takes a security key', () => {
    expect(stepUpRefusal(CHALLENGE, signIn('2026-09-24T09:00:30Z', APP_CODE), WITH_PASSKEY)).toBe('no_passkey');
    expect(stepUpRefusal(CHALLENGE, signIn('2026-09-24T09:00:30Z', ['user']), WITH_PASSKEY)).toBe('no_second_factor');
    expect(stepUpRefusal(CHALLENGE, signIn('2026-09-24T09:00:30Z', PASSKEY), WITH_PASSKEY)).toBeUndefined();
  });

  it('checks in order: the person first, then the time, then the factors', () => {
    const everythingWrong = signIn('2026-09-24T08:00:00Z', ['pwd'], '0199a0f0-0000-7000-8000-000000000012');
    expect(stepUpRefusal(CHALLENGE, everythingWrong, WITH_PASSKEY)).toBe('other_person');
    expect(stepUpRefusal(CHALLENGE, signIn('2026-09-24T08:00:00Z', ['pwd']), WITH_PASSKEY)).toBe(
      'stale_authentication',
    );
  });
});

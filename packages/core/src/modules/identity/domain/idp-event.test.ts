// B6-2b: which of the login service's events we copy, and what each means.
import { describe, expect, it } from 'vitest';

import { classOfIdpEvent, isToldToThePerson, MOST_WATCHED_TYPES, WATCHED_IDP_EVENTS } from './idp-event.ts';

describe('the login service’s events we copy (B6-2b)', () => {
  it('names no more types than one search takes', () => {
    expect(Object.keys(WATCHED_IDP_EVENTS).length).toBeLessThanOrEqual(MOST_WATCHED_TYPES);
  });

  it.each([
    ['user.human.mfa.otp.removed', 'second_factor_removed'],
    ['user.human.mfa.u2f.token.removed', 'second_factor_removed'],
    ['user.human.passwordless.token.removed', 'second_factor_removed'],
    ['user.human.mfa.recoverycode.removed', 'second_factor_removed'],
    ['user.human.password.changed', 'password_changed'],
    ['user.human.password.code.added', 'password_changed'],
    ['user.human.email.changed', 'sign_in_email_changed'],
    ['user.locked', 'sign_in_blocked'],
    ['user.removed', 'sign_in_blocked'],
    ['user.reactivated', 'sign_in_restored'],
    ['user.token.added', 'token_issued'],
    ['user.impersonated', 'impersonated'],
    ['instance.member.added', 'rights_changed'],
    ['org.member.cascade.removed', 'rights_changed'],
  ])('reads %s as %s', (type, eventClass) => {
    expect(classOfIdpEvent(type)).toBe(eventClass);
  });

  it('copies no other type: not a sign-in, not a factor added, not an inherited name', () => {
    for (const type of [
      'user.human.password.check.succeeded',
      'user.human.mfa.otp.added',
      'toString',
      '__proto__',
      '',
    ]) {
      expect(classOfIdpEvent(type)).toBeUndefined();
    }
  });

  it('tells the person and the admins of a change to a sign-in, and no one of a token, impersonation or rights', () => {
    const told = [...new Set(Object.values(WATCHED_IDP_EVENTS))].filter(isToldToThePerson).sort();
    expect(told).toEqual([
      'password_changed',
      'second_factor_removed',
      'sign_in_blocked',
      'sign_in_email_changed',
      'sign_in_restored',
    ]);
  });
});

// B6-2b: which of the login service's events we copy, and what each means.
import { describe, expect, it } from 'vitest';

import {
  classOfIdpEvent,
  endsSessions,
  isOurRoutineChange,
  isToldToThePerson,
  MOST_WATCHED_TYPES,
  PASSKEY_ADDED_EVENTS,
  WATCHED_IDP_EVENTS,
} from './idp-event.ts';

describe('the login service’s events we copy (B6-2b)', () => {
  it('names no more types than one search takes', () => {
    expect(Object.keys(WATCHED_IDP_EVENTS).length).toBeLessThanOrEqual(MOST_WATCHED_TYPES);
  });

  it.each([
    ['user.human.mfa.otp.removed', 'second_factor_removed'],
    ['user.human.mfa.u2f.token.removed', 'second_factor_removed'],
    ['user.human.passwordless.token.removed', 'second_factor_removed'],
    ['user.human.mfa.recoverycode.removed', 'second_factor_removed'],
    ['user.human.mfa.otp.verified', 'second_factor_added'],
    ['user.human.mfa.otp.sms.added', 'second_factor_added'],
    ['user.human.mfa.otp.email.added', 'second_factor_added'],
    ['user.human.mfa.u2f.token.verified', 'second_factor_added'],
    ['user.human.passwordless.token.verified', 'second_factor_added'],
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

  it('copies no other type: not a sign-in, not a factor still to be verified, not an inherited name', () => {
    for (const type of [
      'user.human.password.check.succeeded',
      'user.human.mfa.otp.added',
      'user.human.mfa.u2f.token.added',
      'user.human.passwordless.token.added',
      'toString',
      '__proto__',
      '',
    ]) {
      expect(classOfIdpEvent(type)).toBeUndefined();
    }
  });

  it('ends sessions on a factor added or removed, a password or email changed, or a login blocked; not on one restored (the S68 audit)', () => {
    const ending = [...new Set(Object.values(WATCHED_IDP_EVENTS))].filter(endsSessions).sort();
    expect(ending).toEqual([
      'password_changed',
      'second_factor_added',
      'second_factor_removed',
      'sign_in_blocked',
      'sign_in_email_changed',
    ]);
  });

  it('knows a key added as a copied type, a factor added', () => {
    for (const type of PASSKEY_ADDED_EVENTS) expect(classOfIdpEvent(type)).toBe('second_factor_added');
  });

  it('tells the person and the admins of a change to a sign-in, and no one of a token, impersonation or rights', () => {
    const told = [...new Set(Object.values(WATCHED_IDP_EVENTS))].filter(isToldToThePerson).sort();
    expect(told).toEqual([
      'password_changed',
      'second_factor_added',
      'second_factor_removed',
      'sign_in_blocked',
      'sign_in_email_changed',
      'sign_in_restored',
    ]);
  });
});

describe('our own routine changes in the login service (SA2)', () => {
  const ADMIN = '312000000000000001';
  const DIRECTORY = '312000000000000050';
  const ours = { actors: new Set([ADMIN]), serviceUsers: new Set([DIRECTORY]) };
  const token = (aggregateId: string, editorUserId: string | null = ADMIN) => ({
    type: 'user.token.added',
    eventClass: 'token_issued' as const,
    aggregateType: 'user',
    aggregateId,
    editorUserId,
  });
  const grant = (member: { userId: string; roles: string[] } | undefined, type = 'instance.member.added') => ({
    type,
    eventClass: 'rights_changed' as const,
    aggregateType: 'instance',
    aggregateId: '312000000000000007',
    editorUserId: ADMIN,
    ...(member && { member }),
  });

  it('is ours only when one of our actors makes exactly a change we make', () => {
    expect(isOurRoutineChange(token(DIRECTORY), ours)).toBe(true);
    expect(isOurRoutineChange(grant({ userId: DIRECTORY, roles: ['IAM_OWNER_VIEWER'] }), ours)).toBe(true);
    expect(
      isOurRoutineChange(grant({ userId: DIRECTORY, roles: ['ORG_USER_MANAGER'] }, 'org.member.changed'), ours),
    ).toBe(true);
  });

  it.each([
    ['a token for anyone else', token('312000000000000099')],
    ['a token by another login', token(DIRECTORY, '312000000000000099')],
    ['a token by no one named', token(DIRECTORY, null)],
    ['a token on an aggregate that is not a user', { ...token(DIRECTORY), aggregateType: 'org' }],
    ['a grant to anyone else', grant({ userId: '312000000000000099', roles: ['IAM_OWNER_VIEWER'] })],
    ['an owner’s role to our service user', grant({ userId: DIRECTORY, roles: ['IAM_OWNER'] })],
    ['one of their roles and an owner’s', grant({ userId: DIRECTORY, roles: ['IAM_OWNER_VIEWER', 'ORG_OWNER'] })],
    ['a grant of no role', grant({ userId: DIRECTORY, roles: [] })],
    ['a membership removed', grant({ userId: DIRECTORY, roles: [] }, 'instance.member.removed')],
    ['a grant whose payload wasn’t read', grant(undefined)],
    ['impersonation', { ...token(DIRECTORY), type: 'user.impersonated', eventClass: 'impersonated' as const }],
  ])('is not ours, and alerts: %s', (_what, event) => {
    expect(isOurRoutineChange(event, ours)).toBe(false);
  });

  it('is never ours when the deployment names no one', () => {
    expect(isOurRoutineChange(token(DIRECTORY), { actors: new Set(), serviceUsers: new Set() })).toBe(false);
  });
});

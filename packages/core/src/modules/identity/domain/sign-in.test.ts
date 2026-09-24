import { describe, expect, it } from 'vitest';

import { checkEvidence, checkSubject, type SignInEvidence, SignInRefused, type Subject } from './sign-in.ts';

const who: Subject = { issuer: 'https://auth.example.test', subject: '338719472394810051' };
const proof: SignInEvidence = {
  idpSessionId: 'V1_338719472394810051',
  authTime: new Date('2026-09-24T09:00:00Z'),
  amr: ['pwd', 'otp', 'mfa'],
};

/** Whatever a caller the compiler can't see might pass. */
const loose = <T>(value: T, change: Record<string, unknown>): T => ({ ...value, ...change });

describe('a subject', () => {
  it('is taken as the login service gives it', () => {
    expect(() => {
      checkSubject(who);
    }).not.toThrow();
    expect(() => {
      checkSubject({ issuer: 'x'.repeat(255), subject: '!'.repeat(255) });
    }).not.toThrow();
  });

  it.each([
    ['an empty issuer', { issuer: '' }, 'the issuer'],
    ['a long issuer', { issuer: 'x'.repeat(256) }, 'the issuer'],
    ['an issuer with a space', { issuer: 'https://auth example' }, 'the issuer'],
    ['an issuer that is not text', { issuer: 7 }, 'the issuer'],
    ['an empty subject', { subject: '' }, 'the subject'],
    ['a long subject', { subject: '1'.repeat(256) }, 'the subject'],
    ['a subject with a line break', { subject: '33871\n9472' }, 'the subject'],
    ['a subject beyond ASCII', { subject: '3387é' }, 'the subject'],
    ['no subject', { subject: undefined }, 'the subject'],
  ])('is refused with %s, naming which part', (_, change, part) => {
    expect(() => {
      checkSubject(loose(who, change));
    }).toThrow(new SignInRefused(`${part} is not 1 to 255 visible ASCII characters`));
  });
});

describe("a sign-in's evidence", () => {
  it('is taken with or without the login service session', () => {
    expect(() => {
      checkEvidence(proof);
    }).not.toThrow();
    expect(() => {
      checkEvidence({ ...proof, idpSessionId: undefined, amr: Array.from({ length: 16 }, () => 'x'.repeat(32)) });
    }).not.toThrow();
  });

  it.each([
    ['an empty session ID', { idpSessionId: '' }, /session ID/],
    ['a session ID with a space', { idpSessionId: 'V1 1' }, /session ID/],
    ['a null session ID', { idpSessionId: null }, /session ID/],
    ['no time', { authTime: undefined }, /authentication time/],
    ['an invalid time', { authTime: new Date('never') }, /authentication time/],
    ['a time as a number', { authTime: 1_790_000_000 }, /authentication time/],
    ['no methods', { amr: [] }, /a list of 1 to 16/],
    ['seventeen methods', { amr: Array.from({ length: 17 }, () => 'otp') }, /a list of 1 to 16/],
    ['methods as text', { amr: 'pwd' }, /a list of 1 to 16/],
    ['a method too long', { amr: ['x'.repeat(33)] }, /an authentication method/],
    ['an empty method', { amr: ['pwd', ''] }, /an authentication method/],
    ['a method that is not text', { amr: ['pwd', 1] }, /an authentication method/],
    // eslint-disable-next-line no-sparse-arrays -- the hole is the point
    ['a hole in the methods', { amr: ['pwd', , 'mfa'] }, /an authentication method/],
  ])('is refused with %s', (_, change, message) => {
    expect(() => {
      checkEvidence(loose(proof, change));
    }).toThrow(message);
  });

  it('is refused as SignInRefused', () => {
    expect(() => {
      checkEvidence(loose(proof, { amr: [] }));
    }).toThrow(SignInRefused);
  });
});

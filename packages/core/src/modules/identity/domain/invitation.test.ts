// B4-3a: an invitation's machine, its end, and the address it keeps.
import { describe, expect, it } from 'vitest';

import { EMAIL_MAX, INVITATION, INVITATION_HOURS, invitationEmail, invitationEnds } from './invitation.ts';

describe('an invitation (B4-3a)', () => {
  it('starts as a DRAFT and moves only to OPEN', () => {
    expect(INVITATION.initial).toBe('DRAFT');
    expect(INVITATION.moves).toEqual([{ from: 'DRAFT', to: 'OPEN' }]);
  });

  it('ends 72 hours after it was asked for', () => {
    expect(INVITATION_HOURS).toBe(72);
    expect(invitationEnds(new Date('2026-09-25T09:00:00.123Z'))).toEqual(new Date('2026-09-28T09:00:00.123Z'));
  });
});

describe('the address an invitation keeps (B4-3a)', () => {
  it('keeps an address in lower case', () => {
    expect(invitationEmail('Sara.Khan@Example.TEST')).toBe('sara.khan@example.test');
    expect(invitationEmail('a@b')).toBe('a@b');
  });

  it(`keeps one of ${String(EMAIL_MAX)} characters, and refuses one longer`, () => {
    const longest = `${'a'.repeat(EMAIL_MAX - 'example.test'.length - 1)}@example.test`;
    expect(invitationEmail(longest)).toBe(longest);
    expect(invitationEmail(`a${longest}`)).toBeUndefined();
  });

  it.each([
    ['nothing', ''],
    ['no @', 'sara.example.test'],
    ['nothing before the @', '@example.test'],
    ['nothing after the @', 'sara@'],
    ['two @', 'sara@khan@example.test'],
    ['a space', 'sara khan@example.test'],
    ['a tab', 'sara\tkhan@example.test'],
    ['a new line', 'sara@example.test\n'],
    ['a control character', 'sara\u0000@example.test'],
    ['DEL', 'sara\u007f@example.test'],
    ['broken Unicode', 'sara\ud800@example.test'],
  ])('refuses %s', (_what, value) => {
    expect(invitationEmail(value)).toBeUndefined();
  });

  it('refuses what is not text', () => {
    expect(invitationEmail(undefined)).toBeUndefined();
    expect(invitationEmail(42)).toBeUndefined();
  });
});

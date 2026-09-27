// B5-1b: what a notice's email says. It tells, from IDs and constants alone,
// and does nothing: no link, no token, no approval power (PRD §4.4, SEC-HA-11).
// B6-3b: the one exception, a registered contact's link to confirm a reset,
// which confirms that reset only, and says so.
import { describe, expect, it } from 'vitest';

import { messageFor, type ResetLink } from './messages.ts';
import { type ClaimedNotice, type NoticeKind, SIGN_IN_NOTICE_KINDS, type SignInNoticeKind } from './notice.ts';

const NOTICE: ClaimedNotice = {
  id: '0199a0f0-0000-7000-8000-00000000b5c1',
  orgId: '0199a0f0-0000-7000-8000-00000000b5c2',
  recipientUserId: '0199a0f0-0000-7000-8000-00000000b5c3',
  kind: 'role_granted',
  membershipId: '0199a0f0-0000-7000-8000-00000000b5c4',
  role: 'approver',
  recipientContactId: null,
  toContacts: false,
  aboutId: null,
  createdAt: new Date('2026-09-26T09:00:00Z'),
  attempts: 0,
};

const CONTACT = '0199a0f0-0000-7000-8000-00000000b6c5';

/** A notice about a registered contact, to a contact or an admin (B6-1b). */
const aboutAContact = (kind: 'contact_added' | 'contact_removed', toAContact: boolean): ClaimedNotice => ({
  ...NOTICE,
  kind,
  membershipId: null,
  role: null,
  aboutId: CONTACT,
  recipientUserId: toAContact ? null : NOTICE.recipientUserId,
  recipientContactId: toAContact ? '0199a0f0-0000-7000-8000-00000000b6c6' : null,
});

describe('a notice’s email (B5-1b)', () => {
  it('tells an admin a member was made a finance approver, naming the organisation and membership by ID', () => {
    const message = messageFor(NOTICE, 'admin@example.test');

    expect(message).toMatchObject({ id: NOTICE.id, to: 'admin@example.test' });
    expect(message.subject).toBe('Agent X: a member of your organisation is now a finance approver');
    expect(message.text).toContain('was given the finance approver role.');
    expect(message.text).toContain(`Organisation: ${NOTICE.orgId}`);
    expect(message.text).toContain(`Membership: ${NOTICE.membershipId}`);
  });

  it('says an admin with “an”, and tells of a rejoin as such', () => {
    expect(messageFor({ ...NOTICE, role: 'admin' }, 'a@example.test').subject).toBe(
      'Agent X: a member of your organisation is now an admin',
    );
    const rejoined = messageFor({ ...NOTICE, kind: 'member_rejoined', role: 'viewer' }, 'a@example.test');
    expect(rejoined.subject).toBe('Agent X: a member rejoined your organisation as a viewer');
    expect(rejoined.text).toContain('rejoined it, as a viewer.');
  });

  it('B6-1b tells of a registered contact added, by its ID, and when it starts to count', () => {
    const message = messageFor(aboutAContact('contact_added', false), 'admin@example.test');

    expect(message.subject).toBe('Agent X: a registered contact was added to your organisation');
    expect(message.text).toContain('It counts for confirming sensitive changes only 7 days from now.');
    expect(message.text).toContain(`Registered contact: ${CONTACT}`);
    expect(message.text).not.toContain('Membership:');
    expect(message.text).toContain("You're told because you're an admin of this organisation.");
  });

  it('B6-1b tells a contact why it is told, and of a contact removed', () => {
    const message = messageFor(aboutAContact('contact_removed', true), 'contact@example.test');

    expect(message.subject).toBe('Agent X: a registered contact was removed from your organisation');
    expect(message.text).toContain('A registered contact was removed from one of your Agent X organisations.');
    expect(message.text).toContain("tell the organisation's admins at once");
    expect(message.text).toContain(
      "You're told because this address is one of the organisation's registered contacts.",
    );
    expect(message.text).not.toContain("you're an admin");
  });

  it('B6-2a tells a person of their own login changed, and an admin of a person in their organisation', () => {
    const person = '0199a0f0-0000-7000-8000-00000000b6d1';
    const signIn = (recipientUserId: string, kind: SignInNoticeKind = 'second_factor_removed'): ClaimedNotice => ({
      ...NOTICE,
      kind,
      membershipId: null,
      role: null,
      aboutId: person,
      recipientUserId,
    });

    const own = messageFor(signIn(person), 'person@example.test');
    const admin = messageFor(signIn(NOTICE.recipientUserId ?? ''), 'admin@example.test');

    expect(own.subject).toBe("Agent X: a second factor was removed from a person's login");
    expect(own.text).toContain(`Person: ${person}`);
    expect(own.text).toContain("You're told because this is your own login.");
    expect(admin.text).toContain("You're told because you're an admin of this organisation.");
    expect(admin.text).toContain('someone may be trying to take over this login');
    for (const kind of SIGN_IN_NOTICE_KINDS) {
      const { subject, text } = messageFor(signIn(person, kind), 'person@example.test');
      expect(subject).toMatch(/^Agent X: /);
      expect(`${subject} ${text}`).not.toMatch(/https?:|www\.|token|#/i);
      expect(text).toContain("This email can't approve or change anything.");
    }
    expect(messageFor(signIn(person, 'sign_in_blocked'), 'p@example.test').text).toContain('can no longer sign in');
    expect(messageFor(signIn(person, 'sign_in_restored'), 'p@example.test').text).toContain('can sign in again');
    expect(messageFor(signIn(person, 'password_changed'), 'p@example.test').subject).toContain('password');
    expect(messageFor(signIn(person, 'sign_in_email_changed'), 'p@example.test').subject).toContain('email address');
  });

  describe('B6-3b a reset of a person’s second factor', () => {
    const person = '0199a0f0-0000-7000-8000-00000000b6e1';
    const reset = '0199a0f0-0000-7000-8000-00000000b6e2';
    const link: ResetLink = {
      url: `https://app.example.test/factor-resets/confirm#token=${NOTICE.orgId}.${reset}.${CONTACT}.words`,
      expiresAt: new Date('2026-09-29T09:00:00Z'),
    };
    const aboutReset = (kind: NoticeKind, recipientUserId: string | null, contact: string | null): ClaimedNotice => ({
      ...NOTICE,
      kind,
      membershipId: null,
      role: null,
      aboutId: kind === 'factor_reset_link' ? reset : person,
      recipientUserId,
      recipientContactId: contact,
    });
    const TOLD = [
      'factor_reset_asked',
      'factor_reset_confirmed',
      'factor_reset_cancelled',
      'factor_reset_expired',
      'factor_reset_completed',
    ] as const;

    it('asks a contact to confirm with its link, what it does, until when, and that it confirms that reset alone', () => {
      const { subject, text } = messageFor(aboutReset('factor_reset_link', null, CONTACT), 'c@example.test', link);

      expect(subject).toBe("Agent X: please confirm a reset of a person's second factor");
      expect(text).toContain(`To confirm, open this link and press Confirm:\n${link.url}\n`);
      expect(text).toContain('The link works until 2026-09-29T09:00:00.000Z.');
      expect(text).toContain('by a way you already trust');
      expect(text).toContain('removed 24 hours later, unless an admin cancels the reset first');
      expect(text).toContain(`Reset: ${reset}`);
      expect(text).toContain(
        "This link confirms this one reset only: it can't approve a payment or change anything else",
      );
      expect(text).not.toContain('c@example.test');
      expect(text).not.toContain(person);
    });

    it.each(TOLD)('tells of %s with no link, naming the person, and that it can change nothing', (kind) => {
      const own = messageFor(aboutReset(kind, person, null), 'p@example.test');
      const admin = messageFor(aboutReset(kind, NOTICE.recipientUserId, null), 'a@example.test');
      const contact = messageFor(aboutReset(kind, null, CONTACT), 'c@example.test');

      for (const { subject, text } of [own, admin, contact]) {
        expect(subject).toMatch(/^Agent X: /);
        expect(`${subject} ${text}`).not.toMatch(/https?:|www\.|token|#/i);
        expect(text).toContain(`Person: ${person}`);
        expect(text).toContain("This email can't approve or change anything.");
      }
      expect(own.text).toContain("You're told because this is your own login.");
      expect(admin.text).toContain("You're told because you're an admin of this organisation.");
      expect(contact.text).toContain("one of the organisation's registered contacts");
    });

    it('says what each step means', () => {
      const text = (kind: NoticeKind) => messageFor(aboutReset(kind, person, null), 'p@example.test').text;

      expect(text('factor_reset_asked')).toContain('registered contacts are asked to confirm it');
      expect(text('factor_reset_asked')).toContain('any admin can sign in to Agent X and cancel it');
      expect(text('factor_reset_confirmed')).toContain('It will be removed in 24 hours, unless an admin cancels');
      expect(text('factor_reset_cancelled')).toContain('Nothing was removed.');
      expect(text('factor_reset_expired')).toContain('within 72 hours. Nothing was removed.');
      expect(text('factor_reset_completed')).toContain('set up a new one');
    });

    it('throws for a link notice without its link, and for a link given to any other notice: a bug', () => {
      expect(() => messageFor(aboutReset('factor_reset_link', null, CONTACT), 'c@example.test')).toThrow(RangeError);
      expect(() => messageFor(aboutReset('factor_reset_asked', person, null), 'p@example.test', link)).toThrow(
        RangeError,
      );
      expect(() => messageFor(NOTICE, 'a@example.test', link)).toThrow(RangeError);
    });
  });

  it.each([
    ['a role granted', NOTICE],
    ['a contact added, to a contact', aboutAContact('contact_added', true)],
    ['a contact removed, to an admin', aboutAContact('contact_removed', false)],
  ])('SEC-HA-11 %s: no link, no token, and it says it can change nothing', (_what, notice) => {
    const { subject, text } = messageFor(notice, 'someone@example.test');

    expect(`${subject} ${text}`).not.toMatch(/https?:|www\.|token|#/i);
    expect(text).toContain("This email can't approve or change anything.");
    expect(text).not.toContain('someone@example.test');
  });

  it('SEC-HA-11 carries no link and no token, and says it can change nothing', () => {
    const { subject, text } = messageFor(NOTICE, 'admin@example.test');

    expect(`${subject} ${text}`).not.toMatch(/https?:|www\.|token|#/i);
    expect(text).toContain("This email can't approve or change anything.");
    // Nothing of the recipient but where it goes, and nothing of the member but their membership's ID.
    expect(text).not.toContain('admin@example.test');
    expect(text).not.toContain(NOTICE.recipientUserId);
  });
});

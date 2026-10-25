// B5-1b: what a notice's email says. It tells, from IDs and constants alone,
// and does nothing: no link, no token, no approval power (PRD §4.4, SEC-HA-11).
// B6-3b: the one exception, a registered contact's link to confirm a reset,
// which confirms that reset only, and says so.
import { describe, expect, it } from 'vitest';

import { amountText, messageFor, type PaidRemittance, type ResetLink, type WaitingRequest } from './messages.ts';
import {
  AGENT_NOTICE_KINDS,
  type ClaimedNotice,
  isAboutAPayment,
  isAboutASpendRequest,
  isToAdminsAndApprovers,
  MANDATE_NOTICE_KINDS,
  type NoticeKind,
  SIGN_IN_NOTICE_KINDS,
  type SignInNoticeKind,
  SUPPLIER_NOTICE_KINDS,
} from './notice.ts';

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

  it('tells of a member removed, and that their agents keep running, and of a role taken away (the S68 audit)', () => {
    const removed = messageFor({ ...NOTICE, kind: 'member_removed', role: 'admin' }, 'a@example.test');
    expect(removed.subject).toBe('Agent X: an admin was removed from your organisation');
    expect(removed.text).toContain('Any AI agents they own keep running');
    expect(removed.text).toContain("This email can't approve or change anything.");

    const demoted = messageFor({ ...NOTICE, kind: 'role_removed', role: 'approver' }, 'a@example.test');
    expect(demoted.subject).toBe('Agent X: a member of your organisation is no longer a finance approver');
    expect(`${demoted.subject} ${demoted.text}`).not.toMatch(/https?:|token/i);
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
    // The S68 audit: a factor added, told as a removal is.
    expect(messageFor(signIn(person, 'second_factor_added'), 'p@example.test').subject).toBe(
      "Agent X: a second factor was added to a person's login",
    );
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

  describe('an agent handed to another owner (0034)', () => {
    const agent = '0199a0f0-0000-7000-8000-00000000a034';
    const aboutAgent = (kind: NoticeKind): ClaimedNotice => ({
      ...NOTICE,
      kind,
      membershipId: null,
      role: null,
      aboutId: agent,
    });

    it.each(AGENT_NOTICE_KINDS)('tells of %s, naming the agent by ID alone, and that it can change nothing', (kind) => {
      const { subject, text } = messageFor(aboutAgent(kind), 'a@example.test');

      expect(subject).toMatch(/^Agent X: an AI agent was handed/);
      expect(`${subject} ${text}`).not.toMatch(/https?:|www\.|token|#/i);
      expect(text).toContain(`Agent: ${agent}`);
      expect(text).not.toContain('Registered contact:');
      expect(text).toContain("check the organisation's AI agents");
      expect(text).toContain("This email can't approve or change anything.");
    });

    it('tells the new owner why they are told, and the admins why they are', () => {
      expect(messageFor(aboutAgent('agent_handed_to_you'), 'a@example.test').text).toContain(
        "You're told because you're the agent's new owner.",
      );
      expect(messageFor(aboutAgent('agent_handed_over'), 'a@example.test').text).toContain(
        "You're told because you're an admin of this organisation.",
      );
    });
  });

  describe('B3a a mandate’s moves (0036)', () => {
    const mandate = '0199a0f0-0000-7000-8000-00000000b3a1';
    const aboutMandate = (kind: NoticeKind): ClaimedNotice => ({
      ...NOTICE,
      kind,
      membershipId: null,
      role: null,
      aboutId: mandate,
    });

    it.each(MANDATE_NOTICE_KINDS)(
      'tells of %s, naming the mandate by ID alone, and why an approver is told too',
      (kind) => {
        const message = messageFor(aboutMandate(kind), 'a@example.test');

        expect(message.subject).toContain('mandate');
        expect(message.text).toContain(`Mandate: ${mandate}`);
        expect(message.text).toContain("You're told because you're an admin or approver of this organisation.");
        expect(message.text).toContain("This email can't approve or change anything.");
      },
    );
  });

  describe('C3a a change of the organisation’s own policy (0038)', () => {
    const org = '0199a0f0-0000-7000-8000-00000000c3a1';

    it('tells of organization_policy_changed, naming the organisation by ID alone, admins and approvers', () => {
      const message = messageFor(
        { ...NOTICE, kind: 'organization_policy_changed', membershipId: null, role: null, aboutId: org },
        'a@example.test',
      );

      expect(message.subject).toContain('policy');
      expect(message.text).toContain(`Organisation: ${org}`);
      expect(message.text).toContain("You're told because you're an admin or approver of this organisation.");
      expect(message.text).toContain("check the organisation's policies");
    });
  });

  describe('B1 the organisation frozen or unfrozen (0045, Phase 3)', () => {
    const org = '0199a0f0-0000-7000-8000-0000000003b1';

    it.each([
      ['organization_frozen', 'frozen'],
      ['organization_unfrozen', 'unfrozen'],
    ] as const)('tells of %s, naming the organisation by ID alone, admins and approvers', (kind, word) => {
      const message = messageFor({ ...NOTICE, kind, membershipId: null, role: null, aboutId: org }, 'a@example.test');

      expect(message.subject).toBe(`Agent X: the organisation was ${word}`);
      expect(message.text).toContain(`Organisation: ${org}`);
      expect(message.text).toContain("You're told because you're an admin or approver of this organisation.");
      expect(message.text).toContain('emergency brake');
    });
  });

  describe('E10c our team’s export of the audit log for a case (0050, Phase 3; ADR-005 §6)', () => {
    const entry = '0199a0f0-0000-7000-8000-00000000e10c';

    it('tells every admin, naming the log entry by ID alone and where to read the case reference', () => {
      const message = messageFor(
        { ...NOTICE, kind: 'audit_log_exported', membershipId: null, role: null, aboutId: entry },
        'a@example.test',
      );

      expect(message.subject).toBe("Agent X: our team exported your organisation's audit log");
      expect(message.text).toContain(`Audit log entry: ${entry}`);
      expect(message.text).toContain('open the audit log to see this entry: its case reference');
      expect(message.text).toContain("You're told because you're an admin of this organisation.");
      expect(message.text).toContain("This email can't approve or change anything.");
    });
  });

  describe('Phase 4 B4b an approved payment stopped before it reached the bank (0059; partner decision 3)', () => {
    const request = '0199a0f0-0000-7000-8000-0000000004b4';
    const message = messageFor(
      { ...NOTICE, kind: 'spend_request_stopped', membershipId: null, role: null, aboutId: request },
      'a@example.test',
    );

    it('tells every admin, naming the request by ID alone, that nothing was paid and the money held was freed', () => {
      expect(message.subject).toBe('Agent X: an approved payment was stopped before it reached the bank');
      expect(message.text).toContain('Nothing was paid, and the money held for it was freed.');
      expect(message.text).toContain('Once whatever stopped it is put right, the agent can ask again');
      expect(message.text).toContain(`Spend request: ${request}`);
      expect(message.text).toContain("You're told because you're an admin of this organisation.");
      expect(message.text).toContain("This email can't approve or change anything.");
    });

    it('is about a spend request, told to the admins alone, not the approvers', () => {
      expect(isAboutASpendRequest('spend_request_stopped')).toBe(true);
      expect(isToAdminsAndApprovers('spend_request_stopped')).toBe(false);
      expect(isToAdminsAndApprovers('spend_request_waiting')).toBe(true);
    });
  });

  describe('Phase 4 B1 our team paused or resumed every hand-off to the bank (0057; partner decision 4; SEC-OPS-03)', () => {
    const entry = '0199a0f0-0000-7000-8000-0000000004b1';

    it.each([
      ['handoff_paused', 'paused', 'approved ones wait, and nothing is sent to the bank until we resume'],
      ['handoff_resumed', 'resumed', 'Each approved payment that waited is checked again before it goes'],
    ] as const)(
      'tells every admin of %s, naming the log entry by ID alone and where to read its reason',
      (kind, word, what) => {
        const message = messageFor(
          { ...NOTICE, kind, membershipId: null, role: null, aboutId: entry },
          'a@example.test',
        );

        expect(message.subject).toBe(`Agent X: payments to the bank are ${word}`);
        expect(message.text).toContain(`Agent X's own team ${word}`);
        expect(message.text).toContain(what);
        expect(message.text).toContain(`Audit log entry: ${entry}`);
        expect(message.text).toContain('open the audit log to see this entry and its reason');
        expect(message.text).toContain("You're told because you're an admin of this organisation.");
      },
    );
  });

  describe('B1, B2 a spend request waiting for approval (0045, Phase 3; partner decision 2; SEC-HA-11)', () => {
    const request = '0199a0f0-0000-7000-8000-0000000003b2';
    const waitingNotice: ClaimedNotice = {
      ...NOTICE,
      kind: 'spend_request_waiting',
      membershipId: null,
      role: null,
      aboutId: request,
    };
    const waiting: WaitingRequest = {
      amountMinor: 1_234_567_805n,
      currency: 'AED',
      supplierName: 'Gulf Office Supplies',
      agentName: 'Procurement agent',
      agentId: '0199a0f0-0000-7000-8000-0000000003b4',
      consoleUrl: 'https://app.example.test',
      expiresAt: new Date('2026-10-17T12:05:00.000Z'),
    };
    const message = messageFor(waitingNotice, 'a@example.test', undefined, waiting);

    it('names the request, told to admins and approvers', () => {
      expect(message.subject).toBe("Agent X: an AI agent's spend request is waiting for approval");
      expect(message.text).toContain(`Spend request: ${request}`);
      expect(message.text).toContain("You're told because you're an admin or approver of this organisation.");
    });

    it('shows what it asks, who asked, when it expires in UAE time (E6), and Agent X’s address, read as it is sent (B2)', () => {
      expect(message.text).toContain(
        [
          'Amount: AED 12,345,678.05',
          'Supplier: Gulf Office Supplies',
          `AI agent: Procurement agent (ID ${waiting.agentId})`,
          'Expires: 17 Oct 2026, 16:05 UAE time (2026-10-17T12:05:00.000Z)',
          'Agent X: https://app.example.test',
        ].join('\n'),
      );
    });

    it('carries no approval power: no token, and says the decision is made signed in, with a passkey', () => {
      expect(`${message.subject} ${message.text}`).not.toMatch(/token|[?#]/i);
      expect(message.text).toContain('passkey');
      expect(message.text).toContain("This email can't approve or change anything.");
    });

    it('is sent with its request, and only it is', () => {
      expect(() => messageFor(waitingNotice, 'a@example.test')).toThrow(RangeError);
      expect(() =>
        messageFor({ ...waitingNotice, kind: 'organization_frozen' }, 'a@example.test', undefined, waiting),
      ).toThrow(RangeError);
    });

    it.each([
      [0n, 'AED 0.00'],
      [5n, 'AED 0.05'],
      [100n, 'AED 1.00'],
      [99_999n, 'AED 999.99'],
      [100_000n, 'AED 1,000.00'],
    ])('writes %s minor units as %s', (minor, text) => {
      expect(amountText(minor, 'AED')).toBe(text);
    });
  });

  describe('C2b a payment to a supplier SUCCEEDED (0062, Phase 4; partner decisions 8 and 34a, 34c)', () => {
    const payment = '0199a0f0-0000-7000-8000-0000000c2bc1';
    const remittanceNotice: ClaimedNotice = {
      ...NOTICE,
      kind: 'payment_remittance',
      recipientUserId: null,
      membershipId: null,
      role: null,
      aboutId: payment,
    };
    const paid: PaidRemittance = {
      payerName: 'Falcon Trading LLC',
      invoiceNumber: 'INV-2026-0042',
      bankReference: 'AGX INV-2026-0042',
      amountMinor: 1_234_567_805n,
      currency: 'AED',
    };
    const message = messageFor(remittanceNotice, 'accounts@supplier.example.test', undefined, undefined, paid);

    it('tells the supplier who paid, the invoice number, the bank reference and the amount', () => {
      expect(message).toMatchObject({ id: remittanceNotice.id, to: 'accounts@supplier.example.test' });
      expect(message.subject).toBe('Payment sent to you by Falcon Trading LLC');
      expect(message.text).toContain(
        [
          'Amount: AED 12,345,678.05',
          'Invoice number: INV-2026-0042',
          'Bank reference: AGX INV-2026-0042 (as your bank shows it)',
        ].join('\n'),
      );
    });

    it('carries nothing of ours to someone outside the organisation: no ID, no link, and it can change nothing', () => {
      for (const id of [NOTICE.orgId, payment, NOTICE.recipientUserId ?? '']) expect(message.text).not.toContain(id);
      expect(`${message.subject} ${message.text}`).not.toMatch(/https?:|www\.|token|#/i);
      expect(message.text).toContain("it can't change anything");
      expect(message.text).toContain('never by replying to this email');
    });

    it('is sent with its payment, and only it is', () => {
      expect(() => messageFor(remittanceNotice, 'a@example.test')).toThrow(RangeError);
      expect(() => messageFor(NOTICE, 'a@example.test', undefined, undefined, paid)).toThrow(RangeError);
      expect(() =>
        messageFor(
          remittanceNotice,
          'a@example.test',
          { url: 'https://x.test', expiresAt: NOTICE.createdAt },
          undefined,
          paid,
        ),
      ).toThrow(RangeError);
    });

    it('tells every admin, by the payment’s ID, when the supplier had no email to tell (34c)', () => {
      const told = messageFor(
        { ...remittanceNotice, kind: 'payment_remittance_no_email', recipientUserId: NOTICE.recipientUserId },
        'a@example.test',
      );

      expect(told.subject).toBe('Agent X: a supplier was paid but not emailed');
      expect(told.text).toContain("it has no email address on file, so it wasn't told");
      expect(told.text).toContain(`Payment: ${payment}`);
      expect(told.text).toContain("You're told because you're an admin of this organisation.");
      expect(told.text).toContain("This email can't approve or change anything.");
    });

    it('tells every admin, by the payment’s ID, that two admins marked it failed on their bank’s word (0064; H10)', () => {
      const told = messageFor(
        { ...remittanceNotice, kind: 'payment_marked_failed', recipientUserId: NOTICE.recipientUserId },
        'a@example.test',
      );

      expect(isAboutAPayment('payment_marked_failed')).toBe(true);
      expect(told.subject).toBe('Agent X: a payment was marked failed');
      expect(told.text).toContain('one admin proposed it');
      expect(told.text).toContain('a second admin confirmed it');
      expect(told.text).toContain('contact your bank quoting the payment');
      expect(told.text).not.toMatch(/our team|Agent X support/);
      expect(told.text).toContain(`Payment: ${payment}`);
      expect(told.text).toContain("You're told because you're an admin of this organisation.");
    });

    it.each([
      [
        'payment_mark_proposed',
        'Agent X: a second admin is needed to mark a payment failed',
        "Agent X can't check the bank's reference itself",
      ],
      [
        'payment_mark_withdrawn',
        'Agent X: a proposal to mark a payment failed was withdrawn',
        'withdrew the proposal to mark a payment as failed',
      ],
      [
        'payment_mark_ended',
        'Agent X: the bank answered about a payment proposed to be marked failed',
        'so the proposal is closed',
      ],
    ] as const)('tells every admin, by the payment’s ID, of a %s (0066, H10)', (kind, subject, line) => {
      const told = messageFor({ ...remittanceNotice, kind, recipientUserId: NOTICE.recipientUserId }, 'a@example.test');

      expect(isAboutAPayment(kind)).toBe(true);
      expect(told.subject).toBe(subject);
      expect(told.text).toContain(line);
      expect(told.text).not.toMatch(/our team|Agent X support/);
      expect(told.text).toContain(`Payment: ${payment}`);
      expect(told.text).toContain("You're told because you're an admin of this organisation.");
    });

    it.each([
      ['payment_contradicted', "Agent X: the bank's answer on a payment changed", 'went back on what it said before'],
      ['payment_unproven', 'Agent X: a payment was rejected without proof', "didn't confirm the money stayed"],
      [
        'payment_still_unknown',
        'Agent X: a payment still has no final answer',
        'no final answer from the bank for over a day',
      ],
    ] as const)(
      'tells every admin, by the payment’s ID, of a %s payment to follow up with their own bank (0065, decisions 37b, 38)',
      (kind, subject, line) => {
        const told = messageFor(
          { ...remittanceNotice, kind, recipientUserId: NOTICE.recipientUserId },
          'a@example.test',
        );

        expect(isAboutAPayment(kind)).toBe(true);
        expect(told.subject).toBe(subject);
        expect(told.text).toContain(line);
        expect(told.text).toContain('Agent X keeps checking it with the bank automatically');
        expect(told.text).toContain('contact your bank quoting that payment reference');
        expect(told.text).toContain("Don't pay its invoice again until your bank confirms the money didn't leave");
        expect(told.text).not.toMatch(/our team|Agent X support/);
        expect(told.text).toContain(`Payment: ${payment}`);
        expect(told.text).toContain("You're told because you're an admin of this organisation.");
      },
    );
  });

  describe('E2-1 a change to a supplier (0033)', () => {
    const supplier = '0199a0f0-0000-7000-8000-00000000e201';
    const aboutSupplier = (kind: NoticeKind, toAContact: boolean): ClaimedNotice => ({
      ...NOTICE,
      kind,
      membershipId: null,
      role: null,
      aboutId: supplier,
      recipientUserId: toAContact ? null : NOTICE.recipientUserId,
      recipientContactId: toAContact ? CONTACT : null,
    });

    it.each(SUPPLIER_NOTICE_KINDS)(
      'tells of %s, naming the supplier by ID alone, and that it can change nothing',
      (kind) => {
        const admin = messageFor(aboutSupplier(kind, false), 'a@example.test');
        const contact = messageFor(aboutSupplier(kind, true), 'c@example.test');

        for (const { subject, text } of [admin, contact]) {
          expect(subject).toMatch(/^Agent X: .*supplier/);
          expect(`${subject} ${text}`).not.toMatch(/https?:|www\.|token|#/i);
          expect(text).toContain(`Supplier: ${supplier}`);
          expect(text).not.toContain('Registered contact:');
          expect(text).toContain("check the organisation's suppliers");
          expect(text).toContain("This email can't approve or change anything.");
        }
        expect(admin.text).toContain("You're told because you're an admin of this organisation.");
        expect(contact.text).toContain("one of the organisation's registered contacts");
      },
    );

    it('says what each change means', () => {
      const text = (kind: NoticeKind) => messageFor(aboutSupplier(kind, false), 'a@example.test').text;

      expect(text('supplier_reactivated')).toContain('verified again only if nothing about it changed');
      expect(text('supplier_payee_changed')).toContain('Nothing is paid to them until a second person');
      expect(text('supplier_details_changed')).toContain('until a second person verifies it again');
      expect(text('supplier_verified')).toContain('may now ask to pay it');
      expect(text('supplier_suspended')).toContain('nothing is paid to it until an admin reactivates it');
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

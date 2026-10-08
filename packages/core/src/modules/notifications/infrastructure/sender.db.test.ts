// B5-1b: the notice sender, on the real outbox, with a notifier and an address
// book of the test's own: each due notice sent to the address its recipient
// has now and marked sent; a failed send tried again or given up as the
// notifier says; no address given up at once, an address book away tried
// again; a notifier that throws never loses a notice or stops the run; a run
// stopped between notices; a notice to the admins turned into one to each
// but the member it is about, and those sent in the same run; a notice to the
// registered contacts turned into one to each ACTIVE contact, each sent to the
// address its own row gives (B6-1b); a contact asked to confirm a reset sent
// its link, read at send time, or the notice given up once the reset no
// longer waits (B6-3b). Its log never holds an address, nor a link.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import type { NoticeMessage, ResetLink } from '../domain/messages.ts';
import type { Notice } from '../domain/notice.ts';
import { createOutbox } from './outbox.ts';
import {
  type AddressBook,
  type Admin,
  type Audience,
  type ContactAddresses,
  createNoticeSender,
  type Notifier,
  type ResetLinks,
  type SendOutcome,
} from './sender.ts';
import type { NotificationsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<NotificationsTables>;

const START = new Date('2026-09-26T09:00:00Z');
const ids = new SequentialIds(0xb5b0);
const ORG = '0199a0f0-0000-7000-8000-00000000b5b1';
const ADMIN = '0199a0f0-0000-7000-8000-00000000b5b2';
const OTHER_ADMIN = '0199a0f0-0000-7000-8000-00000000b5b3';
const MEMBERSHIP = '0199a0f0-0000-7000-8000-00000000b5b4';
const MEMBER = '0199a0f0-0000-7000-8000-00000000b5b5';
/** The organisation's active admins: the two, and the member the notices are about, made one. */
const ADMINS: readonly Admin[] = [
  { userId: ADMIN, membershipId: '0199a0f0-0000-7000-8000-00000000b5c1' },
  { userId: OTHER_ADMIN, membershipId: '0199a0f0-0000-7000-8000-00000000b5c2' },
  { userId: MEMBER, membershipId: MEMBERSHIP },
];
/** A viewer of the organisation: a member, but no admin (E2-2b). */
const VIEWER = '0199a0f0-0000-7000-8000-00000000b5b6';
/** The organisation's active members, every role (E2-2b). */
const MEMBERS: readonly string[] = [ADMIN, VIEWER];
/** An approver of the organisation: told of a mandate's moves with its admins (0036). */
const APPROVER = '0199a0f0-0000-7000-8000-00000000b5b7';
/** A mandate the notices are about (0036). */
const MANDATE = '0199a0f0-0000-7000-8000-00000000b6b6';
const ADDRESSES = new Map([
  [ADMIN, 'admin@example.test'],
  [APPROVER, 'approver@example.test'],
  [OTHER_ADMIN, 'other.admin@example.test'],
  [VIEWER, 'viewer@example.test'],
]);
/** The organisation's ACTIVE registered contacts (B6-1b), and the contact the notices are about. */
const CONTACT = '0199a0f0-0000-7000-8000-00000000b6b1';
const OTHER_CONTACT = '0199a0f0-0000-7000-8000-00000000b6b2';
const ABOUT_CONTACT = '0199a0f0-0000-7000-8000-00000000b6b3';
/** A supplier the notices are about (E2-2b). */
const SUPPLIER = '0199a0f0-0000-7000-8000-00000000b6b5';
/** A reset of the member's second factor (B6-3b), and the one link written for CONTACT. */
const RESET = '0199a0f0-0000-7000-8000-00000000b6b4';
const LINK: ResetLink = {
  url: `https://app.example.test/factor-resets/confirm#token=${ORG}.${RESET}.${CONTACT}.a-contacts-own-words`,
  expiresAt: new Date('2026-09-29T09:00:00Z'),
};
const CONTACT_ADDRESSES = new Map([
  [CONTACT, 'finance.office@example.test'],
  [OTHER_CONTACT, 'owner@example.test'],
]);

const clock = { now: (): Date => START };
const outbox = createOutbox({ ids, clock });

const notice = (recipientUserId: string | null): Notice => ({
  orgId: ORG,
  recipientUserId,
  kind: 'role_granted',
  membershipId: MEMBERSHIP,
  role: 'approver',
});

const rows = () =>
  app
    .selectFrom('notifications.outbox')
    .select(['recipient_user_id', 'attempts', 'sent_at', 'given_up_at', 'last_failure'])
    .orderBy('recipient_user_id')
    .execute();

/** A notifier that answers each send with `answer`, and keeps what it was asked to send. */
function notifier(answer: (message: NoticeMessage) => SendOutcome | Error = () => ({ outcome: 'sent' })) {
  const sent: NoticeMessage[] = [];
  const service: Notifier = {
    send: (message) => {
      sent.push(message);
      const outcome = answer(message);
      return outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome);
    },
  };
  return { sent, service };
}

const addressBook = (
  lookup: (userId: string) => string | undefined | Error = (id) => ADDRESSES.get(id),
): AddressBook => ({
  addressOf: (userId) => {
    const found = lookup(userId);
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  },
});

const contactAddresses = (
  lookup: (contactId: string) => string | undefined | Error = (id) => CONTACT_ADDRESSES.get(id),
): ContactAddresses => ({
  addressOf: (orgId, contactId) => {
    expect(orgId).toBe(ORG);
    const found = lookup(contactId);
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  },
});

/** One of the audience's groups, asked of ORG alone: what `find` gives, or its error. */
const group =
  <T>(find: () => T | Error) =>
  (orgId: string): Promise<T> => {
    expect(orgId).toBe(ORG);
    const found = find();
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  };

const audience = (
  admins: () => readonly Admin[] | Error = () => ADMINS,
  contacts: () => readonly string[] | Error = () => [CONTACT, OTHER_CONTACT],
  members: () => readonly string[] | Error = () => MEMBERS,
  // Of the two ACTIVE contacts, only the first counts yet.
  counting: () => readonly string[] | Error = () => [CONTACT],
  deciders: () => readonly string[] | Error = () => [ADMIN, APPROVER],
): Audience => ({
  adminsAndApproversOf: group(deciders),
  adminsOf: group(admins),
  contactsOf: group(contacts),
  membersOf: group(members),
  countingContactsOf: group(counting),
});

const resetLinks = (
  lookup: (resetId: string, contactId: string) => ResetLink | undefined | Error = (resetId, contactId) =>
    resetId === RESET && contactId === CONTACT ? LINK : undefined,
): ResetLinks => ({
  linkFor: (orgId, resetId, contactId) => {
    expect(orgId).toBe(ORG);
    const found = lookup(resetId, contactId);
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  },
});

/** The notice asking one contact to confirm the reset (B6-3b). */
const resetLinkTo = (contact: string): Notice => ({
  orgId: ORG,
  recipientUserId: null,
  recipientContactId: contact,
  kind: 'factor_reset_link',
  membershipId: null,
  role: null,
  aboutId: RESET,
});

/** A notice about a registered contact (B6-1b), to the admins, the contacts, or one contact. */
const aboutAContact = (to: { contact?: string; contacts?: boolean }): Notice => ({
  orgId: ORG,
  recipientUserId: null,
  recipientContactId: to.contact ?? null,
  toContacts: to.contacts === true,
  kind: 'contact_removed',
  membershipId: null,
  role: null,
  aboutId: ABOUT_CONTACT,
});

/** A notice about the supplier (E2-2b), to every member, or to the contacts. */
const aboutASupplier = (toContacts: boolean): Notice => ({
  orgId: ORG,
  recipientUserId: null,
  toContacts,
  kind: 'supplier_payee_changed',
  membershipId: null,
  role: null,
  aboutId: SUPPLIER,
});

function sender(
  service: Notifier,
  addresses: AddressBook = addressBook(),
  admins: Audience = audience(),
  contacts: ContactAddresses = contactAddresses(),
  links: ResetLinks = resetLinks(),
) {
  const capture = new LogCapture();
  const logger = testLogger(capture);
  return {
    capture,
    run: createNoticeSender({
      db: app,
      outbox,
      notifier: service,
      addresses,
      contactAddresses: contacts,
      resetLinks: links,
      audience: admins,
      logger,
    }),
  };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<NotificationsTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
  await sql`insert into directory.orgs (org_id) values (${ORG})`.execute(app);
  for (const [id, subject] of [
    [ADMIN, 'sender-admin'],
    [OTHER_ADMIN, 'sender-other-admin'],
    [MEMBER, 'sender-member'],
    [VIEWER, 'sender-viewer'],
    [APPROVER, 'sender-approver'],
  ]) {
    await sql`insert into identity.users (id, issuer, subject, created_at)
      values (${id}, 'https://auth.example.test', ${subject}, ${START})`.execute(app);
  }
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  await sql`delete from notifications.outbox`.execute(app);
  await app.transaction().execute((tx) => outbox.add(tx, [notice(ADMIN), notice(OTHER_ADMIN)]));
});

describe(`the notice sender (B5-1b, Postgres ${server.version})`, () => {
  it('sends each due notice to the address its recipient has now, keyed by the notice, and marks it sent', async () => {
    const { sent, service } = notifier();

    await sender(service).run.run();

    expect(sent.map(({ to }) => to).sort()).toEqual(['admin@example.test', 'other.admin@example.test']);
    const ids = (await app.selectFrom('notifications.outbox').select('id').execute()).map(({ id }) => id).sort();
    expect(sent.map(({ id }) => id).sort()).toEqual(ids);
    expect(await rows()).toMatchObject([
      { attempts: 1, sent_at: START, given_up_at: null },
      { attempts: 1, sent_at: START, given_up_at: null },
    ]);
    // Nothing is due any more: a second run sends nothing.
    await sender(service).run.run();
    expect(sent).toHaveLength(2);
  });

  it('tries a notice again, or gives it up, as the notifier says', async () => {
    const { service } = notifier(({ to }) =>
      to === 'admin@example.test'
        ? { outcome: 'failed', failure: 'provider_unavailable', lasting: false }
        : { outcome: 'failed', failure: 'address_refused', lasting: true },
    );

    await sender(service).run.run();

    expect(await rows()).toMatchObject([
      { recipient_user_id: ADMIN, attempts: 1, given_up_at: null, last_failure: 'provider_unavailable' },
      { recipient_user_id: OTHER_ADMIN, attempts: 1, given_up_at: START, last_failure: 'address_refused' },
    ]);
  });

  it('gives a notice up at once when its recipient has no address, and tries again when the address book is away', async () => {
    const { sent, service } = notifier();
    const addresses = addressBook((id) => (id === ADMIN ? undefined : new Error('the login service is away')));

    await sender(service, addresses).run.run();

    expect(sent).toEqual([]);
    expect(await rows()).toMatchObject([
      { recipient_user_id: ADMIN, given_up_at: START, last_failure: 'no_address' },
      { recipient_user_id: OTHER_ADMIN, given_up_at: null, last_failure: 'address_unavailable' },
    ]);
  });

  it('counts a notifier that throws as a failed try, and still sends the next notice', async () => {
    const { sent, service } = notifier(({ to }) =>
      to === 'admin@example.test' ? new Error('socket hang up: admin@example.test') : { outcome: 'sent' },
    );

    const { capture, run } = sender(service);
    await run.run();

    expect(sent).toHaveLength(2);
    expect(await rows()).toMatchObject([
      { recipient_user_id: ADMIN, sent_at: null, given_up_at: null, last_failure: 'send_error' },
      { recipient_user_id: OTHER_ADMIN, sent_at: START },
    ]);
    // Its log names the notices and how each went, never an address nor the provider's words.
    const lines = capture.lines();
    expect(lines.map(({ event }) => event).sort()).toEqual(['notification.failed', 'notification.sent']);
    expect(JSON.stringify(lines)).not.toMatch(/@example\.test|socket hang up/);
  });

  it.each([
    ["in the provider's own words", 'Mailbox full: admin@example.test'],
    ["by the outbox's own reason for a lease run out (review)", 'lease_expired'],
  ])("names a notifier's failure given %s as send_failed, and still sends the next", async (_how, failure) => {
    const { sent, service } = notifier(() => ({ outcome: 'failed', failure, lasting: false }));

    await sender(service).run.run();

    expect(sent).toHaveLength(2);
    expect((await rows()).map(({ last_failure }) => last_failure)).toEqual(['send_failed', 'send_failed']);
  });

  it('turns a notice to the admins into one to each but the member it is about, and sends them in the same run', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app.transaction().execute((tx) => outbox.add(tx, [notice(null)]));
    const { sent, service } = notifier();

    const { capture, run } = sender(service);
    await run.run();

    expect(sent.map(({ to }) => to).sort()).toEqual(['admin@example.test', 'other.admin@example.test']);
    expect(await rows()).toMatchObject([
      { recipient_user_id: ADMIN, sent_at: START },
      { recipient_user_id: OTHER_ADMIN, sent_at: START },
      { recipient_user_id: null, sent_at: START },
    ]);
    expect(capture.lines().find(({ event }) => event === 'notification.fanned_out')).toMatchObject({ notices: 2 });
  });

  it('tries a notice to the admins again when they cannot be read, writing none', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app.transaction().execute((tx) => outbox.add(tx, [notice(null)]));
    const { sent, service } = notifier();

    await sender(
      service,
      addressBook(),
      audience(() => new Error('tampered')),
    ).run.run();

    expect(sent).toEqual([]);
    expect(await rows()).toMatchObject([
      { recipient_user_id: null, sent_at: null, given_up_at: null, last_failure: 'audience_unavailable' },
    ]);
  });

  it('B6-2a leaves an admin out of a notice to the admins about their own sign-in: they are told once, as themselves', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    const aboutAdmin = {
      orgId: ORG,
      kind: 'second_factor_removed',
      membershipId: null,
      role: null,
      aboutId: ADMIN,
    } as const;
    await app.transaction().execute((tx) =>
      outbox.add(tx, [
        { ...aboutAdmin, recipientUserId: ADMIN },
        { ...aboutAdmin, recipientUserId: null },
      ]),
    );
    const { sent, service } = notifier();

    await sender(service).run.run();

    // The admin once, as themselves; the other admin, and the member the role notices are about, as admins.
    expect(sent.map(({ to }) => to).sort()).toEqual(['admin@example.test', 'other.admin@example.test']);
    const toAdmin = sent.find(({ to }) => to === 'admin@example.test');
    expect(toAdmin?.text).toContain("You're told because this is your own login.");
    expect(
      (await rows()).filter(({ recipient_user_id }) => recipient_user_id === MEMBER).map(({ sent_at }) => sent_at),
    ).toEqual([null]);
  });

  it('B6-3b leaves the person out of a notice to the admins about a reset of their second factor: told once, as themselves', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    const aboutAdmin = {
      orgId: ORG,
      kind: 'factor_reset_asked',
      membershipId: null,
      role: null,
      aboutId: ADMIN,
    } as const;
    await app.transaction().execute((tx) =>
      outbox.add(tx, [
        { ...aboutAdmin, recipientUserId: ADMIN },
        { ...aboutAdmin, recipientUserId: null },
      ]),
    );
    const { sent, service } = notifier();

    await sender(service).run.run();

    expect(sent.map(({ to }) => to).sort()).toEqual(['admin@example.test', 'other.admin@example.test']);
    expect(sent.find(({ to }) => to === 'admin@example.test')?.text).toContain(
      "You're told because this is your own login.",
    );
  });

  it('B6-3b sends a contact asked to confirm a reset its own link, read at send time, and never logs it', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app.transaction().execute((tx) => outbox.add(tx, [resetLinkTo(CONTACT)]));
    const { sent, service } = notifier();

    const { capture, run } = sender(service);
    await run.run();

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ to: 'finance.office@example.test' });
    expect(sent[0]?.text).toContain(LINK.url);
    expect(sent[0]?.text).toContain('The link works until 2026-09-29T09:00:00.000Z.');
    expect(capture.lines().find(({ event }) => event === 'notification.sent')).toMatchObject({
      kind: 'factor_reset_link',
    });
    expect(JSON.stringify(capture.lines())).not.toMatch(/a-contacts-own-words|factor-resets|@example\.test/);
  });

  it('B6-3b gives a link notice up once its reset no longer waits for a contact, and tries again when links can’t be read', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app.transaction().execute((tx) => outbox.add(tx, [resetLinkTo(OTHER_CONTACT), resetLinkTo(CONTACT)]));
    const { sent, service } = notifier();

    await sender(
      service,
      addressBook(),
      audience(),
      contactAddresses(),
      resetLinks((_reset, contact) => (contact === CONTACT ? new Error('tampered') : undefined)),
    ).run.run();

    expect(sent).toEqual([]);
    const outboxRows = await app
      .selectFrom('notifications.outbox')
      .select(['recipient_contact_id', 'sent_at', 'given_up_at', 'last_failure'])
      .orderBy('recipient_contact_id')
      .execute();
    expect(outboxRows).toEqual([
      { recipient_contact_id: CONTACT, sent_at: null, given_up_at: null, last_failure: 'link_unavailable' },
      { recipient_contact_id: OTHER_CONTACT, sent_at: null, given_up_at: START, last_failure: 'reset_closed' },
    ]);
  });

  it('B6-1b turns a notice to the contacts into one to each ACTIVE contact, each sent to its own address', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app.transaction().execute((tx) => outbox.add(tx, [aboutAContact({ contacts: true })]));
    const { sent, service } = notifier();

    const { capture, run } = sender(service);
    await run.run();

    expect(sent.map(({ to }) => to).sort()).toEqual(['finance.office@example.test', 'owner@example.test']);
    expect(sent.every(({ text }) => text.includes(`Registered contact: ${ABOUT_CONTACT}`))).toBe(true);
    const outboxRows = await app
      .selectFrom('notifications.outbox')
      .select(['recipient_user_id', 'recipient_contact_id', 'to_contacts', 'about_id', 'sent_at'])
      .orderBy('recipient_contact_id')
      .execute();
    expect(outboxRows).toEqual([
      {
        recipient_user_id: null,
        recipient_contact_id: CONTACT,
        to_contacts: false,
        about_id: ABOUT_CONTACT,
        sent_at: START,
      },
      {
        recipient_user_id: null,
        recipient_contact_id: OTHER_CONTACT,
        to_contacts: false,
        about_id: ABOUT_CONTACT,
        sent_at: START,
      },
      {
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: true,
        about_id: ABOUT_CONTACT,
        sent_at: START,
      },
    ]);
    expect(capture.lines().find(({ event }) => event === 'notification.fanned_out')).toMatchObject({ notices: 2 });
    expect(JSON.stringify(capture.lines())).not.toMatch(/@example\.test/);
  });

  it('E2-2b sends a notice about a supplier to every active member, whatever their role, and to the contacts that count now', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app.transaction().execute((tx) => outbox.add(tx, [aboutASupplier(false), aboutASupplier(true)]));
    const { sent, service } = notifier();

    await sender(service).run.run();

    // Not the other admin, who is no member in this audience, nor the contact that doesn't count yet.
    expect(sent.map(({ to }) => to).sort()).toEqual([
      'admin@example.test',
      'finance.office@example.test',
      'viewer@example.test',
    ]);
    expect(sent.every(({ text }) => text.includes(`Supplier: ${SUPPLIER}`))).toBe(true);
    expect(sent.every(({ subject }) => subject.includes("a supplier's bank details"))).toBe(true);
  });

  it('B3a sends a notice about a mandate to every active admin and approver', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    const accepted: Notice = {
      orgId: ORG,
      recipientUserId: null,
      kind: 'mandate_accepted',
      membershipId: null,
      role: null,
      aboutId: MANDATE,
    };
    await app.transaction().execute((tx) => outbox.add(tx, [accepted]));
    const { sent, service } = notifier();

    await sender(service).run.run();

    // Not the other admin or the viewer, who are no admin or approver in this audience.
    expect(sent.map(({ to }) => to).sort()).toEqual(['admin@example.test', 'approver@example.test']);
    expect(sent.every(({ text }) => text.includes(`Mandate: ${MANDATE}`))).toBe(true);
  });

  it.each([
    ['organization_policy_changed', `Organisation: ${ORG}`],
    ['mandate_policy_changed', `Mandate: ${MANDATE}`],
  ] as const)('C3a sends %s to every active admin and approver, naming what it is about', async (kind, about) => {
    await sql`delete from notifications.outbox`.execute(app);
    const changed: Notice = {
      orgId: ORG,
      recipientUserId: null,
      kind,
      membershipId: null,
      role: null,
      aboutId: kind === 'organization_policy_changed' ? ORG : MANDATE,
    };
    await app.transaction().execute((tx) => outbox.add(tx, [changed]));
    const { sent, service } = notifier();

    await sender(service).run.run();

    expect(sent.map(({ to }) => to).sort()).toEqual(['admin@example.test', 'approver@example.test']);
    expect(sent.every(({ text }) => text.includes(about))).toBe(true);
  });

  it('B3a tries a notice about a mandate again when its admins and approvers cannot be read', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app.transaction().execute((tx) =>
      outbox.add(tx, [
        {
          orgId: ORG,
          recipientUserId: null,
          kind: 'mandate_revoked',
          membershipId: null,
          role: null,
          aboutId: MANDATE,
        },
      ]),
    );
    const { sent, service } = notifier();
    const away = () => new Error('tampered');

    await sender(service, addressBook(), audience(undefined, undefined, undefined, undefined, away)).run.run();

    expect(sent).toEqual([]);
    expect((await rows()).map(({ last_failure }) => last_failure)).toEqual(['audience_unavailable']);
  });

  it('E2-2b tries a notice about a supplier again when its members, or its counting contacts, cannot be read', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app.transaction().execute((tx) => outbox.add(tx, [aboutASupplier(false), aboutASupplier(true)]));
    const { sent, service } = notifier();
    const away = () => new Error('tampered');

    await sender(service, addressBook(), audience(undefined, undefined, away, away)).run.run();

    expect(sent).toEqual([]);
    expect((await rows()).map(({ last_failure }) => last_failure)).toEqual([
      'audience_unavailable',
      'audience_unavailable',
    ]);
  });

  it('B6-1b sends a notice to one contact to the address its row gives, and gives it up when it has none', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app
      .transaction()
      .execute((tx) =>
        outbox.add(tx, [aboutAContact({ contact: CONTACT }), aboutAContact({ contact: OTHER_CONTACT })]),
      );
    const { sent, service } = notifier();

    await sender(
      service,
      addressBook(() => new Error('a person is not asked')),
      audience(),
      contactAddresses((id) => (id === CONTACT ? 'finance.office@example.test' : undefined)),
    ).run.run();

    expect(sent.map(({ to }) => to)).toEqual(['finance.office@example.test']);
    const outboxRows = await app
      .selectFrom('notifications.outbox')
      .select(['recipient_contact_id', 'sent_at', 'given_up_at', 'last_failure'])
      .orderBy('recipient_contact_id')
      .execute();
    expect(outboxRows).toEqual([
      { recipient_contact_id: CONTACT, sent_at: START, given_up_at: null, last_failure: null },
      { recipient_contact_id: OTHER_CONTACT, sent_at: null, given_up_at: START, last_failure: 'no_address' },
    ]);
  });

  it('B6-1b tries a notice to the contacts again when they cannot be read, or a contact’s address can’t', async () => {
    await sql`delete from notifications.outbox`.execute(app);
    await app
      .transaction()
      .execute((tx) => outbox.add(tx, [aboutAContact({ contacts: true }), aboutAContact({ contact: CONTACT })]));
    const { sent, service } = notifier();

    await sender(
      service,
      addressBook(),
      audience(
        () => ADMINS,
        () => new Error('tampered'),
      ),
      contactAddresses(() => new Error('tampered')),
    ).run.run();

    expect(sent).toEqual([]);
    const outboxRows = await app
      .selectFrom('notifications.outbox')
      .select(['to_contacts', 'sent_at', 'given_up_at', 'last_failure'])
      .orderBy('to_contacts')
      .execute();
    expect(outboxRows).toEqual([
      { to_contacts: false, sent_at: null, given_up_at: null, last_failure: 'address_unavailable' },
      { to_contacts: true, sent_at: null, given_up_at: null, last_failure: 'audience_unavailable' },
    ]);
  });

  it('never throws when the outbox fails under it: it logs, and the next run goes on (review)', async () => {
    const { service } = notifier();
    const broken = createNoticeSender({
      db: app,
      outbox: { ...outbox, claimDue: () => Promise.reject(new Error('canceling statement due to statement timeout')) },
      notifier: service,
      addresses: addressBook(),
      contactAddresses: contactAddresses(),
      resetLinks: resetLinks(),
      audience: audience(),
      logger: testLogger(),
    });
    const capture = new LogCapture();
    const logged = createNoticeSender({
      db: app,
      outbox: { ...outbox, sent: () => Promise.reject(new Error('connection terminated')) },
      notifier: service,
      addresses: addressBook(),
      contactAddresses: contactAddresses(),
      resetLinks: resetLinks(),
      audience: audience(),
      logger: testLogger(capture),
    });

    await expect(broken.run()).resolves.toBeUndefined();
    await expect(logged.run()).resolves.toBeUndefined();
    expect(capture.lines().map(({ event }) => event)).toContain('notification.run_failed');
  });

  it('stops between notices once its signal is aborted, leaving the rest to their lease', async () => {
    const stopping = new AbortController();
    const { sent, service } = notifier(() => {
      stopping.abort();
      return { outcome: 'sent' };
    });

    await sender(service).run.run(stopping.signal);

    expect(sent).toHaveLength(1);
    expect((await rows()).filter(({ sent_at }) => sent_at === null)).toHaveLength(1);
  });
});

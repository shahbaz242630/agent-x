// B5-1b: the notice sender, on the real outbox, with a notifier and an address
// book of the test's own: each due notice sent to the address its recipient
// has now and marked sent; a failed send tried again or given up as the
// notifier says; no address given up at once, an address book away tried
// again; a notifier that throws never loses a notice or stops the run; a run
// stopped between notices; a notice to the admins turned into one to each
// but the member it is about, and those sent in the same run. Its log never
// holds an address.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import type { NoticeMessage } from '../domain/messages.ts';
import type { Notice } from '../domain/notice.ts';
import { createOutbox } from './outbox.ts';
import {
  type AddressBook,
  type Admin,
  type Audience,
  createNoticeSender,
  type Notifier,
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
const ADDRESSES = new Map([
  [ADMIN, 'admin@example.test'],
  [OTHER_ADMIN, 'other.admin@example.test'],
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

const audience = (admins: () => readonly Admin[] | Error = () => ADMINS): Audience => ({
  adminsOf: (orgId) => {
    expect(orgId).toBe(ORG);
    const found = admins();
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  },
});

function sender(service: Notifier, addresses: AddressBook = addressBook(), admins: Audience = audience()) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  return {
    capture,
    run: createNoticeSender({ db: app, outbox, notifier: service, addresses, audience: admins, logger }),
  };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<NotificationsTables>(
    { ...database.connection('app'), maxConnections: 2 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
  await sql`insert into directory.orgs (org_id) values (${ORG})`.execute(app);
  for (const [id, subject] of [
    [ADMIN, 'sender-admin'],
    [OTHER_ADMIN, 'sender-other-admin'],
    [MEMBER, 'sender-member'],
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

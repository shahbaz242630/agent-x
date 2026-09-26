// B5-1a: the notifications outbox (0021) on the real migrated schema, as the
// app role: notices written in the caller's transaction and rolled back with
// it, refused whole when anything is malformed; taken when due, soonest
// first, each try counted, held for the lease and never by two senders at
// once; marked sent, or tried again further off each time and given up,
// also when the last try's lease runs out; a notice to the admins turned
// into one to each, once; swept once done and past the retention.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { CLAIM_LEASE_MS, createOutbox, MOST_ATTEMPTS, MOST_NOTICES_A_BATCH, OUTBOX_RETENTION_DAYS } from './outbox.ts';
import type { Notice } from '../domain/notice.ts';
import type { NotificationsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<NotificationsTables>;

const START = new Date('2026-09-26T09:00:00Z');
const MINUTE = 60_000;
const DAY = 86_400_000;
const ids = new SequentialIds(0xb5a0);
const ORG = '0199a0f0-0000-7000-8000-00000000b5a1';
const ADMIN = '0199a0f0-0000-7000-8000-00000000b5a2';
const OTHER_ADMIN = '0199a0f0-0000-7000-8000-00000000b5a3';
const MEMBERSHIP = '0199a0f0-0000-7000-8000-00000000b5a4';

/** A clock the tests set, forwards and back: the sweep's far future, then each test's own time. */
const clock = {
  at: START,
  now(): Date {
    return this.at;
  },
  set(to: Date): void {
    this.at = to;
  },
};
const outbox = createOutbox({ ids, clock });

const notice = (change: Partial<Notice> = {}): Notice => ({
  orgId: ORG,
  recipientUserId: ADMIN,
  kind: 'role_granted',
  membershipId: MEMBERSHIP,
  role: 'admin',
  ...change,
});

const rows = () => app.selectFrom('notifications.outbox').selectAll().orderBy('created_at').orderBy('id').execute();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<NotificationsTables>(
    { ...database.connection('app'), maxConnections: 3 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
  await sql`insert into directory.orgs (org_id) values (${ORG})`.execute(app);
  for (const [id, subject] of [
    [ADMIN, 'outbox-admin'],
    [OTHER_ADMIN, 'outbox-other-admin'],
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
  clock.set(new Date(START.getTime() + 10_000 * DAY));
  await sql`update notifications.outbox set given_up_at = ${START}, last_failure = 'test_reset'
    where sent_at is null and given_up_at is null`.execute(app);
  await outbox.sweep(app, 1_000_000);
  expect(await rows()).toEqual([]);
  clock.set(START);
});

describe(`the notifications outbox (B5-1a, Postgres ${server.version})`, () => {
  it('writes each notice due at once, with no tries, on the transaction it is given', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice(), notice({ recipientUserId: OTHER_ADMIN })]));

    expect(await rows()).toMatchObject([
      {
        org_id: ORG,
        recipient_user_id: ADMIN,
        kind: 'role_granted',
        membership_id: MEMBERSHIP,
        role: 'admin',
        created_at: START,
        attempts: 0,
        next_attempt_at: START,
        sent_at: null,
        given_up_at: null,
        last_failure: null,
      },
      { recipient_user_id: OTHER_ADMIN },
    ]);
  });

  it('takes a transaction, never the pool, so a notice is always written with its change (review)', () => {
    const writeOutsideAChange = () =>
      // @ts-expect-error: a pool is no transaction, so a notice can't be written apart from its change.
      outbox.add(app, [notice()]);
    expect(typeof writeOutsideAChange).toBe('function');
  });

  it('rolls a notice back with the change it tells of', async () => {
    const refusal = new Error('the change was refused');
    await expect(
      app.transaction().execute(async (tx) => {
        await outbox.add(tx, [notice()]);
        throw refusal;
      }),
    ).rejects.toBe(refusal);

    expect(await rows()).toEqual([]);
  });

  it.each([
    ['an organisation that is not a UUID', { orgId: 'acme' }],
    ['a recipient that is not a UUID', { recipientUserId: 'someone@example.test' }],
    ['a kind we do not send', { kind: 'free_text' as Notice['kind'] }],
    ['a membership that is not a UUID', { membershipId: '' }],
    ['a role not one of the four', { role: 'owner' as Notice['role'] }],
  ])('refuses the whole batch for %s, writing nothing', async (_what, change) => {
    await expect(app.transaction().execute((tx) => outbox.add(tx, [notice(), notice(change)]))).rejects.toThrow(
      RangeError,
    );
    expect(await rows()).toEqual([]);
  });

  it(`refuses more than ${String(MOST_NOTICES_A_BATCH)} notices at a time`, async () => {
    const many = Array.from({ length: MOST_NOTICES_A_BATCH + 1 }, () => notice());
    await expect(app.transaction().execute((tx) => outbox.add(tx, many))).rejects.toThrow(RangeError);
    expect(await rows()).toEqual([]);
  });

  it('takes the due notices soonest first, holds each for the lease, and takes none again until it runs out', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    clock.set(new Date(START.getTime() + MINUTE));
    await app.transaction().execute((tx) => outbox.add(tx, [notice({ recipientUserId: OTHER_ADMIN })]));

    const first = await outbox.claimDue(app, 1);
    expect(first).toMatchObject([{ recipientUserId: ADMIN, attempts: 0, createdAt: START }]);
    const second = await outbox.claimDue(app, 10);
    expect(second).toMatchObject([{ recipientUserId: OTHER_ADMIN }]);
    expect(await outbox.claimDue(app, 10)).toEqual([]);

    clock.set(new Date(START.getTime() + MINUTE + CLAIM_LEASE_MS));
    expect((await outbox.claimDue(app, 10)).map(({ id }) => id)).toEqual([first[0]?.id, second[0]?.id]);
  });

  it('never takes a notice not yet due', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    clock.set(new Date(START.getTime() - 1));
    expect(await outbox.claimDue(app, 10)).toEqual([]);
  });

  it('FX-RACE lets two senders at once take different notices, never the same one', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice(), notice({ recipientUserId: OTHER_ADMIN })]));

    const [one, two] = await Promise.all([outbox.claimDue(app, 1), outbox.claimDue(app, 1)]);

    expect(one).toHaveLength(1);
    expect(two).toHaveLength(1);
    expect(one[0]?.id).not.toBe(two[0]?.id);
  });

  it('marks a notice sent once, and takes it no more', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    const [claimed] = await outbox.claimDue(app, 1);
    if (claimed === undefined) throw new Error('nothing claimed');

    expect(await outbox.sent(app, claimed.id)).toBe(true);
    expect(await outbox.sent(app, claimed.id)).toBe(false);
    clock.set(new Date(START.getTime() + DAY));
    expect(await outbox.claimDue(app, 10)).toEqual([]);
    expect(await rows()).toMatchObject([{ sent_at: START }]);
  });

  it('tries a failed notice again further off each time, then gives it up after the last try', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    const waits: number[] = [];
    let outcome = '';
    for (let tries = 0; tries < MOST_ATTEMPTS; tries += 1) {
      const [claimed] = await outbox.claimDue(app, 1);
      if (claimed === undefined) throw new Error(`nothing due at try ${String(tries + 1)}`);
      expect(claimed.attempts).toBe(tries);
      outcome = await outbox.failed(app, claimed.id, 'provider_unavailable', false);
      const [row] = await rows();
      if (outcome === 'retry' && row !== undefined) {
        waits.push(row.next_attempt_at.getTime() - clock.now().getTime());
        clock.set(row.next_attempt_at);
      }
    }

    expect(outcome).toBe('given_up');
    expect(waits).toHaveLength(MOST_ATTEMPTS - 1);
    expect(waits.every((wait, at) => at === 0 || wait > (waits[at - 1] ?? 0))).toBe(true);
    expect(await rows()).toMatchObject([
      { attempts: MOST_ATTEMPTS, last_failure: 'provider_unavailable', sent_at: null },
    ]);
    expect((await rows())[0]?.given_up_at).not.toBeNull();
    clock.set(new Date(clock.now().getTime() + 10 * DAY));
    expect(await outbox.claimDue(app, 10)).toEqual([]);
  });

  it("counts a try whose sender died as a try, and gives the notice up once its last try's lease runs out (review)", async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    for (let tries = 0; tries < MOST_ATTEMPTS; tries += 1) {
      const [claimed] = await outbox.claimDue(app, 1);
      expect(claimed?.attempts, `try ${String(tries + 1)}`).toBe(tries);
      // The sender dies: no sent, no failed. The lease runs out.
      clock.set(new Date(clock.now().getTime() + CLAIM_LEASE_MS));
    }

    expect(await outbox.claimDue(app, 10)).toEqual([]);
    expect(await rows()).toMatchObject([
      { attempts: MOST_ATTEMPTS, last_failure: 'lease_expired', given_up_at: clock.now(), sent_at: null },
    ]);
  });

  it('still marks sent a last try only slow past its lease, given up meanwhile (confirmation review)', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    let last = '';
    for (let tries = 0; tries < MOST_ATTEMPTS; tries += 1) {
      const [claimed] = await outbox.claimDue(app, 1);
      last = claimed?.id ?? '';
      clock.set(new Date(clock.now().getTime() + CLAIM_LEASE_MS));
    }
    expect(await outbox.claimDue(app, 10)).toEqual([]);
    expect(await rows()).toMatchObject([{ last_failure: 'lease_expired' }]);

    // The slow sender's send lands after all.
    expect(await outbox.sent(app, last)).toBe(true);
    expect(await rows()).toMatchObject([{ sent_at: clock.now(), given_up_at: null }]);
    expect(await outbox.sent(app, last)).toBe(false);
  });

  it('gives a notice up after its last try, however its tries ended: failed, or its sender gone', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    for (let tries = 0; tries < MOST_ATTEMPTS; tries += 1) {
      const [claimed] = await outbox.claimDue(app, 1);
      if (claimed === undefined) throw new Error(`nothing due at try ${String(tries + 1)}`);
      if (tries % 2 === 0) {
        await outbox.failed(app, claimed.id, 'provider_unavailable', false);
        const [row] = await rows();
        if (row?.given_up_at === null) clock.set(row.next_attempt_at);
      } else {
        clock.set(new Date(clock.now().getTime() + CLAIM_LEASE_MS));
      }
    }

    expect(await outbox.claimDue(app, 10)).toEqual([]);
    const [row] = await rows();
    expect(row?.attempts).toBe(MOST_ATTEMPTS);
    expect(row?.given_up_at).not.toBeNull();
  });

  it('gives a notice up at once for a failure no retry can mend', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    const [claimed] = await outbox.claimDue(app, 1);
    if (claimed === undefined) throw new Error('nothing claimed');

    expect(await outbox.failed(app, claimed.id, 'no_address', true)).toBe('given_up');
    expect(await rows()).toMatchObject([{ attempts: 1, last_failure: 'no_address', given_up_at: START }]);
  });

  it('leaves a notice already sent or given up as it is', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    const [claimed] = await outbox.claimDue(app, 1);
    if (claimed === undefined) throw new Error('nothing claimed');
    await outbox.sent(app, claimed.id);

    expect(await outbox.failed(app, claimed.id, 'provider_unavailable', false)).toBe('done');
    expect(await rows()).toMatchObject([{ attempts: 1, last_failure: null, sent_at: START, given_up_at: null }]);
  });

  it('refuses a failure that is not a short lowercase name, so no provider text is kept', async () => {
    await expect(outbox.failed(app, MEMBERSHIP, 'Mailbox full: someone@example.test', false)).rejects.toThrow(
      RangeError,
    );
  });

  it('writes a notice to the admins with no recipient, and turns it into one to each admin found, once', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice({ recipientUserId: null })]));
    const [claimed] = await outbox.claimDue(app, 1);
    if (claimed === undefined) throw new Error('nothing claimed');
    expect(claimed.recipientUserId).toBeNull();

    clock.set(new Date(START.getTime() + MINUTE));
    expect(await outbox.fanOut(app, claimed.id, [ADMIN, OTHER_ADMIN.toUpperCase(), ADMIN])).toBe(2);
    expect(await outbox.fanOut(app, claimed.id, [ADMIN])).toBe(0);

    expect(await rows()).toMatchObject([
      { recipient_user_id: null, sent_at: new Date(START.getTime() + MINUTE), attempts: 1 },
      ...[ADMIN, OTHER_ADMIN].map((recipient) => ({
        org_id: ORG,
        recipient_user_id: recipient,
        kind: 'role_granted',
        membership_id: MEMBERSHIP,
        role: 'admin',
        attempts: 0,
        next_attempt_at: new Date(START.getTime() + MINUTE),
        sent_at: null,
      })),
    ]);
    expect((await outbox.claimDue(app, 10)).map(({ recipientUserId }) => recipientUserId).sort()).toEqual([
      ADMIN,
      OTHER_ADMIN,
    ]);
  });

  it('marks a notice to the admins sent when no admin is found, writing none', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice({ recipientUserId: null })]));
    const [claimed] = await outbox.claimDue(app, 1);
    if (claimed === undefined) throw new Error('nothing claimed');

    expect(await outbox.fanOut(app, claimed.id, [])).toBe(0);
    expect(await rows()).toMatchObject([{ recipient_user_id: null, sent_at: START }]);
  });

  it('turns only a notice to the admins, never one to a person, and refuses a recipient not a UUID', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice(), notice({ recipientUserId: null })]));
    const [toPerson, toAdmins] = await rows();
    if (toPerson === undefined || toAdmins === undefined) throw new Error('not written');

    expect(await outbox.fanOut(app, toPerson.id, [OTHER_ADMIN])).toBe(0);
    await expect(outbox.fanOut(app, toAdmins.id, ['someone@example.test'])).rejects.toThrow(RangeError);
    expect(await rows()).toHaveLength(2);
  });

  it('sweeps a notice given up once past the retention too', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice()]));
    const [claimed] = await outbox.claimDue(app, 1);
    if (claimed === undefined) throw new Error('nothing claimed');
    await outbox.failed(app, claimed.id, 'no_address', true);

    clock.set(new Date(START.getTime() + OUTBOX_RETENTION_DAYS * DAY));
    expect(await outbox.sweep(app, 10)).toBe(1);
    expect(await rows()).toEqual([]);
  });

  it('sweeps notices done and past the retention, oldest first, and never one still to send', async () => {
    await app.transaction().execute((tx) => outbox.add(tx, [notice(), notice({ recipientUserId: OTHER_ADMIN })]));
    const [claimed] = await outbox.claimDue(app, 1);
    if (claimed === undefined) throw new Error('nothing claimed');
    await outbox.sent(app, claimed.id);

    clock.set(new Date(START.getTime() + OUTBOX_RETENTION_DAYS * DAY - 1));
    expect(await outbox.sweep(app, 10)).toBe(0);
    clock.set(new Date(START.getTime() + OUTBOX_RETENTION_DAYS * DAY));
    expect(await outbox.sweep(app, 10)).toBe(1);
    expect(await rows()).toMatchObject([{ recipient_user_id: OTHER_ADMIN, sent_at: null }]);
  });
});

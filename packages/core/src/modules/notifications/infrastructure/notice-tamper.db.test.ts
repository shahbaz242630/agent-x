// S206 V4 (Threat-Model R-15; 0105): a warning email queued in the outbox, as
// the database's owner (agentx_owner, holding none of the app's keys) can
// change it, on the real migrated schema. A notice deleted before it went,
// marked sent or given up, moved to another person, planted, held back or its
// tries spent raises the integrity alarm from the notice check (or the
// sender), and a moved one is never sent to the new address; a notice sent on
// time, fanned out to the admins, or given up by the app raises nothing.
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { DAY_MS, HOUR_MS } from '../../../shared-kernel/index.ts';
import type { NoticeMessage } from '../domain/messages.ts';
import type { Notice, NoticeRole } from '../domain/notice.ts';
import { createNoticeCheck } from './notice-check.ts';
import { SEALED_FROM } from './notice-seals.ts';
import { createOutbox, MOST_ATTEMPTS, type OutboxTables } from './outbox.ts';
import { createNoticeSender, type Notifier } from './sender.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<OutboxTables>;

/** The chain's records carry Postgres's own time, so the tests' clock starts at the server's: read before they run. */
let START = new Date(0);
const ids = new SequentialIds(0x5206_0004_0000);
/** The person a warning is for, and the one the owner would rather it went to: both admins. */
const VICTIM = '0199a0f0-0000-7000-8000-0000005206a2';
const OTHER = '0199a0f0-0000-7000-8000-0000005206a3';
const MEMBERSHIP = '0199a0f0-0000-7000-8000-0000005206a4';
const ADDRESSES = new Map([
  [VICTIM, 'victim@example.test'],
  [OTHER, 'other@example.test'],
]);
const ROLES = new Map<string, NoticeRole>([
  [VICTIM, 'admin'],
  [OTHER, 'admin'],
]);

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);

/** A clock the tests set. */
const clock = {
  at: START,
  now(): Date {
    return this.at;
  },
  set(to: Date): void {
    this.at = to;
  },
};
const outbox = createOutbox({ ids, clock, keys });

let capture: LogCapture;

/** Each test's own organisation, so the check reads that test's records alone. */
let org: string;

/** A warning to the victim that a second factor was added to their sign-in. */
const warning = (): Notice => ({
  orgId: org,
  recipientUserId: VICTIM,
  kind: 'second_factor_added',
  membershipId: null,
  role: null,
  aboutId: VICTIM,
});

/** A notice to the organisation's admins that a member was removed, fanned out as it is sent. */
const toAdmins = (): Notice => ({
  orgId: org,
  recipientUserId: null,
  kind: 'member_removed',
  membershipId: MEMBERSHIP,
  role: 'approver',
});

/** Queues the notice as a change does, and says its ID. */
async function queued(notice: Notice = warning()): Promise<string> {
  await withTenant(app, org, (tx) => outbox.add(tx, [notice]));
  const row = await app
    .selectFrom('notifications.outbox')
    .select('id')
    .orderBy('created_at', 'desc')
    .orderBy('id', 'desc')
    .executeTakeFirstOrThrow();
  return row.id;
}

/**
 * Runs one statement as agentx_owner, on a connection of its own; behind an organisation's row wall when `tenant` is
 * named, as the owner can set it for itself.
 */
async function asOwner(text: string, values: readonly unknown[], tenant?: string): Promise<void> {
  const owner = await database.connect('owner');
  try {
    await owner.query('begin');
    if (tenant !== undefined) await owner.query("select pg_catalog.set_config('app.org_id', $1, true)", [tenant]);
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text; every value is bound.
    await owner.query(text, values);
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

/** Runs the sender once, and says to whom it sent. */
async function send(): Promise<string[]> {
  const sent: NoticeMessage[] = [];
  const notifier: Notifier = {
    send: (message) => {
      sent.push(message);
      return Promise.resolve({ outcome: 'sent' });
    },
  };
  const refused = () => Promise.reject(new Error('not asked here'));
  await createNoticeSender({
    db: app,
    outbox,
    notifier,
    addresses: { addressOf: (userId) => Promise.resolve(ADDRESSES.get(userId)) },
    contactAddresses: { addressOf: refused },
    resetLinks: { linkFor: refused },
    waitingRequests: { waitingOf: refused },
    remittances: { remittanceOf: refused, emailed: refused, givenUp: refused },
    people: { personOf: refused },
    audience: {
      adminsOf: () => Promise.resolve([{ userId: VICTIM, membershipId: MEMBERSHIP.replace('a4', 'a5') }]),
      adminsAndApproversOf: refused,
      membersOf: refused,
      contactsOf: refused,
      countingContactsOf: refused,
      rolesOf: () => Promise.resolve(ROLES),
    },
    logger: testLogger(capture),
  }).run();
  return sent.map(({ to }) => to);
}

/** The notice check, over `list`, a page and the most pages as the test asks. */
const check = (
  list: () => Promise<readonly string[]> = () => Promise.resolve([org]),
  pages = {},
  done?: (orgId: string) => void,
) =>
  createNoticeCheck({
    list,
    ...(done === undefined ? {} : { done }),
    database: app,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
    lookbackMs: 2 * HOUR_MS,
    ...pages,
  });

/** Runs the notice check at `at`, and says what it found: each alarm's notice and why. */
async function checkAt(at: Date, pages = {}): Promise<{ noticeId: unknown; reason: unknown }[]> {
  clock.set(at);
  const before = alarms().length;
  await check(undefined, pages).run();
  return alarms()
    .slice(before)
    .map(({ noticeId, reason }) => ({ noticeId, reason }));
}

/** The integrity alarms about notices raised since the test began. */
const alarms = () =>
  capture.lines().filter((line) => line.event === 'audit.integrity_failed' && line.check === 'notice');

const rowOf = (id: string) =>
  app
    .selectFrom('notifications.outbox')
    .select(['sent_at', 'given_up_at', 'last_failure'])
    .where('id', '=', id)
    .executeTakeFirst();

const later = (ms: number) => new Date(START.getTime() + ms);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<OutboxTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
  const { rows } = await sql<{ now: Date }>`select date_trunc('second', pg_catalog.now()) as now`.execute(app);
  START = rows[0]?.now ?? START;
  for (const [id, subject] of [
    [VICTIM, 'notice-victim'],
    [OTHER, 'notice-other'],
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
  capture = new LogCapture();
  org = ids.next();
  await sql`insert into directory.orgs (org_id) values (${org})`.execute(app);
  await sql`delete from notifications.outbox`.execute(app);
  clock.set(START);
});

describe(`a queued warning, as the database's owner can change it (S206 V4, Postgres ${server.version})`, () => {
  it('raises nothing for a notice sent on time, now or a day on, and records it on the chain', async () => {
    const id = await queued();
    expect(await send()).toEqual(['victim@example.test']);

    expect(await checkAt(later(HOUR_MS))).toEqual([]);
    expect(await checkAt(later(DAY_MS + HOUR_MS))).toEqual([]);
    const records = await withTenant(app, org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['action', 'subject_type', 'details'])
        .where('subject_id', '=', id)
        .execute(),
    );
    expect(records.map(({ action, subject_type }) => [action, subject_type])).toEqual([['notice.queued', 'notice']]);
    expect(records[0]?.details).toContain(`"recipientId":"${VICTIM}"`);
  });

  it('raises nothing for a notice fanned out to the admins, nor one the app gave up', async () => {
    await queued(toAdmins());
    expect(await send()).toEqual(['victim@example.test']);
    const unaddressed = await queued({ ...warning(), recipientUserId: OTHER, aboutId: OTHER });
    ADDRESSES.delete(OTHER);
    try {
      expect(await send()).toEqual([]);
    } finally {
      ADDRESSES.set(OTHER, 'other@example.test');
    }
    expect(await rowOf(unaddressed)).toMatchObject({ last_failure: 'no_address' });

    expect(await checkAt(later(DAY_MS + HOUR_MS))).toEqual([]);
  });

  it('alarms for a notice deleted before it went', async () => {
    const id = await queued();
    await asOwner('delete from notifications.outbox where id = $1', [id]);

    expect(await send()).toEqual([]);
    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: id, reason: 'gone' }]);
  });

  it.each([
    ['marked sent', 'update notifications.outbox set sent_at = $2 where id = $1'],
    ['given up', "update notifications.outbox set given_up_at = $2, last_failure = 'no_address' where id = $1"],
  ])('alarms for a notice the owner %s, and sends it never', async (_done, statement) => {
    const id = await queued();
    await asOwner(statement, [id, START]);

    expect(await send()).toEqual([]);
    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: id, reason: 'end_seal' }]);
  });

  it('never sends a notice moved to another person: gives it up and alarms, and so does the check', async () => {
    const id = await queued();
    await asOwner('update notifications.outbox set recipient_user_id = $2 where id = $1', [id, OTHER]);

    expect(await send()).toEqual([]);
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'seal', noticeId: id, orgId: org })]);
    expect(await rowOf(id)).toMatchObject({ sent_at: null, last_failure: 'seal_failed' });
    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: id, reason: 'seal' }]);
  });

  it('alarms for a notice whose seal was taken out, as though it were from before seals', async () => {
    const id = await queued();
    await asOwner('update notifications.outbox set mac = null, mac_key_version = null where id = $1', [id]);

    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: id, reason: 'seal' }]);
  });

  it('never sends a notice planted with no seal once seals are kept, and sends one from before them with a warning', async () => {
    const plant = (id: string, at: Date) =>
      asOwner(
        `insert into notifications.outbox (id, org_id, recipient_user_id, kind, about_id, created_at, attempts,
          next_attempt_at) values ($1, $2, $3, 'second_factor_added', $3, $4, 0, $4)`,
        [id, org, OTHER, at],
      );
    const old = ids.next();
    // Queued before the cut-over and due now.
    await plant(old, new Date(Math.min(SEALED_FROM.getTime(), START.getTime()) - DAY_MS));
    expect(await send()).toEqual(['other@example.test']);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'notification.unsealed', noticeId: old }));

    // Later than both the cut-over and the real time, so the planted notice is due.
    clock.set(new Date(Math.max(SEALED_FROM.getTime(), START.getTime()) + HOUR_MS));
    const planted = ids.next();
    await plant(planted, SEALED_FROM);
    expect(await send()).toEqual([]);
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'seal', noticeId: planted })]);
  });

  it('alarms for a notice held back past its deadline, and not before', async () => {
    const id = await queued();
    await asOwner('update notifications.outbox set next_attempt_at = $2 where id = $1', [id, later(30 * DAY_MS)]);

    expect(await send()).toEqual([]);
    expect(await checkAt(later(HOUR_MS))).toEqual([]);
    expect(await checkAt(later(DAY_MS + HOUR_MS))).toEqual([{ noticeId: id, reason: 'unsent' }]);
  });

  it('alarms for a notice whose tries the owner spent, given up unsent', async () => {
    const id = await queued();
    await asOwner('update notifications.outbox set attempts = $2 where id = $1', [id, MOST_ATTEMPTS]);

    expect(await send()).toEqual([]);
    expect(await rowOf(id)).toMatchObject({ sent_at: null, last_failure: 'lease_expired' });
    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: id, reason: 'tries_spent' }]);
  });

  it('writes nothing from a group notice changed after it was claimed: no fan-out, no notice passed on', async () => {
    const id = await queued(toAdmins());
    const [claimed] = await outbox.claimDue(app, 1);
    expect(claimed).toMatchObject({ id, seal: 'sound' });
    await asOwner('update notifications.outbox set role = $2 where id = $1', [id, 'admin']);

    expect(await outbox.fanOut(app, org, id, [VICTIM])).toBe('not_open');
    expect(await outbox.passOn(app, org, id, 'payment_remittance_no_email', 'no_address')).toBe(false);
    await asOwner('update notifications.outbox set role = $2 where id = $1', [id, 'approver']);
    // Its own seal holds again, but asked as another organisation's it is none of that one's.
    expect(await outbox.fanOut(app, ids.next(), id, [VICTIM])).toBe('not_open');
    expect(await rowOf(id)).toEqual({ sent_at: null, given_up_at: null, last_failure: null });
    const written = await app.selectFrom('notifications.outbox').select('id').where('id', '!=', id).execute();
    expect(written).toEqual([]);
  });

  it('reads the records a page at a time, and says when one visit cuts them short', async () => {
    const first = await queued();
    await queued();
    const last = await queued();
    await asOwner('delete from notifications.outbox where id = any($1)', [[first, last]]);

    expect(await checkAt(later(HOUR_MS), { page: 2 })).toEqual([
      { noticeId: last, reason: 'gone' },
      { noticeId: first, reason: 'gone' },
    ]);
    expect(await checkAt(later(HOUR_MS), { page: 1, mostPages: 2 })).toEqual([{ noticeId: last, reason: 'gone' }]);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'notification.check_cut_short', pages: 2, orgId: org }),
    );
  });

  it('raises the chain’s own alarm for a record the owner edited, and none of its own from it', async () => {
    const id = await queued();
    await asOwner(`update audit.events set details = '{"kind":"role_granted"}' where subject_id = $1`, [id], org);
    await asOwner('delete from notifications.outbox where id = $1', [id]);

    expect(await checkAt(later(HOUR_MS))).toEqual([]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'audit.integrity_failed', orgId: org }));
  });

  it('goes on past an organisation it fails to check, says which, and never throws', async () => {
    const id = await queued();
    await asOwner('delete from notifications.outbox where id = $1', [id]);
    const finished: string[] = [];

    clock.set(later(HOUR_MS));
    await check(
      () => Promise.resolve(['not-an-organisation', org]),
      {},
      (done) => finished.push(done),
    ).run();
    expect(finished).toEqual([org]);
    expect(alarms()).toEqual([expect.objectContaining({ noticeId: id, reason: 'gone' })]);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'notification.check_failed', level: 'error', orgId: 'not-an-organisation' }),
    );

    await check(() => Promise.reject(new Error('the directory is away'))).run();
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'notification.check_run_failed' }));
    const stopped = new AbortController();
    stopped.abort();
    await check(undefined, {}, (done) => finished.push(done)).run(stopped.signal);
    expect(finished).toEqual([org]);
  });
});

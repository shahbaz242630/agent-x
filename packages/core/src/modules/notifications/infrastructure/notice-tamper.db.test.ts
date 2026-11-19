// S206 V4 (Threat-Model R-15; 0105): a warning email queued in the outbox, as
// the database's owner (agentx_owner, holding none of the app's keys) can
// change it, on the real migrated schema. A notice deleted before it went,
// marked sent or given up, moved to another person, planted, held back or its
// tries spent raises the integrity alarm from the notice check (or the
// sender), and a moved one is never sent to the new address; a notice sent on
// time, fanned out to the admins, or given up by the app raises nothing.
import {
  createTestDatabase,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { createDatabase, type Database, noStatementTimes, timingStatements, withTenant } from '@agentx/platform/db';
import { CHAIN_START } from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { DAY_MS, HOUR_MS } from '../../../shared-kernel/index.ts';
import type { NoticeMessage } from '../domain/messages.ts';
import type { Notice, NoticeRole } from '../domain/notice.ts';
import { createAuditTrail } from '../../audit/index.ts';
import { createNoticeCheck, NOTICE_CHECK_PASSED } from './notice-check.ts';
import { queuedSeal } from './notice-seals.ts';
import { createOutbox, MOST_ATTEMPTS, type OutboxTables, sealNoticesFromBefore } from './outbox.ts';
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
    ...pages,
  });

/** Runs the notice check at `at`, and says what it found: each alarm's notice and why. */
async function checkAt(at: Date, pages = {}): Promise<{ noticeId: unknown; reason: unknown }[]> {
  clock.set(at);
  const before = alarms().length;
  await check(undefined, pages).run();
  // A visit that failed says nothing of its notices: never taken for a clean one.
  expect(capture.lines().filter(({ event }) => event === 'notification.check_failed')).toEqual([]);
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
    ['marked sent', 'update notifications.outbox set sent_at = $2, before_seals = true where id = $1'],
    [
      'given up',
      "update notifications.outbox set given_up_at = $2, last_failure = 'no_address', before_seals = true where id = $1",
    ],
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
    await asOwner(
      'update notifications.outbox set mac = null, mac_key_version = null, before_seals = true where id = $1',
      [id],
    );
    // Never claimed, so never sent: no seal to judge.
    expect(await send()).toEqual([]);

    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: id, reason: 'seal' }]);
  });

  it('never sends, nor even claims, a notice planted with no seal, however long ago it says it was queued', async () => {
    const planted = ids.next();
    await asOwner(
      `insert into notifications.outbox (id, org_id, recipient_user_id, kind, about_id, created_at, attempts,
        next_attempt_at, before_seals) values ($1, $2, $3, 'second_factor_added', $3, $4, 0, $4, true)`,
      [planted, org, OTHER, new Date('2020-01-01T00:00:00Z')],
    );

    expect(await send()).toEqual([]);
    expect(await rowOf(planted)).toEqual({ sent_at: null, given_up_at: null, last_failure: null });
    // No record to walk, never claimed: the check still says so, once it is a day old.
    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: planted, reason: 'unsealed' }]);
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

  it('goes on from where it stopped, its walks a few at a time, and judges each notice once', async () => {
    const queuedIds: string[] = [];
    for (let n = 0; n < 6; n += 1) queuedIds.push(await queued());
    const [first, , , , , last] = queuedIds;
    await asOwner('delete from notifications.outbox where id = any($1)', [[first, last]]);

    // Four walks of one event: the first four records.
    expect(await checkAt(later(HOUR_MS), { walk: 1 })).toEqual([{ noticeId: first, reason: 'gone' }]);
    // On from there: the last two, and the record of where it stopped.
    expect(await checkAt(later(HOUR_MS), { walk: 1 })).toEqual([{ noticeId: last, reason: 'gone' }]);
    expect(await checkAt(later(HOUR_MS))).toEqual([]);
    const stops = await withTenant(app, org, (tx) =>
      tx.selectFrom('audit.events').select('details').where('action', '=', NOTICE_CHECK_PASSED).execute(),
    );
    // Four notices still to be sent, carried in each record of where it stopped; none new since, none recorded.
    expect(stops).toHaveLength(2);
  });

  it('raises the alarm at a record the owner edited, at the walk that reaches it', async () => {
    const id = await queued();
    const after = await queued();
    await asOwner(`update audit.events set details = '{"kind":"role_granted"}' where subject_id = $1`, [id], org);

    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: undefined, reason: 'chain' }]);
    // The walk gives none of the records it read on a stretch that doesn't hold, not even the sound one after.
    const walk = await createAuditTrail({ keys, ids }).walkFrom(app, org, CHAIN_START, 10, ['notice.queued']);
    expect(walk).toMatchObject({ step: { ok: false }, kept: [] });
    expect(after).not.toBe(id);
  });

  it('finds a record deleted around its walk and put back after: the gap then, the notice gone at the next', async () => {
    await queued();
    await send();
    // A visit before, so the next goes on from its record of where it stopped.
    expect(await checkAt(later(HOUR_MS))).toEqual([]);
    const id = await queued();
    await queued();
    await asOwner('delete from notifications.outbox where id = $1', [id]);
    const owner = await database.connect('owner');
    try {
      await owner.query('begin');
      await owner.query("select pg_catalog.set_config('app.org_id', $1, true)", [org]);
      const [kept] = await owner.query<{ row: unknown }>(
        'select pg_catalog.row_to_json(e) as row from audit.events e where e.subject_id = $1',
        [id],
      );
      await owner.query('delete from audit.events where subject_id = $1', [id]);
      await owner.query('commit');

      expect(await checkAt(later(2 * HOUR_MS))).toEqual([{ noticeId: undefined, reason: 'chain' }]);

      await owner.query('begin');
      await owner.query("select pg_catalog.set_config('app.org_id', $1, true)", [org]);
      await owner.query(
        'insert into audit.events select * from pg_catalog.json_populate_record(null::audit.events, $1)',
        [kept?.row],
      );
      await owner.query('commit');
    } finally {
      await owner.end();
    }
    expect(await checkAt(later(3 * HOUR_MS))).toEqual([{ noticeId: id, reason: 'gone' }]);
  });

  it('queues a notice after its change’s event in one trip, taking no lock of its own', async () => {
    const trail = createAuditTrail({ keys, ids });
    // A row of the change's own, which it locks first.
    const own = await queued();
    const holder = await database.connect('admin');
    try {
      // Someone holds the organisation's chain head: the change's own event waits for it, its row already locked.
      await withTenant(app, org, (tx) =>
        trail.record(tx, org, {
          actor: { type: 'system', id: 'api' },
          action: 'probe.started',
          subject: { type: 'probe', id: org, version: 1 },
          details: {},
        }),
      );
      await holder.query('begin');
      await holder.query('select 1 from audit.heads where org_id = $1 for no key update', [org]);
      const times = noStatementTimes();
      const change = within(
        20_000,
        timingStatements(times, () =>
          withTenant(app, org, async (tx) => {
            await tx.selectFrom('notifications.outbox').select('id').where('id', '=', own).forNoKeyUpdate().execute();
            await trail.record(tx, org, {
              actor: { type: 'system', id: 'api' },
              action: 'probe.changed',
              subject: { type: 'probe', id: org, version: 2 },
              details: {},
            });
            const before = times.trips;
            await outbox.add(tx, [warning()]);
            return times.trips - before;
          }),
        ),
        'the change',
      );
      await waitUntilQueued(database.as('admin'), 1);
      // Waiting on the head alone, its own row held first: the head comes last.
      await expect(
        database.as('admin').query('select 1 from notifications.outbox where id = $1 for update nowait', [own]),
      ).rejects.toMatchObject({ code: '55P03' });
      await holder.query('commit');
      expect(await change).toBe(1);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
    const actions = await withTenant(app, org, (tx) =>
      tx.selectFrom('audit.events').select('action').orderBy('seq').execute(),
    );
    expect(actions.map(({ action }) => action)).toEqual([
      'notice.queued',
      'probe.started',
      'probe.changed',
      'notice.queued',
    ]);
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

  it('carries at most 19 notices still to be sent, stopping before the first it can’t, and alarms for all once late', async () => {
    const held: string[] = [];
    for (let n = 0; n < 27; n += 1) held.push(await queued());
    await asOwner('update notifications.outbox set next_attempt_at = $1', [later(30 * DAY_MS)]);

    expect(await checkAt(later(HOUR_MS))).toEqual([]);
    const late = await checkAt(later(DAY_MS + HOUR_MS));
    expect(late.map(({ noticeId }) => noticeId).toSorted()).toEqual(held.toSorted());
    expect(new Set(late.map(({ reason }) => reason))).toEqual(new Set(['unsent']));
  });

  it('raises the alarm for a record of where it stopped that the owner edited, and goes no further', async () => {
    await queued();
    expect(await checkAt(later(HOUR_MS))).toEqual([]);
    await asOwner(
      `update audit.events set details = '{"carried":"","hash":"00","keyVersion":1,"seq":"1"}' where action = $1`,
      [NOTICE_CHECK_PASSED],
      org,
    );

    expect(await checkAt(later(2 * HOUR_MS))).toEqual([{ noticeId: undefined, reason: 'record' }]);
  });

  it('goes on from the head a change before it really left, once a savepoint took that one back', async () => {
    const trail = createAuditTrail({ keys, ids });
    const event = (action: string) => ({
      actor: { type: 'system', id: 'api' } as const,
      action,
      subject: { type: 'probe', id: org, version: 1 },
      details: {},
    });
    await withTenant(app, org, async (tx) => {
      await trail.record(tx, org, event('probe.kept'));
      await sql`savepoint probe`.execute(tx);
      await trail.record(tx, org, event('probe.taken_back'));
      await sql`rollback to savepoint probe`.execute(tx);
      await outbox.add(tx, [warning()]);
    });

    const actions = await withTenant(app, org, (tx) =>
      tx.selectFrom('audit.events').select('action').orderBy('seq').execute(),
    );
    expect(actions.map(({ action }) => action)).toEqual(['probe.kept', 'notice.queued']);
    expect(await checkAt(later(HOUR_MS))).toEqual([]);
  });

  it('alarms a day on for a notice the owner holds locked, so no sender can take it', async () => {
    const id = await queued();
    const owner = await database.connect('owner');
    try {
      await owner.query('begin');
      await owner.query('select 1 from notifications.outbox where id = $1 for update', [id]);
      expect(await send()).toEqual([]);
      expect(await checkAt(later(HOUR_MS))).toEqual([]);
      expect(await checkAt(later(DAY_MS + HOUR_MS))).toEqual([{ noticeId: id, reason: 'unsent' }]);
    } finally {
      await owner.query('rollback');
      await owner.end();
    }
  });

  it('alarms for a notice not as its record says, though a seal over it holds (sealed after a change)', async () => {
    const id = await queued();
    const row = await app.selectFrom('notifications.outbox').selectAll().where('id', '=', id).executeTakeFirstOrThrow();
    // A seal the app would make over the row moved to another person: as a start's sealing of a stripped row would.
    const moved = { ...row, recipient_user_id: OTHER };
    const { mac, keyVersion } = queuedSeal(keys, moved);
    await asOwner(
      'update notifications.outbox set recipient_user_id = $2, mac = $3, mac_key_version = $4 where id = $1',
      [id, OTHER, mac, keyVersion],
    );

    expect(await checkAt(later(HOUR_MS))).toEqual([{ noticeId: id, reason: 'not_as_recorded' }]);
  });

  it('seals at a start only a notice with no seal and no record: one stripped of its seal stays refused', async () => {
    const recorded = await queued();
    const legacy = ids.next();
    await asOwner(
      `insert into notifications.outbox (id, org_id, recipient_user_id, kind, about_id, created_at, attempts,
        next_attempt_at, before_seals) values ($1, $2, $3, 'second_factor_added', $3, $4, 0, $4, true)`,
      [legacy, org, VICTIM, START],
    );
    await asOwner(
      'update notifications.outbox set mac = null, mac_key_version = null, before_seals = true where id = $1',
      [recorded],
    );

    // Records that can't be read say nothing of which notices have none: none is sealed.
    const admin = database.as('admin');
    await admin.query('revoke select on audit.events from agentx_app');
    try {
      expect(await app.transaction().execute((tx) => sealNoticesFromBefore(tx, app, keys))).toEqual({
        sealed: 0,
        complete: false,
      });
    } finally {
      await admin.query('grant select on audit.events to agentx_app');
    }
    expect(await app.transaction().execute((tx) => sealNoticesFromBefore(tx, app, keys))).toEqual({
      sealed: 1,
      complete: true,
    });
    const sealed = await app.selectFrom('notifications.outbox').select(['id', 'mac']).orderBy('id').execute();
    expect(sealed.map(({ id, mac }) => [id, mac !== null])).toEqual(
      [
        [recorded, false],
        [legacy, true],
      ].toSorted(([a], [b]) => String(a).localeCompare(String(b))),
    );
  });

  it('refuses the release before’s notice with no seal, and its mark sent with no end seal, each whole', async () => {
    const id = await queued();
    await expect(
      app
        .insertInto('notifications.outbox')
        .values({
          id: ids.next(),
          org_id: org,
          recipient_user_id: VICTIM,
          kind: 'second_factor_added',
          membership_id: null,
          role: null,
          about_id: VICTIM,
          created_at: START,
          attempts: 0,
          next_attempt_at: START,
        })
        .execute(),
    ).rejects.toMatchObject({ code: '23514', constraint: 'a_notice_is_sealed' });
    // The release before's sender: its mark sent fails, and the notice stays due for this release's.
    await expect(
      app.updateTable('notifications.outbox').set({ sent_at: START }).where('id', '=', id).execute(),
    ).rejects.toMatchObject({ code: '23514', constraint: 'an_end_is_sealed' });
    expect(await rowOf(id)).toEqual({ sent_at: null, given_up_at: null, last_failure: null });
    expect(await send()).toEqual(['victim@example.test']);
  });

  it('writes no record of where it stopped on a visit held where the last one stopped, carrying the same', async () => {
    for (let n = 0; n < 27; n += 1) await queued();
    await asOwner('update notifications.outbox set next_attempt_at = $1', [later(30 * DAY_MS)]);
    const stops = async () =>
      (
        await withTenant(app, org, (tx) =>
          tx.selectFrom('audit.events').select('seq').where('action', '=', NOTICE_CHECK_PASSED).execute(),
        )
      ).length;

    expect(await checkAt(later(HOUR_MS))).toEqual([]);
    expect(await stops()).toBe(1);
    expect(await checkAt(later(2 * HOUR_MS))).toEqual([]);
    expect(await stops()).toBe(1);
  });
});

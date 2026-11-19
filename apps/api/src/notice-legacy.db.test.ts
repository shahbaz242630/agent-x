// S206 V4: the notices queued before seals, sealed once in the background
// after the API starts, recorded on the platform chain (`notice.legacy_sealed`):
// only before the cutoff, while no notice of this release exists, on a platform
// chain that checks out whole and holds no such record; a pass that couldn't
// read an organisation's records records nothing, so the next one seals the
// rest. Any notice with no seal after that stays without one (never claimed).
import type { AuditTables } from '@agentx/core/modules/audit';
import { createNoticeCheck, type NotificationsTables } from '@agentx/core/modules/notifications';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { LEGACY_SEALED, NOTICE_SEAL_BACKFILL_UNTIL, sealLegacyNotices } from './notice-legacy.ts';
import { recordStart } from './start-record.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<NotificationsTables & PlatformControlsTables & AuditTables>;
let capture: LogCapture;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x5206_0004_1000);
const ORG = '0199a0f0-0000-7000-8000-0000005206c1';
const PERSON = '0199a0f0-0000-7000-8000-0000005206c2';
const AT = new Date('2026-11-19T09:00:00Z');

/** Writes a notice with no seal, as the release before did before 0104 (a row it found then); `done` for one sent. */
async function unsealed(done = false): Promise<string> {
  const id = ids.next();
  await database.as('admin').query(
    `insert into notifications.outbox (id, org_id, recipient_user_id, kind, about_id, created_at, attempts,
      next_attempt_at, sent_at, before_seals) values ($1, $2, $3, 'second_factor_added', $3, $4, 0, $4, $5, true)`,
    [id, ORG, PERSON, AT, done ? AT : null],
  );
  return id;
}

const sealedOf = async (id: string) =>
  (await app.selectFrom('notifications.outbox').select('mac').where('id', '=', id).executeTakeFirstOrThrow()).mac !==
  null;

/** How many notices each record of the pass on the platform chain says it sealed. */
const passes = async () =>
  (
    await app
      .selectFrom('platform_controls.audit_events')
      .select('details')
      .where('action', '=', LEGACY_SEALED)
      .orderBy('seq')
      .execute()
  ).map(({ details }) => (JSON.parse(details) as { notices: number }).notices);

/** A start recorded, as boot records it, then the pass, as main.ts runs it after; at `now`, before the cutoff. */
const startedThenSealed = async (now = AT) => {
  await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });
  await sealLegacyNotices({ database: app, keys, logger: testLogger(capture) }, { now });
};

const startAlarm = () =>
  capture.lines().filter((line) => line.event === 'audit.integrity_failed' && line.check === 'start_record');

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase({ ...database.connection('app'), maxConnections: 4 }, testLogger());
  await database.as('admin').query('insert into directory.orgs (org_id) values ($1)', [ORG]);
  await database
    .as('admin')
    .query(
      "insert into identity.users (id, issuer, subject, created_at) values ($1, 'https://auth.example.test', 'legacy', $2)",
      [PERSON, AT],
    );
});

beforeEach(async () => {
  capture = new LogCapture();
  await database
    .as('admin')
    .query('truncate platform_controls.audit_events, platform_controls.audit_head, notifications.outbox');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the notices from before seals, sealed once (S206 V4, Postgres ${server.version})`, () => {
  it('seals those still to be sent, records how many, and never again', async () => {
    const waiting = [await unsealed(), await unsealed()];
    const sent = await unsealed(true);

    await startedThenSealed();
    expect(await Promise.all(waiting.map(sealedOf))).toEqual([true, true]);
    expect(await sealedOf(sent)).toBe(false);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'notification.legacy_sealed', notices: 2 }),
    );

    // One written with no seal since: the owner's, never sealed by a pass after.
    const planted = await unsealed();
    await startedThenSealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(await passes()).toEqual([2]);
  });

  it('seals nothing, with the alarm, once its record has been edited or deleted, and a row planted', async () => {
    await unsealed();
    await startedThenSealed();
    await startedThenSealed();
    await database
      .as('admin')
      .query(`update platform_controls.audit_events set details = '{"notices":0}' where action = $1`, [LEGACY_SEALED]);
    const planted = await unsealed();
    await startedThenSealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(1);

    await database.as('admin').query('delete from platform_controls.audit_events where action = $1', [LEGACY_SEALED]);
    await startedThenSealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(2);
  });

  it('leaves it for the next pass when an organisation’s records can’t be read, which then seals them', async () => {
    const waiting = await unsealed();
    const admin = database.as('admin');
    await admin.query('revoke select on audit.events from agentx_app');
    try {
      await startedThenSealed();
    } finally {
      await admin.query('grant select on audit.events to agentx_app');
    }
    expect(await sealedOf(waiting)).toBe(false);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'notification.legacy_seal_incomplete', notices: 0 }),
    );
    expect(await passes()).toEqual([]);

    await startedThenSealed();
    expect(await sealedOf(waiting)).toBe(true);
    expect(await passes()).toEqual([1]);
  });

  it('seals nothing past its cutoff, nor once this release has written a notice, and never throws', async () => {
    const waiting = await unsealed();
    await startedThenSealed(NOTICE_SEAL_BACKFILL_UNTIL);
    expect(await sealedOf(waiting)).toBe(false);

    await database.as('admin').query(
      `insert into notifications.outbox (id, org_id, recipient_user_id, kind, about_id, created_at, attempts,
        next_attempt_at, mac, mac_key_version) values ($1, $2, $3, 'second_factor_added', $3, $4, 0, $4, $5, 1)`,
      [ids.next(), ORG, PERSON, AT, Buffer.alloc(32)],
    );
    await startedThenSealed();
    expect(await sealedOf(waiting)).toBe(false);
    expect(await passes()).toEqual([]);

    // A pass that fails (here, the platform chain's head not to be read): said, never thrown.
    await database.as('admin').query('delete from notifications.outbox where not before_seals');
    const admin = database.as('admin');
    await admin.query('revoke select on platform_controls.audit_head from agentx_app');
    try {
      await sealLegacyNotices({ database: app, keys, logger: testLogger(capture) }, { now: AT });
    } finally {
      await admin.query('grant select on platform_controls.audit_head to agentx_app');
    }
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'notification.legacy_seal_failed' }));
  });

  it('leaves it quietly to another replica that has it under way', async () => {
    const waiting = await unsealed();
    const other = await database.connect('admin');
    try {
      await other.query('begin');
      await other.query(
        "select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('notifications.legacy_seal', 0))",
      );
      await startedThenSealed();
    } finally {
      await other.query('rollback');
      await other.end();
    }
    expect(await sealedOf(waiting)).toBe(false);
    expect(capture.lines().filter(({ level }) => level === 'warn' || level === 'error')).toEqual([]);
    await startedThenSealed();
    expect(await sealedOf(waiting)).toBe(true);
  });

  it('records a pass with none to seal, so a row planted later is never sealed, and the check alarms for it', async () => {
    await startedThenSealed();
    expect(await passes()).toEqual([0]);

    const planted = await unsealed();
    await startedThenSealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(await passes()).toEqual([0]);

    const later = new Date(AT.getTime() + 2 * 24 * 60 * 60_000);
    await createNoticeCheck({
      list: () => Promise.resolve([]),
      database: app,
      keys,
      ids,
      clock: { now: () => later },
      logger: testLogger(capture),
    }).run();
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({
        event: 'audit.integrity_failed',
        check: 'notice',
        reason: 'unsealed',
        noticeId: planted,
      }),
    );
  });
});

// S206 V4: the notices queued before seals, sealed once in the background
// after the API starts, recorded on the platform chain (`notice.legacy_sealed`):
// only before the cutoff, while no notice of this release exists, on a platform
// chain that checks out whole and holds no such record; a pass that couldn't
// read an organisation's records records nothing, so the next one seals the
// rest. Any notice with no seal after that stays without one (never claimed).
import type { AuditTables } from '@agentx/core/modules/audit';
import { createNoticeCheck, type NotificationsTables } from '@agentx/core/modules/notifications';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { CheckedPoint } from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { LEGACY_SEALED, NOTICE_SEAL_BACKFILL_UNTIL, type PlatformAnchors, sealLegacyNotices } from './notice-legacy.ts';
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

/** The anchor store, outside the database and out of the owner's reach: here, the platform chain's last anchor kept. */
let anchored: CheckedPoint | undefined;
const anchors: PlatformAnchors = {
  latest: () => Promise.resolve(anchored),
  anchor: (point) => {
    anchored = point;
    return Promise.resolve();
  },
};

/** The anchor check's run: the chain checked from its last anchor and anchored at its head. */
async function anchorCheck(): Promise<void> {
  const report = await createPlatformChain({ keys, ids }).verifyAlone(app, anchored);
  if (!report.ok) throw new Error('the platform chain failed its check');
  anchored = report;
}

/** The pass, as main.ts runs it once the API answers. */
const sealed = (now = AT, with_: PlatformAnchors | undefined = anchors) =>
  sealLegacyNotices({ database: app, keys, logger: testLogger(capture) }, { now, anchors: with_ });

/** A start recorded and the pass, with no anchor check between: as after the owner's change, which it would find. */
const restarted = async () => {
  await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });
  await sealed();
};

/** A start recorded, as boot records it, the anchor check's run, then the pass; at `now`, before the cutoff. */
const startedThenSealed = async (now = AT) => {
  await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });
  await anchorCheck();
  await sealed(now);
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
  anchored = undefined;
  await database
    .as('admin')
    .query('truncate platform_controls.audit_events, platform_controls.audit_head, notifications.outbox');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`SEC-DB-17 the notices from before seals, sealed once (S206 V4, Postgres ${server.version})`, () => {
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
    // Edited, it is there all the same: the pass ends at it (the anchor check finds the edit).
    await restarted();
    expect(await sealedOf(planted)).toBe(false);

    // Deleted, a start after it: a gap in the chain checked from its anchor.
    await database.as('admin').query('delete from platform_controls.audit_events where action = $1', [LEGACY_SEALED]);
    await restarted();
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(1);
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
      await sealed();
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

  it('seals nothing, with the alarm, on a platform chain wiped and begun again, a row planted', async () => {
    await startedThenSealed();
    const admin = database.as('admin');
    await admin.query('truncate platform_controls.audit_events, platform_controls.audit_head');
    await admin.query('delete from notifications.outbox where not before_seals');
    const planted = await unsealed();
    await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });

    await sealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(1);
  });

  it('anchors at once past its record, so deleting it as the chain’s newest is refused, a row planted', async () => {
    await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });
    await anchorCheck();
    const admin = database.as('admin');
    const [head] = await admin.query('select * from platform_controls.audit_head');
    await sealed();
    expect(await passes()).toEqual([0]);
    expect(anchored?.seq).toBe(2n);

    // The record deleted and the head put back as it was before it: no gap, but behind the anchor.
    await admin.query('delete from platform_controls.audit_events where action = $1', [LEGACY_SEALED]);
    await admin.query('update platform_controls.audit_head set seq = $1, hash = $2, mac = $3, mac_key_version = $4', [
      head?.seq,
      head?.hash,
      head?.mac,
      head?.mac_key_version,
    ]);
    const planted = await unsealed();
    await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });

    await sealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(1);
  });

  it('seals nothing, with a warning, with no anchor to check the chain by', async () => {
    const waiting = await unsealed();
    await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });
    await sealed();
    await sealed(AT, undefined);
    expect(await sealedOf(waiting)).toBe(false);
    expect(capture.lines().filter(({ event }) => event === 'notification.legacy_seal_no_anchor')).toHaveLength(2);
  });

  it('seals nothing more when another replica finished the pass while this one read its anchor', async () => {
    await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });
    await anchorCheck();
    let planted: string | undefined;
    const racing: PlatformAnchors = {
      ...anchors,
      // The other replica's whole pass lands between this one's first look and its own transaction; a row planted after.
      latest: async () => {
        await sealed();
        planted = await unsealed();
        return anchored;
      },
    };

    await sealed(AT, racing);
    expect(await passes()).toEqual([0]);
    expect(await sealedOf(planted ?? '')).toBe(false);
  });

  it('says as an error when it can’t anchor past its record, which stands', async () => {
    await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });
    await anchorCheck();
    const failing: PlatformAnchors = { ...anchors, anchor: () => Promise.reject(new Error('the store is away')) };

    await sealed(AT, failing);
    expect(await passes()).toEqual([0]);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'notification.legacy_seal_unanchored', level: 'error' }),
    );
    expect(capture.lines().filter(({ event }) => event === 'notification.legacy_seal_failed')).toEqual([]);
  });
});

// R-15, S207: a database whose first start was already 0105's release's (production's) holds no notice from before
// seals. One marked so is the owner's: never sealed as genuine, and the notice check's alarm a day on.
describe(`SEC-DB-17 a database born sealed: no pass (R-15, S207, Postgres ${server.version})`, () => {
  /** A start as boot records it from 0105's release on: with its time. */
  const startedWithTime = () =>
    recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined, at: AT });

  it('seals nothing a planted notice from before seals, records nothing, and the notice check alarms for it', async () => {
    await startedWithTime();
    const planted = await unsealed();
    await anchorCheck();

    await sealed();
    // Later starts, whatever they record, change nothing: the first one decides.
    await startedThenSealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(await passes()).toEqual([]);
    expect(capture.lines().filter(({ level }) => level === 'warn' || level === 'error')).toEqual([]);
    expect(capture.lines().filter(({ event }) => event === 'notification.legacy_born_sealed')).toHaveLength(2);

    await createNoticeCheck({
      list: () => Promise.resolve([]),
      database: app,
      keys,
      ids,
      clock: { now: () => new Date(AT.getTime() + 2 * 24 * 60 * 60_000) },
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

  it('seals nothing, with the alarm, with no start on the chain (each start records its own first: they were deleted)', async () => {
    const planted = await unsealed();

    await sealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(1);
  });

  it('seals nothing, with the alarm, once the first start’s time is taken out of it, to pass for a database from before', async () => {
    await startedWithTime();
    const planted = await unsealed();
    await anchorCheck();
    await database
      .as('admin')
      .query(`update platform_controls.audit_events set details = '{"release":"r"}' where seq = 1`);

    await sealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(await passes()).toEqual([]);
    expect(startAlarm()).toHaveLength(1);
  });

  it('a first start with a time that isn’t one: seals nothing, the alarm', async () => {
    await createPlatformChain({ keys, ids }).recordAlone(app, {
      actor: { type: 'system', id: 'api' },
      action: 'platform.started',
      details: { release: 'r', rowMacsFrom: 7 },
    });
    const planted = await unsealed();
    await anchorCheck();

    await sealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(1);
  });

  it('a first start whose time is a string but no time: seals nothing, the alarm', async () => {
    await createPlatformChain({ keys, ids }).recordAlone(app, {
      actor: { type: 'system', id: 'api' },
      action: 'platform.started',
      details: { release: 'r', rowMacsFrom: 'not a time' },
    });
    const planted = await unsealed();
    await anchorCheck();

    await sealed();
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(1);
  });

  it('a database from before, its first start deleted by the owner before the pass: reads as born sealed, nothing sealed or recorded, and the notice check and the chain’s whole walk catch it', async () => {
    await recordStart(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release: 'r', gateRef: undefined });
    await startedWithTime();
    const waiting = await unsealed();
    await database.as('admin').query('delete from platform_controls.audit_events where seq = 1');

    await sealed();
    // A stop, never a grant: the notice from before stays unsealed, never claimed, and no pass is recorded.
    expect(await sealedOf(waiting)).toBe(false);
    expect(await passes()).toEqual([]);
    expect(capture.lines().filter(({ event }) => event === 'notification.legacy_born_sealed')).toHaveLength(1);

    await createNoticeCheck({
      list: () => Promise.resolve([]),
      database: app,
      keys,
      ids,
      clock: { now: () => new Date(AT.getTime() + 2 * 24 * 60 * 60_000) },
      logger: testLogger(capture),
    }).run();
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({
        event: 'audit.integrity_failed',
        check: 'notice',
        reason: 'unsealed',
        noticeId: waiting,
      }),
    );
    // The gap the deletion leaves fails the platform chain's walk from its start (the daily walk's alarm).
    const walk = await app.transaction().execute((tx) => createPlatformChain({ keys, ids }).verify(tx, undefined));
    expect(walk.ok).toBe(false);
  });
});

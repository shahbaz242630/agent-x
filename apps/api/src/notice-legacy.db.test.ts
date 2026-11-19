// S206 V4: the notices queued before seals, sealed by the first start of the
// release with seals, in its own record's transaction, which says how many;
// any notice with no seal after that stays without one (never claimed). A
// start record the owner edited to hide that it sealed them is not believed:
// nothing is sealed, with the integrity alarm.
import type { AuditTables } from '@agentx/core/modules/audit';
import type { NotificationsTables } from '@agentx/core/modules/notifications';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { NOTICE_SEAL_BACKFILL_UNTIL, recordStartSealingNotices } from './notice-legacy.ts';

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

/** Writes a notice with no seal, as the release before did before 0105 (a row it found then); `done` for one sent. */
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

const starts = async () =>
  (await app.selectFrom('platform_controls.audit_events').select('details').orderBy('seq').execute()).map(
    ({ details }) => JSON.parse(details) as Record<string, unknown>,
  );

/** A start before the backfill's cutoff, or at `now`. */
const started = (release: string, gateRef?: string, now = AT) =>
  recordStartSealingNotices(
    app,
    keys,
    ids,
    { configHash: `sha256:${'0'.repeat(64)}`, release, gateRef },
    { logger: testLogger(capture), now },
  );

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
  it('seals those still to be sent at the first start, saying how many, and never again', async () => {
    const waiting = [await unsealed(), await unsealed()];
    const sent = await unsealed(true);

    expect(await started('r-first')).toBe(1n);
    expect(await Promise.all(waiting.map(sealedOf))).toEqual([true, true]);
    expect(await sealedOf(sent)).toBe(false);

    // One written with no seal since: the owner's, never sealed by a start after.
    const planted = await unsealed();
    expect(await started('r-second', `LMG-v3-sha256:${'ab'.repeat(32)}`)).toBe(2n);
    expect(await sealedOf(planted)).toBe(false);
    expect((await starts()).map((details) => details.noticesSealed)).toEqual([2, undefined]);
  });

  it('seals nothing, with the alarm, once a start’s record has been edited to hide that it sealed them', async () => {
    expect(await started('r-first')).toBe(1n);
    await database
      .as('admin')
      .query(`update platform_controls.audit_events set details = '{"release":"r-first"}' where seq = 1`);
    const planted = await unsealed();

    expect(await started('r-second')).toBe(2n);
    expect(await sealedOf(planted)).toBe(false);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'audit.integrity_failed', chain: 'platform', check: 'start_record' }),
    );
  });

  it('seals nothing, with the alarm, once a start that sealed them was deleted, and a row planted', async () => {
    expect(await started('r-first')).toBe(1n);
    await database.as('admin').query('delete from platform_controls.audit_events where seq = 1');
    const planted = await unsealed();

    await started('r-second');
    expect(await sealedOf(planted)).toBe(false);
    expect(startAlarm()).toHaveLength(1);
  });

  it('leaves it for the next start when an organisation’s records can’t be read, which then seals them', async () => {
    const waiting = await unsealed();
    const admin = database.as('admin');
    await admin.query('revoke select on audit.events from agentx_app');
    try {
      await started('r-first');
    } finally {
      await admin.query('grant select on audit.events to agentx_app');
    }
    expect(await sealedOf(waiting)).toBe(false);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'notification.legacy_seal_incomplete', notices: 0 }),
    );

    await started('r-second');
    expect(await sealedOf(waiting)).toBe(true);
    expect((await starts()).map((details) => details.noticesSealed)).toEqual([undefined, 1]);
  });

  it('seals nothing past its cutoff, nor once this release has written a notice', async () => {
    const waiting = await unsealed();
    await started('r-late', undefined, NOTICE_SEAL_BACKFILL_UNTIL);
    expect(await sealedOf(waiting)).toBe(false);

    await database.as('admin').query(
      `insert into notifications.outbox (id, org_id, recipient_user_id, kind, about_id, created_at, attempts,
        next_attempt_at, mac, mac_key_version) values ($1, $2, $3, 'second_factor_added', $3, $4, 0, $4, $5, 1)`,
      [ids.next(), ORG, PERSON, AT, Buffer.alloc(32)],
    );
    await started('r-after');
    expect(await sealedOf(waiting)).toBe(false);
    expect((await starts()).map((details) => details.noticesSealed)).toEqual([undefined, undefined]);
  });
});

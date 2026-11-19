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

import { recordStartSealingNotices } from './notice-legacy.ts';

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

const started = (release: string, gateRef?: string) =>
  recordStartSealingNotices(
    app,
    keys,
    ids,
    { configHash: `sha256:${'0'.repeat(64)}`, release, gateRef },
    testLogger(capture),
  );

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
});

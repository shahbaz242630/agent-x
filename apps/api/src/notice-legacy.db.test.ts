// S206 V4: the notices queued before seals, sealed by the first start of the
// release with seals, in its own record's transaction, which says how many;
// any notice with no seal after that stays without one (the sender refuses it).
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import type { NotificationsTables } from '@agentx/core/modules/notifications';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { recordStartSealingNotices } from './notice-legacy.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<NotificationsTables & PlatformControlsTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x5206_0004_1000);
const ORG = '0199a0f0-0000-7000-8000-0000005206c1';
const PERSON = '0199a0f0-0000-7000-8000-0000005206c2';
const AT = new Date('2026-11-19T09:00:00Z');

/** Writes a notice with no seal, as the release before did; `done` for one already sent. */
async function unsealed(done = false): Promise<string> {
  const id = ids.next();
  await app
    .insertInto('notifications.outbox')
    .values({
      id,
      org_id: ORG,
      recipient_user_id: PERSON,
      kind: 'second_factor_added',
      membership_id: null,
      role: null,
      about_id: PERSON,
      created_at: AT,
      attempts: 0,
      next_attempt_at: AT,
      sent_at: done ? AT : null,
    })
    .execute();
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
  recordStartSealingNotices(app, keys, ids, { configHash: `sha256:${'0'.repeat(64)}`, release, gateRef });

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
});

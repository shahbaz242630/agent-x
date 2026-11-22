// SEC-LIM-13 S210 TR-7 (B3): a person's day's sessions and step-ups counted from their platform events of the
// database's last 24 hours, on the real migrated schema, as the app role: only their own, of the action asked, and
// none older than a day; read as a range of 0116's index, however long the person's history.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createPlatformChain, type PlatformControlsTables } from '../../platform-controls/index.ts';
import { personSignedToday, sessionsSpent, stepUpsSpent } from './person-chain-caps.ts';
import { SESSION_ENDED, SESSION_ROTATED } from './signed-ends.ts';
import type { IdentityTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables & PlatformControlsTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x7e70) });
const ACTOR = { type: 'system', id: 'api' } as const;
const NOW = new Date('2026-12-01T09:00:00Z');
const PERSON = '0199a0f0-0000-7000-8000-00000000e701';
const OTHER = '0199a0f0-0000-7000-8000-00000000e702';

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables & PlatformControlsTables>(
    { ...database.connection('app'), maxConnections: 2 },
    testLogger(),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** Records one of the person's events of `action` on the platform chain, now by the database's clock. */
const signed = (action: string, person: string) =>
  chain.recordAlone(app, { actor: ACTOR, action, details: { person, record: person, at: NOW.toISOString() } });

const spent = (most: number) =>
  app.transaction().execute(async (tx) => ({
    sessions: await sessionsSpent(tx, PERSON, NOW, most),
    stepUps: await stepUpsSpent(tx, PERSON, most),
  }));

describe(`SEC-LIM-13 S210 TR-7 a person's day counted from their platform events (Postgres ${server.version})`, () => {
  it('counts the person’s own session ends and rotations of the last day, and none once older than a day', async () => {
    for (const action of [SESSION_ENDED, SESSION_ENDED, SESSION_ROTATED, SESSION_ROTATED]) await signed(action, PERSON);
    // Another person's, and another action naming the person, count for nothing.
    for (const action of [SESSION_ENDED, SESSION_ROTATED]) await signed(action, OTHER);
    await signed('identity.sessions_ended', PERSON);

    expect(await spent(2)).toEqual({ sessions: true, stepUps: true });
    expect(await spent(3)).toEqual({ sessions: false, stepUps: false });

    // A day and an hour on by the database's clock (the owner moving them back stands in for the wait): one of each
    // leaves the window, then the other.
    const owner = database.as('owner');
    const age = (action: string, limit: number) =>
      owner.query(
        `update platform_controls.audit_events set recorded_at = recorded_at - interval '25 hours'
         where seq in (select seq from platform_controls.audit_events
           where action = $1 and details::jsonb ->> 'person' = $2 and recorded_at > now() - interval '1 day'
           order by seq limit $3)`,
        [action, PERSON, limit],
      );
    await age(SESSION_ENDED, 1);
    await age(SESSION_ROTATED, 1);
    expect(await spent(2)).toEqual({ sessions: false, stepUps: false });
    expect(await spent(1)).toEqual({ sessions: true, stepUps: true });
    await age(SESSION_ENDED, 1);
    await age(SESSION_ROTATED, 1);
    expect(await spent(1)).toEqual({ sessions: false, stepUps: false });
  });

  it('reads the day as a range of 0116’s index by action, person and time, never the person’s whole history', async () => {
    // A busy approver's year: 20,000 of each signed long ago, beside 500 other people's, planned by Postgres on its own
    // statistics, no kind of scan set aside; made and planned in one transaction as the owner, rolled back.
    const owner = createDatabase<PlatformControlsTables>(
      { ...database.connection('owner'), maxConnections: 1 },
      testLogger(),
    );
    const plans: string[] = [];
    const rolledBack = new Error('rolled back');
    try {
      await owner.transaction().execute(async (tx) => {
        await sql`
          insert into platform_controls.audit_events
            (seq, id, recorded_at, actor_type, actor_id, action, details, prev_hash, hash, mac, mac_key_version)
          select 3000000 + g, gen_random_uuid(), now() - interval '30 days' - g * interval '1 minute', 'system', 'api',
                 case when g % 2 = 0 then ${SESSION_ENDED} else ${SESSION_ROTATED} end,
                 json_build_object('person', case when g % 3 = 0 then 'p-' || (g % 500) else ${PERSON} end,
                   'record', 'r-' || g, 'at', '2026-01-01T00:00:00.000Z')::text,
                 decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode('00', 'hex'), 1
          from generate_series(1, 60000) as g`.execute(tx);
        await sql`analyze platform_controls.audit_events`.execute(tx);
        for (const action of [SESSION_ENDED, SESSION_ROTATED]) {
          const { rows } = await sql<{
            'QUERY PLAN': string;
          }>`explain select ${personSignedToday(action, PERSON)}`.execute(tx);
          plans.push(rows.map((row) => row['QUERY PLAN']).join('\n'));
        }
        throw rolledBack;
      });
    } catch (error) {
      if (error !== rolledBack) throw error;
    } finally {
      await owner.destroy();
    }
    expect(plans).toHaveLength(2);
    for (const plan of plans) {
      expect(plan).toMatch(/Index (Only )?Scan using audit_events_by_person_time/);
      // The window is a bound of the index, not a filter over every entry of the person's.
      expect(plan).toMatch(/Index Cond: .*recorded_at >/);
      expect(plan).not.toMatch(/Filter: .*recorded_at/);
    }
  });
});

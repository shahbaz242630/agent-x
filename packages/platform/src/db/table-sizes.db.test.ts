// F12: a table's size and its indexes' use as the app's own role reads them,
// on a real migrated database, through a tenant wall that hides every row from it.
import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';
import { tableSizes } from './table-sizes.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;

const ORG = '0199a0f0-0000-7000-8000-00000000f121';

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase({ ...database.connection('app'), maxConnections: 1 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`a table's size (F12, Postgres ${server.version})`, () => {
  it('reads every table and its indexes in one go, ours alone, and sees rows its role can neither see nor read', async () => {
    const before = await tableSizes(app);
    const tables = Object.keys(before.tables);
    expect(tables).toContain('audit.events');
    expect(tables).toContain('access.requests');
    expect(tables.filter((table) => table.startsWith('pg_') || table.startsWith('information_'))).toEqual([]);
    // Every index is its table's, and the audit log's own are among them.
    expect(Object.values(before.indexes).every(({ table }) => tables.includes(table))).toBe(true);
    expect(before.indexes['audit.events_by_action']).toMatchObject({ table: 'audit.events' });
    const access = before.tables['access.requests'];
    expect(access?.indexes).toBeGreaterThan(0);

    // The owner writes behind the wall, long values among it: the app, with no organisation set, sees none of it.
    const owner = await database.connect('owner');
    await owner.query('begin');
    await owner.query("select pg_catalog.set_config('app.org_id', $1, true)", [ORG]);
    await owner.query(
      `insert into access.requests (org_id, id, recorded_at, actor_type, actor_id, method, route, path_ids, status, correlation_id, duration_ms)
       select $1, gen_random_uuid(), now(), 'user', $1, 'GET', '/v1/x', '{}', 200, $1, 1 from generate_series(1, 500)`,
      [ORG],
    );
    await owner.query('commit');
    await owner.end();

    const after = await tableSizes(app);
    expect(after.tables['access.requests']?.rows).toBeGreaterThan(access?.rows ?? Infinity);
    expect(after.tables['access.requests']?.indexes).toBeGreaterThan(access?.indexes ?? Infinity);
    expect(after.tables['audit.events']).toEqual(before.tables['audit.events']);
  });
});

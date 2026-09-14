import { createTestDatabase, type TestDatabase } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase(database.connection('app'));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`createDatabase (Postgres ${server.version})`, () => {
  it('ADR-006: returns bigint columns as exact BigInts, beyond what a float can hold', async () => {
    const { rows } = await sql<{ big: unknown; small: unknown; exact: unknown }>`
      select 9007199254740993::int8 as big, 7::int4 as small, 12.50::numeric as exact
    `.execute(app);
    expect(rows).toEqual([{ big: 9_007_199_254_740_993n, small: 7, exact: '12.50' }]);
  });

  it('names its connections, so they can be told apart on the server', async () => {
    const { rows } = await sql<{ name: string }>`select pg_catalog.current_setting('application_name') as name`.execute(
      app,
    );
    expect(rows[0]?.name).toBe('agentx');
  });

  it('logs in as the role it was given', async () => {
    const { rows } = await sql<{ name: string }>`select session_user::text as name`.execute(app);
    expect(rows[0]?.name).toBe('agentx_app');
  });
});

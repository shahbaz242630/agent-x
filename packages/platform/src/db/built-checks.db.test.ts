// built-checks.json is what the live schema guard holds every CHECK constraint
// to, so this is the one place it is written: from a freshly migrated database,
// on both Postgres versions, as the app role reads it. It sits apart from
// schema-guard.db.test.ts, whose every case starts by wanting a clean guard: a
// file gone stale would stop that file before it could be refreshed.
//
// built-tables.json likewise, for every table.
//
// After a migration that adds a table, or adds or changes a CHECK constraint, refresh them with:
//   corepack pnpm exec vitest run --project db-pg18 packages/platform/src/db/built-checks.db.test.ts -u
import { createTestDatabase, type TestDatabase } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, beforeAll, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import { checkConstraints, relationNames } from './schema-guard.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase(
    { ...database.connection('app'), tls: 'disable' },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'error', eventCapPerMinute: 1000 } },
      destination: { write: () => undefined },
    }),
  );
}, 60_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

it('holds every CHECK constraint a freshly migrated database has, as it prints them', async () => {
  const found = await checkConstraints(app);
  const rows = found
    .map(({ table, name, expression }) => JSON.stringify({ table, name, expression }))
    // By code unit, not the server's collation, so the file reads the same from any server.
    .toSorted((a, b) => (a < b ? -1 : 1));

  expect(found.length).toBeGreaterThan(0);
  await expect(`[\n  ${rows.join(',\n  ')}\n]\n`).toMatchFileSnapshot('./built-checks.json');
});

it('holds every table a freshly migrated database has', async () => {
  const names = (await relationNames(app)).map((name) => JSON.stringify(name)).toSorted((a, b) => (a < b ? -1 : 1));

  expect(names.length).toBeGreaterThan(0);
  await expect(`[\n  ${names.join(',\n  ')}\n]\n`).toMatchFileSnapshot('./built-tables.json');
});

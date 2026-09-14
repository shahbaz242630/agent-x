// CI-06 (ADR-005 §8): the schema db/migrations builds keeps the tenant walls.
// It runs on a copy of the migrated template, once per Postgres version, so
// every new migration is checked here. The rules, and a broken fixture for
// each, are in packages/testing/src/db/schema-checks.ts; the decisions (the
// global tables and the append-only schemas) are in tooling/schema-policy.ts.
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createTestDatabase, schemaProblems, type TestDatabase } from '../../packages/testing/src/index.ts';
import { SCHEMA_POLICY } from '../schema-policy.ts';

const server = inject('postgres');
let database: TestDatabase;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await database.drop();
});

describe(`CI-06 (SEC-TEN-05, 08, 10, SEC-EVD-01) the migrated schema keeps the tenant walls (Postgres ${server.version})`, () => {
  it('passes every check', async () => {
    expect(await schemaProblems(database, SCHEMA_POLICY)).toEqual([]);
  });
});

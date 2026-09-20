// A3c (ADR-012 §2, ADR-007 §1): every authority table the modules declare is
// built the way the signed state and the status guard need it. It runs on a
// copy of the migrated template, once per Postgres version, so every new
// migration is checked here. The rules, and a broken fixture for each, are in
// packages/testing/src/db/authority-checks.ts; the list of the tables is
// tooling/authority-tables.ts.
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { authorityProblems, createTestDatabase, type TestDatabase } from '../../packages/testing/src/index.ts';
import { AUTHORITY_TABLES } from '../authority-tables.ts';

const server = inject('postgres');
let database: TestDatabase;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await database.drop();
});

describe(`A3c (SEC-DB-10) every authority table is built for its signed state (Postgres ${server.version})`, () => {
  it('passes every check', async () => {
    expect(await authorityProblems(database, AUTHORITY_TABLES)).toEqual([]);
  });
});

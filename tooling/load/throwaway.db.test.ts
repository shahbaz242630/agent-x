// The throwaway copy's sentinel (throwaway.ts) on a migrated database: one
// never marked (as staging's is) is refused, one marked as the copy is taken,
// one marked as another copy is refused, and the API's schema guard still finds
// nothing wrong, so the mark itself is never taken for tampering.
import { createDatabase, type Database, liveSchemaProblems } from '../../packages/platform/src/db/index.ts';
import { createTestDatabase, type TestDatabase, testLogger } from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { markThrowaway, sentinelProblem } from './throwaway.ts';

const server = inject('postgres');
const COPY = 'psql-agentx-stg-g-a1b2c3d4';
let database: TestDatabase;
let owner: Database<unknown>;
let app: Database<unknown>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  owner = createDatabase<unknown>(database.connection('owner'), testLogger());
  app = createDatabase<unknown>(database.connection('app'), testLogger());
});

afterAll(async () => {
  await owner.destroy();
  await app.destroy();
  await database.drop();
});

describe("the throwaway copy's sentinel", () => {
  it('is refused on a database never marked, as staging’s is', async () => {
    expect(await sentinelProblem(app, COPY)).toBe(
      `The database at ${COPY} carries no Stage G sentinel, so it may be staging's own: nothing was changed. Run the load-mark job on the copy first.`,
    );
  });

  it('is written by the owner, then read by the app role as this copy and no other', async () => {
    expect(await markThrowaway(owner, COPY)).toBeUndefined();
    expect(await sentinelProblem(app, COPY)).toBeUndefined();
    expect(await sentinelProblem(app, 'psql-agentx-stg-g-zzzzzzzz')).toBe(
      `The database at psql-agentx-stg-g-zzzzzzzz is marked as another copy (agentx-stage-g-throwaway ${COPY}), so it isn't the one named: nothing was changed.`,
    );
  });

  it('leaves the schema guard nothing to find: the mark is in no catalogue it reads', async () => {
    await markThrowaway(owner, COPY);
    expect(
      await liveSchemaProblems(app, {
        appRole: database.connection('app').user,
        ownerRole: database.connection('owner').user,
      }),
    ).toEqual([]);
  });
});

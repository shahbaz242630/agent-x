import { DummyDriver, Kysely, PostgresAdapter, PostgresIntrospector, PostgresQueryCompiler } from 'kysely';
import { describe, expect, it } from 'vitest';

import { assertRuntimeRole, runtimeRoleProblems, UnsafeDatabaseRole } from './runtime-role.ts';

/** A database that answers every query with no rows. */
const answersNothing = new Kysely<unknown>({
  dialect: {
    createAdapter: () => new PostgresAdapter(),
    createDriver: () => new DummyDriver(),
    createIntrospector: (db) => new PostgresIntrospector(db),
    createQueryCompiler: () => new PostgresQueryCompiler(),
  },
});

describe('runtimeRoleProblems', () => {
  it('fails closed when the role cannot be read', async () => {
    expect(await runtimeRoleProblems(answersNothing)).toEqual(['the connected role was not found in pg_roles']);
    await expect(assertRuntimeRole(answersNothing)).rejects.toThrow(UnsafeDatabaseRole);
  });
});

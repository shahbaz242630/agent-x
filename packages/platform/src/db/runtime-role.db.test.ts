import { randomUUID } from 'node:crypto';

import { createTestDatabase, type TestDatabase, type TestRole } from '@agentx/testing';
import { Kysely, PostgresDialect } from 'kysely';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';
import { assertRuntimeRole, runtimeRoleProblems, UnsafeDatabaseRole } from './runtime-role.ts';

const server = inject('postgres');
let database: TestDatabase;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await database.drop();
});

async function problemsFor(role: TestRole): Promise<string[]> {
  const db = createDatabase(database.connection(role));
  try {
    return await runtimeRoleProblems(db);
  } finally {
    await db.destroy();
  }
}

describe(`APP-02 the app refuses to run as a role that can get round the tenant walls (Postgres ${server.version})`, () => {
  it('accepts agentx_app', async () => {
    expect(await problemsFor('app')).toEqual([]);
    const db = createDatabase(database.connection('app'));
    try {
      await expect(assertRuntimeRole(db)).resolves.toBeUndefined();
    } finally {
      await db.destroy();
    }
  });

  it('refuses the migration role, which owns the database, its schemas and its tables', async () => {
    // Postgres makes a database's owner a member of pg_database_owner, which owns the public schema.
    expect(await problemsFor('owner')).toEqual([
      'it is a member of other roles, whose rights it can use (pg_database_owner)',
      'it owns the database',
      'it owns schemas, so it could alter their tables',
      'it owns tables or other relations, so it could switch their row-level security off',
    ]);
  });

  it('refuses the backup role, which bypasses row-level security', async () => {
    expect(await problemsFor('backup')).toEqual(['it has BYPASSRLS']);
  });

  it('refuses the server admin', async () => {
    const problems = await problemsFor('admin');
    expect(problems).toContain('it is a superuser, which bypasses row-level security');
    expect(problems).toContain('it has BYPASSRLS');
    expect(problems).toContain('it can create roles');
    expect(problems).toContain('it can create databases');
  });

  it('refuses a role that is a member of the owner, whose rights it could use', async () => {
    const name = `t_member_${randomUUID().replaceAll('-', '')}`;
    const admin = database.as('admin');
    // eslint-disable-next-line agentx/no-string-built-sql -- Test setup: CREATE ROLE can't take names as parameters; the name is generated.
    await admin.query(`create role ${name} login password 'plain words for a test' in role agentx_owner`);
    // eslint-disable-next-line agentx/no-string-built-sql -- As above.
    await admin.query(`grant connect on database ${database.name} to ${name}`);
    const db = createDatabase({ ...database.connection('app'), user: name, password: 'plain words for a test' });
    try {
      expect(await runtimeRoleProblems(db)).toEqual([
        'it is a member of other roles, whose rights it can use (agentx_owner, pg_database_owner)',
      ]);
      await expect(assertRuntimeRole(db)).rejects.toThrow(/member of other roles/);
    } finally {
      await db.destroy();
      // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup, as above.
      await admin.query(`revoke connect on database ${database.name} from ${name}`);
      // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup, as above.
      await admin.query(`drop role ${name}`);
    }
  });

  it('checks the login role, not a role the session switched to', async () => {
    // The admin logs in and switches to agentx_app at connection time, as PGOPTIONS could.
    const pool = new pg.Pool({ ...database.connection('admin'), ssl: false, max: 1, options: '-c role=agentx_app' });
    const db = new Kysely<unknown>({ dialect: new PostgresDialect({ pool }) });
    try {
      const problems = await runtimeRoleProblems(db);
      expect(problems[0]).toBe('the session has switched to another role (SET ROLE), and can switch back');
      expect(problems).toContain('it is a superuser, which bypasses row-level security');
    } finally {
      await db.destroy();
    }
  });

  it('lists every problem at once in the error', async () => {
    const db = createDatabase(database.connection('owner'));
    try {
      const refusal = await assertRuntimeRole(db).catch((error: unknown) => error);
      expect(refusal).toBeInstanceOf(UnsafeDatabaseRole);
      expect((refusal as UnsafeDatabaseRole).problems).toHaveLength(4);
    } finally {
      await db.destroy();
    }
  });
});

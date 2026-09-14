import { randomUUID } from 'node:crypto';

import { createTestDatabase, LogCapture, type TestDatabase, type TestRole } from '@agentx/testing';
import { Kysely, PostgresDialect } from 'kysely';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase, type DatabaseConnectionOptions } from './database.ts';
import { assertRuntimeRole, runtimeRoleProblems, UnsafeDatabaseRole } from './runtime-role.ts';

const server = inject('postgres');
let database: TestDatabase;

const OWNS_OBJECTS =
  'it owns objects (schemas, tables, functions or types), so it could change them or switch their row-level security off';

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await database.drop();
});

const open = (connection: DatabaseConnectionOptions): Kysely<unknown> =>
  createDatabase(
    connection,
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );

async function problemsFor(connection: DatabaseConnectionOptions): Promise<string[]> {
  const db = open(connection);
  try {
    return await runtimeRoleProblems(db);
  } finally {
    await db.destroy();
  }
}

const problemsOf = (role: TestRole): Promise<string[]> => problemsFor(database.connection(role));

/** Runs `check` as a new login role that `setup` (run by the admin) gives something extra. */
async function asNewRole(setup: (name: string) => readonly string[], check: (name: string) => Promise<void>) {
  const name = `t_role_${randomUUID().replaceAll('-', '')}`;
  const admin = database.as('admin');
  // eslint-disable-next-line agentx/no-string-built-sql -- Test setup: CREATE ROLE can't take names as parameters; the name is generated.
  await admin.query(`create role ${name} login password 'plain words for a test'`);
  // eslint-disable-next-line agentx/no-string-built-sql -- As above.
  await admin.query(`grant connect on database ${database.name} to ${name}`);
  try {
    for (const statement of setup(name)) {
      // eslint-disable-next-line agentx/no-string-built-sql -- As above; the statements are written in the tests below.
      await admin.query(statement);
    }
    await check(name);
  } finally {
    // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup, as above.
    await admin.query(`drop owned by ${name}`);
    // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup, as above.
    await admin.query(`drop role ${name}`);
  }
}

const loginAs = (name: string): DatabaseConnectionOptions => ({
  ...database.connection('app'),
  user: name,
  password: 'plain words for a test',
});

describe(`APP-02 the app refuses to run as a role that can get round the tenant walls (Postgres ${server.version})`, () => {
  it('accepts agentx_app', async () => {
    expect(await problemsOf('app')).toEqual([]);
    const db = open(database.connection('app'));
    try {
      await expect(assertRuntimeRole(db)).resolves.toBeUndefined();
    } finally {
      await db.destroy();
    }
  });

  it('refuses the migration role, which owns the database and what is in it', async () => {
    // Postgres makes a database's owner a member of pg_database_owner, which owns the public schema.
    expect(await problemsOf('owner')).toEqual([
      'it is a member of other roles, whose rights it can use (pg_database_owner)',
      'it owns the database',
      OWNS_OBJECTS,
    ]);
  });

  it('refuses the backup role, which bypasses row-level security', async () => {
    expect(await problemsOf('backup')).toEqual(['it has BYPASSRLS']);
  });

  it('refuses the server admin', async () => {
    const problems = await problemsOf('admin');
    expect(problems).toContain('it is a superuser, which bypasses row-level security');
    expect(problems).toContain('it has BYPASSRLS');
    expect(problems).toContain('it can create roles');
    expect(problems).toContain('it can create databases');
  });

  it('refuses a role that is a member of the owner, whose rights it could use', async () => {
    await asNewRole(
      (name) => [`grant agentx_owner to ${name}`],
      async (name) => {
        expect(await problemsFor(loginAs(name))).toEqual([
          'it is a member of other roles, whose rights it can use (agentx_owner, pg_database_owner)',
        ]);
      },
    );
  });

  it('refuses a role that owns only a function, in any database', async () => {
    await asNewRole(
      (name) => [
        `create schema ${name}_schema`,
        `create function ${name}_schema.helper() returns int language sql as $$ select 1 $$`,
        `alter function ${name}_schema.helper() owner to ${name}`,
      ],
      async (name) => {
        expect(await problemsFor(loginAs(name))).toEqual([OWNS_OBJECTS]);
      },
    );
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
    const db = open(database.connection('owner'));
    try {
      const refusal = await assertRuntimeRole(db).catch((error: unknown) => error);
      expect(refusal).toBeInstanceOf(UnsafeDatabaseRole);
      expect((refusal as UnsafeDatabaseRole).problems).toHaveLength(3);
    } finally {
      await db.destroy();
    }
  });
});

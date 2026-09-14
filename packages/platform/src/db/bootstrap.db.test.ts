// What db/bootstrap and the baseline migration leave behind, read back from a
// server prepared exactly as a real one is (tooling/test-db/global-setup.ts).
import { createTestDatabase, type TestDatabase } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

const server = inject('postgres');
let database: TestDatabase;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await database.drop();
});

describe(`db/bootstrap/roles.sql: the three roles (Postgres ${server.version})`, () => {
  it('creates them with exactly the attributes ADR-005 §3 gives them', async () => {
    const rows = await database.as('admin').query(
      `select rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls
       from pg_catalog.pg_roles where rolname like 'agentx\\_%' order by rolname`,
    );
    const role = {
      rolsuper: false,
      rolcreaterole: false,
      rolcreatedb: false,
      rolcanlogin: true,
      rolreplication: false,
    };
    expect(rows).toEqual([
      { rolname: 'agentx_app', ...role, rolinherit: false, rolbypassrls: false },
      { rolname: 'agentx_backup', ...role, rolinherit: false, rolbypassrls: true },
      { rolname: 'agentx_owner', ...role, rolinherit: true, rolbypassrls: false },
    ]);
  });

  it('makes none of them a member of any role', async () => {
    const rows = await database.as('admin').query(
      `select member.rolname from pg_catalog.pg_auth_members m
       join pg_catalog.pg_roles member on member.oid = m.member
       where member.rolname like 'agentx\\_%'`,
    );
    expect(rows).toEqual([]);
  });
});

describe('db/bootstrap/database.sql: who may connect', () => {
  it('lets only the app and backup roles connect, besides the owner, and no one else create temporary tables', async () => {
    for (const name of [server.templateDatabase, database.name]) {
      const rows = await database.as('admin').query<{ grantee: string; privilege: string }>(
        `select coalesce(grantee.rolname, 'PUBLIC') as grantee, acl.privilege_type as privilege
         from pg_catalog.pg_database d, pg_catalog.aclexplode(d.datacl) acl
         left join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
         where d.datname = $1 and acl.grantee <> d.datdba
         order by 1, 2`,
        [name],
      );
      expect(rows).toEqual([
        { grantee: 'agentx_app', privilege: 'CONNECT' },
        { grantee: 'agentx_backup', privilege: 'CONNECT' },
      ]);
    }
  });

  it('makes agentx_owner the owner', async () => {
    const rows = await database
      .as('admin')
      .query('select pg_catalog.pg_get_userbyid(datdba) as owner from pg_catalog.pg_database where datname = $1', [
        database.name,
      ]);
    expect(rows).toEqual([{ owner: 'agentx_owner' }]);
  });
});

describe('db/migrations/0001_baseline.sql: rights every role would otherwise get', () => {
  it('takes the public schema away from PUBLIC', async () => {
    const rows = await database.as('admin').query(
      `select pg_catalog.has_schema_privilege('agentx_app', 'public', 'USAGE') as app_usage,
              pg_catalog.has_schema_privilege('agentx_app', 'public', 'CREATE') as app_create,
              pg_catalog.has_schema_privilege('agentx_backup', 'public', 'USAGE') as backup_usage`,
    );
    expect(rows).toEqual([{ app_usage: false, app_create: false, backup_usage: false }]);
  });

  it('keeps the app from running a function the owner creates later, until it is granted', async () => {
    const owner = database.as('owner');
    await owner.query('create schema baseline_check');
    await owner.query('grant usage on schema baseline_check to agentx_app');
    await owner.query('create function baseline_check.answer() returns int language sql as $$ select 42 $$');

    await expect(database.as('app').query('select baseline_check.answer()')).rejects.toThrow(/permission denied/);
    await owner.query('grant execute on function baseline_check.answer() to agentx_app');
    expect(await database.as('app').query('select baseline_check.answer() as answer')).toEqual([{ answer: 42 }]);
  });
});

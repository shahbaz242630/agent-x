// What the set-up job refuses before it connects (bootstrap files it can't
// send as they are, a database name it can't use), and how it judges what the
// server reports afterwards. Its work on a real server is tested in
// tooling/checks/db-setup.db.test.ts.
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import {
  databaseProblems,
  type DatabaseRow,
  type GrantRow,
  loadBootstrap,
  publicSchemaProblems,
  roleProblems,
  type RoleRow,
  ServerSetupRefused,
  setUpServer,
} from './server-setup.ts';

const BOOTSTRAP = fileURLToPath(new URL('../../../../db/bootstrap', import.meta.url));

const folders: string[] = [];
afterEach(() => {
  for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true });
});

/** A copy of db/bootstrap with one file changed. */
function bootstrapWith(file: string, change: (sql: string) => string): string {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-bootstrap-'));
  folders.push(folder);
  cpSync(BOOTSTRAP, folder, { recursive: true });
  const target = path.join(folder, file);
  writeFileSync(target, change(readFileSync(target, 'utf8')));
  return folder;
}

describe('loadBootstrap', () => {
  it("reads db/bootstrap's four files in the job's order, statement by statement, with the database's name filled in", async () => {
    const bootstrap = await loadBootstrap(BOOTSTRAP, 'agentx');
    expect(bootstrap.roles.map(({ file, roles, statements }) => ({ file, roles, count: statements.length }))).toEqual([
      { file: 'roles.sql', roles: ['agentx_owner', 'agentx_app', 'agentx_backup'], count: 3 },
      { file: 'zitadel-role.sql', roles: ['zitadel'], count: 1 },
    ]);
    expect(bootstrap.databases).toEqual([
      {
        file: 'database.sql',
        database: 'agentx',
        owner: 'agentx_owner',
        statements: [
          'CREATE DATABASE "agentx" OWNER agentx_owner',
          'REVOKE ALL ON DATABASE "agentx" FROM PUBLIC',
          'GRANT CONNECT ON DATABASE "agentx" TO agentx_app, agentx_backup',
        ],
      },
      {
        file: 'zitadel-database.sql',
        database: 'zitadel',
        owner: 'zitadel',
        statements: ['CREATE DATABASE zitadel OWNER zitadel', 'REVOKE ALL ON DATABASE zitadel FROM PUBLIC'],
      },
    ]);
  });

  it.each([
    [
      'a psql meta-command',
      'roles.sql',
      (sql: string) => `\\set ON_ERROR_STOP on\n${sql}`,
      'roles.sql has a psql meta-command, which only psql understands',
    ],
    [
      'another psql variable',
      'zitadel-role.sql',
      (sql: string) => `${sql}\nALTER ROLE zitadel PASSWORD :'login';`,
      'zitadel-role.sql has a psql variable other than :"db"',
    ],
    ['no statements', 'zitadel-database.sql', () => '-- nothing here\n', 'zitadel-database.sql has no statements'],
  ])('refuses a file with %s', async (_, file, change, problem) => {
    await expect(loadBootstrap(bootstrapWith(file, change), 'agentx')).rejects.toEqual(
      new ServerSetupRefused([problem]),
    );
  });

  it('refuses a database name that needs quoting', async () => {
    await expect(loadBootstrap(BOOTSTRAP, 'Agent"X')).rejects.toEqual(
      new ServerSetupRefused(['Agent"X is not a plain Postgres name']),
    );
  });
});

describe('setUpServer', () => {
  it("refuses to make the login service's database the app's, before it connects", async () => {
    const logger = createLogger({
      service: 'db-setup-test',
      config: { environment: 'test', release: 'test', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: { write: () => true },
    });
    const attempt = setUpServer({
      // Port 1: nothing answers there, so a connection attempt would fail differently.
      admin: { host: '127.0.0.1', port: 1, database: 'postgres', user: 'admin', password: 'x', tls: 'disable' },
      database: 'zitadel',
      logins: { owner: 'a', app: 'b', backup: 'c', zitadel: 'd' },
      directory: BOOTSTRAP,
      logger,
    });
    await expect(attempt).rejects.toEqual(
      new ServerSetupRefused(["the app's database can't be zitadel, the login service's own"]),
    );
  });
});

/** A role as db/bootstrap makes it, with only its differences from the rest given. */
const role = (rolname: string, rolinherit = false, rolbypassrls = false): RoleRow => ({
  rolname,
  rolsuper: false,
  rolinherit,
  rolcreaterole: false,
  rolcreatedb: false,
  rolcanlogin: true,
  rolreplication: false,
  rolbypassrls,
});

const ROLES: readonly RoleRow[] = [
  role('agentx_owner', true),
  role('agentx_app'),
  role('agentx_backup', false, true),
  role('zitadel'),
];

describe('roleProblems', () => {
  it('passes the four roles as db/bootstrap makes them, members of nothing', () => {
    expect(roleProblems(ROLES, [])).toEqual([]);
  });

  it('names a missing role', () => {
    expect(roleProblems(ROLES.slice(0, 3), [])).toEqual(['zitadel does not exist']);
  });

  it.each([
    ['rolsuper', true],
    ['rolcreaterole', true],
    ['rolcreatedb', true],
    ['rolreplication', true],
    ['rolcanlogin', false],
    ['rolinherit', true],
    ['rolbypassrls', true],
  ] as const)('names a role whose %s was made %s', (attribute, value) => {
    const rows = ROLES.map((row) => (row.rolname === 'agentx_app' ? { ...row, [attribute]: value } : row));
    expect(roleProblems(rows, [])).toEqual(['agentx_app does not have the attributes db/bootstrap gives it']);
  });

  it('names every membership it is shown', () => {
    expect(
      roleProblems(ROLES, [
        { member: 'agentx_owner', role: 'agentx_app' },
        { member: 'cloud_admin', role: 'zitadel' },
      ]),
    ).toEqual([
      'agentx_owner is a member of agentx_app, which db/bootstrap never grants',
      'cloud_admin is a member of zitadel, which db/bootstrap never grants',
    ]);
  });
});

const DATABASES: readonly DatabaseRow[] = [
  { name: 'agentx', owner: 'agentx_owner', defaults: false },
  { name: 'zitadel', owner: 'zitadel', defaults: false },
];
const GRANTS: readonly GrantRow[] = [
  { name: 'agentx', grantee: 'agentx_backup', privilege: 'CONNECT' },
  { name: 'agentx', grantee: 'agentx_app', privilege: 'CONNECT' },
];

describe('databaseProblems', () => {
  it('passes the two databases owned by their roles, the app and backup roles let into the app database only', () => {
    expect(databaseProblems('agentx', DATABASES, GRANTS)).toEqual([]);
  });

  it('names a missing database', () => {
    expect(databaseProblems('agentx', DATABASES.slice(0, 1), GRANTS)).toEqual(['the database zitadel does not exist']);
  });

  it('names a database owned by another role', () => {
    const rows = [DATABASES[0], { name: 'zitadel', owner: 'agentx_owner', defaults: false }].filter(
      (row) => row !== undefined,
    );
    expect(databaseProblems('agentx', rows, GRANTS)).toEqual([
      'the database zitadel is owned by agentx_owner, not zitadel',
    ]);
  });

  it("names a database that still has Postgres's default rights", () => {
    const rows = DATABASES.map((row) => ({ ...row, defaults: row.name === 'agentx' }));
    expect(databaseProblems('agentx', rows, [])).toEqual([
      "the database agentx still has Postgres's default rights: PUBLIC may connect",
    ]);
  });

  it('names who else is let in, and who should be, in the same order whatever order the server gives', () => {
    const grants = [...GRANTS, { name: 'agentx', grantee: 'PUBLIC', privilege: 'TEMPORARY' }];
    expect(databaseProblems('agentx', DATABASES, grants)).toEqual([
      'the database agentx lets in PUBLIC TEMPORARY, agentx_app CONNECT, agentx_backup CONNECT besides its owner, not agentx_app CONNECT, agentx_backup CONNECT',
    ]);
    expect(databaseProblems('agentx', DATABASES, GRANTS.slice(0, 1))).toEqual([
      'the database agentx lets in agentx_backup CONNECT besides its owner, not agentx_app CONNECT, agentx_backup CONNECT',
    ]);
    expect(
      databaseProblems('agentx', DATABASES, [
        ...GRANTS,
        { name: 'zitadel', grantee: 'agentx_app', privilege: 'CONNECT' },
      ]),
    ).toEqual(['the database zitadel lets in agentx_app CONNECT besides its owner, not no one']);
    expect(databaseProblems('agentx', DATABASES, [])).toEqual([
      'the database agentx lets in no one besides its owner, not agentx_app CONNECT, agentx_backup CONNECT',
    ]);
  });
});

describe('publicSchemaProblems', () => {
  it.each(['agentx_owner', 'pg_database_owner', undefined])(
    'passes a public schema owned by %s, PUBLIC with no right on it',
    (owner) => {
      expect(publicSchemaProblems('agentx', owner, [])).toEqual([]);
    },
  );

  it('names a public schema someone else owns, and every right PUBLIC keeps on it', () => {
    expect(publicSchemaProblems('agentx', 'azure_pg_admin', ['CREATE', 'USAGE'])).toEqual([
      "the public schema of agentx is owned by azure_pg_admin, not the database's owner",
      'PUBLIC still has CREATE, USAGE on the public schema of agentx',
    ]);
  });
});

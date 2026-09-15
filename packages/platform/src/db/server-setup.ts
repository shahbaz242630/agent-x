// A new Postgres server's roles and databases (ADR-002, ADR-005 §3), set up
// by the database set-up job (apps/db-setup) as the server admin. The same
// job runs against the compose stack's Postgres, where the admin is the
// superuser, and against Azure's, where the admin has CREATEROLE and CREATEDB
// but is no superuser (Database.md "Setting up a new server").
//
// - The roles and databases come from db/bootstrap, sent one statement at a
//   time, as psql does. A file runs only when none of what it creates exists,
//   and the job stops when some of it does and some doesn't: a half-made
//   server is repaired by hand, never guessed at.
// - Every role gets its login as a SCRAM verifier worked out here
//   (scram.ts), so the login itself never reaches the server or its log.
// - An admin that isn't a superuser can create a database owned by another
//   role, or change that database's rights, only with that role's rights
//   (PostgreSQL 16 and later). The job lends itself those rights for exactly
//   those steps and takes them back after, leaving the admin with only the
//   ADMIN OPTION Postgres gives the creator of a role.
// - Azure gives the public schema of every new database to its own admin
//   group and lets every role create objects there, unlike Postgres since
//   version 15. In the app's database the job lays it out as Postgres does:
//   the database's owner controls it, and PUBLIC has no right on it.
// - It then checks the result and refuses a server that differs from
//   db/bootstrap: a role with other attributes, a database with other
//   owners or rights, a public schema someone else owns or PUBLIC may use.
//   The checks are plain functions over what the server reports, so each is
//   tested on its own (server-setup.test.ts).
// - It is safe to run again: it creates only what is missing and sets every
//   login afresh, which is how a login is rotated.
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import pg from 'pg';

import type { Logger } from '../observability/index.ts';
import { type DatabaseConnectionOptions, poolConfig } from './database.ts';
import { scramVerifier } from './scram.ts';
import { splitStatements } from './sql-statements.ts';

/** The roles the job gives logins to, by what they're for. */
export type SetupLogins = Readonly<Record<'owner' | 'app' | 'backup' | 'zitadel', string>>;

const ROLE: Readonly<Record<keyof SetupLogins, string>> = {
  owner: 'agentx_owner',
  app: 'agentx_app',
  backup: 'agentx_backup',
  zitadel: 'zitadel',
};

/** The login service's database, beside the app's (ADR-002). */
const ZITADEL_DATABASE = 'zitadel';

/** An arbitrary advisory-lock key, used only by this job, so two runs can't interleave. */
const LOCK_KEY = 7_402_531_127;

/** The one psql variable db/bootstrap uses: the app database's name, in database.sql. */
const DATABASE_VARIABLE = ':"db"';

const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

export interface ServerSetupOptions {
  /** The server admin's connection, to a database that exists on every server (postgres). */
  readonly admin: DatabaseConnectionOptions;
  /** The app's database to create (agentx). */
  readonly database: string;
  /** Each role's login. Never logged; sent only as a SCRAM verifier. */
  readonly logins: SetupLogins;
  /** The folder of bootstrap files, db/bootstrap. */
  readonly directory: string;
  readonly logger: Logger;
}

export interface ServerSetupOutcome {
  readonly rolesCreated: readonly string[];
  readonly databasesCreated: readonly string[];
}

/** The bootstrap files, or the server afterwards, aren't what db/bootstrap says. Names only, never values. */
export class ServerSetupRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`Server set-up refused: ${problems.join('; ')}`);
    this.name = 'ServerSetupRefused';
    this.problems = problems;
  }
}

/** A role file, what it creates (all of it in one transaction), and its statements. */
interface RoleStep {
  readonly file: string;
  readonly roles: readonly string[];
  readonly statements: readonly string[];
}

/** A database file, the database it creates and the role that owns it, and its statements. */
interface DatabaseStep {
  readonly file: string;
  readonly database: string;
  readonly owner: string;
  readonly statements: readonly string[];
}

/** db/bootstrap, read and ready to send, in the order the job runs it. */
export interface Bootstrap {
  readonly roles: readonly RoleStep[];
  readonly databases: readonly DatabaseStep[];
}

const quoted = (name: string): string => {
  if (!IDENTIFIER.test(name)) throw new ServerSetupRefused([`${name} is not a plain Postgres name`]);
  return `"${name}"`;
};

/**
 * Reads each bootstrap file and fills in the database's name. Anything psql
 * would treat specially, other than that one variable, is refused: the job
 * sends the statements as they are.
 */
export async function loadBootstrap(directory: string, database: string): Promise<Bootstrap> {
  const problems: string[] = [];
  const statementsOf = async (file: string): Promise<string[]> => {
    const sql = (await readFile(path.join(directory, file), 'utf8'))
      .replaceAll('\r\n', '\n')
      .replaceAll(DATABASE_VARIABLE, quoted(database));
    if (/^\s*\\/m.test(sql)) problems.push(`${file} has a psql meta-command, which only psql understands`);
    if (/:["'][A-Za-z_]/.test(sql)) problems.push(`${file} has a psql variable other than ${DATABASE_VARIABLE}`);
    const statements = splitStatements(sql);
    if (statements.length === 0) problems.push(`${file} has no statements`);
    return statements;
  };
  const bootstrap: Bootstrap = {
    roles: [
      { file: 'roles.sql', roles: [ROLE.owner, ROLE.app, ROLE.backup], statements: await statementsOf('roles.sql') },
      { file: 'zitadel-role.sql', roles: [ROLE.zitadel], statements: await statementsOf('zitadel-role.sql') },
    ],
    databases: [
      { file: 'database.sql', database, owner: ROLE.owner, statements: await statementsOf('database.sql') },
      {
        file: 'zitadel-database.sql',
        database: ZITADEL_DATABASE,
        owner: ROLE.zitadel,
        statements: await statementsOf('zitadel-database.sql'),
      },
    ],
  };
  if (problems.length > 0) throw new ServerSetupRefused(problems);
  return bootstrap;
}

// The checks: what the server reports, judged against what db/bootstrap makes.

export interface RoleRow {
  readonly rolname: string;
  readonly rolsuper: boolean;
  readonly rolinherit: boolean;
  readonly rolcreaterole: boolean;
  readonly rolcreatedb: boolean;
  readonly rolcanlogin: boolean;
  readonly rolreplication: boolean;
  readonly rolbypassrls: boolean;
}

/** A membership of one of our roles, or one the admin granted itself in one. */
export interface MembershipRow {
  readonly member: string;
  readonly role: string;
}

/** The attributes db/bootstrap gives each role that differ between them. */
const EXPECTED_ROLES: Readonly<Record<string, { inherit: boolean; bypassRls: boolean }>> = {
  [ROLE.owner]: { inherit: true, bypassRls: false },
  [ROLE.app]: { inherit: false, bypassRls: false },
  [ROLE.backup]: { inherit: false, bypassRls: true },
  [ROLE.zitadel]: { inherit: false, bypassRls: false },
};

/** Each role as db/bootstrap makes it, and no membership db/bootstrap never grants. */
export function roleProblems(rows: readonly RoleRow[], memberships: readonly MembershipRow[]): string[] {
  const attributes = Object.entries(EXPECTED_ROLES).flatMap(([name, expected]) => {
    const row = rows.find((candidate) => candidate.rolname === name);
    if (row === undefined) return [`${name} does not exist`];
    const same =
      row.rolcanlogin &&
      !row.rolsuper &&
      !row.rolcreaterole &&
      !row.rolcreatedb &&
      !row.rolreplication &&
      row.rolinherit === expected.inherit &&
      row.rolbypassrls === expected.bypassRls;
    return same ? [] : [`${name} does not have the attributes db/bootstrap gives it`];
  });
  return [
    ...attributes,
    ...memberships.map(({ member, role }) => `${member} is a member of ${role}, which db/bootstrap never grants`),
  ];
}

export interface DatabaseRow {
  readonly name: string;
  readonly owner: string;
  /** True when the database still has Postgres's default rights (no ACL at all), which let PUBLIC connect. */
  readonly defaults: boolean;
}

/** One right on a database, given to a role other than its owner (PUBLIC by that name). */
export interface GrantRow {
  readonly name: string;
  readonly grantee: string;
  readonly privilege: string;
}

/** Each database owned by its role, with no one but the roles that belong there let in. */
export function databaseProblems(
  database: string,
  rows: readonly DatabaseRow[],
  grants: readonly GrantRow[],
): string[] {
  const expected: readonly { name: string; owner: string; connect: readonly string[] }[] = [
    { name: database, owner: ROLE.owner, connect: [ROLE.app, ROLE.backup] },
    { name: ZITADEL_DATABASE, owner: ROLE.zitadel, connect: [] },
  ];
  return expected.flatMap(({ name, owner, connect }) => {
    const row = rows.find((candidate) => candidate.name === name);
    if (row === undefined) return [`the database ${name} does not exist`];
    if (row.owner !== owner) return [`the database ${name} is owned by ${row.owner}, not ${owner}`];
    if (row.defaults) return [`the database ${name} still has Postgres's default rights: PUBLIC may connect`];
    // Sorted here, not by the server, whose collation could order PUBLIC anywhere.
    const actual = grants
      .filter((grant) => grant.name === name)
      .map((grant) => `${grant.grantee} ${grant.privilege}`)
      .sort();
    const wanted = connect.map((role) => `${role} CONNECT`).sort();
    const described = (list: readonly string[]): string => (list.length === 0 ? 'no one' : list.join(', '));
    return actual.join(',') === wanted.join(',')
      ? []
      : [`the database ${name} lets in ${described(actual)} besides its owner, not ${described(wanted)}`];
  });
}

/** Who may own the public schema: the database's owner, or Postgres's stand-in for it. */
const PUBLIC_SCHEMA_OWNERS: readonly string[] = [ROLE.owner, 'pg_database_owner'];

/** In the app's database: the owner controls the public schema, if there is one, and PUBLIC has no right on it. */
export function publicSchemaProblems(
  database: string,
  owner: string | undefined,
  publicPrivileges: readonly string[],
): string[] {
  return [
    ...(owner === undefined || PUBLIC_SCHEMA_OWNERS.includes(owner)
      ? []
      : [`the public schema of ${database} is owned by ${owner}, not the database's owner`]),
    ...(publicPrivileges.length === 0
      ? []
      : [`PUBLIC still has ${publicPrivileges.join(', ')} on the public schema of ${database}`]),
  ];
}

// The work.

type Client = pg.Client;

async function connect(options: DatabaseConnectionOptions, logger: Logger): Promise<Client> {
  const client = new pg.Client(poolConfig({ ...options, applicationName: 'agentx-db-setup' }));
  // A lost connection is also reported as an event; with no listener, Node
  // would crash the process instead of letting the failing query report it.
  client.on('error', (error: unknown) => {
    logger.error('db_setup.connection_lost', { err: error });
  });
  await client.connect();
  return client;
}

/** Runs each statement on its own, as psql does. */
async function run(client: Client, statements: readonly string[]): Promise<void> {
  for (const statement of statements) {
    // eslint-disable-next-line agentx/no-string-built-sql -- db/bootstrap is reviewed SQL from the repository, the one other place SQL text comes from a file; the database name filled in is checked as a plain Postgres name.
    await client.query(statement);
  }
}

async function existingRoles(client: Client, names: readonly string[]): Promise<string[]> {
  const { rows } = await client.query<{ name: string }>(
    'select rolname as name from pg_catalog.pg_roles where rolname = any($1) order by 1',
    [names],
  );
  return rows.map((row) => row.name);
}

async function databaseExists(client: Client, name: string): Promise<boolean> {
  const { rows } = await client.query('select 1 from pg_catalog.pg_database where datname = $1', [name]);
  return rows.length > 0;
}

/** Runs `work` in a transaction. A rollback that fails too is logged; the error that caused it is what's thrown. */
async function inTransaction(client: Client, logger: Logger, work: () => Promise<void>): Promise<void> {
  await client.query('begin');
  try {
    await work();
    await client.query('commit');
  } catch (error) {
    // If the rollback fails too, the connection is gone, and closing it rolls back anyway.
    await client.query('rollback').catch((rollbackError: unknown) => {
      logger.warn('db_setup.rollback_failed', { err: rollbackError });
    });
    throw error;
  }
}

/** Runs a role file when none of its roles exist, in one transaction. Returns what it created. */
async function createRoles(client: Client, logger: Logger, step: RoleStep): Promise<readonly string[]> {
  const found = await existingRoles(client, step.roles);
  if (found.length === step.roles.length) return [];
  if (found.length > 0) {
    throw new ServerSetupRefused([
      `${step.file} creates ${step.roles.join(', ')}, but only ${found.join(', ')} exist: repair the server by hand`,
    ]);
  }
  await inTransaction(client, logger, () => run(client, step.statements));
  logger.info('db_setup.roles_created', { file: step.file, roles: step.roles });
  return step.roles;
}

/**
 * Runs `work` with the owner's rights. A superuser has them already; any other
 * admin grants itself membership in the owner for the length of the work and
 * revokes it after, which drops only the grant it made itself.
 */
async function withOwnerRights(
  client: Client,
  logger: Logger,
  owner: { readonly role: string; readonly superuser: boolean },
  work: () => Promise<void>,
): Promise<void> {
  if (owner.superuser) return work();
  // eslint-disable-next-line agentx/no-string-built-sql -- A role name can't be a bound parameter; it's one of this file's fixed names, checked as a plain Postgres name.
  await client.query(`grant ${quoted(owner.role)} to current_user with inherit true, set true`);
  // eslint-disable-next-line agentx/no-string-built-sql -- As above: a fixed role name, checked.
  const giveBack = (): Promise<unknown> => client.query(`revoke ${quoted(owner.role)} from current_user`);
  try {
    await work();
  } catch (error) {
    // The next run's check reports a grant left behind, and its own run takes it back; the work's error is what's thrown.
    await giveBack().catch((revokeError: unknown) => {
      logger.warn('db_setup.owner_rights_kept', { role: owner.role, err: revokeError });
    });
    throw error;
  }
  await giveBack();
}

/** Gives every role its login, together: all of them change, or none does. */
async function setLogins(client: Client, logger: Logger, logins: SetupLogins): Promise<void> {
  const roles = Object.entries(ROLE) as [keyof SetupLogins, string][];
  await inTransaction(client, logger, async () => {
    for (const [use, role] of roles) {
      // eslint-disable-next-line agentx/no-string-built-sql -- ALTER ROLE takes no bound parameters. The role is a fixed name, checked; a verifier holds only base64, digits, `$` and `:`, nothing that could end the quoted string (scram.ts).
      await client.query(`alter role ${quoted(role)} password '${scramVerifier(logins[use])}'`);
    }
  });
  logger.info('db_setup.logins_set', { roles: roles.map(([, role]) => role) });
}

/** Who owns the app database's public schema, or undefined when it has none. */
async function publicSchemaOwner(client: Client): Promise<string | undefined> {
  const { rows } = await client.query<{ owner: string }>(
    "select pg_catalog.pg_get_userbyid(nspowner) as owner from pg_catalog.pg_namespace where nspname = 'public'",
  );
  return rows[0]?.owner;
}

/**
 * In the app's database, the public schema as Postgres lays it out since
 * version 15: the database's owner controls it, and PUBLIC may do nothing
 * there. Azure hands it to its own admin group and lets every role create
 * objects in it; the baseline migration, which runs as the owner, can then
 * neither revoke that nor run at all. So the job gives the schema to the
 * owner, as Postgres would, and takes PUBLIC's rights away. Returns what the
 * check finds afterwards.
 */
async function securePublicSchema(client: Client, logger: Logger, database: string): Promise<string[]> {
  const before = await publicSchemaOwner(client);
  if (before !== undefined) {
    if (!PUBLIC_SCHEMA_OWNERS.includes(before)) {
      await client.query('alter schema public owner to agentx_owner');
      logger.info('db_setup.public_schema_given_to_owner', { from: before });
    }
    await client.query('revoke all on schema public from public');
  }
  const { rows } = await client.query<{ privilege: string }>(
    `select acl.privilege_type as privilege
     from pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) acl
     where n.nspname = 'public' and acl.grantee = 0
     order by 1`,
  );
  return publicSchemaProblems(
    database,
    await publicSchemaOwner(client),
    rows.map((row) => row.privilege),
  );
}

/** The roles and databases as the server reports them, judged. */
async function serverProblems(client: Client, database: string): Promise<string[]> {
  const names = Object.keys(EXPECTED_ROLES);
  const { rows: roles } = await client.query<RoleRow>(
    `select rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls
     from pg_catalog.pg_roles where rolname = any($1)`,
    [names],
  );
  const { rows: memberships } = await client.query<MembershipRow>(
    `select member.rolname as member, granted.rolname as role
     from pg_catalog.pg_auth_members m
     join pg_catalog.pg_roles member on member.oid = m.member
     join pg_catalog.pg_roles granted on granted.oid = m.roleid
     where member.rolname = any($1) or (m.member = m.grantor and granted.rolname = any($1))
     order by 1, 2`,
    [names],
  );
  const databases = [database, ZITADEL_DATABASE];
  const { rows } = await client.query<DatabaseRow>(
    `select datname as name, pg_catalog.pg_get_userbyid(datdba) as owner, datacl is null as defaults
     from pg_catalog.pg_database where datname = any($1)`,
    [databases],
  );
  const { rows: grants } = await client.query<GrantRow>(
    `select d.datname as name, coalesce(grantee.rolname, 'PUBLIC') as grantee, acl.privilege_type as privilege
     from pg_catalog.pg_database d, pg_catalog.aclexplode(d.datacl) acl
     left join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
     where d.datname = any($1) and acl.grantee <> d.datdba`,
    [databases],
  );
  return [...roleProblems(roles, memberships), ...databaseProblems(database, rows, grants)];
}

/** Sets up the server, checks it, and returns what was created. Throws ServerSetupRefused listing every problem. */
export async function setUpServer(options: ServerSetupOptions): Promise<ServerSetupOutcome> {
  const { database, logger } = options;
  if (database === ZITADEL_DATABASE) {
    throw new ServerSetupRefused(["the app's database can't be zitadel, the login service's own"]);
  }
  const bootstrap = await loadBootstrap(options.directory, database);
  const admin = await connect(options.admin, logger);
  try {
    await admin.query('select pg_catalog.pg_advisory_lock($1)', [LOCK_KEY]);
    const { rows } = await admin.query<{ superuser: boolean }>(
      'select rolsuper as superuser from pg_catalog.pg_roles where rolname = current_user',
    );
    const superuser = rows[0]?.superuser === true;

    const rolesCreated: string[] = [];
    for (const step of bootstrap.roles) rolesCreated.push(...(await createRoles(admin, logger, step)));
    await setLogins(admin, logger, options.logins);

    const databasesCreated: string[] = [];
    const schemaProblems: string[] = [];
    for (const step of bootstrap.databases) {
      const missing = !(await databaseExists(admin, step.database));
      const isApp = step.database === database;
      if (!missing && !isApp) continue;
      await withOwnerRights(admin, logger, { role: step.owner, superuser }, async () => {
        if (missing) {
          await run(admin, step.statements);
          databasesCreated.push(step.database);
          logger.info('db_setup.database_created', { file: step.file, database: step.database });
        }
        if (!isApp) return;
        const inside = await connect({ ...options.admin, database }, logger);
        try {
          schemaProblems.push(...(await securePublicSchema(inside, logger, database)));
        } finally {
          await inside.end();
        }
      });
    }

    const problems = [...(await serverProblems(admin, database)), ...schemaProblems];
    if (problems.length > 0) throw new ServerSetupRefused(problems);
    return { rolesCreated, databasesCreated };
  } finally {
    await admin.end();
  }
}

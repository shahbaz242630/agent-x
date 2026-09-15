// The database set-up job's work (setUpServer) on a server of its own, laid
// out the way Azure's is (ADR-002; Database.md "Setting up a new server"):
// the admin has CREATEROLE and CREATEDB but is no superuser, it belongs to a
// group that owns the public schema of every new database, and every role
// may create objects there. The shared test server can't serve: its roles
// already exist, and other test files log in with their passwords.
// The steps run in order, each on the server the one before left.
import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { runMigrations } from '../../packages/platform/src/db/index.ts';
import { scramVerifier } from '../../packages/platform/src/db/scram.ts';
import { ServerSetupRefused, type SetupLogins, setUpServer } from '../../packages/platform/src/db/server-setup.ts';
import { createLogger } from '../../packages/platform/src/observability/index.ts';
import { findLeaks, LogCapture, openClient, queryOnce } from '../../packages/testing/src/index.ts';
import { containerLogs, type PostgresContainer, psql, startPostgres } from '../test-db/docker.ts';
import { POSTGRES_IMAGES } from '../test-db/postgres-images.ts';

const server = inject('postgres');
const BOOTSTRAP = fileURLToPath(new URL('../../db/bootstrap', import.meta.url));
const APP_DATABASE = 'agentx';

/** A fresh login, random, for this run only. */
const newLogin = (): string => randomBytes(18).toString('hex');
const newLogins = (): SetupLogins => ({ owner: newLogin(), app: newLogin(), backup: newLogin(), zitadel: newLogin() });

const superuserLogin = newLogin();
const adminLogin = newLogin();
const weakAdminLogin = newLogin();
/** Every login handed out in this file, to look for in the server's log. */
const handedOut: string[] = [superuserLogin, adminLogin, weakAdminLogin];

/** The Azure-like layout, made by the superuser before the job runs. */
const AZURE_LAYOUT = `
CREATE ROLE azure_pg_admin NOLOGIN;
CREATE ROLE cloud_admin LOGIN CREATEROLE CREATEDB BYPASSRLS PASSWORD :'admin_login';
CREATE ROLE weak_admin LOGIN CREATEROLE CREATEDB NOBYPASSRLS PASSWORD :'weak_login';
GRANT azure_pg_admin TO cloud_admin, weak_admin;
ALTER SYSTEM SET log_statement = 'all';
SELECT pg_catalog.pg_reload_conf();
\\c template1
ALTER SCHEMA public OWNER TO azure_pg_admin;
GRANT ALL ON SCHEMA public TO PUBLIC;
`;

let container: PostgresContainer;
let logins: SetupLogins;

beforeAll(async () => {
  const image = Object.values(POSTGRES_IMAGES).find((candidate) => candidate.startsWith(`postgres:${server.version}-`));
  if (image === undefined) throw new Error(`no pinned image for Postgres ${server.version}`);
  container = await startPostgres(image, superuserLogin, Date.now());
  await psql(container.id, AZURE_LAYOUT, { admin_login: adminLogin, weak_login: weakAdminLogin });
}, 600_000);

afterAll(async () => {
  await container.stop();
});

const connection = (user: string, password: string, database = 'postgres') => ({
  host: '127.0.0.1',
  port: container.port,
  database,
  user,
  password,
  tls: 'disable' as const,
});

/** One query as a login, on a connection of its own. */
const queryAs = <Row extends object = Record<string, unknown>>(
  user: string,
  login: string,
  database: string,
  text: string,
): Promise<Row[]> => queryOnce<Row>(connection(user, login, database), text);

const asSuperuser = <Row extends object = Record<string, unknown>>(
  text: string,
  database = 'postgres',
): Promise<Row[]> => queryAs<Row>('postgres', superuserLogin, database, text);

/** Starts a run, and hands back its log as it is written, whether the run ends well or not. */
function start(admin: { user: string; login: string }, roleLogins: SetupLogins, database = APP_DATABASE) {
  handedOut.push(...Object.values(roleLogins));
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'db-setup-test',
    config: { environment: 'test', release: 'test', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  const run = setUpServer({
    admin: connection(admin.user, admin.login),
    database,
    logins: roleLogins,
    directory: BOOTSTRAP,
    logger,
  });
  return { run, capture, events: () => capture.lines().map((line) => line.event) };
}

async function setUp(admin: { user: string; login: string }, roleLogins: SetupLogins, database = APP_DATABASE) {
  const { run, capture } = start(admin, roleLogins, database);
  return { outcome: await run, capture };
}

const cloudAdmin = () => ({ user: 'cloud_admin', login: adminLogin });

/** The job's server process once it has reached a step, waiting there, from Postgres's own view of it. */
async function jobWaitingAt(step: 'a lock' | 'CREATE DATABASE'): Promise<number> {
  const text =
    step === 'a lock'
      ? "select pid from pg_catalog.pg_stat_activity where application_name = 'agentx-db-setup' and wait_event_type = 'Lock'"
      : "select pid from pg_catalog.pg_stat_activity where application_name = 'agentx-db-setup' and query like 'CREATE DATABASE%'";
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const [found] = await asSuperuser<{ pid: number }>(text);
    if (found !== undefined) return found.pid;
    await sleep(25);
  }
  throw new Error(`the set-up job never waited at ${step}`);
}

/** The memberships the admin granted itself, which a run takes back when it is done. */
const selfGrants = () =>
  asSuperuser<{ role: string }>(
    `select granted.rolname as role from pg_catalog.pg_auth_members m
     join pg_catalog.pg_roles granted on granted.oid = m.roleid
     where m.member = 'cloud_admin'::regrole and m.grantor = m.member`,
  );

describe(`the database set-up job on an Azure-like server (Postgres ${server.version})`, () => {
  it("stops at the roles when the admin can't give agentx_backup BYPASSRLS, and leaves the server as it was", async () => {
    const attempt = setUp({ user: 'weak_admin', login: weakAdminLogin }, newLogins());
    await expect(attempt).rejects.toMatchObject({ code: '42501' });
    expect(
      await asSuperuser<{ rolname: string }>(
        "select rolname from pg_catalog.pg_roles where rolname like 'agentx\\_%' or rolname = 'zitadel'",
      ),
    ).toEqual([]);
  });

  it('sets up a new server as an admin that is no superuser: four roles, two databases', async () => {
    logins = newLogins();
    const { outcome, capture } = await setUp(cloudAdmin(), logins);
    expect(outcome).toEqual({
      rolesCreated: ['agentx_owner', 'agentx_app', 'agentx_backup', 'zitadel'],
      databasesCreated: [APP_DATABASE, 'zitadel'],
    });
    expect(capture.lines().map((line) => line.event)).toEqual([
      'db_setup.roles_created',
      'db_setup.roles_created',
      'db_setup.logins_set',
      'db_setup.database_created',
      'db_setup.public_schema_given_to_owner',
      'db_setup.database_created',
    ]);
    expect(findLeaks(capture.text, Object.values(logins))).toEqual([]);
  });

  it('gives each role exactly the attributes db/bootstrap writes', async () => {
    const rows = await asSuperuser(
      `select rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls
       from pg_catalog.pg_roles where rolname like 'agentx\\_%' or rolname = 'zitadel' order by rolname`,
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
      { rolname: 'zitadel', ...role, rolinherit: false, rolbypassrls: false },
    ]);
  });

  it("leaves the admin only the ADMIN OPTION Postgres gives a role's creator: no lent rights stay", async () => {
    const rows = await asSuperuser(
      `select granted.rolname as role, grantor.rolname as grantor, m.admin_option, m.inherit_option, m.set_option
       from pg_catalog.pg_auth_members m
       join pg_catalog.pg_roles granted on granted.oid = m.roleid
       join pg_catalog.pg_roles grantor on grantor.oid = m.grantor
       where m.member = 'cloud_admin'::regrole and granted.rolname <> 'azure_pg_admin'
       order by 1`,
    );
    const creator = { grantor: 'postgres', admin_option: true, inherit_option: false, set_option: false };
    expect(rows).toEqual(
      ['agentx_app', 'agentx_backup', 'agentx_owner', 'zitadel'].map((name) => ({ role: name, ...creator })),
    );
  });

  it("makes each database its role's, and lets in only the roles that belong there", async () => {
    const owners = await asSuperuser(
      `select datname, pg_catalog.pg_get_userbyid(datdba) as owner from pg_catalog.pg_database
       where datname in ('agentx', 'zitadel') order by 1`,
    );
    expect(owners).toEqual([
      { datname: APP_DATABASE, owner: 'agentx_owner' },
      { datname: 'zitadel', owner: 'zitadel' },
    ]);
    await expect(queryAs('agentx_app', logins.app, APP_DATABASE, 'select 1 as one')).resolves.toEqual([{ one: 1 }]);
    await expect(queryAs('agentx_backup', logins.backup, APP_DATABASE, 'select 1 as one')).resolves.toHaveLength(1);
    await expect(queryAs('agentx_owner', logins.owner, APP_DATABASE, 'select 1 as one')).resolves.toHaveLength(1);
    await expect(queryAs('zitadel', logins.zitadel, 'zitadel', 'select 1 as one')).resolves.toHaveLength(1);
    await expect(queryAs('agentx_app', logins.app, 'zitadel', 'select 1')).rejects.toMatchObject({ code: '42501' });
    await expect(queryAs('zitadel', logins.zitadel, APP_DATABASE, 'select 1')).rejects.toMatchObject({ code: '42501' });
  });

  it('works out the verifier Postgres itself makes from the same login and salt', async () => {
    // Postgres hashes a login sent as it is, with SCRAM-SHA-256 by default since version 14: the one
    // place in this file a login reaches the server, for a throwaway role, so the job's arithmetic is
    // checked against Postgres's own. Any other hashing would store another format, and fail below.
    const login = newLogin();
    await psql(container.id, "CREATE ROLE verifier_check LOGIN PASSWORD :'login';", { login });
    try {
      const [stored] = await asSuperuser<{ verifier: string }>(
        "select rolpassword as verifier from pg_catalog.pg_authid where rolname = 'verifier_check'",
      );
      const [, head = ''] = (stored?.verifier ?? '').split('$');
      const [iterations = '', salt = ''] = head.split(':');
      expect(Number(iterations)).toBe(4096);
      expect(scramVerifier(login, { salt: Buffer.from(salt, 'base64'), iterations: Number(iterations) })).toBe(
        stored?.verifier,
      );
    } finally {
      await asSuperuser('drop role verifier_check');
    }
  });

  it("gives the public schema Azure's admin group owns to the database's owner, and takes PUBLIC off it", async () => {
    expect(
      await asSuperuser(
        "select pg_catalog.pg_get_userbyid(nspowner) as owner from pg_catalog.pg_namespace where nspname = 'public'",
        APP_DATABASE,
      ),
    ).toEqual([{ owner: 'agentx_owner' }]);
    const rows = await asSuperuser(
      `select acl.privilege_type from pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) acl
       where n.nspname = 'public' and acl.grantee = 0`,
      APP_DATABASE,
    );
    expect(rows).toEqual([]);
    await expect(
      queryAs('agentx_app', logins.app, APP_DATABASE, 'create table public.planted (id int)'),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('leaves a server the migrations run on as the owner, where the baseline changes nothing it may not', async () => {
    const applied = await runMigrations({
      connection: connection('agentx_owner', logins.owner, APP_DATABASE),
      directory: fileURLToPath(new URL('../../db/migrations', import.meta.url)),
      logger: createLogger({
        service: 'db-setup-test',
        config: { environment: 'test', release: 'test', log: { level: 'warn', eventCapPerMinute: 1000 } },
        destination: { write: () => true },
      }),
    });
    expect(applied.length).toBeGreaterThan(0);
  });

  it('never sends a login to the server: with every statement logged, the log holds verifiers', async () => {
    const log = await containerLogs(container.id);
    expect(log).toMatch(/alter role "agentx_app" password 'SCRAM-SHA-256\$4096:/);
    expect(handedOut.filter((login) => log.includes(login))).toEqual([]);
  });

  it('runs again: creates nothing, and rotates every login', async () => {
    const rotated = newLogins();
    const { outcome } = await setUp(cloudAdmin(), rotated);
    expect(outcome).toEqual({ rolesCreated: [], databasesCreated: [] });
    await expect(queryAs('agentx_app', logins.app, APP_DATABASE, 'select 1')).rejects.toMatchObject({
      code: '28P01',
    });
    await expect(queryAs('agentx_app', rotated.app, APP_DATABASE, 'select 1 as one')).resolves.toHaveLength(1);
    logins = rotated;
  });

  it('puts back what PUBLIC was given on the public schema since', async () => {
    await asSuperuser('grant create on schema public to public', APP_DATABASE);
    await setUp(cloudAdmin(), logins);
    expect(
      await asSuperuser(
        `select 1 from pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) acl
         where n.nspname = 'public' and acl.grantee = 0`,
        APP_DATABASE,
      ),
    ).toEqual([]);
  });

  it('creates a missing database once, even with two runs at the same time', async () => {
    await asSuperuser('drop database zitadel');
    const runs = await Promise.all([setUp(cloudAdmin(), logins), setUp(cloudAdmin(), logins)]);
    expect(runs.flatMap((run) => run.outcome.databasesCreated)).toEqual(['zitadel']);
  });

  it.each([
    [
      'a role given an attribute',
      'alter role agentx_app createdb',
      'alter role agentx_app nocreatedb',
      'agentx_app does not have the attributes db/bootstrap gives it',
    ],
    [
      'a role made a member of another',
      'grant agentx_app to agentx_owner',
      'revoke agentx_app from agentx_owner',
      'agentx_owner is a member of agentx_app, which db/bootstrap never grants',
    ],
    [
      "another role let into the login service's database",
      'grant connect on database zitadel to agentx_app',
      'revoke connect on database zitadel from agentx_app',
      'the database zitadel lets in agentx_app CONNECT besides its owner, not no one',
    ],
    [
      'a role added to one of ours',
      'create role backdoor_member login in role zitadel',
      'drop role backdoor_member',
      'backdoor_member is a member of zitadel, which db/bootstrap never grants',
    ],
    [
      'the lent rights of an earlier run left behind',
      'grant zitadel to cloud_admin with set true granted by cloud_admin',
      'revoke zitadel from cloud_admin granted by cloud_admin',
      'cloud_admin is a member of zitadel, which db/bootstrap never grants',
    ],
    [
      "the login service's database handed to another role",
      'alter database zitadel owner to agentx_owner',
      'alter database zitadel owner to zitadel',
      'the database zitadel is owned by agentx_owner, not zitadel',
    ],
    [
      "the app's database opened to everyone",
      'grant connect on database agentx to public',
      'revoke connect on database agentx from public',
      'the database agentx lets in PUBLIC CONNECT, agentx_app CONNECT, agentx_backup CONNECT besides its owner, not agentx_app CONNECT, agentx_backup CONNECT',
    ],
  ])('refuses a server with %s, naming it', async (_, change, undo, problem) => {
    await asSuperuser(change);
    try {
      await expect(setUp(cloudAdmin(), logins)).rejects.toEqual(new ServerSetupRefused([problem]));
    } finally {
      await asSuperuser(undo);
    }
  });

  it('fails a run whose connection the server ends, logging why, and changes no login', async () => {
    const [before] = await asSuperuser("select rolpassword from pg_catalog.pg_authid where rolname = 'agentx_owner'");
    const blocker = await openClient(connection('postgres', superuserLogin));
    try {
      // Holds agentx_app's row, so the job waits inside its transaction after changing agentx_owner's login.
      await blocker.query('begin');
      await blocker.query('alter role agentx_app connection limit -1');
      const { run, events } = start(cloudAdmin(), newLogins());
      // Watched from the start: the run fails while the test is still cutting its connection.
      const ended = run.then(
        () => undefined,
        (error: unknown) => error,
      );
      await asSuperuser(`select pg_catalog.pg_terminate_backend(${String(await jobWaitingAt('a lock'))})`);
      expect(await ended).toMatchObject({ code: '57P01' });
      expect(events()).toEqual(expect.arrayContaining(['db_setup.connection_lost', 'db_setup.rollback_failed']));
    } finally {
      await blocker.query('rollback');
      await blocker.end();
    }
    expect(await asSuperuser("select rolpassword from pg_catalog.pg_authid where rolname = 'agentx_owner'")).toEqual([
      before,
    ]);
  });

  it('keeps the rights it lent itself when its connection is lost mid-step, and the next run takes them back', async () => {
    await asSuperuser('drop database zitadel');
    // CREATE DATABASE waits while anyone else is connected to the template it copies.
    const holder = await openClient(connection('postgres', superuserLogin, 'template1'));
    try {
      const { run, events } = start(cloudAdmin(), logins);
      const ended = run.then(
        () => undefined,
        (error: unknown) => error,
      );
      await asSuperuser(`select pg_catalog.pg_terminate_backend(${String(await jobWaitingAt('CREATE DATABASE'))})`);
      expect(await ended).toMatchObject({ code: '57P01' });
      expect(events()).toEqual(expect.arrayContaining(['db_setup.connection_lost', 'db_setup.owner_rights_kept']));
    } finally {
      await holder.end();
    }
    expect(await selfGrants()).toEqual([{ role: 'zitadel' }]);
    const { outcome } = await setUp(cloudAdmin(), logins);
    expect(outcome.databasesCreated).toEqual(['zitadel']);
    expect(await selfGrants()).toEqual([]);
  });

  it("refuses an ADMIN OPTION another admin gave it, which only Postgres's own grant to a role's creator is exempt from", async () => {
    // Postgres refuses an ADMIN OPTION a role grants itself, so the only other way in is another admin's grant.
    await asSuperuser(
      'create role other_admin nologin; grant zitadel to other_admin with admin true; ' +
        'grant zitadel to cloud_admin with admin true, inherit false, set false granted by other_admin',
    );
    try {
      await expect(setUp(cloudAdmin(), logins)).rejects.toEqual(
        new ServerSetupRefused([
          'cloud_admin is a member of zitadel, which db/bootstrap never grants',
          'other_admin is a member of zitadel, which db/bootstrap never grants',
        ]),
      );
    } finally {
      await asSuperuser('revoke zitadel from cloud_admin granted by other_admin; drop role other_admin');
    }
  });

  it('never runs an operator the migration role planted, and refuses to finish while one waits there (security review, S13)', async () => {
    const asOwner = (text: string) => queryAs('agentx_owner', logins.owner, APP_DATABASE, text);
    // An exact match for the job's own comparison of an oid with a number, in the public schema the
    // owner controls, and a schema named after the admin, which "$user" would put first on its path.
    await asOwner(
      "create function public.trap(a pg_catalog.oid, b pg_catalog.int4) returns boolean language plpgsql as $trap$\nbegin execute 'create role backdoor login in role zitadel'; return pg_catalog.oideq(a, b::pg_catalog.oid); end\n$trap$",
    );
    await asOwner(
      'create operator public.= (leftarg = pg_catalog.oid, rightarg = pg_catalog.int4, function = public.trap)',
    );
    await asOwner('create schema cloud_admin');
    try {
      await expect(setUp(cloudAdmin(), logins)).rejects.toEqual(
        new ServerSetupRefused([
          'the public schema of agentx holds 2 functions or operators; nothing of ours puts any there',
          'agentx has a schema named after the admin (cloud_admin), which would come first on its search path',
        ]),
      );
      // A superuser's session doesn't run it either (on this server it also names cloud_admin's rights: see below).
      await expect(setUp({ user: 'postgres', login: superuserLogin }, logins)).rejects.toMatchObject({
        problems: expect.arrayContaining([
          'the public schema of agentx holds 2 functions or operators; nothing of ours puts any there',
        ]) as unknown,
      });
      expect(await asSuperuser("select 1 from pg_catalog.pg_roles where rolname = 'backdoor'")).toEqual([]);
    } finally {
      await asOwner('drop schema cloud_admin');
      await asOwner('drop operator public.= (pg_catalog.oid, pg_catalog.int4)');
      await asOwner('drop function public.trap(pg_catalog.oid, pg_catalog.int4)');
    }
  });

  it("changes nothing in a database by the app's name that it did not make", async () => {
    await asSuperuser('create database foreign_app');
    try {
      await expect(setUp(cloudAdmin(), logins, 'foreign_app')).rejects.toEqual(
        new ServerSetupRefused(['the database foreign_app is owned by postgres, not agentx_owner']),
      );
      // Still Azure's layout, untouched: the job never connected to it.
      expect(
        await asSuperuser(
          "select pg_catalog.pg_get_userbyid(nspowner) as owner from pg_catalog.pg_namespace where nspname = 'public'",
          'foreign_app',
        ),
      ).toEqual([{ owner: 'azure_pg_admin' }]);
    } finally {
      await asSuperuser('drop database foreign_app');
    }
  });

  it('leaves an app database without a public schema as it is', async () => {
    await asSuperuser('drop schema public', APP_DATABASE);
    try {
      await expect(setUp(cloudAdmin(), logins)).resolves.toMatchObject({
        outcome: { rolesCreated: [], databasesCreated: [] },
      });
    } finally {
      await asSuperuser('create schema public authorization agentx_owner', APP_DATABASE);
    }
  });

  it("refuses to finish for another admin than the one that made the roles, naming that admin's rights", async () => {
    // The compose stack's superuser, which makes its own roles, is covered in apps/db-setup/src/main.db.test.ts.
    await expect(setUp({ user: 'postgres', login: superuserLogin }, logins)).rejects.toEqual(
      new ServerSetupRefused(
        ['agentx_app', 'agentx_backup', 'agentx_owner', 'zitadel'].map(
          (role) => `cloud_admin is a member of ${role}, which db/bootstrap never grants`,
        ),
      ),
    );
    expect(await asSuperuser("select 1 from pg_catalog.pg_auth_members where member = 'postgres'::regrole")).toEqual(
      [],
    );
  });

  it('refuses a half-made set of roles rather than guess', async () => {
    await asSuperuser('revoke connect on database agentx from agentx_backup');
    await asSuperuser('drop role agentx_backup');
    await expect(setUp(cloudAdmin(), logins)).rejects.toEqual(
      new ServerSetupRefused([
        'roles.sql creates agentx_owner, agentx_app, agentx_backup, but only agentx_app, agentx_owner exist: repair the server by hand',
      ]),
    );
  });
});

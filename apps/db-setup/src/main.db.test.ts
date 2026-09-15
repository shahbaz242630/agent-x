// The set-up job against a real Postgres (Rule Book §6), as the compose stack
// runs it: the admin is the superuser, the roles already exist, and the job
// gives each the login it already has, so the other test files, which log in
// with those logins, see no change. It creates a database of its own for the
// app, and the login service's role and database, and removes them after.
// tooling/checks/db-setup.db.test.ts covers the job's work in depth, on a
// server of its own laid out like Azure's.
import { randomBytes } from 'node:crypto';

import type { Output } from '@agentx/platform/observability';
import { findLeaks, LogCapture, queryOnce } from '@agentx/testing';
import { afterAll, describe, expect, inject, it } from 'vitest';

import { runDbSetup, type SetupProcess } from './main.ts';

const server = inject('postgres');
const database = `agentx_setup_${randomBytes(4).toString('hex')}`;
/** The login service's role for this run, with a random login. */
const zitadelRole = { user: 'zitadel', password: randomBytes(18).toString('hex') };

class FakeProcess implements SetupProcess {
  readonly stdout: Output = { write: () => true };
  readonly stderr: Output = { write: () => true };
  exitCode: number | string | null | undefined = undefined;
}

function envFor(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    AGENTX_ENV: 'test',
    AGENTX_DB_HOST: server.host,
    AGENTX_DB_PORT: String(server.port),
    AGENTX_DB_NAME: database,
    AGENTX_DB_TLS: 'disable',
    AGENTX_DB_ADMIN_USER: server.admin.user,
    AGENTX_DB_ADMIN_PASSWORD: server.admin.password,
    AGENTX_DB_OWNER_PASSWORD: server.roles.owner.password,
    AGENTX_DB_APP_PASSWORD: server.roles.app.password,
    AGENTX_DB_BACKUP_PASSWORD: server.roles.backup.password,
    AGENTX_DB_ZITADEL_PASSWORD: zitadelRole.password,
    ...overrides,
  };
}

async function run(env: Record<string, string>) {
  const host = new FakeProcess();
  const capture = new LogCapture();
  const code = await runDbSetup(host, { env, destination: capture });
  return { code, host, capture, events: () => capture.lines().map((line) => line.event) };
}

const asAdmin = (text: string) =>
  queryOnce(
    {
      host: server.host,
      port: server.port,
      database: 'postgres',
      user: server.admin.user,
      password: server.admin.password,
      tls: 'disable',
    },
    text,
  );

afterAll(async () => {
  await asAdmin(`drop database if exists ${database}`);
  await asAdmin('drop database if exists zitadel');
  await asAdmin('drop role if exists zitadel');
});

describe(`the set-up job as the compose stack runs it (Postgres ${server.version})`, () => {
  it("creates the app's database and the login service's, keeps the roles, and exits 0", async () => {
    const { code, host, capture, events } = await run(envFor());
    expect({ code, exitCode: host.exitCode }).toEqual({ code: 0, exitCode: 0 });
    expect(events()[0]).toBe('db_setup.starting');
    expect(capture.lines().at(-1)).toMatchObject({
      event: 'db_setup.done',
      databasesCreated: [database, 'zitadel'],
    });
    const logins = [
      server.admin.password,
      ...Object.values(server.roles).map((role) => role.password),
      zitadelRole.password,
    ];
    expect(findLeaks(capture.text, logins)).toEqual([]);
    // A superuser needs no rights lent: it holds no membership afterwards.
    expect(
      await asAdmin('select 1 from pg_catalog.pg_auth_members where member = current_user::pg_catalog.regrole'),
    ).toEqual([]);
  });

  it('left every role able to log in with the login it had', async () => {
    const connection = { host: server.host, port: server.port, database, tls: 'disable' as const };
    await expect(queryOnce({ ...connection, ...server.roles.app }, 'select 1 as one')).resolves.toEqual([{ one: 1 }]);
    await expect(queryOnce({ ...connection, database: 'zitadel', ...zitadelRole }, 'select 1 as one')).resolves.toEqual(
      [{ one: 1 }],
    );
  });

  it("logs the failure and exits 1 when the admin's login is wrong", async () => {
    const { code, capture } = await run(envFor({ AGENTX_DB_ADMIN_PASSWORD: randomBytes(18).toString('hex') }));
    expect(code).toBe(1);
    expect(capture.lines().at(-1)).toMatchObject({
      event: 'db_setup.failed',
      err: expect.objectContaining({
        message: expect.stringContaining('password authentication failed') as unknown,
      }) as unknown,
    });
  });
});

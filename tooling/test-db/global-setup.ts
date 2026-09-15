// Vitest global setup for the database test projects (db-pg16 and db-pg18,
// in vitest.config.ts). It starts one throwaway server for the project's
// Postgres version and prepares it the way a real server is prepared:
// db/bootstrap as the server admin, then db/migrations as agentx_owner, into a
// template database. Each test file copies the template (createTestDatabase in
// packages/testing). Vitest runs this only when database tests are queued.
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import type { TestProject } from 'vitest/node';

import { runMigrations } from '../../packages/platform/src/db/index.ts';
import { createLogger } from '../../packages/platform/src/observability/index.ts';
import type { TestPostgresServer } from '../../packages/testing/src/index.ts';
import { psql, removeExpiredContainers, startPostgres } from './docker.ts';
import { POSTGRES_IMAGES } from './postgres-images.ts';

declare module 'vitest' {
  export interface ProvidedContext {
    postgres: TestPostgresServer;
  }
}

const TEMPLATE = 'agentx_template';
const repoFile = (relative: string): string => fileURLToPath(new URL(`../../${relative}`, import.meta.url));

/** A fresh login for this run only: random, never written anywhere. */
const newLogin = (): string => randomBytes(24).toString('hex');

/** Sets each role's login for this run. psql quotes the values. */
const SET_LOGINS = `
ALTER ROLE agentx_owner PASSWORD :'owner_login';
ALTER ROLE agentx_app PASSWORD :'app_login';
ALTER ROLE agentx_backup PASSWORD :'backup_login';
`;

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const image = POSTGRES_IMAGES[project.name];
  if (image === undefined) throw new Error(`No Postgres image is pinned for the Vitest project ${project.name}`);

  await removeExpiredContainers(Date.now());
  const admin = { user: 'postgres', password: newLogin() };
  const container = await startPostgres(image, admin.password, Date.now());
  try {
    const roles = {
      owner: { user: 'agentx_owner', password: newLogin() },
      app: { user: 'agentx_app', password: newLogin() },
      backup: { user: 'agentx_backup', password: newLogin() },
    };
    await psql(container.id, await readFile(repoFile('db/bootstrap/roles.sql'), 'utf8'));
    await psql(container.id, SET_LOGINS, {
      owner_login: roles.owner.password,
      app_login: roles.app.password,
      backup_login: roles.backup.password,
    });
    await psql(container.id, await readFile(repoFile('db/bootstrap/database.sql'), 'utf8'), { db: TEMPLATE });

    const host = '127.0.0.1';
    await runMigrations({
      connection: { host, port: container.port, database: TEMPLATE, ...roles.owner, tls: 'disable' },
      directory: repoFile('db/migrations'),
      logger: createLogger({
        service: 'test-db',
        config: { environment: 'test', release: 'test', log: { level: 'warn', eventCapPerMinute: 1000 } },
        destination: { write: () => undefined },
      }),
    });
    // Copies only from here on: nothing may connect to the template and change it.
    await psql(container.id, `ALTER DATABASE ${TEMPLATE} WITH IS_TEMPLATE true ALLOW_CONNECTIONS false;`);

    const version = (await psql(container.id, 'SHOW server_version;')).trim().split(' ')[0] ?? 'unknown';
    project.provide('postgres', {
      version,
      host,
      port: container.port,
      admin,
      roles,
      templateDatabase: TEMPLATE,
    });
  } catch (error) {
    await container.stop();
    throw error;
  }
  return () => container.stop();
}

import { setTimeout as sleep } from 'node:timers/promises';

import { createTestDatabase, LogCapture, type TestDatabase } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;
let capture: LogCapture;

const backendId = async (db: Kysely<unknown>): Promise<number> => {
  const { rows } = await sql<{ pid: number }>`select pg_catalog.pg_backend_pid() as pid`.execute(db);
  return rows[0]?.pid ?? 0;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  capture = new LogCapture();
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  app = createDatabase({ ...database.connection('app'), maxConnections: 1 }, logger);
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`createDatabase (Postgres ${server.version})`, () => {
  it('ADR-006: returns bigint columns as exact BigInts, beyond what a float can hold', async () => {
    const { rows } = await sql<{ big: unknown; small: unknown; exact: unknown }>`
      select 9007199254740993::int8 as big, 7::int4 as small, 12.50::numeric as exact
    `.execute(app);
    expect(rows).toEqual([{ big: 9_007_199_254_740_993n, small: 7, exact: '12.50' }]);
  });

  it('names its connections, so they can be told apart on the server', async () => {
    const { rows } = await sql<{ name: string }>`select pg_catalog.current_setting('application_name') as name`.execute(
      app,
    );
    expect(rows[0]?.name).toBe('agentx');
  });

  it('logs in as the role it was given', async () => {
    const { rows } = await sql<{ name: string }>`select session_user::text as name`.execute(app);
    expect(rows[0]?.name).toBe('agentx_app');
  });

  const lostCount = (): number => capture.lines().filter((line) => line.event === 'db.connection_lost').length;

  /** Waits up to a second for the logger to have reported `count` lost connections. */
  const lostReaches = async (count: number): Promise<number> => {
    for (let waited = 0; waited < 50 && lostCount() < count; waited += 1) await sleep(20);
    return lostCount();
  };

  it('survives an idle connection being cut off (a restart or failover): it logs it once and reconnects', async () => {
    const logged = capture.lines().length;
    const before = await backendId(app);
    // The superuser ends the app's idle connection, as a server restart would.
    await database.as('admin').query('select pg_catalog.pg_terminate_backend($1)', [before]);
    expect(await lostReaches(1)).toBe(1);
    expect(capture.lines().slice(logged)).toHaveLength(1);
    expect(await backendId(app)).not.toBe(before);
  });

  it('survives a connection being cut off in the middle of a query: the query fails, the app carries on', async () => {
    const lostBefore = lostCount();
    const running = sql`select pg_catalog.pg_sleep(30)`.execute(app);
    const rejected = running.then(
      () => false,
      () => true,
    );
    // Find the app's running query and end its connection, as a failover would.
    let ended = false;
    for (let tries = 0; tries < 100 && !ended; tries += 1) {
      const [row] = await database.as('admin').query<{ ended: boolean }>(
        `select bool_or(pg_catalog.pg_terminate_backend(pid)) as ended from pg_catalog.pg_stat_activity
           where datname = $1 and usename = 'agentx_app' and state = 'active' and query like '%pg_sleep%'`,
        [database.name],
      );
      ended = row?.ended === true;
      if (!ended) await sleep(20);
    }
    expect(ended).toBe(true);
    expect(await rejected).toBe(true);
    expect(await lostReaches(lostBefore + 1)).toBe(lostBefore + 1);
    // The pool replaced the connection, and the next query works.
    expect(await backendId(app)).toBeGreaterThan(0);
  });
});

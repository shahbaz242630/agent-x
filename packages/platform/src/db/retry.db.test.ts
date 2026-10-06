// ADR-006 §6 against a real Postgres: a transaction Postgres fails as one
// party of a deadlock (40P01) is tried again and commits; the other party's
// work stands. The deadlock is forced, never left to chance: the holder takes
// row 2, the party waits on it holding row 1, then the holder asks for row 1.
// The party waited first and has the shorter deadlock_timeout, so it is the
// one Postgres fails.
import { createTestDatabase, LogCapture, type TestDatabase, waitUntilQueued } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import { retryingTransaction, TRANSACTION_RETRIED } from './retry.ts';

const server = inject('postgres');
let database: TestDatabase;
let db: Kysely<Record<string, never>>;
const lines = new LogCapture();
const logger = createLogger({
  service: 'test',
  config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 10_000 } },
  destination: lines,
});

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  await database.as('admin').query('create schema probe');
  await database.as('admin').query('create table probe.rows (id int primary key, n int not null)');
  await database.as('admin').query('insert into probe.rows values (1, 0), (2, 0)');
  db = createDatabase({ ...database.connection('admin'), maxConnections: 2 }, logger);
});

afterAll(async () => {
  await db.destroy();
  await database.drop();
});

describe(`a deadlock retried (ADR-006 §6, Postgres ${server.version})`, () => {
  it('tries the failed party again, which then commits, with one line saying so', async () => {
    let tries = 0;
    const holder = await database.connect('admin');
    try {
      await holder.query('begin');
      await holder.query("select pg_catalog.set_config('deadlock_timeout', '10s', true)");
      await holder.query('update probe.rows set n = n + 10 where id = 2');

      const party = retryingTransaction(logger, 'probe.both_rows', () =>
        db.transaction().execute(async (tx) => {
          tries += 1;
          await sql`select pg_catalog.set_config('deadlock_timeout', '100ms', true)`.execute(tx);
          await sql`update probe.rows set n = n + 1 where id = 1`.execute(tx);
          await sql`update probe.rows set n = n + 1 where id = 2`.execute(tx);
        }),
      );
      await waitUntilQueued(database.as('admin'), 1);
      // The holder now waits on row 1, which the party holds: a deadlock, which fails the party.
      await holder.query('update probe.rows set n = n + 10 where id = 1');
      await holder.query('commit');
      await party;
    } finally {
      await holder.end();
    }

    expect(tries).toBe(2);
    expect(await database.as('admin').query('select id, n from probe.rows order by id')).toEqual([
      { id: 1, n: 11 },
      { id: 2, n: 11 },
    ]);
    expect(lines.lines().filter(({ event }) => event === TRANSACTION_RETRIED)).toEqual([
      expect.objectContaining({ operation: 'probe.both_rows', failure: 'deadlock', try: 1 }),
    ]);
  });
});

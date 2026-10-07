// ADR-006 §6 against a real Postgres: a transaction Postgres fails as one
// party of a deadlock (40P01) is tried again and commits; the other party's
// work stands. The deadlock is forced, never left to chance. Postgres checks
// a waiter for a deadlock once, when its deadlock_timeout runs out, so the
// party is made the one that closes the cycle: it takes row 1 and stops at a
// gate; the holder, holding row 2, queues on row 1; then the party asks for
// row 2. Its check (100 ms) runs after the cycle exists, long before the
// holder's (10 s), so the party is the one failed.
import { createTestDatabase, LogCapture, type TestDatabase, testLogger, waitUntilQueued } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';
import { retryingTransaction, TRANSACTION_RETRIED } from './retry.ts';

const server = inject('postgres');
let database: TestDatabase;
let db: Kysely<Record<string, never>>;
const lines = new LogCapture();
const logger = testLogger(lines);

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
    let tookRow1 = (): void => undefined;
    const row1Taken = new Promise<void>((resolve) => {
      tookRow1 = resolve;
    });
    let openGate = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      openGate = resolve;
    });
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
          // The first try stops here, holding row 1, until the holder queues on it.
          if (tries === 1) {
            tookRow1();
            await gate;
          }
          await sql`update probe.rows set n = n + 1 where id = 2`.execute(tx);
        }),
      );
      await row1Taken;
      const holderTakesRow1 = holder.query('update probe.rows set n = n + 10 where id = 1');
      await waitUntilQueued(database.as('admin'), 1);
      // The party now asks for row 2, which the holder has: the cycle closes, and the party is failed.
      openGate();
      await holderTakesRow1;
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

// PL-63 item 6: a transaction can't stay open for ever on the pool's connections.
import { createTestDatabase, LogCapture, type TestDatabase, testLogger } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';
import { limitedTransaction } from './tenant.ts';
import { holdOpenOnPurpose, IDLE_SECONDS, TRANSACTION_SECONDS } from './transaction-limits.ts';

const server = inject('postgres');
let database: TestDatabase;
let db: Kysely<unknown>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'empty' });
  db = createDatabase(
    { ...database.connection('admin'), applicationName: 'limits', maxConnections: 2 },
    testLogger(new LogCapture()),
  );
});

afterAll(async () => {
  await db.destroy();
  await database.drop();
});

const settingOn = async (on: Kysely<unknown>, name: string) => {
  const { rows } = await sql<{ value: string | null }>`
    select pg_catalog.current_setting(${name}, true) as value
  `.execute(on);
  return rows[0]?.value ?? null;
};

/** Whether this server has a limit on a whole transaction (17 and later). */
const limitsWholeTransactions = async () => Number(await settingOn(db, 'server_version_num')) >= 170_000;

const pauseMs = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('how long a transaction may stay open', () => {
  it('every pool connection carries both limits; on 16, the one it has', async () => {
    expect(await settingOn(db, 'idle_in_transaction_session_timeout')).toBe(`${String(IDLE_SECONDS / 60)}min`);
    expect(await settingOn(db, 'transaction_timeout')).toBe(
      (await limitsWholeTransactions()) ? `${String(TRANSACTION_SECONDS / 60)}min` : null,
    );
  });

  it('ends a transaction left idle past the limit: its statement fails, and the pool goes on', async () => {
    await expect(
      limitedTransaction(db, async (tx) => {
        await sql`select pg_catalog.set_config('idle_in_transaction_session_timeout', '50ms', true)`.execute(tx);
        await pauseMs(300);
        await sql`select 1`.execute(tx);
      }),
    ).rejects.toThrow();
    const { rows } = await sql<{ one: number }>`select 1 as one`.execute(db);
    expect(rows).toEqual([{ one: 1 }]);
  });

  it('lifts both for one transaction held open on purpose, and for no other', async () => {
    const whole = await limitsWholeTransactions();
    await limitedTransaction(db, async (tx) => {
      await holdOpenOnPurpose(tx);
      expect(await settingOn(tx, 'idle_in_transaction_session_timeout')).toBe('0');
      expect(await settingOn(tx, 'transaction_timeout')).toBe(whole ? '0' : null);
    });
    expect(await settingOn(db, 'idle_in_transaction_session_timeout')).toBe(`${String(IDLE_SECONDS / 60)}min`);
    expect(await settingOn(db, 'transaction_timeout')).toBe(whole ? `${String(TRANSACTION_SECONDS / 60)}min` : null);
  });

  it('lifted, a transaction outlives what would have ended it', async () => {
    await limitedTransaction(db, async (tx) => {
      await sql`select pg_catalog.set_config('idle_in_transaction_session_timeout', '50ms', true)`.execute(tx);
      await holdOpenOnPurpose(tx);
      await pauseMs(300);
      await sql`select 1`.execute(tx);
    });
  });
});

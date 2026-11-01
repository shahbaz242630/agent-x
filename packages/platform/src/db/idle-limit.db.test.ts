// PL-63 item 6: a transaction can't sit open for ever on the pool's connections.
import { createTestDatabase, LogCapture, type TestDatabase, testLogger } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase, IDLE_IN_TRANSACTION_SECONDS } from './database.ts';
import { holdOpenOnPurpose, limitedTransaction } from './tenant.ts';

const server = inject('postgres');
let database: TestDatabase;
let db: Kysely<unknown>;
const LIMIT = `${String(IDLE_IN_TRANSACTION_SECONDS / 60)}min`;

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

const idleLimit = async (on: Kysely<unknown>) => {
  const { rows } = await sql<{ value: string }>`
    select pg_catalog.current_setting('idle_in_transaction_session_timeout') as value
  `.execute(on);
  return rows[0]?.value;
};

const pauseMs = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const shortly = sql`select pg_catalog.set_config('idle_in_transaction_session_timeout', '50ms', true)`;

describe('how long a transaction may sit open', () => {
  it('every pool connection carries the limit from its start', async () => {
    expect(await idleLimit(db)).toBe(LIMIT);
  });

  it('ends a transaction left idle past the limit: its statement fails, and the pool goes on', async () => {
    await expect(
      limitedTransaction(db, async (tx) => {
        await shortly.execute(tx);
        await pauseMs(300);
        await sql`select 1`.execute(tx);
      }),
    ).rejects.toThrow();
    const { rows } = await sql<{ one: number }>`select 1 as one`.execute(db);
    expect(rows).toEqual([{ one: 1 }]);
  });

  it('lifted on purpose, a transaction outlives it, and the limit is back after', async () => {
    await limitedTransaction(db, async (tx) => {
      await shortly.execute(tx);
      await holdOpenOnPurpose(tx);
      expect(await idleLimit(tx)).toBe('0');
      await pauseMs(300);
      await sql`select 1`.execute(tx);
    });
    expect(await idleLimit(db)).toBe(LIMIT);
  });
});

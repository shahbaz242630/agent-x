// How long a transaction may stay open (PL-63 item 6, 4D2e A). Postgres can't
// clear dead rows while one stays open, so one left by a bug or a hung process
// slows every organisation: measured on the laptop, 147 s took dead rows from
// about 2,000 to about 39,000. Postgres ends the connection past either limit,
// so the transaction rolls back and its locks go, whatever the app is doing.
//
// On the pool's connections alone, once each as it opens, so no request pays a
// trip. Never on a migration's or the set-up job's: those run through
// poolConfig with their own client, and a migration may rightly take longer.
import { sql, type Transaction } from 'kysely';
import type pg from 'pg';

/** Between two statements: no transaction of ours waits on anything but the database this long. */
export const IDLE_SECONDS = 60;

/**
 * A whole transaction: past the longest real one, the anchor check's verifyAlone,
 * which the app itself ends at 120 s (`ANCHOR_CHECK_DEADLINE_MS`), with room for
 * its deadline to act first.
 */
export const TRANSACTION_SECONDS = 180;

/** The first version with `transaction_timeout`. Tests still run on 16, which would refuse the name. */
const TRANSACTION_TIMEOUT_FROM = 170_000;

const onVersions = (setting: string): string =>
  `case when pg_catalog.current_setting('server_version_num')::int >= ${String(TRANSACTION_TIMEOUT_FROM)} then ${setting} end`;

/** Sets both limits for the connection's whole life. */
export async function limitTransactions(client: pg.ClientBase): Promise<void> {
  await client.query(
    `select pg_catalog.set_config('idle_in_transaction_session_timeout', '${String(IDLE_SECONDS)}s', false), ` +
      onVersions(`pg_catalog.set_config('transaction_timeout', '${String(TRANSACTION_SECONDS)}s', false)`),
  );
}

/**
 * Lifts both limits for this transaction alone. For the load test's stuck
 * organisation, which holds its rows open for a whole phase on purpose, and
 * for nothing in the product.
 */
export async function holdOpenOnPurpose<Schema>(tx: Transaction<Schema>): Promise<void> {
  await sql`select pg_catalog.set_config('idle_in_transaction_session_timeout', '0', true), ${sql.raw(
    onVersions(`pg_catalog.set_config('transaction_timeout', '0', true)`),
  )}`.execute(tx);
}

// The lease on the API's jobs (0068, 4D2e D): which process leads, on the
// database's clock, and the heartbeat a `web` copy reads. The row lock an UPDATE
// waits for is judged again on the row as it then stands, so two takers can't both
// win: the later sees the earlier's `until`.
//
// Each runs in a transaction with limits of its own, under the 10 seconds the
// process gives a try (background.ts). Its giving up cancels nothing: without these,
// a session sitting on the row would leave one more blocked statement holding a
// connection each try, until the pool, and every request with it, had none left.
import { limitedTransaction, limitStatementsTo } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { PlatformControlsTables } from './tables.ts';

type LeaseDatabase = Kysely<PlatformControlsTables>;

/** How long a lease statement may run, and wait for the row. Milliseconds, as Postgres reads a bare number. */
export interface LeaseLimits {
  readonly statementMs: number;
  readonly lockMs: number;
}

const LEASE_LIMITS: LeaseLimits = { statementMs: 8_000, lockMs: 5_000 };

function limited<Result>(
  database: LeaseDatabase,
  limits: LeaseLimits,
  work: (tx: Transaction<PlatformControlsTables>) => Promise<Result>,
): Promise<Result> {
  return limitedTransaction(database, async (tx) => {
    await limitStatementsTo(tx, limits);
    return work(tx);
  });
}

/**
 * Takes or renews the lease for `termSeconds`, and says whether this holder now
 * has it. `beating` moves the heartbeat with it, in the same statement.
 */
export function takeJobLease(
  database: LeaseDatabase,
  holder: string,
  beating: boolean,
  termSeconds: number,
  limits: LeaseLimits = LEASE_LIMITS,
): Promise<boolean> {
  return limited(database, limits, async (tx) => {
    const { rows } = await sql<{ name: string }>`
      UPDATE platform_controls.job_lease
      SET holder = ${holder}::uuid,
          until = pg_catalog.now() + pg_catalog.make_interval(secs => ${termSeconds}::double precision),
          renewed_at = pg_catalog.now(),
          beating_at = CASE WHEN ${beating}::boolean THEN pg_catalog.now() ELSE beating_at END
      WHERE name = 'jobs' AND (holder = ${holder}::uuid OR until < pg_catalog.now())
      RETURNING name`.execute(tx);
    return rows.length === 1;
  });
}

/** Gives the lease up at once, if this holder still has it. The heartbeat stays as it was. */
export function releaseJobLease(
  database: LeaseDatabase,
  holder: string,
  limits: LeaseLimits = LEASE_LIMITS,
): Promise<void> {
  return limited(database, limits, async (tx) => {
    await sql`
      UPDATE platform_controls.job_lease
      SET holder = NULL, until = '-infinity'
      WHERE name = 'jobs' AND holder = ${holder}::uuid`.execute(tx);
  });
}

/** Whether the jobs' heartbeat moved within this long, on the database's clock. Never moved: no. */
export async function jobsBeating(database: LeaseDatabase, withinSeconds: number): Promise<boolean> {
  const { rows } = await limitedTransaction(database, (tx) =>
    sql<{ beating: boolean | null }>`
      SELECT beating_at >= pg_catalog.now() - pg_catalog.make_interval(secs => ${withinSeconds}::double precision) AS beating
      FROM platform_controls.job_lease
      WHERE name = 'jobs'`.execute(tx),
  );
  return rows[0]?.beating === true;
}

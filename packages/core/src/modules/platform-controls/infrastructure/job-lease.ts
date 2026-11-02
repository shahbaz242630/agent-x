// The lease on the API's jobs (0068, 4D2e D): which process leads, on the
// database's clock, and the heartbeat a `web` copy reads. One statement each, and
// the row lock an UPDATE waits for is judged again on the row as it then stands,
// so two takers can't both win: the later sees the earlier's `until`.
import { type Kysely, sql } from 'kysely';

import type { PlatformControlsTables } from './tables.ts';

type LeaseDatabase = Kysely<PlatformControlsTables>;

/**
 * Takes or renews the lease for `termSeconds`, and says whether this holder now
 * has it. `beating` moves the heartbeat with it, in the same statement.
 */
export async function takeJobLease(
  database: LeaseDatabase,
  holder: string,
  beating: boolean,
  termSeconds: number,
): Promise<boolean> {
  const { rows } = await sql<{ name: string }>`
    UPDATE platform_controls.job_lease
    SET holder = ${holder}::uuid,
        until = pg_catalog.now() + pg_catalog.make_interval(secs => ${termSeconds}::double precision),
        renewed_at = pg_catalog.now(),
        beating_at = CASE WHEN ${beating}::boolean THEN pg_catalog.now() ELSE beating_at END
    WHERE name = 'jobs' AND (holder = ${holder}::uuid OR until < pg_catalog.now())
    RETURNING name`.execute(database);
  return rows.length === 1;
}

/** Gives the lease up at once, if this holder still has it. The heartbeat stays as it was. */
export async function releaseJobLease(database: LeaseDatabase, holder: string): Promise<void> {
  await sql`
    UPDATE platform_controls.job_lease
    SET holder = NULL, until = '-infinity'
    WHERE name = 'jobs' AND holder = ${holder}::uuid`.execute(database);
}

/** Whether the jobs' heartbeat moved within this long, on the database's clock. Never moved: no. */
export async function jobsBeating(database: LeaseDatabase, withinSeconds: number): Promise<boolean> {
  const { rows } = await sql<{ beating: boolean | null }>`
    SELECT beating_at >= pg_catalog.now() - pg_catalog.make_interval(secs => ${withinSeconds}::double precision) AS beating
    FROM platform_controls.job_lease
    WHERE name = 'jobs'`.execute(database);
  return rows[0]?.beating === true;
}

// What the app role can tell of the migration ledger without reading it (4D2e).
//
// The image before a release starts against a database the release has already
// migrated, and its schema check then finds that release's new objects (staging,
// 3 Nov). To tell a release in progress from a plant, it needs to know a newer
// migration than its own was applied just now. The ledger, migrations.applied,
// says so, but the app role has no right on it (schema-policy.ts) and is given
// none here. Two marks in the catalogue say enough, and any role may read both:
//
// - pg_class.reltuples: the rows the ledger held when last counted. A catalogue
//   column, so it outlives a restart; on a table this small ANALYZE counts every row.
// - pg_stat_all_tables.n_live_tup: the rows it holds now, kept up as each change
//   commits. A row added, counted and deleted again leaves reltuples one too high,
//   but not this.
// - pg_stat_all_tables.last_analyze: when an ANALYZE by hand last counted them.
//   Autovacuum's own counts stamp a different column, so only a role allowed to
//   maintain the table stamps this one: the migration job does, on every run.
//
// Any can be missing (a new database, a reset of the server's statistics): that
// is no evidence of a release, and the check raises its alarm as before.
import { fileURLToPath } from 'node:url';

import { type Kysely, sql } from 'kysely';

import { loadMigrations } from './migrate.ts';

/** The migration files shipped in this image, beside the code (the Dockerfile copies db/ whole). */
const BUILT_MIGRATIONS = fileURLToPath(new URL('../../../../db/migrations', import.meta.url));

export interface LedgerMarks {
  /** How many rows the ledger held when last counted; -1 when never counted. */
  readonly rows: number;
  /** How many it holds now, by the server's statistics; 0 when it has none. */
  readonly liveRows: number;
  /** How long ago it was last counted by hand, by the database's own clock; undefined when never. */
  readonly countedMsAgo: number | undefined;
}

interface LedgerMarksRow {
  readonly rows: number;
  readonly live_rows: number;
  readonly counted_ms_ago: number | null;
}

/** The ledger's marks, or undefined when the database has no ledger at all. */
export async function readLedgerMarks<Schema>(db: Kysely<Schema>): Promise<LedgerMarks | undefined> {
  // By name through pg_namespace: a cast to regclass would need a right on the schema. The age is
  // taken on the database's clock, the one that wrote the stamp, so no skew between two clocks stretches it.
  const { rows } = await sql<LedgerMarksRow>`
    select c.reltuples::pg_catalog.float8 as rows,
           coalesce(s.n_live_tup, 0)::pg_catalog.float8 as live_rows,
           (extract(epoch from pg_catalog.now() - s.last_analyze) * 1000)::pg_catalog.float8 as counted_ms_ago
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    left join pg_catalog.pg_stat_all_tables s on s.relid = c.oid
    where n.nspname = 'migrations' and c.relname = 'applied' and c.relkind = 'r'
  `.execute(db);
  const [row] = rows;
  return row === undefined
    ? undefined
    : { rows: row.rows, liveRows: row.live_rows, countedMsAgo: row.counted_ms_ago ?? undefined };
}

/** The names of the migrations this image was built with, in order. */
export async function builtMigrationNames(directory: string = BUILT_MIGRATIONS): Promise<string[]> {
  return (await loadMigrations(directory)).map(({ name }) => name);
}

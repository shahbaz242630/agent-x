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
// - pg_stat_all_tables.last_analyze: when an ANALYZE by hand last counted them.
//   Autovacuum's own counts stamp a different column, so only a role allowed to
//   maintain the table stamps this one: the migration job does, after applying a file.
//
// Either can be missing (a new database, a reset of the server's statistics): that
// is no evidence of a release, and the check raises its alarm as before.
import { fileURLToPath } from 'node:url';

import { type Kysely, sql } from 'kysely';

import { loadMigrations } from './migrate.ts';

/** The migration files shipped in this image, beside the code (the Dockerfile copies db/ whole). */
const BUILT_MIGRATIONS = fileURLToPath(new URL('../../../../db/migrations', import.meta.url));

export interface LedgerMarks {
  /** How many rows the ledger held when last counted; -1 when never counted. */
  readonly rows: number;
  /** When it was last counted by hand, as the migration job does after applying a file. */
  readonly countedAt: Date | undefined;
}

interface LedgerMarksRow {
  readonly rows: number;
  readonly counted_at: Date | null;
}

/** The ledger's marks, or undefined when the database has no ledger at all. */
export async function readLedgerMarks<Schema>(db: Kysely<Schema>): Promise<LedgerMarks | undefined> {
  // By name through pg_namespace: a cast to regclass would need a right on the schema.
  const { rows } = await sql<LedgerMarksRow>`
    select c.reltuples::pg_catalog.float8 as rows, s.last_analyze as counted_at
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    left join pg_catalog.pg_stat_all_tables s on s.relid = c.oid
    where n.nspname = 'migrations' and c.relname = 'applied' and c.relkind = 'r'
  `.execute(db);
  const [row] = rows;
  return row === undefined ? undefined : { rows: row.rows, countedAt: row.counted_at ?? undefined };
}

/** The names of the migrations this image was built with, in order. */
export async function builtMigrationNames(directory: string = BUILT_MIGRATIONS): Promise<string[]> {
  return (await loadMigrations(directory)).map(({ name }) => name);
}

// How big each of our tables is on disk, and how often each index is used
// (4D2e F12, PL-65): a load run reads it before and after, to replace the
// estimates its growth figures began as, and to show which indexes earn their
// bytes. The app's own role may read this: a size or a scan count needs no
// right on the table and shows no row, so it reads the same through a tenant wall.
import { type Kysely, sql } from 'kysely';

/** One table's bytes: its rows' pages, its indexes, and what Postgres keeps aside for long values (TOAST). */
export interface TableSize {
  readonly rows: number;
  readonly indexes: number;
  readonly longValues: number;
}

/** One index: its table, its bytes, and how many times it was scanned since the server's counts began. */
export interface IndexUse {
  readonly table: string;
  readonly bytes: number;
  readonly scans: number;
}

/** Every plain table by `schema.table`, and every index of theirs by `schema.index`. */
export interface TableSizes {
  readonly tables: Readonly<Record<string, TableSize>>;
  readonly indexes: Readonly<Record<string, IndexUse>>;
}

interface SizeRow {
  readonly table: string;
  readonly rows: string;
  readonly indexes: string;
  readonly long_values: string;
  /** Built by the query itself, so its shape is known; empty for a table with no index. */
  readonly index_use: Readonly<Record<string, { bytes: number; scans: number }>>;
}

/**
 * One query for every table, never one a table. Whole disk pages, so dead rows
 * count. A partition is its own entry, and a partitioned parent holds nothing,
 * so none.
 */
export async function tableSizes<Schema>(db: Kysely<Schema>): Promise<TableSizes> {
  const { rows } = await sql<SizeRow>`
    select pg_catalog.format('%I.%I', n.nspname, c.relname) as table,
           pg_catalog.pg_table_size(c.oid) - t.long_values as rows,
           pg_catalog.pg_indexes_size(c.oid) as indexes,
           t.long_values,
           coalesce((select pg_catalog.json_object_agg(
                       pg_catalog.format('%I.%I', s.schemaname, s.indexrelname),
                       pg_catalog.json_build_object('bytes', pg_catalog.pg_relation_size(s.indexrelid), 'scans', s.idx_scan))
                     from pg_catalog.pg_stat_user_indexes s where s.relid = c.oid), '{}') as index_use
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    cross join lateral (
      select coalesce(pg_catalog.pg_total_relation_size(nullif(c.reltoastrelid, 0)), 0) as long_values
    ) t
    where c.relkind = 'r' and n.nspname not in ('pg_catalog', 'information_schema')
      and not pg_catalog.starts_with(n.nspname, 'pg_')
  `.execute(db);
  const tables: Record<string, TableSize> = {};
  const indexes: Record<string, IndexUse> = {};
  for (const row of rows) {
    tables[row.table] = { rows: Number(row.rows), indexes: Number(row.indexes), longValues: Number(row.long_values) };
    for (const [index, { bytes, scans }] of Object.entries(row.index_use)) {
      indexes[index] = { table: row.table, bytes, scans };
    }
  }
  return { tables, indexes };
}

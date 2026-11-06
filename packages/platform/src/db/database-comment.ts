// The connected database's own comment: for the load test's throwaway copy
// alone (tooling/load/throwaway.ts), whose mark it is, and for nothing in the
// product. A comment sits in no catalogue the schema guard reads (pg_shdescription),
// so a mark there can't be taken for tampering, and any role can read it.
import { type Kysely, sql } from 'kysely';

/** The connected database's comment, or null when it has none. */
export async function databaseComment<Schema>(db: Kysely<Schema>): Promise<string | null> {
  const { rows } = await sql<{ comment: string | null }>`
    select pg_catalog.shobj_description(d.oid, 'pg_database') as comment
    from pg_catalog.pg_database d
    where d.datname = pg_catalog.current_database()
  `.execute(db);
  return rows[0]?.comment ?? null;
}

/** Sets the connected database's comment, which only its owner may. */
export async function commentOnDatabase<Schema>(db: Kysely<Schema>, comment: string): Promise<void> {
  const { rows } = await sql<{ name: string }>`select pg_catalog.current_database() as name`.execute(db);
  await sql`comment on database ${sql.id(rows[0]?.name ?? '')} is ${sql.lit(comment)}`.execute(db);
}

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

/**
 * Sets the connected database's comment, which only its owner may. COMMENT takes
 * no parameter, so the text goes in as one (a setting of this transaction alone)
 * and the server quotes it (format's %L): nothing is spliced into SQL here.
 */
export async function commentOnDatabase<Schema>(db: Kysely<Schema>, comment: string): Promise<void> {
  await db.transaction().execute(async (tx) => {
    // eslint-disable-next-line agentx/tenant-setting-only-in-with-tenant -- Transaction-local (is_local true) in its own transaction, the comment's text as a parameter: no tenant, nothing left on the connection.
    await sql`select pg_catalog.set_config('agentx.database_comment', ${comment}, true)`.execute(tx);
    await sql`do $$ begin
      execute pg_catalog.format('comment on database %I is %L', pg_catalog.current_database(),
        pg_catalog.current_setting('agentx.database_comment'));
    end $$`.execute(tx);
  });
}

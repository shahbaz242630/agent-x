// The directory's list of organisations (ADR-005 §6): IDs only, in a global
// table, so work that runs across organisations can find each one and then
// work inside its own withTenant. An organisation is added in the same
// transaction as its own row (the organizations module's), which points here,
// so the two can't part: the row can't be written without its entry, and the
// app can't delete an entry.
import { assertTenant } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { DirectoryTables } from './tables.ts';

/**
 * Adds the organisation to the directory, in the caller's transaction, which
 * must be withTenant's for that organisation: the one creating its row. An
 * organisation already listed is refused by the table's key, so the whole
 * creation rolls back.
 */
export async function registerOrganization(tx: Transaction<DirectoryTables>, orgId: string): Promise<void> {
  await assertTenant(tx, orgId);
  await tx.insertInto('directory.orgs').values({ org_id: orgId }).execute();
}

/**
 * Every organisation the directory lists, by ID in lower case as Postgres
 * prints a uuid, in order: for work across organisations, which then works
 * inside each one's own withTenant (B1d-2: the anchor check). Its own
 * transaction, each statement limited to 10 seconds, so a hung read gives
 * its connection back.
 */
export function listedOrganizations(db: Kysely<DirectoryTables>): Promise<string[]> {
  return db
    .transaction()
    .setIsolationLevel('read committed')
    .execute(async (tx) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      const rows = await tx.selectFrom('directory.orgs').select('org_id').orderBy('org_id').execute();
      return rows.map((row) => row.org_id);
    });
}

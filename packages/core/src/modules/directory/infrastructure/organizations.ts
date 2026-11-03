// The directory's list of organisations (ADR-005 §6): IDs only, in a global
// table, so work that runs across organisations can find each one and then
// work inside its own withTenant. An organisation is added in the same
// transaction as its own row (the organizations module's), which points here,
// so the two can't part: the row can't be written without its entry, and the
// app can't delete an entry.
import { assertTenant } from '@agentx/platform/db';
import { type Kysely, type Transaction } from 'kysely';

import { readAlone } from './read-alone.ts';
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

/** How many IDs one statement reads: well within its 10 seconds on the table's key. */
const LIST_PAGE = 50_000;

/**
 * Every organisation the directory lists, by ID in lower case as Postgres
 * prints a uuid, in order: for work across organisations, which then works
 * inside each one's own withTenant (B1d-2: the anchor check). Its own
 * transaction, each statement limited to 10 seconds, so a hung read gives
 * its connection back.
 */
export async function listedOrganizations(
  db: Kysely<DirectoryTables>,
  page = LIST_PAGE,
  answeredWithinMs?: number,
): Promise<string[]> {
  const listed: string[] = [];
  // In pages, each a statement within its limit, so no number of organisations can make the read fail whole.
  for (;;) {
    const after = listed.at(-1);
    const rows = await readAlone(
      db,
      (tx) => {
        const all = tx.selectFrom('directory.orgs').select('org_id');
        const rest = after === undefined ? all : all.where('org_id', '>', after);
        return rest.orderBy('org_id').limit(page).execute();
      },
      answeredWithinMs,
    );
    for (const row of rows) listed.push(row.org_id);
    if (rows.length < page) return listed;
  }
}

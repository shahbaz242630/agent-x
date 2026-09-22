// The directory's list of organisations (ADR-005 §6): IDs only, in a global
// table, so work that runs across organisations can find each one and then
// work inside its own withTenant. An organisation is added in the same
// transaction as its own row (the organizations module's), which points here,
// so the two can't part: the row can't be written without its entry, and the
// app can't delete an entry.
import { assertTenant } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

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

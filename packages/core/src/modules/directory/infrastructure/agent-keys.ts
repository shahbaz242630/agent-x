// The directory's list of agent keys (0027): a key's ID and its organisation,
// in a global table, so a request carrying a key can be placed in its
// organisation before any is known (ADR-005 §6). An entry is added in the
// same transaction as the key it names (the agents module's), which can't be
// written without it. An entry grants nothing: the key, with its secret's
// MAC, is read by that ID inside the organisation's own withTenant and
// verified there.
import { assertTenant } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { DirectoryTables } from './tables.ts';

/**
 * Lists the key as its organisation's, in the caller's transaction, which
 * must be withTenant's for that organisation: the one issuing the key. A key
 * ID listed already, anywhere, is refused by the table's key, so the whole
 * change rolls back.
 */
export async function registerAgentKey(
  tx: Transaction<DirectoryTables>,
  { orgId, keyId }: { readonly orgId: string; readonly keyId: string },
): Promise<void> {
  await assertTenant(tx, orgId);
  await tx.insertInto('directory.agent_keys').values({ key_id: keyId, org_id: orgId }).execute();
}

/**
 * The organisation the key's ID is listed in, in lower case as Postgres
 * prints a uuid, or undefined: where to look, never what is found there, as
 * the key is then read and verified inside that organisation's withTenant.
 * One statement in a transaction of its own, limited to 10 seconds, so a hung
 * read gives its connection back.
 */
export function listedAgentKey(db: Kysely<DirectoryTables>, keyId: string): Promise<string | undefined> {
  return db
    .transaction()
    .setIsolationLevel('read committed')
    .execute(async (tx) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      const entry = await tx
        .selectFrom('directory.agent_keys')
        .select('org_id')
        .where('key_id', '=', keyId)
        .executeTakeFirst();
      return entry?.org_id;
    });
}

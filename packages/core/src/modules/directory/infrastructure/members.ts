// The directory's list of who belongs where (0015): a person's organisations,
// by IDs alone, in a global table, so they can be found before any one
// organisation is known (ADR-005 §6). An entry is added in the same
// transaction as the membership it points to (the identity module's), which
// can't be written without it. An entry grants nothing: the membership, with
// its role and status, is read inside the organisation's own withTenant.
import { assertTenant } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { DirectoryTables } from './tables.ts';

/** A person's entry: who, where, and the ID of their membership there. */
export interface MemberEntry {
  readonly orgId: string;
  readonly userId: string;
  readonly membershipId: string;
}

/**
 * Lists the person as belonging to the organisation, by their membership's
 * ID, in the caller's transaction, which must be withTenant's for that
 * organisation: the one adding the membership. An entry there already is
 * refused by the table's key, so the whole change rolls back.
 */
export async function registerMember(
  tx: Transaction<DirectoryTables>,
  { orgId, userId, membershipId }: MemberEntry,
): Promise<void> {
  await assertTenant(tx, orgId);
  await tx
    .insertInto('directory.members')
    .values({ user_id: userId, org_id: orgId, membership_id: membershipId })
    .execute();
}

/**
 * The ID of the membership the directory names for the person in this
 * organisation, or undefined, in the caller's transaction, which must be
 * withTenant's for that organisation. Where to look, never what is found
 * there: the membership is then read by that ID and verified.
 */
export async function listedMembership(
  tx: Transaction<DirectoryTables>,
  orgId: string,
  userId: string,
): Promise<string | undefined> {
  await assertTenant(tx, orgId);
  const entry = await tx
    .selectFrom('directory.members')
    .select('membership_id')
    .where('org_id', '=', orgId)
    .where('user_id', '=', userId)
    .executeTakeFirst();
  return entry?.membership_id;
}

/**
 * The organisations the directory lists the person in, by ID in lower case as
 * Postgres prints a uuid, in order. A place to look, never an answer: each is
 * then checked inside its own withTenant, where a membership deactivated
 * since is found as it is. Its own transaction, each statement limited to 10
 * seconds, so a hung read gives its connection back.
 */
export function organizationsOf(db: Kysely<DirectoryTables>, userId: string): Promise<string[]> {
  return db
    .transaction()
    .setIsolationLevel('read committed')
    .execute(async (tx) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      const rows = await tx
        .selectFrom('directory.members')
        .select('org_id')
        .where('user_id', '=', userId)
        .orderBy('org_id')
        .execute();
      return rows.map((row) => row.org_id);
    });
}

/**
 * The organisation's entries, by person, at most `most` of them in order of
 * membership ID, in the caller's transaction, which must be withTenant's for
 * that organisation. Where to look: each membership is then read by its ID
 * and verified.
 */
export async function listedMembers(
  tx: Transaction<DirectoryTables>,
  orgId: string,
  most: number,
): Promise<MemberEntry[]> {
  await assertTenant(tx, orgId);
  const entries = await tx
    .selectFrom('directory.members')
    .select(['user_id', 'membership_id'])
    .where('org_id', '=', orgId)
    .orderBy('membership_id')
    .orderBy('user_id')
    .limit(most)
    .execute();
  return entries.map((entry) => ({ orgId, userId: entry.user_id, membershipId: entry.membership_id }));
}

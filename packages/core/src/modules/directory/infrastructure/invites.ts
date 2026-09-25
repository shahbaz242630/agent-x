// The directory's list of invitation tokens (0016): a token's SHA-256, never
// the token, with its organisation and invitation, in a global table, so an
// invitation can be found as it is accepted, before any organisation is known
// (ADR-005 §6). An entry is added in the same transaction as the invitation it
// points to opens (the identity module's). An entry grants nothing: the
// invitation is read and verified inside the organisation's own withTenant.
import { assertTenant } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type { DirectoryTables } from './tables.ts';

/** A token's entry: its SHA-256, and the invitation it opens. */
export interface InviteEntry {
  readonly orgId: string;
  readonly invitationId: string;
  /** The token's SHA-256: 32 bytes. */
  readonly tokenHash: Buffer;
}

/**
 * Lists the token as the invitation's, in the caller's transaction, which
 * must be withTenant's for that organisation: the one opening the
 * invitation. A second token for the invitation is refused by the table's
 * key, so the whole change rolls back.
 */
export async function registerInvite(
  tx: Transaction<DirectoryTables>,
  { orgId, invitationId, tokenHash }: InviteEntry,
): Promise<void> {
  await assertTenant(tx, orgId);
  await tx
    .insertInto('directory.invites')
    .values({ token_hash: tokenHash, org_id: orgId, invitation_id: invitationId })
    .execute();
}

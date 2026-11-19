// A connection's refresh head (0102; R-15, S206): the one refresh token of
// the connection that may be used now, kept in a signed state of its own, so
// the database's owner can't make a used refresh token current again (by
// clearing its `used_at`, or deleting and putting back the rows its use made)
// without removing signed events, which the chain's own checks find. An
// authority table, on the product's list, at the connection's level in the
// lock order (ADR-006 §6: 3b, after the connection). Its row's ID is its
// connection's (its key's).
//
// A connection gets its row as it is made, naming its first refresh token
// (the code's or device's exchange); each refresh moves it to the refresh
// token it issued. One made before 0102 has none (`unset`) until its next
// refresh adds it.
import type { SignedStateTable } from '@agentx/platform/db';

import type { SignedStates, StateCheck, TamperSign, VerifiedState } from '../../audit/index.ts';
import type { AgentsTransaction } from './agents.ts';

/** A connection's refresh head, as the signed state reads, records and checks it. */
export const CONNECTION_HEADS = {
  table: 'agents.connection_heads',
  subject: 'connection_head',
  fields: [{ column: 'refresh_id', type: 'uuid' }],
} as const satisfies SignedStateTable;

/** The head, verified; none yet (`unset`: a connection not refreshed since 0102); or tampered with (its alarm raised). */
export type HeadCheck =
  | { readonly outcome: 'set'; readonly refreshId: string; readonly state: VerifiedState }
  | { readonly outcome: 'unset' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

function headFrom(state: StateCheck): HeadCheck {
  if (state.outcome === 'tampered') return state;
  if (state.outcome === 'missing') return { outcome: 'unset' };
  // The column is a uuid, and the seal holds it to what was written.
  return { outcome: 'set', refreshId: (state.fields.get('refresh_id') ?? '').toLowerCase(), state };
}

/**
 * The connection's head, locked for change, in the caller's transaction, which must be withSignedStates' for the
 * organisation and have read the connection itself first (3b): two refreshes of one connection go one at a time.
 */
export async function headOf(
  tx: AgentsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
): Promise<HeadCheck> {
  return headFrom(await states.verifiedState(tx, CONNECTION_HEADS, key, 'change'));
}

/**
 * Moves the connection's head to the refresh token just issued, in the caller's transaction, which read it with
 * headOf: the row added and sealed if it had none, otherwise changed. Takes the chain head's lock (it comes last).
 */
export async function headMoved(
  tx: AgentsTransaction,
  states: SignedStates,
  read: Exclude<HeadCheck, { readonly outcome: 'tampered' }>,
  {
    orgId,
    id,
    refreshId,
    at,
  }: { readonly orgId: string; readonly id: string; readonly refreshId: string; readonly at: Date },
): Promise<void> {
  const fields = { refresh_id: refreshId };
  const change = {
    actor: { type: 'system' as const, id: 'oauth-server' },
    action: 'connection_head.moved',
    details: { refreshId },
  };
  if (read.outcome === 'set') {
    await states.record(tx, CONNECTION_HEADS, { orgId, id }, read.state, fields, change);
    return;
  }
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (as a remittance setting's, suppliers/remittance.ts)
    .insertInto(CONNECTION_HEADS.table)
    .values({ org_id: orgId, id, ...fields, created_at: at })
    .execute();
  await states.record(tx, CONNECTION_HEADS, { orgId, id }, 'new', fields, change);
}

/**
 * Whether a write failed because the connection's head was made by another transaction first: two refreshes of a
 * connection that had none (made before 0102) at once, the second's insert refused by the table's key.
 */
export const isHeadTaken = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  (error as { code?: unknown }).code === '23505' &&
  (error as { constraint?: unknown }).constraint === 'connection_heads_pkey';

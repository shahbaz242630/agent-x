// Memberships (0015): a person in an organisation, with a role. An authority
// table (ADR-012 §2), so whose it is, its role, its status and when it began
// must equal the membership's latest signed event, and every read a decision
// rests on goes through the audit module's verifiedState with the description
// below. The description is on the product's authority-table list
// (packages/core/src/authority-tables.ts), which CI, the lint rules and the
// live schema guard all read.
//
// A membership is added in one transaction, withSignedStates' for its
// organisation: its directory entry first (the row points at it), then its
// row, then its first signed state. The insert is the one query on this table
// outside the audit module's steps, as for an organisation's row
// (organizations.ts says why a plain insert is safe, and must stay plain).
//
// A person's membership is found by the ID their directory entry names, never
// by reading this table for the person (which would read it past its signed
// state), and then verified: the signed state must name the same person, so
// an entry pointed at someone else's membership finds nothing.
import type { SignedStateTable } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import {
  type AuditActor,
  type AuditTables,
  type RecordedState,
  type SignedStates,
  type SignedStatesServices,
  type TamperSign,
  withSignedStates,
} from '../../audit/index.ts';
import { type DirectoryTables, listedMembership, registerMember } from '../../directory/index.ts';
import { isRole, MEMBERSHIP, type Role } from '../domain/membership.ts';
import type { IdentityTables } from './tables.ts';

/** A membership's row, as the signed state reads, records and moves it. */
export const MEMBERSHIPS = {
  table: 'identity.memberships',
  subject: 'membership',
  fields: [
    { column: 'user_id', type: 'uuid' },
    { column: 'role', type: 'text' },
    { column: 'status', type: 'text' },
    { column: 'joined_at', type: 'timestamptz' },
  ],
  rules: MEMBERSHIP,
} as const satisfies SignedStateTable & { readonly rules: typeof MEMBERSHIP };

/** A transaction on the tables a membership is added and read in, opened by withSignedStates for its organisation. */
export type MembershipsTransaction = Transaction<IdentityTables & DirectoryTables & AuditTables>;

export interface NewMembership {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  /** The person, an identity.users ID. */
  readonly userId: string;
  readonly role: Role;
  readonly joinedAt: Date;
  /** Who is adding it. */
  readonly actor: AuditActor;
}

/**
 * Adds the membership, ACTIVE, in the caller's transaction, which must be
 * withSignedStates' for its organisation; `states` are that transaction's. A
 * person with a membership there already is refused by the directory's key.
 */
export async function addMembership(
  tx: MembershipsTransaction,
  states: SignedStates,
  { orgId, id, userId, role, joinedAt, actor }: NewMembership,
): Promise<RecordedState> {
  await registerMember(tx, { orgId, userId, membershipId: id });
  const fields = { user_id: userId, role, status: MEMBERSHIP.initial, joined_at: joinedAt };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(MEMBERSHIPS.table)
    .values({ org_id: orgId, id, ...fields })
    .execute();
  return states.record(tx, MEMBERSHIPS, { orgId, id }, 'new', fields, {
    actor,
    action: 'membership.created',
    details: { role },
  });
}

/**
 * The person's membership of the organisation, verified: active with its
 * role, deactivated, none, or tampered with (the alarm is raised, and the
 * organisation held). Anything but `active` grants nothing.
 */
export type MembershipCheck =
  | { readonly outcome: 'active'; readonly id: string; readonly role: Role }
  | { readonly outcome: 'deactivated'; readonly id: string }
  | { readonly outcome: 'none' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The person's membership of the organisation, read for a decision (`share`)
 * in the caller's transaction, which must be withSignedStates' for it.
 */
export async function membershipOf(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
  userId: string,
): Promise<MembershipCheck> {
  const id = await listedMembership(tx, orgId, userId);
  if (id === undefined) return { outcome: 'none' };
  const state = await states.verifiedState(tx, MEMBERSHIPS, { orgId, id }, 'share');
  if (state.outcome === 'missing') return { outcome: 'none' };
  if (state.outcome === 'tampered') return state;
  // The entry named another person's membership: not this person's, whatever it grants.
  if (state.fields.get('user_id') !== userId.toLowerCase()) return { outcome: 'none' };
  if (state.fields.get('status') !== 'ACTIVE') return { outcome: 'deactivated', id };
  const role = state.fields.get('role');
  // The table's check holds the role to the four, and the seal to what was written.
  if (!isRole(role)) throw new Error(`A verified membership holds a role that isn't one: ${id}`);
  return { outcome: 'active', id, role };
}

/**
 * The person's membership of the organisation, read for a decision in a
 * transaction of its own, withSignedStates' for the organisation: what a
 * request's access check reads (B4-2a). A membership found tampered with
 * raises the alarm and holds the organisation, logged through `services`'
 * logger. Each statement is limited to 10 seconds, so a hung read gives its
 * connection back and the request fails rather than hangs.
 */
export function membershipFor(
  db: Kysely<IdentityTables & DirectoryTables & AuditTables>,
  services: SignedStatesServices,
  orgId: string,
  userId: string,
): Promise<MembershipCheck> {
  return withSignedStates(db, orgId, services, async (tx, states) => {
    await sql`set local statement_timeout = '10s'`.execute(tx);
    return membershipOf(tx, states, orgId, userId);
  });
}

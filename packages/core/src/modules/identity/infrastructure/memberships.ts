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
  type VerifiedState,
  withSignedStates,
} from '../../audit/index.ts';
import { type DirectoryTables, listedMembers, listedMembership, registerMember } from '../../directory/index.ts';
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

/** A deactivated membership brought back: which, with what role, from when, and by whom. */
export interface Reactivation {
  readonly orgId: string;
  readonly id: string;
  readonly role: Role;
  /** When it came back: its new start, as a member returning isn't an established one (ADR-012 §1). */
  readonly joinedAt: Date;
  readonly actor: AuditActor;
}

/**
 * Brings a deactivated membership back, in the caller's transaction, which
 * must be withSignedStates' for its organisation and read it for change
 * (membershipOf's `change`): its role and start set first, then
 * DEACTIVATED>ACTIVE (0019). Throws if it isn't there, verified, and
 * deactivated: the caller read it so just now, in this transaction.
 */
export async function reactivateMembership(
  tx: MembershipsTransaction,
  states: SignedStates,
  { orgId, id, role, joinedAt, actor }: Reactivation,
): Promise<void> {
  const key = { orgId, id };
  const current = await states.verifiedState(tx, MEMBERSHIPS, key, 'change');
  if (current.outcome !== 'verified' || current.fields.get('status') !== 'DEACTIVATED') {
    throw new Error(`a membership read as deactivated is not: ${current.outcome}`);
  }
  await states.record(
    tx,
    MEMBERSHIPS,
    key,
    current,
    { role, joined_at: joinedAt },
    { actor, action: 'membership.renewed', details: { roleFrom: current.fields.get('role') ?? null, roleTo: role } },
  );
  const moved = await states.changeStatus(tx, MEMBERSHIPS, key, 'reactivate', {
    actor,
    action: 'membership.reactivated',
    details: { role },
  });
  if (moved.outcome !== 'changed') throw new Error(`a deactivated membership did not move back: ${moved.outcome}`);
}

/**
 * Whether an error is the directory's key refusing a second entry for the
 * person in the organisation (0015): a membership added since the caller
 * checked there was none, by a write at the same moment (B4-4c, B4-4d).
 */
export const isMembershipTaken = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  (error as { code?: unknown }).code === '23505' &&
  (error as { constraint?: unknown }).constraint === 'members_pkey';

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
 * The person's membership of the organisation, read for a decision (`share`),
 * or for a change the caller may make to it (`change`: a deactivated one
 * brought back, B4-5c), in the caller's transaction, which must be
 * withSignedStates' for it.
 */
export async function membershipOf(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
  userId: string,
  lock: 'share' | 'change' = 'share',
): Promise<MembershipCheck> {
  const id = await listedMembership(tx, orgId, userId);
  if (id === undefined) return { outcome: 'none' };
  const state = await states.verifiedState(tx, MEMBERSHIPS, { orgId, id }, lock);
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

/**
 * The organisation's members, read and verified in a transaction of their
 * own, withSignedStates' for the organisation: what the members route
 * reads (B4-2b). Each statement is limited to 10 seconds.
 */
export function membersFor(
  db: Kysely<IdentityTables & DirectoryTables & AuditTables>,
  services: SignedStatesServices,
  orgId: string,
): Promise<MembersList> {
  return withSignedStates(db, orgId, services, async (tx, states) => {
    await sql`set local statement_timeout = '10s'`.execute(tx);
    return membersOf(tx, states, orgId);
  });
}

/** The most members an organisation's list gives: more is refused, never cut short unseen. */
export const MOST_MEMBERS = 500;

/** A member, as their verified membership says. */
export interface MemberRecord {
  readonly id: string;
  readonly userId: string;
  readonly role: Role;
  readonly status: 'ACTIVE' | 'DEACTIVATED';
  readonly joinedAt: Date;
}

/**
 * The organisation's members, each verified, in order of membership ID; or
 * tampered with, at the first membership that is (the alarm is raised, and
 * the organisation held), so no list is given that holds one that can't be
 * believed.
 */
export type MembersList =
  | { readonly outcome: 'listed'; readonly members: readonly MemberRecord[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** More members than a list gives (MOST_MEMBERS): a page of them is for later. */
export class TooManyMembers extends Error {
  constructor() {
    super(`The organisation has more than ${String(MOST_MEMBERS)} members, more than a list gives`);
    this.name = 'TooManyMembers';
  }
}

/**
 * The organisation's members, each read for a decision (`share`) and
 * verified, in the caller's transaction, which must be withSignedStates' for
 * it. Each membership is found by the ID an entry names; an entry naming
 * someone else's membership, or none, finds nothing, and each membership is
 * given once, as its own signed state says whose it is.
 */
export async function membersOf(tx: MembershipsTransaction, states: SignedStates, orgId: string): Promise<MembersList> {
  const entries = await listedMembers(tx, orgId, MOST_MEMBERS + 1);
  if (entries.length > MOST_MEMBERS) throw new TooManyMembers();
  const members: MemberRecord[] = [];
  for (const { userId, membershipId: id } of entries) {
    const read = await memberOf(tx, states, { orgId, id }, 'share');
    if (read.outcome === 'tampered') return read;
    if (read.outcome === 'missing' || read.member.userId !== userId) continue;
    members.push(read.member);
  }
  return { outcome: 'listed', members };
}

/** A membership read by its ID and verified, with the state a change records from; missing; or tampered with. */
export type MemberCheck =
  | { readonly outcome: 'found'; readonly member: MemberRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The membership, by its ID, read and verified in the caller's transaction,
 * which must be withSignedStates' for its organisation: `share` for a
 * decision, `change` for a change (its state then what `record` takes). Whose
 * it is comes from its signed state; the caller compares it with the person
 * the directory named.
 */
export async function memberOf(
  tx: MembershipsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
): Promise<MemberCheck> {
  const state = await states.verifiedState(tx, MEMBERSHIPS, key, lock);
  if (state.outcome !== 'verified') return state;
  const userId = state.fields.get('user_id');
  const role = state.fields.get('role');
  const status = state.fields.get('status');
  const joinedAt = state.fields.get('joined_at');
  if (
    typeof userId !== 'string' ||
    !isRole(role) ||
    (status !== 'ACTIVE' && status !== 'DEACTIVATED') ||
    typeof joinedAt !== 'string'
  ) {
    throw new Error(`A verified membership holds a field that isn't one of its own: ${key.id}`);
  }
  return {
    outcome: 'found',
    member: { id: key.id.toLowerCase(), userId, role, status, joinedAt: new Date(joinedAt) },
    state,
  };
}

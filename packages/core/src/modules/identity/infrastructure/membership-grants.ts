// A membership's grant summary (0085; OR1, CF Phase 1 E3-1 (b)): who granted
// or confirmed its role, when it last stopped being a verifier's, and the
// membership version it was kept in step with. An authority table of the
// membership's own (ADR-012 §2), read through its signed state and on the
// product's authority-table list, at the membership's level in the lock order
// (ADR-006 §6: 2a), after its membership. Its row's ID is its membership's.
//
// Each membership change keeps it, in the change's own transaction, read for
// the change after the membership: added with a new membership (its adder,
// and whoever asked for, opened or confirmed an invitation the person
// accepted there), and moved on by a return, a role change or a deactivation.
// Nothing is ever taken from it, so it never looks cleaner than the history
// it stands for. A membership added before 0085 has none (`unbuilt`) until
// the API's job builds it from the history (grant-building.ts); its changes
// meanwhile leave it unbuilt, as the history the job reads holds them. One
// not in step with its membership as a change finds it (behind: since 0089 no
// image in service leaves one, OR1c) refuses the change, its alarm raised; the
// job brings it up to date from the history. An invitation a deactivated
// member accepts is added only when they are brought back, which reads them
// all again.
import type { SignedStateTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import {
  type AuditActor,
  type AuditTables,
  type SignedStates,
  SignedStateFailed,
  type StateCheck,
  type TamperSign,
  TooManyEventsToRead,
  type VerifiedState,
} from '../../audit/index.ts';
import {
  type GrantChange,
  grantsAfter,
  type GrantSummary,
  INVITATION_GRANTS,
  NO_GRANTS,
} from '../domain/two-person.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import type { IdentityTables } from './tables.ts';

/**
 * A transaction on the tables a membership is added and read in, opened by withSignedStates for its organisation. Kept
 * here, beside the grant summaries it carries, and re-exported by memberships.ts, so the two files don't import each other.
 */
export type MembershipsTransaction = Transaction<IdentityTables & DirectoryTables & AuditTables>;

/** A membership's grant summary, as the signed state reads, records and checks it. */
export const MEMBERSHIP_GRANTS = {
  table: 'identity.membership_grants',
  subject: 'membership_grant',
  fields: [
    { column: 'granted_by', type: 'text' },
    { column: 'verifier_changed_at', type: 'timestamptz' },
    { column: 'membership_version', type: 'integer' },
  ],
} as const satisfies SignedStateTable;

/**
 * The membership's summary, verified: what it holds, the membership version it
 * was kept at, and the state a change records from; none yet (`unbuilt`, a
 * membership added before 0085); or tampered with (its alarm raised).
 */
export type GrantsCheck =
  | {
      readonly outcome: 'kept';
      readonly summary: GrantSummary;
      readonly membershipVersion: number;
      readonly state: VerifiedState;
    }
  | { readonly outcome: 'unbuilt' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** The people a summary names, as its sealed text holds them: lower-case user IDs, sorted, comma-joined. */
const grantedByText = (grantedBy: ReadonlySet<string>): string => [...grantedBy].sort().join(',');

/** The summary a signed read of its row holds. */
export function grantsFrom(state: StateCheck): GrantsCheck {
  if (state.outcome === 'tampered') return state;
  if (state.outcome === 'missing') return { outcome: 'unbuilt' };
  const granted = state.fields.get('granted_by');
  const changedAt = state.fields.get('verifier_changed_at');
  const version = Number(state.fields.get('membership_version'));
  // 0085's checks hold the columns to their shapes, and the seal to what was written.
  if (typeof granted !== 'string' || changedAt === undefined || !Number.isSafeInteger(version)) {
    throw new Error("A verified grant summary holds a field that isn't one of its own");
  }
  return {
    outcome: 'kept',
    summary: {
      grantedBy: new Set(granted === '' ? [] : granted.split(',')),
      verifierChangedAt: changedAt === null ? undefined : new Date(changedAt),
    },
    membershipVersion: version,
    state,
  };
}

/** The fields a summary is sealed with. */
const fieldsOf = (summary: GrantSummary, membershipVersion: number) => ({
  granted_by: grantedByText(summary.grantedBy),
  verifier_changed_at: summary.verifierChangedAt ?? null,
  membership_version: membershipVersion,
});

/** The membership's summary read for its change, in the caller's transaction, after the membership itself. */
export async function grantsToChange(
  tx: MembershipsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
): Promise<GrantsCheck> {
  return grantsFrom(await states.verifiedState(tx, MEMBERSHIP_GRANTS, key, 'change'));
}

/**
 * Adds the membership's summary, sealed: for a membership just added (its
 * first), or one the job builds from the history (`membership_grant.built`).
 */
export async function addGrants(
  tx: MembershipsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  summary: GrantSummary,
  membershipVersion: number,
  change: { readonly actor: AuditActor; readonly action: 'membership_grant.kept' | 'membership_grant.built' },
): Promise<void> {
  const fields = fieldsOf(summary, membershipVersion);
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (as a membership's, memberships.ts)
    .insertInto(MEMBERSHIP_GRANTS.table)
    .values({ org_id: key.orgId, id: key.id, ...fields })
    .execute();
  await states.record(tx, MEMBERSHIP_GRANTS, key, 'new', fields, { ...change, details: {} });
}

/**
 * Moves the summary on with its membership's change, in the caller's
 * transaction, which read it for the change (`grantsToChange`) and has just
 * recorded the membership from `fromVersion` to `membershipVersion`. One
 * unbuilt is left for the job, whose history holds this change. One not at
 * `fromVersion` (OR1c) throws, raised as a mismatch (the alarm, and the hold),
 * so the change rolls back: moved on, it would claim a version whose grants it
 * never saw.
 */
export async function keepGrants(
  tx: MembershipsTransaction,
  states: SignedStates,
  read: Exclude<GrantsCheck, { readonly outcome: 'tampered' }>,
  key: { readonly orgId: string; readonly id: string },
  {
    change,
    fromVersion,
    membershipVersion,
    actor,
  }: { change: GrantChange; fromVersion: number; membershipVersion: number; actor: AuditActor },
): Promise<void> {
  if (read.outcome === 'unbuilt') return;
  if (read.membershipVersion !== fromVersion) {
    states.mismatch(MEMBERSHIP_GRANTS.subject, key);
    throw new SignedStateFailed('tampered', "A membership's grant summary isn't in step with its membership");
  }
  await states.record(
    tx,
    MEMBERSHIP_GRANTS,
    key,
    read.state,
    fieldsOf(grantsAfter(read.summary, change), membershipVersion),
    {
      actor,
      action: 'membership_grant.kept',
      details: {},
    },
  );
}

/**
 * A summary left behind its membership brought up to date by the job, its
 * alarm already raised, in the caller's transaction, which read it for the
 * change: what the history says, with nothing it held taken away, at the
 * membership's version.
 */
export async function bringUpToDate(
  tx: MembershipsTransaction,
  states: SignedStates,
  read: Extract<GrantsCheck, { readonly outcome: 'kept' }>,
  key: { readonly orgId: string; readonly id: string },
  {
    summary,
    membershipVersion,
    actor,
    action,
  }: { summary: GrantSummary; membershipVersion: number; actor: AuditActor; action: 'membership_grant.built' },
): Promise<void> {
  // Neither set ever names the member, so no one is taken out here.
  const upToDate = grantsAfter(read.summary, {
    memberUserId: '',
    granters: summary.grantedBy,
    verifierChangedAt: summary.verifierChangedAt,
  });
  await states.record(tx, MEMBERSHIP_GRANTS, key, read.state, fieldsOf(upToDate, membershipVersion), {
    actor,
    action,
    details: {},
  });
}

/** The read's summary, or the tamper sign thrown: its alarm is raised, and the change's transaction rolls back. */
export function grantsBelieved(read: GrantsCheck): Exclude<GrantsCheck, { readonly outcome: 'tampered' }> {
  if (read.outcome === 'tampered') {
    throw new SignedStateFailed('tampered', `A membership's grant summary can't be believed (${read.sign})`);
  }
  return read;
}

/** The most invitations one person accepted in an organisation that a membership's summary reads. */
export const MOST_ACCEPTED = 100;

/** Every time the log can hold. */
const WHOLE_LOG = { from: new Date(0), to: new Date('9999-12-31T00:00:00Z') } as const;

/**
 * Who asked for, opened or confirmed any invitation the person accepted in the
 * organisation, from its log (user IDs, lower case): an accepted one later
 * declined counts, as it always has (two-person.ts). In the caller's
 * transaction, which records the acceptance before it. Past MOST_ACCEPTED
 * acceptances it throws rather than read part; the log tampered with throws
 * too, its alarm raised.
 */
export async function invitationGrantersOf(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
  userId: string,
): Promise<readonly string[]> {
  const accepted = await states.logPageOf(tx, orgId, {
    ...WHOLE_LOG,
    actions: ['invitation.acceptance_recorded'],
    actor: { type: 'user', id: userId },
    limit: MOST_ACCEPTED,
  });
  if (accepted.outcome === 'tampered') {
    throw new SignedStateFailed('tampered', `The log can't be believed (${accepted.sign})`);
  }
  if (accepted.next !== null) throw new TooManyEventsToRead(MOST_ACCEPTED);
  const invitations = [...new Set(accepted.events.map(({ event }) => event.subject.id.toLowerCase()))];
  if (invitations.length === 0) return [];
  const grants = await states.historyOf(tx, orgId, {
    subjectTypes: ['invitation'],
    subjectIds: invitations,
    actions: [...INVITATION_GRANTS],
    limit: MOST_ACCEPTED * INVITATION_GRANTS.size,
  });
  if (grants.outcome === 'tampered') {
    throw new SignedStateFailed('tampered', `The log can't be believed (${grants.sign})`);
  }
  return grants.events
    .filter(({ event }) => event.actor.type === 'user')
    .map(({ event }) => event.actor.id.toLowerCase());
}

/**
 * The summary a membership just added starts with, sealed in its transaction:
 * whoever added it (a person; the operator's command grants nothing) and
 * whoever asked for, opened or confirmed an invitation the person accepted.
 */
export async function grantsForNewMembership(
  tx: MembershipsTransaction,
  states: SignedStates,
  {
    orgId,
    id,
    userId,
    actor,
    membershipVersion,
  }: {
    readonly orgId: string;
    readonly id: string;
    readonly userId: string;
    readonly actor: AuditActor;
    readonly membershipVersion: number;
  },
): Promise<void> {
  const granters = [...(await invitationGrantersOf(tx, states, orgId, userId)), ...byPerson(actor)];
  const summary = grantsAfter(NO_GRANTS, { memberUserId: userId, granters });
  await addGrants(tx, states, { orgId, id }, summary, membershipVersion, { actor, action: 'membership_grant.kept' });
}

/** The actor, when a person: who a change by them grants a role to counts among its granters. */
export const byPerson = (actor: AuditActor): readonly string[] =>
  actor.type === 'user' ? [actor.id.toLowerCase()] : [];

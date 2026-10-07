// Accepting a mandate's waiting draft (PRD §3 `MandateEvidence`, §4.1; BR-05;
// Phase 2 B3): the draft becomes the version in force, with who accepted it
// and when, in one signed change; a mandate waiting for its first acceptance
// then moves to ACTIVE. The version it replaces is SUPERSEDED by being no
// longer current (PRD §4.1). The accept event, with the version's terms hash
// and the step-up's evidence the use case passes, is the MandateEvidence.
//
// Before accepting, the use case reads every mandate of the agent through its
// signed state (`mandatesOfAgent`): B2's open-mandate query goes by the row's
// status, so an open mandate flipped to ended past the app is caught here,
// before a second one goes live (S89 review).
import type { Transaction } from 'kysely';

import type { AuditActor, AuditDetails, AuditTables, SignedStates, VerifiedState } from '../../audit/index.ts';
import type { MandateRecord } from './drafts.ts';
import { MANDATES } from './mandates.ts';
import type { MandatesTables } from './tables.ts';

type MandatesTransaction = Transaction<MandatesTables & AuditTables>;

/**
 * The agent a mandate gives authority to, in one statement, or undefined for
 * none of the organisation's: read before any lock, so the agent can be
 * locked before its mandates (ADR-006 §6). `fixed_at_creation` holds the
 * column even against the app, and the mandate's verified read after checks
 * it against the seal.
 */
export async function agentOfMandate(
  tx: MandatesTransaction,
  orgId: string,
  mandateId: string,
): Promise<string | undefined> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a column fixed at creation, checked by the mandate's verified read that follows
    .selectFrom(MANDATES.table)
    .select('agent_id')
    .where('org_id', '=', orgId)
    .where('id', '=', mandateId)
    .executeTakeFirst();
  return row?.agent_id;
}

/** The IDs of the agent's mandates, in order of ID, in one statement: each to be read through its signed state. */
export async function mandatesOfAgent(
  tx: MandatesTransaction,
  orgId: string,
  agentId: string,
): Promise<readonly string[]> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state by the caller before it decides anything
    .selectFrom(MANDATES.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('agent_id', '=', agentId)
    .orderBy('id')
    .execute();
  return rows.map(({ id }) => id);
}

/** An acceptance, as the use case makes it. */
export interface Acceptance {
  readonly orgId: string;
  /** The draft accepted: the one waiting, bound by the step-up to its terms hash. */
  readonly versionId: string;
  /** The membership of the admin accepting it, checked active by the use case, and when. */
  readonly acceptedBy: string;
  readonly acceptedAt: Date;
  readonly actor: AuditActor;
  /** The evidence: the terms hash and the step-up's proof. */
  readonly details: AuditDetails;
}

/**
 * Makes the mandate's waiting draft its version in force, in the caller's
 * transaction (withSignedStates' for its organisation), from the mandate read
 * for change here (`of`); then ACTIVE, if it waited for its first. Only the
 * draft waiting, on a mandate waiting or ACTIVE: anything else is a
 * RangeError, as the use case refuses it first.
 */
export async function acceptDraft(
  tx: MandatesTransaction,
  states: SignedStates,
  of: { readonly mandate: MandateRecord; readonly state: VerifiedState },
  { orgId, versionId, acceptedBy, acceptedAt, actor, details }: Acceptance,
): Promise<void> {
  const { mandate } = of;
  if (mandate.pendingVersionId !== versionId.toLowerCase()) throw new RangeError('Only the draft waiting is accepted');
  if (mandate.status !== 'PENDING_ACCEPTANCE' && mandate.status !== 'ACTIVE') {
    throw new RangeError('Only a mandate waiting or ACTIVE takes a version');
  }
  const key = { orgId, id: mandate.id };
  await states.record(
    tx,
    MANDATES,
    key,
    of.state,
    {
      current_version_id: mandate.pendingVersionId,
      pending_version_id: null,
      accepted_by: acceptedBy,
      accepted_at: acceptedAt,
    },
    {
      actor,
      action: 'mandate.accepted',
      details: { ...details, versionId: mandate.pendingVersionId, replaced: mandate.currentVersionId },
    },
  );
  if (mandate.status === 'ACTIVE') return;
  const activated = await states.changeStatus(tx, MANDATES, key, 'accept', {
    actor,
    action: 'mandate.activated',
    details: { versionId: mandate.pendingVersionId },
  });
  if (activated.outcome !== 'changed')
    throw new Error(`A mandate read as waiting didn't activate: ${activated.outcome}`);
}

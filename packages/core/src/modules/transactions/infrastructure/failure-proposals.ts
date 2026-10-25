// An admin's proposal to mark an UNKNOWN payment failed (0066; Phase 4 gate
// H10): an authority table read and moved through the audit module's signed
// states, its status by its machine (domain/failure-proposal.ts). Locked at
// its transaction's level (ADR-006 §6: 10), after its transaction.
//
// - `proposeFailure`: born OPEN with the bank's reference and its proposer,
//   and signed (`failure_proposal.made`); a second OPEN one for the payment is
//   refused by 0066's `one_open_proposal_a_payment`, so callers read first.
// - `openProposalOf`: the payment's OPEN proposal, if any, through its signed state;
//   `proposalOf`, one by its ID.
// - `moveProposal`: withdrawn or confirmed, from the state verified for change.
import type { SignedStateTable, StatusTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type {
  AuditActor,
  AuditDetails,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
} from '../../audit/index.ts';
import { FAILURE_PROPOSAL, type FailureProposalEvent, type FailureProposalStatus } from '../domain/failure-proposal.ts';
import { movedAsRead } from '../../../shared-kernel/index.ts';
import type { TransactionsTables } from './tables.ts';

/** A proposal's row, as the signed state reads, records and moves it. */
export const FAILURE_PROPOSALS = {
  table: 'transactions.failure_proposals',
  subject: 'failure_proposal',
  fields: [
    { column: 'transaction_id', type: 'uuid' },
    { column: 'evidence_ref', type: 'text' },
    { column: 'proposed_by', type: 'uuid' },
    { column: 'status', type: 'text' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  rules: FAILURE_PROPOSAL,
  // Its payment, its reference, its proposer and when, fixed when it is made: 0066's `fixed_at_creation`.
  fixedAtCreation: ['transaction_id', 'evidence_ref', 'proposed_by', 'created_at'],
  // Clearing the integrity hold checks those that can still free a payment.
  liveStatuses: ['OPEN'],
} as const satisfies SignedStateTable &
  StatusTable<FailureProposalStatus, FailureProposalEvent> & {
    readonly fixedAtCreation: readonly string[];
    readonly liveStatuses: readonly string[];
  };

type ProposalsTransaction = Transaction<TransactionsTables & AuditTables>;

/** A proposal as its signed state holds it. */
export interface FailureProposalRecord {
  readonly id: string;
  readonly transactionId: string;
  readonly evidenceRef: string;
  readonly proposedBy: string;
  readonly status: FailureProposalStatus;
  readonly createdAt: Date;
}

/** The payment's OPEN proposal: none, verified (with its state, for a step-up's binding), or tampered with. */
export type OpenProposal =
  | { readonly outcome: 'none' }
  | {
      readonly outcome: 'found';
      readonly proposal: FailureProposalRecord;
      readonly state: { readonly eventId: string };
    }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** Opens the proposal, OPEN, and signs it, in the caller's transaction (withSignedStates'), after its transaction (10). */
export async function proposeFailure(
  tx: ProposalsTransaction,
  states: SignedStates,
  proposal: {
    readonly orgId: string;
    readonly id: string;
    readonly transactionId: string;
    readonly evidenceRef: string;
    readonly proposedBy: string;
    readonly createdAt: Date;
  },
  change: { readonly actor: AuditActor; readonly details: AuditDetails },
): Promise<RecordedState> {
  const { orgId, id, transactionId, evidenceRef, proposedBy, createdAt } = proposal;
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below
    .insertInto(FAILURE_PROPOSALS.table)
    .values({
      org_id: orgId,
      id,
      transaction_id: transactionId,
      evidence_ref: evidenceRef,
      proposed_by: proposedBy,
      status: FAILURE_PROPOSAL.initial,
      created_at: createdAt,
    })
    .execute();
  return states.record(
    tx,
    FAILURE_PROPOSALS,
    { orgId, id },
    'new',
    {
      transaction_id: transactionId,
      evidence_ref: evidenceRef,
      proposed_by: proposedBy,
      status: FAILURE_PROPOSAL.initial,
      created_at: createdAt,
    },
    { actor: change.actor, action: 'failure_proposal.made', details: { ...change.details, transactionId } },
  );
}

/**
 * The payment's OPEN proposal, read through its signed state and locked as
 * `lock` asks, in the caller's transaction, after the payment itself (10).
 * Found by the open index, then verified: a row whose seal fails is tampered.
 */
export async function openProposalOf(
  tx: ProposalsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly transactionId: string },
  lock: 'share' | 'change',
): Promise<OpenProposal> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- finds the ID alone; the row is read through its signed state just below
    .selectFrom(FAILURE_PROPOSALS.table)
    .select('id')
    .where('org_id', '=', key.orgId)
    .where('transaction_id', '=', key.transactionId)
    .where('status', '=', 'OPEN')
    .executeTakeFirst();
  if (row === undefined) return { outcome: 'none' };
  const read = await proposalOf(tx, states, { orgId: key.orgId, id: row.id }, lock);
  // Found by its ID a moment ago, and never deleted (0066's grants): one gone since (deleted past the app as this
  // read waited on its lock) is a tamper sign, its alarm raised and the organisation held.
  if (read.outcome !== 'missing') return read;
  states.mismatch(FAILURE_PROPOSALS.subject, { orgId: key.orgId, id: row.id });
  return { outcome: 'tampered', sign: 'deleted' };
}

/** A proposal by its ID, read through its signed state and locked as `lock` asks: found, missing or tampered with. */
export async function proposalOf(
  tx: ProposalsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
): Promise<Exclude<OpenProposal, { outcome: 'none' }> | { readonly outcome: 'missing' }> {
  const state = await states.verifiedState(tx, FAILURE_PROPOSALS, key, lock);
  if (state.outcome !== 'verified') return state;
  const { fields } = state;
  const proposal: FailureProposalRecord = {
    id: key.id.toLowerCase(),
    transactionId: String(fields.get('transaction_id')),
    evidenceRef: String(fields.get('evidence_ref')),
    proposedBy: String(fields.get('proposed_by')),
    status: fields.get('status') as FailureProposalStatus,
    createdAt: new Date(String(fields.get('created_at'))),
  };
  return { outcome: 'found', proposal, state: { eventId: state.eventId } };
}

/** Each move's action, as the organisation's log names it. */
const MOVED_AS = { withdraw: 'withdrawn', confirm: 'confirmed', end: 'ended' } as const satisfies Record<
  FailureProposalEvent,
  string
>;

/** Withdraws, confirms or ends the proposal, verified for change in this transaction; throws if its machine refuses. */
export async function moveProposal(
  tx: ProposalsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  event: FailureProposalEvent,
  change: { readonly actor: AuditActor; readonly details: AuditDetails },
): Promise<void> {
  const moved = await states.changeStatus(tx, FAILURE_PROPOSALS, key, event, {
    actor: change.actor,
    action: `failure_proposal.${MOVED_AS[event]}`,
    details: change.details,
  });
  // Read OPEN for change by its caller under this lock: anything but a change is something past the app.
  movedAsRead(moved, "An OPEN proposal didn't move");
}

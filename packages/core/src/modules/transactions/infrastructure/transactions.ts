// A handed-off request's transaction (0058; PRD §3 `Transaction`, §4.3;
// ADR-007 §7–§13; Phase 4 B3): the single source of truth for its outcome, an
// authority table read and moved through the audit module's signed states,
// its status by its machine (domain/transaction.ts), the partner's own words
// for it beside, signed too (PRD §6.2).
//
// - `openTransaction`: born SUBMISSION_PENDING with its instruction, in the
//   hand-off's Tx A, and signed (`transaction.opened`).
// - `transactionOf`: read through its signed state.
// - `moveTransaction`: the partner's facts as it gave them (its status, its
//   reference, a reject code, when it says the status changed), recorded
//   first where any differ, then the status moved by its machine, both from
//   the state verified for change (Tx B, ADR-007 §9; events and lookups, E1).
import type { SignedStateTable, StatusTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type {
  AuditActor,
  AuditDetails,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import { TRANSACTION, type TransactionEvent, type TransactionStatus } from '../domain/transaction.ts';
import type { TransactionsTables } from './tables.ts';

/** A transaction's row, as the signed state reads, records and moves it. */
export const TRANSACTIONS = {
  table: 'transactions.transactions',
  subject: 'transaction',
  fields: [
    { column: 'instruction_id', type: 'uuid' },
    { column: 'status', type: 'text' },
    { column: 'provider_status', type: 'text' },
    { column: 'payment_instruction_ref', type: 'text' },
    { column: 'reject_code', type: 'text' },
    { column: 'provider_changed_at', type: 'timestamptz' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  rules: TRANSACTION,
  // Its instruction and when it was opened, fixed when it is made: 0058's `fixed_at_creation` refuses any change after.
  fixedAtCreation: ['instruction_id', 'created_at'],
  // Clearing the integrity hold checks those whose outcome can still move.
  liveStatuses: ['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN', 'SUCCEEDED'],
} as const satisfies SignedStateTable &
  StatusTable<TransactionStatus, TransactionEvent> & {
    readonly fixedAtCreation: readonly string[];
    readonly liveStatuses: readonly string[];
  };

/** A transaction on the transactions and the audit tables, withSignedStates' for its organisation. */
export type TransactionsTransaction = Transaction<TransactionsTables & AuditTables>;

/** The partner's own words for the payment (PRD §6.2), each as it gave it, or null where it gave none. */
export interface ProviderFacts {
  readonly providerStatus: string | null;
  readonly paymentInstructionRef: string | null;
  readonly rejectCode: string | null;
  /** When the partner says the status changed (`regulatedEventTimestamp`). */
  readonly providerChangedAt: Date | null;
}

/** A transaction as its signed state holds it. */
export interface TransactionRecord extends ProviderFacts {
  readonly id: string;
  readonly instructionId: string;
  readonly status: TransactionStatus;
  readonly createdAt: Date;
}

/** The transaction, verified (with its state, to change it from); none; or tampered with (its alarm raised). */
export type TransactionCheck =
  | { readonly outcome: 'found'; readonly transaction: TransactionRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** A signed change's actor and evidence. */
export interface TransactionChange {
  readonly actor: AuditActor;
  readonly details: AuditDetails;
}

/**
 * Opens the instruction's transaction, SUBMISSION_PENDING, and signs it, in
 * the caller's transaction (withSignedStates'), after its instruction (both at
 * ADR-006 §6 level 10), its event recorded at the head's place, last.
 */
export async function openTransaction(
  tx: TransactionsTransaction,
  states: SignedStates,
  {
    orgId,
    id,
    instructionId,
    createdAt,
  }: {
    readonly orgId: string;
    readonly id: string;
    readonly instructionId: string;
    readonly createdAt: Date;
  },
  change: TransactionChange,
): Promise<RecordedState> {
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below
    .insertInto(TRANSACTIONS.table)
    .values({ org_id: orgId, id, instruction_id: instructionId, status: TRANSACTION.initial, created_at: createdAt })
    .execute();
  return states.record(
    tx,
    TRANSACTIONS,
    { orgId, id },
    'new',
    {
      instruction_id: instructionId,
      status: TRANSACTION.initial,
      provider_status: null,
      payment_instruction_ref: null,
      reject_code: null,
      provider_changed_at: null,
      created_at: createdAt,
    },
    { actor: change.actor, action: 'transaction.opened', details: { ...change.details, instructionId } },
  );
}

/**
 * The record a verified state holds: every field is the table's own (a map of
 * them all, each its text or null), held to its kind by 0058's checks and the
 * status guard, and the seal to what was written.
 */
function recordOf(id: string, fields: ReadonlyMap<string, string | null>): TransactionRecord {
  const nullable = (column: string) => fields.get(column) as string | null;
  const changedAt = nullable('provider_changed_at');
  return {
    id,
    instructionId: String(fields.get('instruction_id')),
    status: fields.get('status') as TransactionStatus,
    providerStatus: nullable('provider_status'),
    paymentInstructionRef: nullable('payment_instruction_ref'),
    rejectCode: nullable('reject_code'),
    providerChangedAt: changedAt === null ? null : new Date(changedAt),
    createdAt: new Date(String(fields.get('created_at'))),
  };
}

/** The transaction, read through its signed state, locked as `lock` asks, in the caller's transaction. */
export async function transactionOf(
  tx: TransactionsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
): Promise<TransactionCheck> {
  const state = await states.verifiedState(tx, TRANSACTIONS, key, lock);
  if (state.outcome !== 'verified') return state;
  return { outcome: 'found', transaction: recordOf(key.id.toLowerCase(), state.fields), state };
}

/** What a move came to: moved (or the facts alone noted), refused by the machine, or the row tampered with or gone. */
export type TransactionMoved =
  | { readonly outcome: 'moved'; readonly from: TransactionStatus; readonly to: TransactionStatus }
  | { readonly outcome: 'refused'; readonly from: TransactionStatus }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** The facts as the row writes them, each column its text or null. */
const factsSet = ({ providerStatus, paymentInstructionRef, rejectCode, providerChangedAt }: ProviderFacts) => ({
  provider_status: providerStatus,
  payment_instruction_ref: paymentInstructionRef,
  reject_code: rejectCode,
  provider_changed_at: providerChangedAt,
});

const sameFacts = (record: ProviderFacts, facts: ProviderFacts): boolean =>
  record.providerStatus === facts.providerStatus &&
  record.paymentInstructionRef === facts.paymentInstructionRef &&
  record.rejectCode === facts.rejectCode &&
  record.providerChangedAt?.getTime() === facts.providerChangedAt?.getTime();

/**
 * Moves the transaction by `event` with the partner's `facts`, in the
 * caller's transaction (withSignedStates'), its row read for change here: the
 * facts recorded first where they differ (`transaction.provider_noted`), then
 * the status by its machine (`transaction.<event>`). An event its machine
 * doesn't allow from where it is changes nothing (`refused`): the caller
 * decides what that means (a webhook late, or a reconciliation exception).
 */
export async function moveTransaction(
  tx: TransactionsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  event: TransactionEvent,
  facts: ProviderFacts,
  change: TransactionChange,
): Promise<TransactionMoved> {
  const read = await transactionOf(tx, states, key, 'change');
  if (read.outcome !== 'found') return read;
  const from = read.transaction.status;
  if (!TRANSACTION.transition(from, event).ok) return { outcome: 'refused', from };
  if (!sameFacts(read.transaction, facts)) {
    await states.record(tx, TRANSACTIONS, key, read.state, factsSet(facts), {
      actor: change.actor,
      action: 'transaction.provider_noted',
      details: change.details,
    });
  }
  const moved = await states.changeStatus(tx, TRANSACTIONS, key, event, {
    actor: change.actor,
    action: `transaction.${event}`,
    details: change.details,
  });
  if (moved.outcome !== 'changed') {
    // Verified and locked for change, and the machine allows the move: anything else is something past the app.
    throw new Error(`A transaction verified for change didn't move: ${key.id} (${moved.outcome})`);
  }
  return { outcome: 'moved', from: moved.from, to: moved.to };
}

// What a payment's move does beyond itself (Phase 4 C3, C2b), in the
// transaction that moved it, once its holdings are locked (ADR-006 §6: the
// transaction read for change, 10; its holdings, 11; the move, 12): what its
// request holds settled as it now stands (the outcomes module), and, on
// SUCCEEDED, its supplier's remittance email queued (partner decision 34a).
// Every move of a payment goes through here (Tx B, the sweep, the bank check
// and the operator marking one failed, E1a, E1c), so neither is ever left
// out, each after `lockPayment`. Here in core, not the API, as the operator's
// command moves payments too. The email's setting and address are read as it
// is sent (`remittances.ts`), never here: they sit at level 6, above the
// locks already held.
import type { DatabaseTransaction } from '@agentx/platform/db';

import type { AuditTables, SignedStates } from '../../audit/index.ts';
import { instructionOf, type InstructionsTables } from '../../instructions/index.ts';
import type { LimitReservationsTables } from '../../limit-reservations/index.ts';
import type { Notice, NotificationsTables, Outbox } from '../../notifications/index.ts';
import { type PaymentExecution, paymentStateOf } from '../../providers/index.ts';
import type { SpendRequestsTables } from '../../spend-requests/index.ts';
import {
  type ProviderFacts,
  type TransactionEvent,
  transactionOf,
  type TransactionsTables,
  type TransactionStatus,
} from '../../transactions/index.ts';
import { lockHoldingsOf, settleHoldings } from './outcomes.ts';

type PaymentOutcomeTables = LimitReservationsTables & SpendRequestsTables & AuditTables & NotificationsTables;

/** The partner's answer as a transaction's facts (PRD §6.2), its own words kept. */
export const factsOf = (execution: PaymentExecution): ProviderFacts => ({
  providerStatus: execution.providerStatus,
  paymentInstructionRef: execution.paymentInstructionRef,
  rejectCode: execution.rejectCode,
  providerChangedAt: execution.statusChangedAt,
});

/** The move after SUBMITTED that the rail's state now asks for (rail map §4). */
export const AFTER_SUBMITTED: Readonly<Record<ReturnType<typeof paymentStateOf>, TransactionEvent>> = {
  PROCESSING: 'processing',
  SUCCEEDED: 'succeed',
  FAILED: 'fail',
  UNKNOWN: 'lose_track',
};

/** An answer with no facts of the partner's: a move alone. */
export const NO_FACTS: ProviderFacts = {
  providerStatus: null,
  paymentInstructionRef: null,
  rejectCode: null,
  providerChangedAt: null,
};

/** The transaction and its instruction, both verified, as `lockPayment` read them. */
export type LockedPayment = Readonly<{
  transaction: Extract<Awaited<ReturnType<typeof transactionOf>>, { outcome: 'found' }>['transaction'];
  instruction: Extract<Awaited<ReturnType<typeof instructionOf>>, { outcome: 'found' }>['instruction'];
}>;

/**
 * The transaction read for change (10), then its request's reservation and
 * claim locked (11), before a move takes the head (12; ADR-006 §6); throws for
 * a transaction that can't be believed (its alarm raised), or one not its
 * request's. With no request named (the operator's, which lists nothing), its
 * signed instruction's.
 */
export async function lockPayment(
  tx: DatabaseTransaction<PaymentOutcomeTables & InstructionsTables & TransactionsTables>,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  requestId?: string,
): Promise<LockedPayment> {
  const read = await transactionOf(tx, states, key, 'change');
  if (read.outcome !== 'found') throw new Error(`A handed-off transaction can't be believed: ${key.id}`);
  const instruction = await instructionOf(tx, states, { orgId: key.orgId, id: read.transaction.instructionId });
  if (
    instruction.outcome !== 'found' ||
    (requestId !== undefined && instruction.instruction.spendRequestId !== requestId.toLowerCase())
  ) {
    throw new Error(`A handed-off transaction's instruction can't be believed: ${key.id}`);
  }
  await lockHoldingsOf(tx, requestId ?? instruction.instruction.spendRequestId);
  return { transaction: read.transaction, instruction: instruction.instruction };
}

/** The payment just moved, and when. */
export interface PaymentMoved {
  readonly orgId: string;
  readonly requestId: string;
  readonly transactionId: string;
  readonly status: TransactionStatus;
  readonly at: Date;
}

/** The supplier's remittance email for the payment, to the supplier itself (0062). */
const remittanceOf = (orgId: string, transactionId: string): Notice => ({
  orgId,
  recipientUserId: null,
  kind: 'payment_remittance',
  membershipId: null,
  role: null,
  aboutId: transactionId,
});

/**
 * Settles what the payment's request holds as it now stands, and queues its
 * remittance once it SUCCEEDED: at most once a payment, as its machine
 * reaches SUCCEEDED once and the outbox holds one remittance a transaction
 * (0062). A caller must never move a payment to SUCCEEDED twice (E1's
 * partner events included): the second remittance would be refused, and the
 * move with it.
 */
export async function settlePayment(
  tx: DatabaseTransaction<PaymentOutcomeTables>,
  outbox: Outbox,
  { orgId, requestId, transactionId, status, at }: PaymentMoved,
): Promise<void> {
  await settleHoldings(tx, { requestId, status, at });
  if (status === 'SUCCEEDED') await outbox.add(tx, [remittanceOf(orgId, transactionId)]);
}

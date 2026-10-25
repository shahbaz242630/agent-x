// An UNKNOWN payment marked failed by the customer's admin, once the bank has
// confirmed in writing that it never accepted it (ADR-007 §10; partner
// decision 38, S144, replacing decision 35's "our team only": a payment's
// follow-up is between the customer and their bank). The bank check (E1a)
// leaves a payment UNKNOWN when the bank's answer proves nothing either way;
// this is how one leaves it without the bank's own status query. The route,
// its step-up and its confirm are the API's (`payment-marks.ts`).
//
// In the caller's transaction, under withSignedStates for the organisation,
// once it has read the payment for change (10) and found it markable (UNKNOWN
// is checked again here, never left to the caller alone): its
// request's holdings locked (11, `lockPayment`); `transaction.fail` on its
// chain (12, the admin its actor, naming the bank's evidence reference and
// the step-up and statement confirmed); its held money and its order given
// back (`settlePayment`); and a notice to every admin (0064). The bank check
// keeps checking it for 7 days from the mark, as it does a paid one, so the
// bank paying it after all is said (E1a's contradiction).
import type { DatabaseTransaction } from '@agentx/platform/db';

import type { AuditTables, SignedStates } from '../../audit/index.ts';
import type { InstructionsTables } from '../../instructions/index.ts';
import type { LimitReservationsTables } from '../../limit-reservations/index.ts';
import type { NotificationsTables, Outbox } from '../../notifications/index.ts';
import type { SpendRequestsTables } from '../../spend-requests/index.ts';
import { moveTransaction, type TransactionsTables } from '../../transactions/index.ts';
import { lockPayment, NO_FACTS, settlePayment } from './payment-outcome.ts';

/** Every table the change reaches: the payment, its holdings, the chain and the admins' notice. */
export type MarkFailedTables = AuditTables &
  NotificationsTables &
  TransactionsTables &
  InstructionsTables &
  LimitReservationsTables &
  SpendRequestsTables;

/** How long after its hand-off a payment may be marked failed: past the bank's longest time to settle one. */
export const MARK_FAILED_AFTER_MS = 24 * 60 * 60_000;

/** A payment to mark failed, read for change and found UNKNOWN past MARK_FAILED_AFTER_MS by the caller. */
export interface MarkFailed {
  readonly orgId: string;
  readonly transactionId: string;
  readonly userId: string;
  /** The bank's evidence reference, the step-up's evidence and the statement confirmed: kept on the move's event. */
  readonly details: Readonly<Record<string, string>> & { readonly evidenceRef: string };
  readonly at: Date;
}

/** Moves the payment UNKNOWN → FAILED, settles its holdings and tells every admin, in `tx`. */
export async function markFailed(
  tx: DatabaseTransaction<MarkFailedTables>,
  states: SignedStates,
  outbox: Outbox,
  { orgId, transactionId, userId, details, at }: MarkFailed,
): Promise<void> {
  const key = { orgId, id: transactionId };
  const locked = await lockPayment(tx, states, key);
  // Its caller found it UNKNOWN; checked again here, under the lock, as the machine lets one under way fail too.
  const { status } = locked.transaction;
  if (status !== 'UNKNOWN')
    throw new Error(`Only an UNKNOWN payment is marked failed, not ${status}: ${transactionId}`);
  // Verified and locked for change just now, and UNKNOWN, so the machine moves it.
  await moveTransaction(tx, states, key, 'fail', NO_FACTS, {
    actor: { type: 'user', id: userId },
    details: { via: 'admin', ...details },
  });
  await settlePayment(tx, outbox, {
    orgId,
    requestId: locked.instruction.spendRequestId,
    transactionId,
    status: 'FAILED',
    at,
  });
  await outbox.add(tx, [
    {
      orgId,
      recipientUserId: null,
      kind: 'payment_marked_failed',
      membershipId: null,
      role: null,
      aboutId: transactionId,
    },
  ]);
}

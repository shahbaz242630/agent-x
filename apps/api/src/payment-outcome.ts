// What a payment's move does beyond itself (Phase 4 C3, C2b), in the
// transaction that moved it, once its holdings are locked (ADR-006 §6: the
// transaction read for change, 10; its holdings, 11; the move, 12): what its
// request holds settled as it now stands (the outcomes module), and, on
// SUCCEEDED, its supplier's remittance email queued (partner decision 34a).
// Every move of a payment goes through here (Tx B and the sweep today, E1's
// partner events next), so neither is ever left out. The email's setting and
// address are read as it is sent (`remittances.ts`), never here: they sit at
// level 6, above the locks already held.
import type { AuditTables } from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import type { Notice, NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { settleHoldings } from '@agentx/core/modules/outcomes';
import type { SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import type { TransactionStatus } from '@agentx/core/modules/transactions';
import type { DatabaseTransaction } from '@agentx/platform/db';

type PaymentOutcomeTables = LimitReservationsTables & SpendRequestsTables & AuditTables & NotificationsTables;

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

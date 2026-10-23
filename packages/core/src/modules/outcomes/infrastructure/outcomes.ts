// A payment's outcome applied to what its request holds (Phase 4 C3; ADR-004:
// the outcomes module applies transaction results to reservations and order
// claims; ADR-006 §10–§11), in the transaction that moves the payment:
// `lockHoldingsOf` takes the request's reservation and claim (ADR-006 §6
// level 11) after its transaction (10) and before the audit head the move
// signs at (12); `settleHoldings` then moves both as the payment now stands
// (settlement.ts). `paymentHoldsOf` is the holdings check's reader of
// the same, so a reservation or claim moved past the app is alarmed.
import type { Transaction } from 'kysely';

import type { AuditTables, SignedStates } from '../../audit/index.ts';
import {
  type LimitReservationsTables,
  lockReservationsOf,
  settleReservationsOf,
} from '../../limit-reservations/index.ts';
import { lockClaimsOf, type PaymentHolds, releaseClaim, type SpendRequestsTables } from '../../spend-requests/index.ts';
import { paymentsOfRequests, type PaymentsTables, type TransactionStatus } from '../../transactions/index.ts';
import { settlementOf } from './settlement.ts';

type HoldingsTransaction = Transaction<LimitReservationsTables & SpendRequestsTables & AuditTables>;

/** Locks the request's reservation and order claim (level 11), before the move that settles them takes the head. */
export async function lockHoldingsOf(tx: HoldingsTransaction, requestId: string): Promise<void> {
  await lockReservationsOf(tx, [requestId]);
  await lockClaimsOf(tx, [requestId]);
}

/**
 * The request's reservation and claim moved as its payment now stands, in the
 * transaction that moved the payment, once lockHoldingsOf has locked them.
 */
export async function settleHoldings(
  tx: HoldingsTransaction,
  { requestId, status, at }: { readonly requestId: string; readonly status: TransactionStatus; readonly at: Date },
): Promise<void> {
  const { reservation, releasesClaim } = settlementOf(status);
  if (reservation !== null) await settleReservationsOf(tx, { requestId, to: reservation, at });
  if (releasesClaim) await releaseClaim(tx, { requestId, releasedAt: at });
}

/**
 * The holdings check's `PaymentsOf` (spend-requests): each handed-off
 * request's payment, read through its signed instruction and transaction, as
 * what it must hold; one that can't be believed is `unreadable`.
 */
export async function paymentHoldsOf(
  tx: Transaction<PaymentsTables & AuditTables>,
  states: SignedStates,
  orgId: string,
  requestIds: readonly string[],
): Promise<ReadonlyMap<string, PaymentHolds>> {
  const payments = await paymentsOfRequests(tx, states, orgId, requestIds);
  return new Map(
    [...payments].map(([id, payment]) => [
      id,
      payment.outcome === 'found' ? settlementOf(payment.status).holds : 'unreadable',
    ]),
  );
}

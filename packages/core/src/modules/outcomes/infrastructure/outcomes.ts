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
  givenBack,
  type LimitReservationsTables,
  lockReservationsOf,
  settleReservationsOf,
  windowsGivenBack,
} from '../../limit-reservations/index.ts';
import {
  lockClaimsOf,
  lockedTotalOf,
  type PaymentHolds,
  releaseClaim,
  type SpendRequestsTables,
} from '../../spend-requests/index.ts';
import { paymentsOfRequests, type PaymentsTables, type TransactionStatus } from '../../transactions/index.ts';
import { settlementOf } from './settlement.ts';

type HoldingsTransaction = Transaction<LimitReservationsTables & SpendRequestsTables & AuditTables>;

/** Each transaction's month total lockHoldingsOf locked, by request ID in lower case, for settleHoldings to give back to. */
const totalsLocked = new WeakMap<HoldingsTransaction, Map<string, LockedTotal>>();

type LockedTotal = Awaited<ReturnType<typeof lockedTotalOf>>;

/**
 * Locks the request's reservation and order claim (level 11), then its month's
 * total for change (11a, GM-1a: a verified failure gives its capacity back),
 * then its payee windows (11b, GM-1b, in order of ID), before the move that
 * settles them takes the head. The total and windows are found by the
 * request's signed state and sealed decision; a request whose decision sealed
 * no month (decided before E1) holds none.
 */
export async function lockHoldingsOf(
  tx: HoldingsTransaction,
  states: SignedStates,
  {
    orgId,
    requestId,
    givesBack = true,
  }: {
    readonly orgId: string;
    readonly requestId: string;
    /** False for a move that can only keep capacity held (to UNKNOWN): no total read or locked, no trip for it. */
    readonly givesBack?: boolean;
  },
): Promise<void> {
  await lockReservationsOf(tx, [requestId]);
  await lockClaimsOf(tx, [requestId]);
  if (!givesBack) return;
  // Read FOR SHARE (8) after the payment (10) and these (11), against the order: safe, as a handed-off request's status
  // never moves again, so no one takes it for change (an ending, a carry, a void take only pending ones), and this read
  // neither waits on nor blocks any holder of 10 or 11. Its total (11a) comes after, before the move's head (12).
  const locked = await lockedTotalOf(tx, states, { orgId, id: requestId }, 'share');
  const ofTx = totalsLocked.get(tx) ?? new Map<string, LockedTotal>();
  ofTx.set(requestId.toLowerCase(), locked);
  totalsLocked.set(tx, ofTx);
}

/**
 * The request's reservation and claim moved as its payment now stands, in the
 * transaction that moved the payment, once lockHoldingsOf has locked them; on
 * a verified failure or cancellation, its amount given back to its month's
 * total, recorded as the API's.
 */
export async function settleHoldings(
  tx: HoldingsTransaction,
  states: SignedStates,
  {
    orgId,
    requestId,
    status,
    at,
  }: { readonly orgId: string; readonly requestId: string; readonly status: TransactionStatus; readonly at: Date },
): Promise<void> {
  const { reservation, releasesClaim } = settlementOf(status);
  if (reservation === 'RELEASED') {
    // Locked by lockHoldingsOf in this transaction (lockPayment's): one missing gives nothing back, which the holdings
    // check then finds as a total holding more than its reservations, never less.
    await givenBack(tx, states, orgId, totalsLocked.get(tx)?.get(requestId.toLowerCase()), {
      at,
      change: {
        actor: { type: 'system', id: 'api' },
        action: 'month_total.released',
        details: { requestIds: requestId.toLowerCase() },
      },
    });
    // Its payee windows likewise (GM-1b), read for change with the total: none read, nothing given back, which the
    // holdings check then finds as a window holding more than its reservations, never less.
    const held = totalsLocked.get(tx)?.get(requestId.toLowerCase());
    if (held !== undefined && held !== null) {
      await windowsGivenBack(tx, states, orgId, held.windowsRead, held.windows, {
        at,
        change: { actor: { type: 'system', id: 'api' }, action: 'payee_window.released', details: {} },
      });
    }
  }
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

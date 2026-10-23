// What a payment's outcome does to what its request holds (Phase 4 C3;
// ADR-006 §10–§11; PRD §3.1): its reservation is the agent's monthly
// capacity, its order claim the invoice it pays.
// - Under way: both held as they were.
// - Succeeded: the reservation FINALISED (spent), the claim kept for good, so
//   the invoice is never paid again. A reversal after it gives nothing back
//   in the MVP.
// - Unknown: the reservation BLOCKED_UNKNOWN and the claim kept: possibly
//   paid, so it still uses capacity and still blocks the order (SEC-LIM-02),
//   until verified evidence or a reconciliation settles it.
// - A verified failure or cancellation: both released, so the capacity is
//   back and the order may be asked for again.
import type { ReservationSettlement } from '../../limit-reservations/index.ts';
import type { PaymentHolds } from '../../spend-requests/index.ts';
import type { TransactionStatus } from '../../transactions/index.ts';

/** What a payment in one status holds, and how reaching it moves the reservation and the claim. */
export interface Settlement {
  readonly holds: PaymentHolds;
  /** Where the reservation moves on reaching it; null where it stays as it is. */
  readonly reservation: ReservationSettlement | null;
  readonly releasesClaim: boolean;
}

const UNDER_WAY: Settlement = { holds: 'following', reservation: null, releasesClaim: false };
const SPENT: Settlement = { holds: 'spent', reservation: 'FINALISED', releasesClaim: false };
const ENDED: Settlement = { holds: 'ended', reservation: 'RELEASED', releasesClaim: true };

const SETTLEMENTS: Readonly<Record<TransactionStatus, Settlement>> = {
  SUBMISSION_PENDING: UNDER_WAY,
  SUBMITTED: UNDER_WAY,
  PROCESSING: UNDER_WAY,
  SUCCEEDED: SPENT,
  // Already FINALISED by its success: a reversal gives no capacity back (PRD §3.1).
  REVERSED: SPENT,
  UNKNOWN: { holds: 'blocked', reservation: 'BLOCKED_UNKNOWN', releasesClaim: false },
  FAILED: ENDED,
  CANCELLED: ENDED,
};

/** What a payment in this status holds, and how it moves what its request holds. */
export const settlementOf = (status: TransactionStatus): Settlement => SETTLEMENTS[status];

// What a spend request must hold elsewhere, by its signed status (ADR-006
// §8–§11; ADR-012 §2: reservations and claims are checked against the signed
// decisions; SEC-DB-09; Phase 2 E1). A reservation and an order claim carry
// no signed state of their own, so a release or a deletion past the app would
// otherwise give capacity back, or let an order be paid twice, unseen. The
// holdings check compares them with the request, verified, and raises the
// integrity alarm (`holding`) for any that don't match:
// - waiting for approval, approved or ready: exactly one reservation, HELD,
//   for the request's own agent, mandate, supplier and amount, and exactly
//   one claim, open, on its own supplier and order;
// - handed off: the same, but the reservation follows the payment (HELD,
//   FINALISED or BLOCKED_UNKNOWN), never RELEASED;
// - ended (denied, expired, cancelled): nothing held: no reservation or a
//   RELEASED one, no claim or a released one;
// - VALIDATING: never seen once committed (a request leaves it in the
//   transaction that made it), so it never matches.
import type { Money } from '../../../shared-kernel/index.ts';
import type { SpendRequestStatus } from './spend-request.ts';

/** The request as its signed state holds it, what the check compares by. */
export interface RequestHolding {
  readonly agentId: string;
  readonly mandateId: string | null;
  readonly supplierId: string;
  readonly amount: Money;
  readonly status: SpendRequestStatus;
}

/** A reservation of the request, as its table holds it. */
export interface ReservationHolding {
  readonly agentId: string;
  readonly mandateId: string;
  readonly supplierId: string;
  readonly amountMinor: bigint;
  readonly currency: string;
  readonly state: string;
}

/** An order claim of the request: whether it is released, and whether it is on the request's own supplier and order. */
export interface ClaimHolding {
  readonly released: boolean;
  readonly itsOwn: boolean;
}

/** What each status holds: its capacity and order, the same while its payment is followed, nothing, or never seen. */
const HOLDS: Readonly<Record<SpendRequestStatus, 'holding' | 'handed_off' | 'ended' | 'never'>> = {
  VALIDATING: 'never',
  APPROVAL_REQUIRED: 'holding',
  APPROVED: 'holding',
  INSTRUCTION_READY: 'holding',
  HANDED_OFF: 'handed_off',
  DENIED: 'ended',
  EXPIRED: 'ended',
  CANCELLED: 'ended',
};

/** A handed-off request's reservation follows its payment, never given back before a verified failure (Phase 4–5). */
const FOLLOWING_THE_PAYMENT: ReadonlySet<string> = new Set(['HELD', 'FINALISED', 'BLOCKED_UNKNOWN']);

/** Whether the request's reservations and claims are exactly what its signed status says they must be. */
export function holdingsMatch(
  request: RequestHolding,
  reservations: readonly ReservationHolding[],
  claims: readonly ClaimHolding[],
): boolean {
  const holds = HOLDS[request.status];
  if (holds === 'never' || reservations.length > 1 || claims.length > 1) return false;
  if (holds === 'ended') {
    return reservations.every(({ state }) => state === 'RELEASED') && claims.every(({ released }) => released);
  }
  const [reservation] = reservations;
  const [claim] = claims;
  if (reservation === undefined || claim === undefined || claim.released || !claim.itsOwn) return false;
  const stateHeld = holds === 'holding' ? reservation.state === 'HELD' : FOLLOWING_THE_PAYMENT.has(reservation.state);
  return (
    stateHeld &&
    reservation.agentId === request.agentId &&
    reservation.mandateId === request.mandateId &&
    reservation.supplierId === request.supplierId &&
    reservation.amountMinor === request.amount.minor &&
    reservation.currency === request.amount.currency
  );
}

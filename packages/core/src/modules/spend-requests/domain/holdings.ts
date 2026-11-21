// What a spend request must hold elsewhere, by its signed status (ADR-006
// §8–§11; ADR-012 §2: reservations and claims are checked against the signed
// decisions; SEC-DB-09; Phase 2 E1). A reservation and an order claim carry
// no signed state of their own, so a release or a deletion past the app would
// otherwise give capacity back, or let an order be paid twice, unseen. The
// holdings check compares them with the request, verified, and raises the
// integrity alarm (`holding`) for any that don't match:
// - waiting for approval, approved or ready: exactly one reservation, HELD,
//   for the request's own agent, mandate, supplier and amount, in the month
//   and at the instant its decision sealed (`held`; requests decided before
//   E1 sealed none), and exactly one claim, open, on its own supplier and
//   order; each on the payee key its decision sealed a keyed hash of (E1b:
//   a claim or reservation whose key was nulled or swapped past the app
//   would let a supplier record made again for the same account be paid
//   the same invoice; requests decided before E1b sealed none);
// - handed off: as its payment says (Phase 4 C3, ADR-006 §10–§11; the
//   outcomes module reads it): under way, the same; succeeded (or reversed
//   since: no capacity back in the MVP), the reservation FINALISED and the
//   claim open; unknown, BLOCKED_UNKNOWN and the claim open (possibly paid);
//   a verified failure or cancellation, nothing held, as an ended request;
//   a payment that can't be read (its instruction or transaction tampered
//   with, or gone) never matches;
// - ended (denied, expired, cancelled): nothing held: no reservation or a
//   RELEASED one, no claim or a released one; but where its signed ending
//   kept its capacity (AT13d: ended past what the digest remembers), its one
//   reservation stays HELD as decided, as its month total and windows kept the
//   amount, and its claim released;
// - VALIDATING: never seen once committed (a request leaves it in the
//   transaction that made it), so it never matches.
import type { Money } from '../../../shared-kernel/index.ts';
import type { SpendRequestStatus } from './spend-request.ts';

/** The keyed hash of a request's payee key its decision sealed (E1b): lower-case hex, and its key's version. */
export interface PayeeSeal {
  readonly mac: string;
  readonly keyVersion: number;
}

/**
 * What a decision sealed of what it holds: its reservation's month and
 * instant (E1), and its payee seal, `none` for a decision made before E1b
 * sealed one, or `unreadable` where its details hold one that isn't whole.
 */
export interface HeldSealed {
  readonly month: string;
  readonly reservedAt: Date;
  readonly payee: PayeeSeal | 'none' | 'unreadable';
  /** Whether it was decided by G5's engine, which writes the claim's bank key (0043): its sealed `possibleDuplicate`. */
  readonly bankKeyed: boolean;
  /**
   * The payee windows its capacity was added to (GM-1b, 0112), by ID: an ending gives back to these, whatever the
   * unsealed reservation says. Null for a decision made before GM-1b, counted in its supplier's window alone.
   */
  readonly windows: readonly string[] | null;
}

/** What a decision that holds capacity seals (signRequest's `held`): always a payee seal, its windows and its slots. */
export interface HeldAs extends Omit<HeldSealed, 'payee' | 'bankKeyed' | 'windows'> {
  readonly payee: PayeeSeal;
  readonly windows: readonly string[];
  /** The order slots its claim joined (TR-2, 0114), by ID: an ending lets go of these, whatever the claim says. */
  readonly slots: readonly string[];
}

/**
 * What a handed-off request's payment says it must hold (C3), as the outcomes
 * module reads it from the transaction: `following` while under way, `spent`
 * once it succeeded, `blocked` while unknown, `ended` after a verified
 * failure or cancellation, `unreadable` where it can't be believed.
 */
export type PaymentHolds = 'following' | 'spent' | 'blocked' | 'ended' | 'unreadable';

/** The request as its signed state holds it, what the check compares by. */
export interface RequestHolding {
  readonly agentId: string;
  readonly mandateId: string | null;
  readonly supplierId: string;
  readonly amount: Money;
  readonly status: SpendRequestStatus;
  /** What its decision sealed of what it holds; null for a decision that sealed none. */
  readonly held: HeldSealed | null;
  /** A handed-off request's payment; one handed off without it never matches. */
  readonly payment?: PaymentHolds | undefined;
  /** Ended, whether its signed ending kept its capacity (AT13d): its reservation then stays HELD, as decided. */
  readonly capacityKept?: boolean | undefined;
}

/** A reservation of the request, as its table holds it. */
export interface ReservationHolding {
  readonly agentId: string;
  readonly mandateId: string;
  readonly supplierId: string;
  readonly amountMinor: bigint;
  readonly currency: string;
  readonly state: string;
  readonly month: string;
  readonly reservedAt: Date;
  /** Whether its payee key is the one its request's decision sealed (true where none was sealed). */
  readonly payeeAsSealed: boolean;
}

/**
 * An order claim of the request: whether it is released, whether it is on
 * the request's own supplier and order, and whether its payee key is the one
 * the decision sealed (true where none was sealed).
 */
export interface ClaimHolding {
  readonly released: boolean;
  readonly itsOwn: boolean;
  readonly payeeAsSealed: boolean;
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

/** A payee seal's MAC: HMAC-SHA-256, in lower-case hex. */
const SEAL_MAC = /^[0-9a-f]{64}$/;

/**
 * What a decision's details sealed of what it holds (`heldMonth`, `heldAt`,
 * and from E1b `payeeSeal`, `payeeSealKeyVersion`); null where they hold no
 * month and instant.
 */
export function heldOf(details: Readonly<Record<string, unknown>> | undefined): HeldSealed | null {
  const month = details?.heldMonth;
  const at = details?.heldAt;
  if (typeof month !== 'string' || typeof at !== 'string') return null;
  return {
    month,
    reservedAt: new Date(at),
    payee: payeeSealOf(details),
    bankKeyed: typeof details?.possibleDuplicate === 'boolean',
    windows: windowsOf(details?.payeeWindows),
  };
}

/** A window's ID as signRequest seals it: a UUID in lower case. */
const WINDOW_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The window IDs a decision sealed (`payeeWindows`, comma between): null for none (decided before GM-1b). The chain's
 * MAC keeps the event as the app wrote it, so text not in that form is no list of windows at all: null too.
 */
export function windowsOf(sealed: unknown): readonly string[] | null {
  if (typeof sealed !== 'string') return null;
  const ids = sealed.split(',');
  return ids.every((id) => WINDOW_ID.test(id)) ? ids : null;
}

/**
 * The order slot IDs a decision sealed (`orderSlots`, TR-2), or its slots' cutover named, in the same form as its
 * windows: null for none.
 */
export const slotIdsOf = (sealed: unknown): readonly string[] | null => windowsOf(sealed);

/** The payee seal the details hold: none before E1b; unreadable if either half is there but not whole. */
function payeeSealOf(details: Readonly<Record<string, unknown>> | undefined): HeldSealed['payee'] {
  const mac = details?.payeeSeal;
  const keyVersion = details?.payeeSealKeyVersion;
  if (mac === undefined && keyVersion === undefined) return 'none';
  const whole =
    typeof mac === 'string' &&
    SEAL_MAC.test(mac) &&
    typeof keyVersion === 'number' &&
    Number.isSafeInteger(keyVersion) &&
    keyVersion >= 1;
  return whole ? { mac, keyVersion } : 'unreadable';
}

/** Whether the status still holds capacity and its order: waiting, approved, ready or handed off. */
export const holdsNow = (status: SpendRequestStatus): boolean =>
  HOLDS[status] === 'holding' || HOLDS[status] === 'handed_off';

/** The reservation's state while a request holds: HELD until its payment is spent or unknown. */
const RESERVATION_STATE: Readonly<Record<'holding' | 'following' | 'spent' | 'blocked', string>> = {
  holding: 'HELD',
  following: 'HELD',
  spent: 'FINALISED',
  blocked: 'BLOCKED_UNKNOWN',
};

/** Whether the request's reservations and claims are exactly what its signed status says they must be. */
export function holdingsMatch(
  request: RequestHolding,
  reservations: readonly ReservationHolding[],
  claims: readonly ClaimHolding[],
): boolean {
  const byStatus = HOLDS[request.status];
  // A handed-off request holds as its payment says (C3), never given back before a verified failure.
  const holds = byStatus === 'handed_off' ? (request.payment ?? 'unreadable') : byStatus;
  if (holds === 'never' || holds === 'unreadable' || reservations.length > 1 || claims.length > 1) return false;
  const [reservation] = reservations;
  if (holds === 'ended') {
    const claimsReleased = claims.every(({ released }) => released);
    // Its signed ending kept its capacity (AT13d): its one reservation stays HELD, as decided; otherwise none holds.
    if (request.capacityKept === true) {
      return claimsReleased && reservation !== undefined && reservationAsDecided(request, reservation, 'HELD');
    }
    return reservations.every(({ state }) => state === 'RELEASED') && claimsReleased;
  }
  const [claim] = claims;
  if (reservation === undefined || claim === undefined || claim.released || !claim.itsOwn) return false;
  if (!claim.payeeAsSealed) return false;
  return reservationAsDecided(request, reservation, RESERVATION_STATE[holds]);
}

/** Whether the reservation is in `state`, on its payee as sealed, holding exactly what the request was decided to. */
function reservationAsDecided(request: RequestHolding, reservation: ReservationHolding, state: string): boolean {
  return (
    reservation.payeeAsSealed &&
    reservation.state === state &&
    reservation.agentId === request.agentId &&
    reservation.mandateId === request.mandateId &&
    reservation.supplierId === request.supplierId &&
    reservation.amountMinor === request.amount.minor &&
    reservation.currency === request.amount.currency &&
    (request.held === null ||
      (reservation.month === request.held.month &&
        reservation.reservedAt.getTime() === request.held.reservedAt.getTime()))
  );
}

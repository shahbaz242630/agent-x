// A beneficiary registration (ADR-014 §3; SEC-PAY-06, SEC-PAY-08; Phase 1
// E2-1): a supplier's payee registered with the partner, which Agent X starts
// and names with its own ID (the partner's idempotency key for it).
//
// It starts STARTED, before the partner is called (Tx 1). The partner's
// answer, server to server, ends it: REGISTERED with the partner's reference,
// or FAILED with why. A call lost on the way leaves it UNKNOWN, until the
// partner is asked again by our ID, which ends it the same way. The database's
// status guard holds the same moves (0033).
//
// Its payee key comes from one source per partner, never mixed (ADR-014 §3):
// the partner's stable identity for the account; or, with none, our keyed
// fingerprint of the IBAN, taken during a pass-through; or, from the hosted
// form alone with no identity, none (risk R-13).
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const BENEFICIARY_REGISTRATION = defineStateMachine({
  name: 'beneficiary_registration',
  states: ['STARTED', 'REGISTERED', 'FAILED', 'UNKNOWN'],
  initial: 'STARTED',
  events: {
    registered: { from: ['STARTED', 'UNKNOWN'], to: 'REGISTERED' },
    failed: { from: ['STARTED', 'UNKNOWN'], to: 'FAILED' },
    lost: { from: ['STARTED'], to: 'UNKNOWN' },
  },
});

export type RegistrationStatus = (typeof BENEFICIARY_REGISTRATION.states)[number];

/** How the details reach the partner (ADR-014 §3): its hosted form, or passed through in one request's memory. */
export const REGISTRATION_ROUTES = ['hosted', 'pass_through'] as const;
export type RegistrationRoute = (typeof REGISTRATION_ROUTES)[number];

/** The partner's name check of the payee (Confirmation of Payee). */
export const NAME_CHECKS = ['match', 'partial', 'no_match', 'unavailable'] as const;
export type NameCheck = (typeof NAME_CHECKS)[number];

/** Why a registration failed: details the rail can't pay, the hosted form not filled in time, or none the partner knows. */
export const REGISTRATION_FAILURES = ['invalid_details', 'expired', 'unknown'] as const;
export type RegistrationFailure = (typeof REGISTRATION_FAILURES)[number];

/** Where a payee key comes from: the partner's stable identity, our fingerprint of the IBAN, or nowhere. */
export type PayeeKeySource = 'partner' | 'fingerprint' | 'none';

/** What the partner offers, as its adapter's capabilities say (the providers module's RailCapabilities). */
interface PartnerOffer {
  readonly beneficiaryRoutes: readonly string[];
  readonly stablePayeeIdentity: boolean;
}

/**
 * The payee key's one source for this partner (ADR-014 §3): its stable
 * identity where it gives one, whatever the route; with none, our fingerprint,
 * so a partner offering pass-through registers by it alone, since a hosted
 * registration would leave a payee with no key beside those with one; and
 * none only where the hosted form is all there is (R-13). A route the
 * partner doesn't offer, or the hosted form where pass-through must be used,
 * is a RangeError.
 */
export function payeeKeySource(offer: PartnerOffer, route: RegistrationRoute): PayeeKeySource {
  if (!offer.beneficiaryRoutes.includes(route)) throw new RangeError(`The partner offers no ${route} route`);
  if (offer.stablePayeeIdentity) return 'partner';
  if (route === 'pass_through') return 'fingerprint';
  if (offer.beneficiaryRoutes.includes('pass_through')) {
    throw new RangeError('With no stable payee identity, a partner offering pass-through registers by it alone');
  }
  return 'none';
}

// The payment side of the partner's adapter (PRD §6, §6.2; ADR-007 §8–§11;
// ADR-014 §1–§2; rail map §3–§4; Phase 4 B2): Agent X hands the licensed
// partner a policy-approved payment intent, and reads back how it stands. The
// partner executes; Agent X never claims to (ADR-014 §1).
//
// - `submitApprovedIntent`: our instruction ID is the partner's idempotency
//   key (≤ 40 characters, no spaces: a UUID fits), so the same intent
//   submitted again inside the partner's window answers as the first did and
//   never makes a second payment (BR-14). It answers accepted (the partner's
//   instruction, as it stands), or refused with the partner's positive proof
//   that no payment was made (a 4xx that creates nothing: `FAILED` alone, ADR-007
//   §9, §11). Anything else (a timeout, no answer, 409, 429, 5xx) throws
//   RailUnavailable: the outcome is unknown, and the caller never resends; it
//   looks the payment up by our key, then by its status (rail map §4).
// - `getExecution`: the payment by our instruction ID (the rail's lookup by
//   key), or `not_found`. A "not found" never proves non-acceptance (ADR-007
//   §11): the caller keeps the payment UNKNOWN.
//
// The partner's own status is kept as it said it (`providerStatus`, PRD §6.2),
// and `paymentStateOf` maps it to the rail-neutral one (rail map §4): only the
// creditor's account credited is SUCCEEDED (STA-1, until the partner's answer
// says another status may count); a `Rejected` is FAILED only with the
// partner's proof that the business's account was never debited (STA-4, or a
// reject code that proves it), and UNKNOWN otherwise.

/** The rail's five payment statuses (rail map §4, `AEPaymentStatus`). */
export const PROVIDER_STATUSES = [
  'Pending',
  'AcceptedSettlementCompleted',
  'AcceptedWithoutPosting',
  'AcceptedCreditSettlementCompleted',
  'Rejected',
] as const;
export type ProviderStatus = (typeof PROVIDER_STATUSES)[number];

/** The rail-neutral state a partner's status maps to (PRD §4.3): the transaction's machine decides the rest. */
export type PaymentState = 'PROCESSING' | 'SUCCEEDED' | 'FAILED' | 'UNKNOWN';

/**
 * A policy-approved payment intent, as Agent X hands it to the partner
 * (ADR-014 §1): every field from records Agent X verified at the hand-off,
 * none from the agent's request but the amount and order it asked for.
 */
export interface ApprovedPaymentIntent {
  readonly organizationId: string;
  /** Ours, made before the call and kept (ADR-007 §7): the partner's idempotency key and correlation reference. */
  readonly instructionId: string;
  /** The partner's consent the business approved at its bank (PRD §6.2 `accountConsentId`). */
  readonly accountConsentId: string;
  /** The supplier's payee, from its verified version (PRD §6 "never from the request payload"). */
  readonly beneficiaryRef: string;
  /** Minor units of `currency` (ADR-006): a bounded whole number, never a float. */
  readonly amountMinor: bigint;
  readonly currency: string;
  /** The rail's payment reference (1–35 characters of its set, rail map §5), made at hand-off. */
  readonly paymentReference: string;
}

/** The payment as the partner holds it now, normalised: its own words kept for evidence (PRD §6.2). */
export interface PaymentExecution {
  readonly organizationId: string;
  readonly instructionId: string;
  /** The partner's reference for its instruction (PRD §6.2 `paymentInstructionRef`). */
  readonly paymentInstructionRef: string;
  readonly providerStatus: ProviderStatus;
  /** The reject code the partner gave, as it gave it (an `AANI.` code on this rail), or null. */
  readonly rejectCode: string | null;
  /**
   * Whether the partner has proved the business's account was never debited
   * (STA-4, or a reject code that proves it). Only a `Rejected` can carry it;
   * the adapter decides it from the partner's own answer, never the caller.
   */
  readonly noDebitProven: boolean;
  /** When the partner says the status last changed (PRD §6.2 `regulatedEventTimestamp`). */
  readonly statusChangedAt: Date;
  readonly amountMinor: bigint;
  readonly currency: string;
}

/**
 * How a submission ended, when the partner answered:
 * - `accepted`: the partner's instruction, as it stands now
 * - `refused`: the partner's positive proof that no payment was made (a 4xx
 *   that creates nothing), with its code: FAILED, and the reservation may go
 */
export type SubmissionResult =
  | { readonly kind: 'accepted'; readonly execution: PaymentExecution }
  | { readonly kind: 'refused'; readonly code: string };

/** A payment Agent X handed off, by our instruction ID. */
export interface PartnerExecutionRef {
  readonly organizationId: string;
  readonly instructionId: string;
}

/** The payment as the partner holds it, or `not_found`, which proves nothing (ADR-007 §11). */
export type ExecutionLookup =
  { readonly kind: 'found'; readonly execution: PaymentExecution } | { readonly kind: 'not_found' };

/** The rail-neutral state of a partner's answer (rail map §4). */
export function paymentStateOf(execution: Pick<PaymentExecution, 'providerStatus' | 'noDebitProven'>): PaymentState {
  switch (execution.providerStatus) {
    case 'AcceptedCreditSettlementCompleted':
      return 'SUCCEEDED';
    case 'Rejected':
      return execution.noDebitProven ? 'FAILED' : 'UNKNOWN';
    // Settled at the debtor, or accepted but not yet credited: still on its way (rail map §4).
    case 'Pending':
    case 'AcceptedSettlementCompleted':
    case 'AcceptedWithoutPosting':
      return 'PROCESSING';
  }
}

/** The rail's idempotency key, which our instruction ID is: at most 40 characters, no spaces (rail map §3). */
export const PARTNER_IDEMPOTENCY_KEY = /^[^\s]{1,40}$/;

/** The rail's payment reference: 1–35 characters, ASCII letters, digits, spaces and `/?:().,'+-` (rail map §5). */
export const RAIL_PAYMENT_REFERENCE = /^[A-Za-z0-9 /?:().,'+-]{1,35}$/;

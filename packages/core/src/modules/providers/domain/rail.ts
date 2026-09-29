// The payment partner's adapter (PRD §6 `FinancialRailAdapter`, ADR-004 §8,
// ADR-010 §4): the one place a partner's API is known. Everything else in
// Agent X sees only the normalised answers below: references, availability
// and a masked summary, never the partner's own fields or an account number
// (PRD §6, ADR-014 §3).
//
// The contract grows with the phase that first uses each part. Phase 1 D1-1:
// linking a business's bank account (PRD §2.3; rail map §2). The partner's
// payee registration comes with D1-2; the hand-off, its status and events
// with Phase 4.
//
// Linking, on any rail:
// 1. Agent X starts a link with its own ID for it; the partner answers with a
//    session and where to send the person (to the partner, then their bank).
// 2. The business approves at its bank; nothing that comes back through the
//    browser is trusted.
// 3. Agent X asks the partner, server to server, how the link it started for
//    that organisation ended: linked, waiting, or refused.
// 4. From then on the partner's state of the source is read by its reference,
//    again only for the organisation that linked it.

/**
 * What a source may do, whatever the rail calls it:
 * - `PENDING`: the business hasn't finished at its bank
 * - `ACTIVE`: new requests may use it
 * - `SUSPENDED`: new requests stop while it lasts; it can come back
 * - `UNAVAILABLE`: for good; using the account again means a new link
 */
export const SOURCE_AVAILABILITIES = ['PENDING', 'ACTIVE', 'SUSPENDED', 'UNAVAILABLE'] as const;
export type SourceAvailability = (typeof SOURCE_AVAILABILITIES)[number];

/** A link Agent X starts: `linkId` is ours, and the partner's idempotency key for it. */
export interface LinkContext {
  readonly organizationId: string;
  readonly linkId: string;
}

/** The partner's session for a link, and where the person goes to approve it. */
export interface PartnerLinkSession {
  readonly linkId: string;
  readonly sessionRef: string;
  /** The partner's page, which takes the person on to their bank. */
  readonly authoriseUrl: string;
  readonly expiresAt: Date;
}

/**
 * The limits the bank holds the consent to, whatever Agent X's mandates say
 * (rail map §1.3): in minor units of `currency` (ADR-006), per `period`.
 */
export interface ConsentControls {
  readonly currency: string;
  readonly period: 'day' | 'week' | 'month' | 'year';
  readonly maxPaymentMinor: bigint;
  readonly maxPeriodMinor: bigint;
  readonly maxPeriodPayments: number;
}

/** What may be shown of the account (BR-02): no account number, no balance. */
export interface SourceSummary {
  readonly holderName: string;
  readonly accountType: 'retail' | 'sme' | 'corporate';
  readonly currency: string;
  /** The country and the last four characters of the account number, such as `AE…6026`. */
  readonly hint: string;
}

/** A linked source as the partner holds it now. */
export interface FundingSourceState {
  readonly organizationId: string;
  /** The partner's reference for the source: stays the same when the consent is renewed. */
  readonly externalRef: string;
  /** The partner's consent (PRD §6.2 `accountConsentId`): a renewal replaces it (rail map §2 step 5). */
  readonly accountConsentId: string;
  /** The consent this one renewed, or null for the first. */
  readonly replacesConsentId: string | null;
  readonly availability: SourceAvailability;
  /** The partner's own word for the consent's status, kept for evidence (PRD §6.2). */
  readonly consentStatus: string;
  /** When the partner says the status last changed (PRD §6.2 `regulatedEventTimestamp`). */
  readonly statusChangedAt: Date;
  readonly consentExpiresAt: Date;
  readonly controls: ConsentControls;
  readonly summary: SourceSummary;
}

/**
 * How a link ended, as the partner says server to server:
 * - `linked`: the source, now the partner's
 * - `waiting`: the business hasn't finished at its bank yet; ask again later
 * - `refused`: `rejected` at the bank, `expired` before it was approved, or
 *   `unknown`: no link of that ID for that organisation (another
 *   organisation's link answers the same as none)
 */
export type LinkOutcome =
  | { readonly kind: 'linked'; readonly source: FundingSourceState }
  | { readonly kind: 'waiting' }
  | { readonly kind: 'refused'; readonly reason: 'rejected' | 'expired' | 'unknown' };

/** A source the partner holds for an organisation. */
export interface SourceRef {
  readonly organizationId: string;
  readonly externalRef: string;
}

/** The source, or `not_found`: none of that reference for that organisation. */
export type SourceLookup =
  { readonly kind: 'found'; readonly source: FundingSourceState } | { readonly kind: 'not_found' };

/**
 * The partner couldn't be asked, or didn't answer in time: nothing is known
 * of the call's outcome, so the caller asks again later and never assumes.
 */
export class RailUnavailable extends Error {
  constructor() {
    super('The payment partner did not answer');
    this.name = 'RailUnavailable';
  }
}

/** The adapter every partner implements, and its fake (Rule Book §6: both pass the same contract tests). */
export interface FinancialRailAdapter {
  startSourceLink(input: LinkContext): Promise<PartnerLinkSession>;
  confirmSourceLink(input: LinkContext): Promise<LinkOutcome>;
  getSourceState(ref: SourceRef): Promise<SourceLookup>;
}

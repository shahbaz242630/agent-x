// The payment partner's adapter (PRD §6 `FinancialRailAdapter`, ADR-004 §8,
// ADR-010 §4): the one place a partner's API is known. Everything else in
// Agent X sees only the normalised answers below: references, availability
// and a masked summary, never the partner's own fields or an account number
// (PRD §6, ADR-014 §3).
//
// The contract grows with the phase that first uses each part. Phase 1:
// linking a business's bank account (D1-1; PRD §2.3, rail map §2) and
// registering a supplier as the partner's payee (D1-2; ADR-014 §3). The
// hand-off, its status and events come with Phase 4.
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

/** A partner's name, as Agent X keeps it on a link or a registration: lower-case words, such as `fake`. */
export const PARTNER_NAME = /^[a-z][a-z0-9_]{0,31}$/;

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

// Registering a payee (ADR-014 §3), on any rail. The supplier's bank details
// go to the partner, never into Agent X's storage, by one of two routes:
// - `hosted`: the partner's own form, so the details never touch Agent X
// - `pass_through`: the details a person typed, forwarded within the same
//   request and held only in its memory
// Either way Agent X names the registration with its own ID (the partner's
// idempotency key), and reads how it ended from the partner, server to
// server, by that ID and only for its organisation: after a timeout, after
// the hosted form, and before the payee is used.

export const BENEFICIARY_ROUTES = ['hosted', 'pass_through'] as const;
export type BeneficiaryRoute = (typeof BENEFICIARY_ROUTES)[number];

/** What this partner offers, which decides how suppliers are registered (0f; BEN-1, BEN-2). */
export interface RailCapabilities {
  readonly beneficiaryRoutes: readonly BeneficiaryRoute[];
  /**
   * Whether the partner gives the same payee identity for the same account
   * in an organisation (ADR-014 §3's payee key source (a)); if not, the
   * payee key is our fingerprint (pass-through) or there is none (R-13).
   */
  readonly stablePayeeIdentity: boolean;
}

/** The details a person typed for a pass-through registration: held in memory for that one request. */
export interface PayeeDetails {
  readonly name: string;
  readonly iban: string;
}

/** A registration Agent X starts: `registrationId` is ours, and the partner's idempotency key for it. */
export type BeneficiaryRegistration =
  | { readonly route: 'hosted'; readonly organizationId: string; readonly registrationId: string }
  | {
      readonly route: 'pass_through';
      readonly organizationId: string;
      readonly registrationId: string;
      readonly payee: PayeeDetails;
    };

/**
 * The partner's name check of the payee (Confirmation of Payee; rail map §3):
 * the name matches the account's holder, partly, not at all, or the account's
 * bank couldn't say.
 */
export type PayeeNameCheck = 'match' | 'partial' | 'no_match' | 'unavailable';

/** A payee the partner registered, as it holds it now. */
export interface BeneficiaryState {
  readonly organizationId: string;
  readonly registrationId: string;
  /** The partner's opaque reference for the payee (PRD §6.2 `beneficiaryRef`). */
  readonly beneficiaryRef: string;
  /** The partner's identity for the account in this organisation, or null where it gives none. */
  readonly payeeIdentity: string | null;
  readonly nameCheck: PayeeNameCheck;
  /** The account holder's name as the bank masks it, for a call-back to compare; null where none came back. */
  readonly maskedName: string | null;
  /** The country and last four characters of the account number, such as `AE…6026`. */
  readonly hint: string;
  readonly registeredAt: Date;
}

/**
 * How a registration stands, as the partner says server to server:
 * - `registered`: the payee, now the partner's
 * - `waiting`: the hosted form hasn't been filled in yet; send the person to `formUrl`
 * - `refused`: `invalid_details` (not an account this rail can pay),
 *   `expired` (the form wasn't filled in time), or `unknown`: no
 *   registration of that ID for that organisation (another organisation's
 *   answers the same as none)
 */
export type BeneficiaryOutcome =
  | { readonly kind: 'registered'; readonly beneficiary: BeneficiaryState }
  | { readonly kind: 'waiting'; readonly formUrl: string; readonly expiresAt: Date }
  | { readonly kind: 'refused'; readonly reason: 'invalid_details' | 'expired' | 'unknown' };

/** A registration Agent X started for an organisation. */
export interface BeneficiaryRef {
  readonly organizationId: string;
  readonly registrationId: string;
}

/** The adapter every partner implements, and its fake (Rule Book §6: both pass the same contract tests). */
export interface FinancialRailAdapter {
  /** The origin of the partner's own pages: an `authoriseUrl` must be on it (the S68 audit). */
  readonly authoriseOrigin: string;
  /** The origin of the partner's hosted payee form: a `formUrl` must be on it, as an `authoriseUrl` on the other. */
  readonly formOrigin: string;
  capabilities(): Promise<RailCapabilities>;
  startSourceLink(input: LinkContext): Promise<PartnerLinkSession>;
  confirmSourceLink(input: LinkContext): Promise<LinkOutcome>;
  getSourceState(ref: SourceRef): Promise<SourceLookup>;
  /** Registering again with the same ID answers as the first did, whatever details come with it. */
  registerBeneficiary(input: BeneficiaryRegistration): Promise<BeneficiaryOutcome>;
  getBeneficiaryState(ref: BeneficiaryRef): Promise<BeneficiaryOutcome>;
}

/**
 * Whether a partner's `authoriseUrl` or `formUrl` may be sent to a person's
 * browser (the S68 audit): a page of the partner's own, on `origin`, over HTTPS, naming no one's
 * credentials. Anything else (`javascript:`, `data:`, plain HTTP, another
 * host) a person is never sent to, whatever the partner answered.
 */
export function isPartnerPage(url: string, origin: string): boolean {
  if (!URL.canParse(url)) return false;
  const page = new URL(url);
  return page.protocol === 'https:' && page.origin === origin && page.username === '' && page.password === '';
}

/**
 * Whether the bank's limits are in the account's own currency (the S68
 * audit): Agent X keeps one currency for a source, the limits', and shows it
 * to agents as the source's; an answer whose limits are in another currency
 * than the account's is one Agent X can't keep truthfully, so it is refused,
 * never stored. Codes are compared exactly: an adapter gives ISO 4217's own
 * upper-case codes, and one that doesn't fails safe (refused, logged).
 */
export const limitsInAccountCurrency = (source: Pick<FundingSourceState, 'controls' | 'summary'>): boolean =>
  source.controls.currency === source.summary.currency;

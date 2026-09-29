// A funding source (PRD §2.3, §3 `FundingSourceReference`; BR-01, BR-02): the
// business's own bank account, linked through the payment partner. Agent X
// keeps only the partner's reference for it, the consent the bank gave, the
// bank's controls and what may be shown of it; never an account number or a
// balance.
//
// Two statuses decide whether it may fund a request:
// - Agent X's own: ACTIVE, or SUSPENDED by the business (the kill switch,
//   ADR-012 §5) and back, or ENDED once the partner says it is gone for good,
//   when using the account again means a new link. The database's status
//   guard holds the same moves (0029).
// - The partner's latest word, its availability (as the providers module's
//   adapter normalises it, rail.ts): a source may be waiting at the bank,
//   suspended there, or gone.
// Only a source ACTIVE in both, before its consent's expiry, may fund one
// (PRD §2.3 step 5: loss of the partner's permission makes it unavailable
// for new requests).
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const FUNDING_SOURCE = defineStateMachine({
  name: 'funding_source',
  states: ['ACTIVE', 'SUSPENDED', 'ENDED'],
  initial: 'ACTIVE',
  events: {
    suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
    reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
    end: { from: ['ACTIVE', 'SUSPENDED'], to: 'ENDED' },
  },
});

type FundingSourceStatus = (typeof FUNDING_SOURCE.states)[number];

/**
 * How a link ended, as the partner said server to server: `linked` (the
 * source it made), `rejected` at the bank, `expired` before it was approved,
 * or `unknown` to the partner.
 */
export const LINK_OUTCOMES = ['linked', 'rejected', 'expired', 'unknown'] as const;
export type LinkOutcomeKind = (typeof LINK_OUTCOMES)[number];

/** A partner's name, as Agent X keeps it: lower-case words, such as `fake`. */
export const PARTNER_NAME = /^[a-z][a-z0-9_]{0,31}$/;

/** The partner's word for a source, as the adapter gives it (PENDING, ACTIVE, SUSPENDED, UNAVAILABLE). */
type SourceAvailability = 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'UNAVAILABLE';

/** The limits the bank holds the consent to, in minor units of `currency`, per `period`. */
interface SourceControls {
  readonly currency: string;
  readonly period: 'day' | 'week' | 'month' | 'year';
  readonly maxPaymentMinor: bigint;
  readonly maxPeriodMinor: bigint;
  readonly maxPeriodPayments: number;
}

/** What may be shown of the account (BR-02): no account number, no balance. */
interface SourceSummary {
  readonly holderName: string;
  readonly accountType: 'retail' | 'sme' | 'corporate';
  /** The country and the last four characters of the account number, such as `AE…6026`. */
  readonly hint: string;
}

/** A source, as its signed state says. */
export interface SourceRecord {
  readonly id: string;
  readonly partner: string;
  /** The partner's reference for the source: the same through a renewal. */
  readonly externalRef: string;
  readonly status: FundingSourceStatus;
  readonly availability: SourceAvailability;
  /** The partner's own word for the consent, kept as evidence. */
  readonly consentStatus: string;
  readonly accountConsentId: string;
  readonly replacesConsentId: string | null;
  readonly consentExpiresAt: Date;
  readonly controls: SourceControls;
  readonly summary: SourceSummary;
  /** When the partner says the consent's status last changed. */
  readonly partnerChangedAt: Date;
}

/** Whether the source may fund a new request now: ACTIVE to Agent X and to the partner, its consent not yet expired. */
export const mayFund = (
  source: Pick<SourceRecord, 'status' | 'availability' | 'consentExpiresAt'>,
  now: Date,
): boolean => source.status === 'ACTIVE' && source.availability === 'ACTIVE' && now < source.consentExpiresAt;

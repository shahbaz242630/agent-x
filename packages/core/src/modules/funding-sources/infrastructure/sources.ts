// Funding sources (0029): a business's bank account, linked through the
// partner. An authority table (ADR-012 §2), so the partner and its reference,
// Agent X's status, the partner's availability and word for the consent, the
// consent and the one it renewed, its expiry, the bank's controls and what
// may be shown of the account must equal the source's latest signed event,
// and every read goes through the audit module's verifiedState with the
// description below. The description is on the product's authority-table
// list (packages/core/src/authority-tables.ts), at the funding source's level
// in the lock order (ADR-006 §6: 5).
//
// A source is added in one transaction, withSignedStates' for its
// organisation, with the link that made it: its row, then its first signed
// state. The insert is the one query on this table outside the audit
// module's steps, as for an agent's row (agents.ts says why a plain insert is
// safe). The seal is a MAC over the fields, so the holder's name is never put
// in an event.
import type { SignedStateTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type {
  AuditActor,
  AuditDetails,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import { type FundingSourceState, SOURCE_AVAILABILITIES } from '../../providers/index.ts';
import { FUNDING_SOURCE, PARTNER_NAME, type SourceRecord } from '../domain/source.ts';
import type { FundingSourcesTables } from './tables.ts';

/** A source's row, as the signed state reads, records and moves it. */
export const SOURCES = {
  table: 'funding_sources.sources',
  subject: 'funding_source',
  fields: [
    { column: 'link_id', type: 'uuid' },
    { column: 'partner', type: 'text' },
    { column: 'external_ref', type: 'text' },
    { column: 'status', type: 'text' },
    { column: 'availability', type: 'text' },
    { column: 'consent_status', type: 'text' },
    { column: 'account_consent_id', type: 'text' },
    { column: 'replaces_consent_id', type: 'text' },
    { column: 'consent_expires_at', type: 'timestamptz' },
    { column: 'currency', type: 'text' },
    { column: 'limit_period', type: 'text' },
    { column: 'max_payment_minor', type: 'integer' },
    { column: 'max_period_minor', type: 'integer' },
    { column: 'max_period_payments', type: 'integer' },
    { column: 'holder_name', type: 'text' },
    { column: 'account_type', type: 'text' },
    { column: 'hint', type: 'text' },
    { column: 'partner_changed_at', type: 'timestamptz' },
  ],
  rules: FUNDING_SOURCE,
} as const satisfies SignedStateTable & { readonly rules: typeof FUNDING_SOURCE };

/** A transaction on the tables sources are added and read in, opened by withSignedStates for their organisation. */
export type FundingSourcesTransaction = Transaction<FundingSourcesTables & AuditTables>;

/** What the partner says of a source: its answer, or what a source holds of the last one. */
type PartnerWord = Pick<
  FundingSourceState,
  'availability' | 'consentStatus' | 'accountConsentId' | 'replacesConsentId' | 'consentExpiresAt' | 'statusChangedAt'
> & {
  readonly controls: SourceRecord['controls'];
  readonly summary: SourceRecord['summary'];
};

/** The fields the partner's answer sets, sealed: everything but the link, the partner, its reference and Agent X's status. */
const partnerFields = (state: PartnerWord) => ({
  availability: state.availability,
  consent_status: state.consentStatus,
  account_consent_id: state.accountConsentId,
  replaces_consent_id: state.replacesConsentId,
  consent_expires_at: state.consentExpiresAt,
  currency: state.controls.currency,
  limit_period: state.controls.period,
  max_payment_minor: state.controls.maxPaymentMinor,
  max_period_minor: state.controls.maxPeriodMinor,
  max_period_payments: state.controls.maxPeriodPayments,
  holder_name: state.summary.holderName,
  account_type: state.summary.accountType,
  hint: state.summary.hint,
  partner_changed_at: state.statusChangedAt,
});

/** The facts of the partner's answer an event names: never the holder's name. */
const partnerDetails = (state: FundingSourceState): AuditDetails => ({
  availability: state.availability,
  consentStatus: state.consentStatus,
  accountConsentId: state.accountConsentId,
  consentExpiresAt: state.consentExpiresAt.toISOString(),
});

const sameOrganisation = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

export interface NewSource {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  /** The link that made it, read with `change` and settled in the same transaction. */
  readonly linkId: string;
  readonly partner: string;
  /** The source as the partner confirmed it, server to server, for this organisation. */
  readonly state: FundingSourceState;
  readonly createdAt: Date;
  /** Who is linking it. */
  readonly actor: AuditActor;
  /** More facts for its event. */
  readonly details?: AuditDetails;
}

/**
 * Adds the source, ACTIVE, in the caller's transaction, which must be
 * withSignedStates' for its organisation. Refused before any SQL runs: a
 * partner's answer for another organisation, one the partner says is gone
 * for good (a new link is needed), and a partner's name that isn't one.
 */
export async function addSource(
  tx: FundingSourcesTransaction,
  states: SignedStates,
  { orgId, id, linkId, partner, state, createdAt, actor, details = {} }: NewSource,
): Promise<RecordedState> {
  if (!sameOrganisation(state.organizationId, orgId))
    throw new RangeError("The partner's answer is another organisation's");
  if (state.availability === 'UNAVAILABLE') throw new RangeError('A source the partner says is gone is never added');
  if (!PARTNER_NAME.test(partner)) throw new RangeError('A partner is named in lower-case words');
  const fields = {
    link_id: linkId,
    partner,
    external_ref: state.externalRef,
    status: FUNDING_SOURCE.initial,
    ...partnerFields(state),
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(SOURCES.table)
    .values({ org_id: orgId, id, ...fields, created_at: createdAt })
    .execute();
  return states.record(tx, SOURCES, { orgId, id }, 'new', fields, {
    actor,
    action: 'funding_source.linked',
    details: { ...details, linkId, partner, ...partnerDetails(state) },
  });
}

/** A source read by its ID and verified, with the state a change records from; missing; or tampered with. */
export type SourceCheck =
  | { readonly outcome: 'found'; readonly source: SourceRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const WHOLE = /^[1-9][0-9]{0,18}$/;

/** One of `words`, or undefined. */
const oneOf = <const Word extends string>(words: readonly Word[], value: string | undefined): Word | undefined =>
  words.find((word) => word === value);

/** The source's record from its verified fields, or undefined when one isn't of its kind. */
function recordOf(id: string, fields: ReadonlyMap<string, string | null>): SourceRecord | undefined {
  const text = (column: string): string | undefined => fields.get(column) ?? undefined;
  const whole = (column: string): string | undefined => {
    const value = text(column);
    return value !== undefined && WHOLE.test(value) ? value : undefined;
  };
  const time = (column: string): Date | undefined => {
    const value = new Date(text(column) ?? Number.NaN);
    return Number.isNaN(value.getTime()) ? undefined : value;
  };
  const linkId = text('link_id');
  const partner = text('partner');
  const externalRef = text('external_ref');
  const status = oneOf(FUNDING_SOURCE.states, text('status'));
  const availability = oneOf(SOURCE_AVAILABILITIES, text('availability'));
  const consentStatus = text('consent_status');
  const accountConsentId = text('account_consent_id');
  const consentExpiresAt = time('consent_expires_at');
  const currency = text('currency');
  const period = oneOf(['day', 'week', 'month', 'year'], text('limit_period'));
  const [maxPayment, maxPeriod, maxPayments] = [
    whole('max_payment_minor'),
    whole('max_period_minor'),
    whole('max_period_payments'),
  ];
  const holderName = text('holder_name');
  const accountType = oneOf(['retail', 'sme', 'corporate'], text('account_type'));
  const hint = text('hint');
  const partnerChangedAt = time('partner_changed_at');
  if (
    linkId === undefined ||
    partner === undefined ||
    externalRef === undefined ||
    status === undefined ||
    availability === undefined ||
    consentStatus === undefined ||
    accountConsentId === undefined ||
    consentExpiresAt === undefined ||
    currency === undefined ||
    period === undefined ||
    maxPayment === undefined ||
    maxPeriod === undefined ||
    maxPayments === undefined ||
    holderName === undefined ||
    accountType === undefined ||
    hint === undefined ||
    partnerChangedAt === undefined
  ) {
    return undefined;
  }
  return {
    id,
    linkId,
    partner,
    externalRef,
    status,
    availability,
    consentStatus,
    accountConsentId,
    replacesConsentId: fields.get('replaces_consent_id') ?? null,
    consentExpiresAt,
    controls: {
      currency,
      period,
      maxPaymentMinor: BigInt(maxPayment),
      maxPeriodMinor: BigInt(maxPeriod),
      maxPeriodPayments: Number(maxPayments),
    },
    summary: { holderName, accountType, hint },
    partnerChangedAt,
  };
}

/**
 * The source, by its ID, read and verified in the caller's transaction, which
 * must be withSignedStates' for its organisation: `share` for a decision,
 * `change` for a change (its state then what `record` takes). Tampered with,
 * the alarm is raised and the organisation held; anything but `found` grants
 * nothing, and a found source funds nothing but as `mayFund` says.
 */
export async function sourceOf(
  tx: FundingSourcesTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
): Promise<SourceCheck> {
  const state = await states.verifiedState(tx, SOURCES, key, lock);
  if (state.outcome !== 'verified') return state;
  const source = recordOf(key.id.toLowerCase(), state.fields);
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (source === undefined)
    throw new Error(`A verified funding source holds a field that isn't one of its own: ${key.id}`);
  return { outcome: 'found', source, state };
}

/** The partner's answer names another source than the one it was asked about. */
export class NotThisSource extends Error {
  constructor() {
    super("The partner's answer is for another source");
    this.name = 'NotThisSource';
  }
}

/** A field's value as two are compared: a time by its instant, anything else as it is. */
const comparable = (value: unknown): unknown => (value instanceof Date ? value.getTime() : value);

/**
 * Whether the partner's answer says anything of the source other than it
 * holds: every field the answer sets, compared one by one, so a field added
 * to the answer is compared with the rest.
 */
function partnerChanged(source: SourceRecord, state: FundingSourceState): boolean {
  const held: Readonly<Record<string, unknown>> = partnerFields({
    ...source,
    statusChangedAt: source.partnerChangedAt,
  });
  return Object.entries(partnerFields(state)).some(([column, value]) => comparable(value) !== comparable(held[column]));
}

/**
 * Brings the source up to the partner's latest answer, in the caller's
 * transaction, which read it with `change` (`found`): the fields the partner
 * sets, recorded only when one of them changed; and when the partner says it
 * is gone for good, the source ENDED, so it funds nothing again. An answer
 * for another organisation's source, or another source, is refused
 * (`NotThisSource`) before any SQL runs. Gives the source as it now stands.
 */
export async function updateFromPartner(
  tx: FundingSourcesTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  found: { readonly source: SourceRecord; readonly state: VerifiedState },
  answer: { readonly state: FundingSourceState; readonly actor: AuditActor },
): Promise<SourceRecord> {
  const { source } = found;
  const { state, actor } = answer;
  if (!sameOrganisation(state.organizationId, key.orgId) || state.externalRef !== source.externalRef) {
    throw new NotThisSource();
  }
  if (partnerChanged(source, state)) {
    await states.record(tx, SOURCES, key, found.state, partnerFields(state), {
      actor,
      action: 'funding_source.partner_changed',
      details: partnerDetails(state),
    });
  }
  const ends = state.availability === 'UNAVAILABLE' && source.status !== 'ENDED';
  if (ends) {
    const ended = await states.changeStatus(tx, SOURCES, key, 'end', {
      actor,
      action: 'funding_source.ended',
      details: { consentStatus: state.consentStatus },
    });
    // Verified and locked for change just above, in this transaction: it ends, or something past the app is at work.
    if (ended.outcome !== 'changed') throw new Error(`A funding source the partner says is gone didn't end: ${key.id}`);
  }
  return {
    ...source,
    status: ends ? 'ENDED' : source.status,
    availability: state.availability,
    consentStatus: state.consentStatus,
    accountConsentId: state.accountConsentId,
    replacesConsentId: state.replacesConsentId,
    consentExpiresAt: new Date(state.consentExpiresAt),
    controls: { ...state.controls },
    summary: {
      holderName: state.summary.holderName,
      accountType: state.summary.accountType,
      hint: state.summary.hint,
    },
    partnerChangedAt: new Date(state.statusChangedAt),
  };
}

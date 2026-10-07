// A mandate version's terms (PRD §3 `Mandate`, §3.1; ADR-006 §1; BR-05,
// BR-06; Phase 2 B2): what an agent may spend, on whom, from where, and until
// when. Checked here before anything is written, and the module's floor after
// it; the database's checks (0035) hold the same shapes.
//
// The limits nest: approval threshold ≤ per-order ≤ monthly (PRD §3.3: over
// the mandate's own limits is REQUIRE_NEW_MANDATE, never an approval). All
// three are in the mandate's one currency, as Money (A1).
//
// The terms are checked against the bank consent of their funding source
// (partner, S86–S87): per payment always, and per month when the consent's
// period is a month. Strict (the default) refuses a limit above the
// consent's; flexible allows it, with a warning the bank may refuse it.
import { compare, type Money, UUID, visibleName } from '../../../shared-kernel/index.ts';
import { type ConsentLimits, MOST_ALLOWED_SUPPLIERS } from './mandate.ts';

/** A version's terms, as a member gives them (the amounts already Money, from the API's edge). */
export interface MandateTerms {
  readonly purpose: string;
  readonly perOrderLimit: Money;
  readonly monthlyLimit: Money;
  readonly approvalThreshold: Money;
  /** The suppliers it may pay, by ID. */
  readonly supplierIds: readonly string[];
  readonly fundingSourceId: string;
  /** The split-order check (ADR-014 §5): on by default. */
  readonly splitCheck: boolean;
  readonly consentLimits: ConsentLimits;
  /** When it ends, if it does: otherwise until revoked. */
  readonly endsAt: Date | null;
}

/** The terms can't be a mandate's; `problems` say why. */
export class MandateTermsRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The mandate's terms were refused: ${problems.join('; ')}`);
    this.name = 'MandateTermsRefused';
    this.problems = problems;
  }
}

/** The most characters a mandate's purpose may have: the table's own limit. */
export const PURPOSE_MOST = 200;

/**
 * The terms as a version keeps them: the purpose composed (NFC), the
 * suppliers in lower case, sorted, each once; or `MandateTermsRefused`
 * naming each problem.
 */
export function mandateTerms(terms: MandateTerms, now: Date): MandateTerms {
  const { name: purpose, problems } = visibleName(terms.purpose, PURPOSE_MOST, 'the purpose');
  const { perOrderLimit, monthlyLimit, approvalThreshold } = terms;
  const currencies = new Set([perOrderLimit.currency, monthlyLimit.currency, approvalThreshold.currency]);
  if (currencies.size !== 1) problems.push('the limits are not all in one currency');
  else {
    if (compare(approvalThreshold, perOrderLimit) > 0)
      problems.push('the approval threshold is above the per-order limit');
    if (compare(perOrderLimit, monthlyLimit) > 0) problems.push('the per-order limit is above the monthly limit');
  }
  const supplierIds = [...new Set(terms.supplierIds.map((id) => id.toLowerCase()))].sort();
  if (supplierIds.length === 0 || supplierIds.length > MOST_ALLOWED_SUPPLIERS) {
    problems.push(`the mandate names 1 to ${String(MOST_ALLOWED_SUPPLIERS)} suppliers`);
  }
  if (supplierIds.length !== terms.supplierIds.length) problems.push('a supplier is named twice');
  if (!supplierIds.every((id) => UUID.test(id))) problems.push('a supplier is not named by its ID');
  if (!UUID.test(terms.fundingSourceId)) problems.push('the funding source is not named by its ID');
  // An invalid date is no end either.
  const ends = terms.endsAt?.getTime();
  if (ends !== undefined && (Number.isNaN(ends) || ends <= now.getTime()))
    problems.push('the mandate ends in the past');
  if (problems.length > 0) throw new MandateTermsRefused(problems);
  return { ...terms, purpose, supplierIds, fundingSourceId: terms.fundingSourceId.toLowerCase() };
}

/** What a funding source's bank consent allows (PRD §3 `FundingSourceReference`). */
export interface ConsentAllows {
  readonly currency: string;
  readonly maxPayment: Money;
  readonly maxPeriod: Money;
  readonly limitPeriod: 'day' | 'week' | 'month' | 'year';
}

/**
 * The terms against the bank consent: per payment always; per month when the
 * consent counts by the month (another period can't be compared with a month
 * without guessing). `problems` name where they go past it, whatever the
 * setting (shown later too, as the bank can change the consent); `refused`
 * for strict terms past it, or a currency other than the consent's whatever
 * the setting. Flexible terms are kept, the problems their warnings.
 */
export function consentCheck(
  terms: MandateTerms,
  consent: ConsentAllows,
): { readonly refused: boolean; readonly problems: readonly string[] } {
  if (terms.perOrderLimit.currency !== consent.currency) {
    return { refused: true, problems: ['the mandate is not in its funding source’s currency'] };
  }
  const past: string[] = [];
  if (compare(terms.perOrderLimit, consent.maxPayment) > 0) {
    past.push('the per-order limit is above the bank consent’s per payment');
  }
  if (consent.limitPeriod === 'month' && compare(terms.monthlyLimit, consent.maxPeriod) > 0) {
    past.push('the monthly limit is above the bank consent’s per month');
  }
  return { refused: terms.consentLimits === 'strict' && past.length > 0, problems: past };
}

// The mandates module (ADR-004, PRD §3 `Mandate` / `MandateEvidence`, §4.1;
// Phase 2 B): the spending authority an organisation gives one of its agents,
// and the versions of its terms, both authority tables read through their
// signed states (B1). Drafting and reading them (B2); accepting and moving
// them come with B3–B4, their routes composed in the API.
export {
  CONSENT_LIMITS,
  type ConsentLimits,
  DEFAULT_CONSENT_LIMITS,
  DEFAULT_SPLIT_WINDOW_HOURS,
  isEnded,
  MANDATE,
  type MandateStatus,
  MOST_ALLOWED_SUPPLIERS,
  OPEN_STATES,
  SPLIT_WINDOW_HOURS,
} from './domain/mandate.ts';
export {
  type ConsentAllows,
  consentWarnings,
  type MandateTerms,
  mandateTerms,
  MandateTermsRefused,
  PURPOSE_MOST,
} from './domain/terms.ts';
export {
  draftMandate,
  draftsSince,
  draftVersion,
  type MandateRecord,
  type MandateShown,
  mandateOf,
  mandatesPage,
  type MandateVersionRecord,
  mandateVersionOf,
  MOST_DRAFTS_A_DAY,
  MOST_MANDATES_A_PAGE,
  oneDraftAtATime,
  openMandateOfAgent,
} from './infrastructure/drafts.ts';
export { MANDATE_VERSIONS, MANDATES } from './infrastructure/mandates.ts';
export type { MandatesTables } from './infrastructure/tables.ts';

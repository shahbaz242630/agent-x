// The mandates module (ADR-004, PRD §3 `Mandate` / `MandateEvidence`, §4.1;
// Phase 2 B): the spending authority an organisation gives one of its agents,
// and the versions of its terms, both authority tables read through their
// signed states (B1). Drafting, accepting and moving them, with their routes,
// come with B2–B5.
export {
  CONSENT_LIMITS,
  type ConsentLimits,
  DEFAULT_SPLIT_WINDOW_HOURS,
  DEFAULT_TIME_ZONE,
  MANDATE,
  type MandateStatus,
  MOST_ALLOWED_SUPPLIERS,
  SPLIT_WINDOW_HOURS,
} from './domain/mandate.ts';
export { MANDATE_VERSIONS, MANDATES } from './infrastructure/mandates.ts';
export type { MandatesTables } from './infrastructure/tables.ts';

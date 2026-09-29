// The funding-sources module (ADR-004, PRD §2.3; Phase 1 D2): an
// organisation's links to its own bank account through the payment partner,
// and the sources they make, an authority table read through its signed
// state (D2-2). Linking, with its routes, is composed in the API (D2-3); the
// partner is known only through the providers module's adapter.
export { FUNDING_SOURCE, type LinkOutcomeKind, mayFund, type SourceRecord } from './domain/source.ts';
export {
  addLink,
  LinkNotOpen,
  linkOf,
  type LinkRecord,
  linksStartedSince,
  MOST_LINKS_STARTED_A_DAY,
  oneLinkStartAtATime,
  settleLink,
} from './infrastructure/links.ts';
export { addSource, SOURCES, sourceOf } from './infrastructure/sources.ts';
export type { FundingSourcesTables } from './infrastructure/tables.ts';

// The funding-sources module (ADR-004, PRD §2.3; Phase 1 D2): an
// organisation's links to its own bank account through the payment partner,
// and the sources they make, an authority table read through its signed
// state (D2-2). Linking, with its routes, is composed in the API (D2-3); the
// partner is known only through the providers module's adapter.
export { FUNDING_SOURCE } from './domain/source.ts';
export { SOURCES } from './infrastructure/sources.ts';

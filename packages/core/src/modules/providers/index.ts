// The providers module (ADR-004 §8, PRD §6; Phase 1 D1): the payment
// partner's adapter contract, its fake, and the checks every adapter's
// answers pass. The only module that knows a partner's API; `funding-sources`,
// `suppliers` and the hand-off see only its normalised answers.
export { AccountNumberLeak, accountHint, withoutAccountNumbers } from './domain/account-numbers.ts';
export {
  type ConsentControls,
  type FinancialRailAdapter,
  type FundingSourceState,
  type LinkContext,
  type LinkOutcome,
  type PartnerLinkSession,
  RailUnavailable,
  SOURCE_AVAILABILITIES,
  type SourceAvailability,
  type SourceLookup,
  type SourceRef,
  type SourceSummary,
} from './domain/rail.ts';
export {
  type ApproveOptions,
  createFakeRail,
  type FakeBank,
  type FakeRail,
  type FakeRailOptions,
  USUAL_CONTROLS,
} from './infrastructure/fake-rail.ts';

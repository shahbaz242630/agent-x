// The spend-requests module (ADR-004, PRD §3 `SpendRequest`, §3.2, §4.2;
// Phase 2 D): an agent's spend requests, an authority table read through its
// signed state, and the order claims that keep one order from being paid
// twice (D1), with the duplicate check and claiming an order (D3); a request
// made VALIDATING with its decision and moved by it (D4). Deciding and
// reserving are composed in the API (decideAndReserve), the agent asking
// through its route (D4r), its text checked here, with the bank reference its
// order reference becomes (decision 8); and the holdings check, comparing each
// request's reservation and claim with its signed state (E1); a request
// waiting for approval expired after 72 hours, or cancelled before hand-off,
// its holdings released (D7, D8), or rejected by a person with a reason
// (Phase 3 B4a), or approved by one, weighed again (B4b); and one whose
// authority no longer stands voided, its holdings released (C1).
export {
  askedText,
  BANK_REFERENCE_MOST,
  bankKeyOf,
  bankReferenceOf,
  ORDER_REFERENCE_MOST,
  orderReferenceOf,
  REQUEST_PURPOSE_MOST,
  SpendAskRefused,
} from './domain/asked.ts';
export { SPEND_REQUEST, type SpendRequestStatus } from './domain/spend-request.ts';
export {
  checkHoldings,
  holdingsRecordChecks,
  type HoldingsChecked,
  heldAsDecidedOf,
  MOST_CHECKED_A_PAGE,
} from './infrastructure/holdings-check.ts';
export type { HeldAs } from './domain/holdings.ts';
export { type Approval, approveRequest } from './infrastructure/approvals.ts';
export {
  type DecidedAgainst,
  decidedAgainst,
  holdsCapacity,
  insertRequest,
  MOST_REQUESTS_A_PAGE,
  type NewRequest,
  requestOf,
  requestsPage,
  signRequest,
  type SpendRequestCheck,
  type SpendRequestListed,
  type SpendRequestRecord,
} from './infrastructure/decisions.ts';
export { REJECT_REASON_MOST, rejectReason } from './domain/rejection.ts';
export {
  type Canceller,
  cancelRequest,
  type Ended,
  expireRequest,
  type Rejection,
  denialOf,
  type RejectionShown,
  rejectRequest,
  requestsWaitingSince,
  type SubjectsNamed,
  type Voided,
  type VoidingShown,
  voidPendingOf,
  voidRequest,
  WAITS_FOR_APPROVAL_MS,
  waitedOut,
} from './infrastructure/endings.ts';
export {
  type AuthorityNow,
  isPendingChoice,
  type Pausable,
  PENDING_CHOICES,
  PENDING_STATUSES,
  type PendingChoice,
} from './domain/voids.ts';
export { claimOrder, claimsOn, type OrderOf, type OrderWeighed, releaseClaim } from './infrastructure/order-claims.ts';
export { sealPayee } from './infrastructure/payee-seal.ts';
export { SPEND_REQUESTS } from './infrastructure/requests.ts';
export type { SpendRequestsTables } from './infrastructure/tables.ts';

// The spend-requests module (ADR-004, PRD §3 `SpendRequest`, §3.2, §4.2;
// Phase 2 D): an agent's spend requests, an authority table read through its
// signed state, and the order claims that keep one order from being paid
// twice (D1), with the duplicate check and claiming an order (D3); a request
// made VALIDATING with its decision and moved by it (D4). Deciding and
// reserving are composed in the API (decideAndReserve), the agent asking
// through its route (D4r), its text checked here, with the bank reference its
// order reference becomes (decision 8).
export {
  askedText,
  BANK_REFERENCE_MOST,
  bankReferenceOf,
  ORDER_REFERENCE_MOST,
  REQUEST_PURPOSE_MOST,
  SpendAskRefused,
} from './domain/asked.ts';
export { SPEND_REQUEST, type SpendRequestStatus } from './domain/spend-request.ts';
export {
  holdsCapacity,
  insertRequest,
  type NewRequest,
  requestOf,
  signRequest,
  type SpendRequestCheck,
  type SpendRequestRecord,
} from './infrastructure/decisions.ts';
export { claimOrder, hasOpenClaim, type OrderOf, releaseClaim } from './infrastructure/order-claims.ts';
export { SPEND_REQUESTS } from './infrastructure/requests.ts';
export type { SpendRequestsTables } from './infrastructure/tables.ts';

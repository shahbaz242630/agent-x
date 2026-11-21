// The spend-requests module (ADR-004, PRD §3 `SpendRequest`, §3.2, §4.2;
// Phase 2 D): an agent's spend requests, an authority table read through its
// signed state, and the order claims that keep one order from being paid
// twice (D1), with the duplicate check and claiming an order (D3); a request
// made VALIDATING with its decision and moved by it (D4). Deciding and
// reserving are composed in the API (decideAndReserve), the agent asking
// through its route (D4r), its text checked here, with the bank reference its
// order reference becomes (decision 8); and the holdings check, comparing each
// request's reservation and claim with its signed state (E1); a request
// waiting for approval expired after its wait (E6), or cancelled before hand-off,
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
  approvedAtLooks,
  checkHoldings,
  holdingsRecordChecks,
  type HoldingsChecked,
  decisionOf,
  decisionsOf,
  type Decided,
  MOST_CHECKED_A_PAGE,
  NO_PAYMENTS,
  type PaymentsOf,
  requestHoldingsWhole,
} from './infrastructure/holdings-check.ts';
export type { HeldAs, HeldSealed, PaymentHolds } from './domain/holdings.ts';
export { type Approval, approveRequest } from './infrastructure/approvals.ts';
export {
  type DecidedAgainst,
  decidedAgainst,
  holdsCapacity,
  insertRequestStatement,
  MOST_REQUESTS_A_PAGE,
  type NewRequest,
  requestOf,
  requestsOf,
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
  requestExpiryDue,
  requestsDueToExpire,
  requestsDueToExpireRead,
  settleCarried,
  type SubjectsNamed,
  type Voided,
  type VoidingShown,
  voidPendingOf,
  lockedHoldingsOf,
  lockedTotalOf,
  voidedWith,
  voidRequest,
  windowsHeldOf,
} from './infrastructure/endings.ts';
export {
  APPROVAL_WAITS,
  type ApprovalClock,
  type ApprovalWaitHours,
  expiresAtOf,
  LONGEST_APPROVAL_WAIT,
  waitedOut,
} from './domain/approval-wait.ts';
export {
  APPROVAL_HORIZON_MS,
  type AuthorityNow,
  isPending,
  isPendingChoice,
  PAUSED_IN,
  type Pausable,
  PENDING_CHOICES,
  PENDING_STATUSES,
  type PendingChoice,
  VOID_CAUSES,
  type VoidCause,
} from './domain/voids.ts';
export {
  claimAnswered,
  claimStatement,
  claimsOnEach,
  lockClaimsOf,
  type OrderClaimsSeen,
  orderKeyRead,
  type OrderOf,
  type OrderWeighed,
  releaseClaim,
} from './infrastructure/order-claims.ts';
export {
  type BankEntry,
  heldBy,
  type Holders,
  MOST_BANK_ENTRIES,
  noHolders,
  SLOT_KINDS,
  type SlotKind,
  slotsLook,
} from './domain/order-slots.ts';
export {
  checkOrderSlots,
  keyHashOf,
  MOST_SLOTS_CHECKED_A_PAGE,
  ORDER_SLOTS,
  type OrderSlotCheck,
  orderHashOf,
  orderSlotId,
  type OrderSlotKey,
  orderSlotKeys,
  orderSlotOf,
  orderSlotOrder,
  orderSlotsCutOver,
  orderSlotsCutOverFind,
  orderSlotsOf,
  orderSlotToSend,
  type OrderToSlot,
  recordOrderSlot,
  SLOTS_CUTOVER_ACTION,
  SLOTS_CUTOVER_SUBJECT,
  SLOTS_NAMED_ACTION,
  SLOTS_NAMED_SUBJECT,
  type SlotsChecked,
  slotsLetGo,
  slotsMissing,
  type SlotTake,
  slotTakesOf,
  type SlotToWrite,
} from './infrastructure/order-slots.ts';
export {
  type DecisionMonthTotal,
  type DecisionSlots,
  type DecisionWindows,
  monthLockedAndTotalsWeighed,
  totalsWeighed,
} from './infrastructure/weighed-totals.ts';
export { type CutoverDone, cutOverMonthTotals } from './infrastructure/month-totals-cutover.ts';
export { cutOverPayeeWindows, type WindowsCutoverDone } from './infrastructure/payee-windows-cutover.ts';
export { cutOverOrderSlots, type SlotsCutoverDone } from './infrastructure/order-slots-cutover.ts';
export { sealPayee } from './infrastructure/payee-seal.ts';
export { requestDueNow, SPEND_REQUESTS } from './infrastructure/requests.ts';
export type { SpendRequestsTables } from './infrastructure/tables.ts';

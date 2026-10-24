// The outcomes module (ADR-004; ADR-006 §10–§11; Phase 4 C3): a payment's
// outcome applied to what its request holds, its monthly capacity and its
// order claim, in the transaction that moves the payment; and what each
// payment must hold, for the holdings check; and every move of a payment
// locked and settled the one way (`lockPayment`, `settlePayment`: the API's
// and the operator's, E1c); and an UNKNOWN payment marked failed by Agent X's
// own team on the bank's written word (E1c).
export { type Settlement, settlementOf } from './infrastructure/settlement.ts';
export { lockHoldingsOf, paymentHoldsOf, settleHoldings } from './infrastructure/outcomes.ts';
export {
  AFTER_SUBMITTED,
  answerAbout,
  factsOf,
  type LockedPayment,
  lockPayment,
  moveDetails,
  NO_FACTS,
  type PaymentMoved,
  settlePayment,
} from './infrastructure/payment-outcome.ts';
export {
  MARK_FAILED_AFTER_MS,
  type MarkedFailed,
  MarkFailedRefused,
  type MarkFailedRequest,
  type MarkFailedTables,
  markPaymentFailed,
  PLATFORM_MARKED_FAILED,
} from './infrastructure/mark-failed.ts';

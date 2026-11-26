// The outcomes module (ADR-004; ADR-006 §10–§11; Phase 4 C3): a payment's
// outcome applied to what its request holds, its monthly capacity and its
// order claim, in the transaction that moves the payment; and what each
// payment must hold, for the holdings check; and every move of a payment
// locked and settled the one way (`lockPayment`, `settlePayment`); and an
// UNKNOWN payment marked failed by the customer's admin on the bank's written
// word (E1c; partner decision 38).
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
export { contradicts, PAYMENT_ALERT_SUBJECT } from './infrastructure/contradiction.ts';
export {
  contradictionsOf,
  MOST_PAYMENTS_A_PAGE,
  paymentOf,
  type PaymentRecord,
  type PaymentsAsked,
  paymentsPage,
} from './infrastructure/payments-page.ts';
export {
  MARK_FAILED_AFTER_MS,
  type MarkFailed,
  markFailed,
  type MarkFailedTables,
} from './infrastructure/mark-failed.ts';
// Each organisation's money path in counts, for the money-path snapshot (GA4, PRD §9.3).
export {
  type HeldMoney,
  type MoneyPath,
  moneyPathOf,
  moneyPathRead,
  type MoneyPathRow,
  type MoneyPathWindow,
} from './infrastructure/money-path.ts';

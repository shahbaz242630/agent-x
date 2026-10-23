// The outcomes module (ADR-004; ADR-006 §10–§11; Phase 4 C3): a payment's
// outcome applied to what its request holds, its monthly capacity and its
// order claim, in the transaction that moves the payment; and what each
// payment must hold, for the holdings check.
export { type Settlement, settlementOf } from './infrastructure/settlement.ts';
export { lockHoldingsOf, paymentHoldsOf, settleHoldings } from './infrastructure/outcomes.ts';

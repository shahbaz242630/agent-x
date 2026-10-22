// A transaction's status (PRD §4.3; ADR-007 §7–§13; Phase 4 B3): the single
// source of truth for a handed-off request's outcome. Born SUBMISSION_PENDING
// with its instruction in the hand-off's Tx A (PRD's CREATED is never stored:
// the two are made together); the partner's answers and events move it. The
// database's status guard holds the same moves (0058).
//
// - `submitted`: the partner accepted the instruction.
// - `processing`: the partner says it is under way (rail map §4: Pending, or
//   settled at the debtor but not yet credited).
// - `succeed`: the creditor's account credited (STA-1). From SUBMITTED too: a
//   lookup can find it done before any event said it was under way.
// - `fail`: only with positive proof of non-acceptance (ADR-007 §9, §11):
//   from SUBMISSION_PENDING for a refusal that made nothing, later for a
//   rejection the partner proves never debited.
// - `cancel`: a verified partner cancellation.
// - `lose_track`: the outcome can't be known (a timeout, a dropped
//   connection, a rejection after a debit): UNKNOWN, which resolves only from
//   verified partner evidence or an approved reconciliation.
// - `reverse`: a verified partner reversal after success, never an Agent X refund.
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const TRANSACTION = defineStateMachine({
  name: 'transaction',
  states: ['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'UNKNOWN', 'REVERSED'],
  initial: 'SUBMISSION_PENDING',
  events: {
    submitted: { from: ['SUBMISSION_PENDING'], to: 'SUBMITTED' },
    processing: { from: ['SUBMITTED'], to: 'PROCESSING' },
    succeed: { from: ['SUBMITTED', 'PROCESSING', 'UNKNOWN'], to: 'SUCCEEDED' },
    fail: { from: ['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN'], to: 'FAILED' },
    cancel: { from: ['SUBMITTED', 'PROCESSING', 'UNKNOWN'], to: 'CANCELLED' },
    lose_track: { from: ['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING'], to: 'UNKNOWN' },
    reverse: { from: ['SUCCEEDED'], to: 'REVERSED' },
  },
});

export type TransactionStatus = (typeof TRANSACTION.states)[number];
export type TransactionEvent = Parameters<typeof TRANSACTION.transition>[1];

/** Whether the outcome is settled: nothing more is expected of the partner but a reversal. */
export const isSettled = (status: TransactionStatus): boolean =>
  status === 'SUCCEEDED' || status === 'FAILED' || status === 'CANCELLED' || status === 'REVERSED';

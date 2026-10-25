// The transactions module (ADR-004; PRD §3 `Transaction`, §4.3; Phase 4 B3):
// a handed-off request's transaction, the single source of truth for its
// outcome, opened in the hand-off's Tx A and moved by the partner's answers;
// and an admin's proposal to mark an UNKNOWN one failed (0066, gate H10).
export { isSettled, TRANSACTION, type TransactionEvent, type TransactionStatus } from './domain/transaction.ts';
export { FAILURE_PROPOSAL, type FailureProposalStatus } from './domain/failure-proposal.ts';
export {
  FAILURE_PROPOSALS,
  type FailureProposalRecord,
  moveProposal,
  type OpenProposal,
  openProposalOf,
  proposalOf,
  proposeFailure,
} from './infrastructure/failure-proposals.ts';
export {
  moveTransaction,
  noteTransactionFacts,
  openTransaction,
  type PaymentCheck,
  paymentsOfRequests,
  type ProviderFacts,
  TRANSACTIONS,
  transactionOf,
} from './infrastructure/transactions.ts';
export type { PaymentsTables, TransactionsTables } from './infrastructure/tables.ts';

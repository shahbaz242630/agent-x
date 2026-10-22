// The transactions module (ADR-004; PRD §3 `Transaction`, §4.3; Phase 4 B3):
// a handed-off request's transaction, the single source of truth for its
// outcome, opened in the hand-off's Tx A and moved by the partner's answers.
export { TRANSACTION } from './domain/transaction.ts';
export {
  moveTransaction,
  noteTransactionFacts,
  openTransaction,
  type ProviderFacts,
  TRANSACTIONS,
  transactionOf,
} from './infrastructure/transactions.ts';
export type { TransactionsTables } from './infrastructure/tables.ts';

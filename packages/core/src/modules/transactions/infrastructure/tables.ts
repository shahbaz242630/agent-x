import type { Generated } from 'kysely';

import type { InstructionsTables } from '../../instructions/index.ts';

/** The transactions schema's tables (db/migrations/0058_instructions_transactions.sql, 0066_failure_proposals.sql), as Kysely sees them. */
export interface TransactionsTables {
  'transactions.transactions': TransactionsTable;
  'transactions.failure_proposals': FailureProposalsTable;
}

/** The tables a payment is read from (paymentsOfRequests): its instruction and its transaction. */
export type PaymentsTables = TransactionsTables & InstructionsTables;

interface TransactionsTable {
  org_id: string;
  id: string;
  instruction_id: string;
  status: string;
  provider_status: Generated<string | null>;
  payment_instruction_ref: Generated<string | null>;
  reject_code: Generated<string | null>;
  provider_changed_at: Generated<Date | null>;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface FailureProposalsTable {
  org_id: string;
  id: string;
  transaction_id: string;
  evidence_ref: string;
  /** The admin's user ID. */
  proposed_by: string;
  /** OPEN, WITHDRAWN or CONFIRMED. */
  status: string;
  created_at: Date;
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

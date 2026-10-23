import type { Generated } from 'kysely';

import type { InstructionsTables } from '../../instructions/index.ts';

/** The transactions schema's table (db/migrations/0058_instructions_transactions.sql), as Kysely sees it. */
export interface TransactionsTables {
  'transactions.transactions': TransactionsTable;
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

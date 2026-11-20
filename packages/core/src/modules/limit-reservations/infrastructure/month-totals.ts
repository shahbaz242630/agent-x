// An agent's monthly total as a signed running total (0109; GM-1a, R-15;
// ADR-006 §8; ADR-012 §2): what its month's reservations hold, one row an agent,
// month and currency, read and changed through its signed state in the same
// transactions that reserve and release, so the database's owner can't give
// capacity back by deleting or zeroing reservations. On the product's
// authority-table list (packages/core/src/authority-tables.ts), at level 11a.
import type { SignedStateTable } from '@agentx/platform/db';

/** A month's total row, as the signed state reads, records and checks it. */
export const MONTH_TOTALS = {
  table: 'limit_reservations.month_totals',
  subject: 'month_total',
  fields: [
    { column: 'agent_id', type: 'uuid' },
    { column: 'month', type: 'text' },
    { column: 'currency', type: 'text' },
    { column: 'held_minor', type: 'integer' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  // Fixed when the total is made: 0109's `fixed_at_creation` refuses any change after.
  fixedAtCreation: ['agent_id', 'month', 'currency', 'created_at'],
} as const satisfies SignedStateTable & { readonly fixedAtCreation: readonly string[] };

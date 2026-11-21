// A payee's split window as signed hourly totals (0112; GM-1b, R-15;
// ADR-006 §8 and §9; ADR-014 §5; ADR-012 §2): what its reservations hold, hour
// by hour, as far back as any split window reaches, read and changed through
// its signed state in the same transactions that reserve and release, so the
// database's owner can't take a payment past its approval by deleting, zeroing
// or releasing the payee's reservations. On the product's authority-table list
// (packages/core/src/authority-tables.ts), at level 11b: after a request (8),
// its reservation (11) and its agent's month total (11a), before the audit
// head (12).
import type { SignedStateTable } from '@agentx/platform/db';

/** A payee's window row, as the signed state reads, records and checks it. */
export const PAYEE_WINDOWS = {
  table: 'limit_reservations.payee_windows',
  subject: 'payee_window',
  fields: [
    { column: 'supplier_id', type: 'uuid' },
    { column: 'payee_key', type: 'text' },
    { column: 'currency', type: 'text' },
    { column: 'held_by_hour', type: 'text' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  // Fixed when the window is made: 0112's `fixed_at_creation` refuses any change after.
  fixedAtCreation: ['supplier_id', 'payee_key', 'currency', 'created_at'],
} as const satisfies SignedStateTable & { readonly fixedAtCreation: readonly string[] };

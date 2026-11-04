// When the hold history's job next has work in an organisation (4D2e D10): its marks'
// due read, as signed-states.ts' mayBeHeld looks, believed in nothing. A choice of
// when to look alone: the job reads the hold verified before it does anything.
import { sql, type Transaction } from 'kysely';

import { HOLD_SUBJECT } from '../domain/integrity-hold.ts';
import type { AuditTables } from './tables.ts';

/**
 * Now, while the newest event about the organisation's hold, as the table holds it, set it; else none: a hold stands
 * until it is cleared, and its history is checked while it does. Not run: a statement for the caller's trip, in
 * withTenant's transaction for the organisation (0005's events_by_subject).
 */
export const holdHistoryDue = (tx: Transaction<AuditTables>, orgId: string, now: Date) => {
  const held = orgId.toLowerCase();
  const newest = tx
    .selectFrom('audit.events')
    .select('action')
    .where('org_id', '=', held)
    .where('subject_type', '=', HOLD_SUBJECT)
    .where('subject_id', '=', held)
    .orderBy('seq', 'desc')
    .limit(1);
  return tx.selectNoFrom(
    sql<Date | null>`case when (${newest}) = 'integrity_hold.set' then ${now}::timestamptz end`.as('due'),
  );
};

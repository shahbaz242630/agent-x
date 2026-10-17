// How many events a range of the organisation's log holds, and the newest of
// them, for a download of it (Phase 3 E10b, decision 24): counted before the
// download is recorded, so one past its cap is refused with nothing written,
// and the download holds exactly the events up to that seq however many are
// recorded while it is read. One statement on 0048's indexes.
import { sql, type Transaction } from 'kysely';

import type { AuditTables } from './tables.ts';

/** A range of the log, as a page reads one (LogPageToRead), with no start or limit. */
export interface LogRange {
  readonly from: Date;
  readonly to: Date;
  readonly actions?: readonly string[] | undefined;
}

/** The events recorded in [from, to), of `actions` when named: how many, and the newest's seq (null for none). */
export async function eventsInRange(
  tx: Transaction<AuditTables>,
  orgId: string,
  { from, to, actions }: LogRange,
): Promise<{ readonly events: number; readonly upToSeq: bigint | null }> {
  let query = tx
    .selectFrom('audit.events')
    .select([sql<number>`pg_catalog.count(*)::int`.as('events'), sql<bigint | null>`pg_catalog.max(seq)`.as('up_to')])
    .where('org_id', '=', orgId)
    .where('recorded_at', '>=', from)
    .where('recorded_at', '<', to);
  if (actions !== undefined) query = query.where('action', 'in', [...actions]);
  const row = await query.executeTakeFirstOrThrow();
  return { events: row.events, upToSeq: row.up_to };
}

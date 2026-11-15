// How many events a range of the organisation's log holds, and the newest of
// them, for a download of it (Phase 3 E10b, decision 24): counted before the
// download is recorded, so one past its cap is refused with nothing written,
// and the download holds exactly the events up to that seq however many are
// recorded while it is read. One statement on 0048's, 0051's and 0005's indexes.
import { sql, type Transaction } from 'kysely';

import { actorAsKept, type AuditActor, type AuditSubjectKey } from '../domain/event.ts';
import { subjectsAre } from './audit-trail.ts';
import type { AuditTables } from './tables.ts';

/** A range of the log, as a page reads one (LogPageToRead), with no start or limit. */
export interface LogRange {
  readonly from: Date;
  readonly to: Date;
  readonly actions?: readonly string[] | undefined;
  readonly actor?: AuditActor | undefined;
  readonly subjects?: readonly AuditSubjectKey[] | undefined;
}

/** The events recorded in [from, to), of `actions`, `actor` and `subjects` when named: how many, and the newest's seq (null for none). */
export async function eventsInRange(
  tx: Transaction<AuditTables>,
  orgId: string,
  { from, to, actions, actor, subjects }: LogRange,
): Promise<{ readonly events: number; readonly upToSeq: bigint | null }> {
  let query = tx
    .selectFrom('audit.events as e')
    .select([sql<number>`pg_catalog.count(*)::int`.as('events'), sql<bigint | null>`pg_catalog.max(seq)`.as('up_to')])
    .where('org_id', '=', orgId)
    .where('recorded_at', '>=', from)
    .where('recorded_at', '<', to);
  if (actions !== undefined) query = query.where('action', 'in', [...actions]);
  if (actor !== undefined) {
    const kept = actorAsKept(actor);
    query = query.where('actor_type', '=', kept.type).where('actor_id', '=', kept.id);
  }
  // The trail's own check and pairs, as a page reads them (`e` names the table there as here).
  if (subjects !== undefined) query = query.where(sql<boolean>`${subjectsAre(subjects)}`);
  const row = await query.executeTakeFirstOrThrow();
  return { events: row.events, upToSeq: row.up_to };
}

// How often one actor did one thing lately, read from the organisation's own
// log (Phase 2 G6; partner decision 11b): a count alone, for a budget. 0044's
// `agent_cancels` holds an agent's own `spend_request.cancelled` events, so
// that count is a short scan however long the log.
import { sql, type Transaction } from 'kysely';

import type { AuditActor } from '../domain/event.ts';
import type { AuditTables } from './tables.ts';

/** How many `action` events `actor` recorded in the organisation after `since`, in one statement. */
export async function actorEventsSince(
  tx: Transaction<AuditTables>,
  orgId: string,
  actor: AuditActor,
  action: string,
  since: Date,
): Promise<number> {
  const row = await tx
    .selectFrom('audit.events')
    .select(sql<number>`pg_catalog.count(*)::int`.as('recorded'))
    .where('org_id', '=', orgId)
    .where('action', '=', action)
    .where('actor_type', '=', actor.type)
    .where('actor_id', '=', actor.id)
    .where('recorded_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.recorded;
}

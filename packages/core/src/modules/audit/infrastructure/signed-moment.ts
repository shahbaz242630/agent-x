// The moment a set of signed rows was read at (Phase 6 C2a review): rows read
// across more than one transaction (ADR-006's lock order splits a spend
// request's evidence in two) are one moment only if none of them moved while
// the others were read. Each row was believed by its newest signed event
// (verifiedState), so its moment is that event's seq; together they hold at
// the newest of those seqs, unless a row read earlier has a newer signed event
// at or before it, and then it moved in between. One statement, on the events'
// (org_id, id) key and 0005's index by object. A comparison of seqs alone:
// every event shown is still read through the trail, believed whole.
import { sql, type Transaction } from 'kysely';

import type { AuditSubjectKey } from '../domain/event.ts';
import { HAS_STATE_SEAL } from './audit-trail.ts';
import type { AuditTables } from './tables.ts';

/** A row read through its signed state: its object, and the event its state was believed by (VerifiedState.eventId). */
export interface SignedRowRead {
  readonly subject: AuditSubjectKey;
  readonly eventId: string;
}

/** The statement's one row: the moment, and whether a row moved before it (or was believed by an event not there). */
interface MomentRow {
  readonly up_to: string;
  readonly moved: boolean;
}

/**
 * The seq the rows hold at together, from `fromSeq` at least (`moment`); or
 * `moved`, when one of them has a newer signed event at or before that seq.
 * At least one row is asked about. A row believed by an event the log doesn't
 * hold (only a bug could) is never a moment: it reads as `moved`, so the
 * caller reads again and gives up rather than answer from it.
 */
export async function signedMoment(
  tx: Transaction<AuditTables>,
  orgId: string,
  rows: readonly SignedRowRead[],
  fromSeq: bigint,
): Promise<{ readonly outcome: 'moment'; readonly upToSeq: bigint } | { readonly outcome: 'moved' }> {
  const read = rows.map(({ subject, eventId }) => sql`(${subject.type}, ${subject.id}::uuid, ${eventId}::uuid)`);
  const { rows: found } = await sql<MomentRow>`
    with r (subject_type, subject_id, event_id) as (values ${sql.join(read)}),
    s as (
      select r.subject_type, r.subject_id, e.seq
      from r left join audit.events e on e.org_id = ${orgId} and e.id = r.event_id
    ),
    m as (
      select greatest(${fromSeq}::bigint, pg_catalog.max(s.seq)) as up_to,
             pg_catalog.bool_or(s.seq is null) as unknown
      from s
    )
    select m.up_to::text as up_to, m.unknown or exists (
      select 1 from s join audit.events e
        on e.org_id = ${orgId} and e.subject_type = s.subject_type and e.subject_id = s.subject_id
      where e.seq > s.seq and e.seq <= m.up_to and pg_catalog.strpos(e.details, ${HAS_STATE_SEAL}) > 0
    ) as moved
    from m
  `.execute(tx);
  // An aggregate over the rows asked: always one row.
  const [moment] = found as [MomentRow];
  return moment.moved ? { outcome: 'moved' } : { outcome: 'moment', upToSeq: BigInt(moment.up_to) };
}

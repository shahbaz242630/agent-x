// Reading one person's own activity log (Phase 6 6E1a, CO8, PL-48; decision
// 26's L8): the requests they made naming no organisation they are verified in
// (`access.person_requests`, 0052), for their own page and download and our
// export for a case. Every read here names the one person whose rows it reads:
// there is no read of the table that doesn't (the table is global, so nothing
// else would wall one person's rows from another's). Their rows in an
// organisation's log stay that organisation's admins' record (D1).
//
// As an organisation's (activity-reads.ts): a page is the rows recorded in
// [from, to), newest first by (time, ID), on 0052's `person_requests_by_person`
// index; `next` names where the next page starts before. A range is counted,
// and its last-written row's ID named, in one statement, so a download reads
// only the rows written by then.
import { sql, type Transaction } from 'kysely';

import { type ClientClues, TIME_ZONE_SOURCES } from './activity-log.ts';
import { type ActivityCursor, oneOf } from './activity-reads.ts';
import type { ActivityTables } from './tables.ts';

/** A range of one person's log: [from, to). */
export interface PersonRange {
  readonly from: Date;
  readonly to: Date;
}

/** A page of one person's log to read: a range, where it starts before (newest when not named), and how many at most. */
export interface PersonPageToRead extends PersonRange {
  readonly before?: ActivityCursor | undefined;
  /** A download's rows alone: those written by the time it was counted (personInRange). */
  readonly writtenUpTo?: string | undefined;
  readonly limit: number;
}

/** One row of a person's own log. */
export interface PersonActivityRow {
  readonly id: string;
  readonly recordedAt: Date;
  /** The organisation the request's header named, where the person wasn't verified in it: their own claim, kept as one. */
  readonly claimedOrg: string | null;
  readonly method: string;
  readonly route: string;
  readonly pathIds: readonly string[];
  readonly status: number;
  readonly reason: string | null;
  readonly correlationId: string;
  readonly durationMs: number;
  readonly client: ClientClues;
}

type PersonTx = Transaction<ActivityTables>;

/** The person's rows in the range: theirs alone. */
const rowsOf = (tx: PersonTx, userId: string, { from, to }: PersonRange) =>
  tx
    .selectFrom('access.person_requests')
    .where('user_id', '=', userId)
    .where('recorded_at', '>=', from)
    .where('recorded_at', '<', to);

/** A page of the person's own log, newest first, and where the next starts before (null at the end). */
export async function personPage(
  tx: PersonTx,
  userId: string,
  asked: PersonPageToRead,
): Promise<{ readonly rows: readonly PersonActivityRow[]; readonly next: ActivityCursor | null }> {
  let query = rowsOf(tx, userId, asked).selectAll();
  const { before, writtenUpTo } = asked;
  if (before !== undefined) query = query.where(sql<boolean>`(recorded_at, id) < (${before.at}, ${before.id}::uuid)`);
  if (writtenUpTo !== undefined) query = query.where(sql<boolean>`id <= ${writtenUpTo}::uuid`);
  // One more than the page, to know whether another follows.
  const found = await query
    .orderBy('recorded_at', 'desc')
    .orderBy('id', 'desc')
    .limit(asked.limit + 1)
    .execute();
  const rows = found.slice(0, asked.limit).map((row): PersonActivityRow => ({
    id: row.id,
    recordedAt: row.recorded_at,
    claimedOrg: row.claimed_org,
    method: row.method,
    route: row.route,
    pathIds: row.path_ids,
    status: row.status,
    reason: row.reason,
    correlationId: row.correlation_id,
    durationMs: row.duration_ms,
    client: {
      ip: row.ip ?? undefined,
      place: row.country === null ? undefined : { country: row.country, city: row.city ?? undefined },
      timeZone:
        row.time_zone === null || row.time_zone_from === null
          ? undefined
          : { name: row.time_zone, from: oneOf(TIME_ZONE_SOURCES, row.time_zone_from, 'a time zone source') },
    },
  }));
  const last = rows.at(-1);
  return {
    rows,
    next: found.length > asked.limit && last !== undefined ? { at: last.recordedAt, id: last.id } : null,
  };
}

/** How many of the person's rows a range holds, and the ID of the last written (null for none), in one statement. */
export async function personInRange(
  tx: PersonTx,
  userId: string,
  range: PersonRange,
): Promise<{ readonly rows: number; readonly writtenUpTo: string | null }> {
  // The last written as activity-reads.ts's activityInRange reads it.
  const counted = await rowsOf(tx, userId, range)
    .select([
      sql<number>`pg_catalog.count(*)::int`.as('rows'),
      sql<string | null>`pg_catalog.max(id::text)`.as('written_up_to'),
    ])
    .executeTakeFirstOrThrow();
  return { rows: counted.rows, writtenUpTo: counted.written_up_to };
}

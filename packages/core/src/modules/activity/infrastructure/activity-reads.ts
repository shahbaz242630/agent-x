// Reading an organisation's activity log (Phase 3 L5, decision 26: admins
// only), for its page, its download and the operator's export for a case
// (L7). Inside the organisation's transaction, so its row-level security
// holds the read too.
//
// - A page is the rows recorded in [from, to), by one person or agent when
//   one is named, newest first by (time, ID), on 0052's two indexes; `next`
//   names the last row's time and ID, where the next page starts before.
// - A range is counted, and its newest row named, in two statements: a
//   download is refused past its cap before it is recorded, then reads up to
//   that row (`upTo`), however many are written while it is read.
import { sql, type Transaction } from 'kysely';

import type { ClientClues } from './activity-log.ts';
import type { ActivityTables } from './tables.ts';

/** Who a row is by: a verified member or agent of the organisation. */
export interface ActivityActor {
  readonly type: 'user' | 'agent';
  readonly id: string;
}

/** A row's place in the log, newest first: its time, then its ID. */
export interface ActivityCursor {
  readonly at: Date;
  readonly id: string;
}

/** A range of the log: [from, to), one actor's rows only when one is named. */
export interface ActivityRange {
  readonly from: Date;
  readonly to: Date;
  readonly actor?: ActivityActor | undefined;
}

/** A page of the log to read: a range, where it starts before or at (newest when neither), and how many at most. */
export interface ActivityPageToRead extends ActivityRange {
  readonly before?: ActivityCursor | undefined;
  /** A download's first batch: from this row on, itself included. */
  readonly upTo?: ActivityCursor | undefined;
  readonly limit: number;
}

/** One row of the log, as an organisation is shown it. */
export interface ActivityRow {
  readonly id: string;
  readonly recordedAt: Date;
  readonly actor: ActivityActor;
  readonly method: string;
  readonly route: string;
  readonly pathIds: readonly string[];
  readonly status: number;
  readonly reason: string | null;
  readonly correlationId: string;
  readonly durationMs: number;
  readonly client: ClientClues;
}

type ActivityTx = Transaction<ActivityTables>;

const actorType = (type: string): ActivityActor['type'] => {
  if (type === 'user' || type === 'agent') return type;
  throw new RangeError(`an activity log row is by an actor of no known type: ${type}`);
};

const timeZoneFrom = (from: string): 'browser' | 'organisation' => {
  if (from === 'browser' || from === 'organisation') return from;
  throw new RangeError(`an activity log row's time zone came from nowhere known: ${from}`);
};

/** The rows of `orgId` in its range: its own, by its actor when one is named. */
const rowsIn = (tx: ActivityTx, orgId: string, { from, to, actor }: ActivityRange) => {
  let query = tx
    .selectFrom('access.requests')
    .where('org_id', '=', orgId)
    .where('recorded_at', '>=', from)
    .where('recorded_at', '<', to);
  if (actor !== undefined) query = query.where('actor_type', '=', actor.type).where('actor_id', '=', actor.id);
  return query;
};

/** A page of the log, newest first, and where the next starts before (null at the end). */
export async function activityPage(
  tx: ActivityTx,
  orgId: string,
  asked: ActivityPageToRead,
): Promise<{ readonly rows: readonly ActivityRow[]; readonly next: ActivityCursor | null }> {
  let query = rowsIn(tx, orgId, asked).selectAll();
  const { before, upTo } = asked;
  if (before !== undefined) query = query.where(sql<boolean>`(recorded_at, id) < (${before.at}, ${before.id}::uuid)`);
  if (upTo !== undefined) query = query.where(sql<boolean>`(recorded_at, id) <= (${upTo.at}, ${upTo.id}::uuid)`);
  // One more than the page, to know whether another follows.
  const found = await query
    .orderBy('recorded_at', 'desc')
    .orderBy('id', 'desc')
    .limit(asked.limit + 1)
    .execute();
  const rows = found.slice(0, asked.limit).map((row): ActivityRow => ({
    id: row.id,
    recordedAt: row.recorded_at,
    actor: { type: actorType(row.actor_type), id: row.actor_id },
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
          : { name: row.time_zone, from: timeZoneFrom(row.time_zone_from) },
    },
  }));
  const last = rows.at(-1);
  return {
    rows,
    next: found.length > asked.limit && last !== undefined ? { at: last.recordedAt, id: last.id } : null,
  };
}

/** How many rows a range holds, and its newest (null for none). */
export async function activityInRange(
  tx: ActivityTx,
  orgId: string,
  range: ActivityRange,
): Promise<{ readonly rows: number; readonly newest: ActivityCursor | null }> {
  const counted = await rowsIn(tx, orgId, range)
    .select(sql<number>`pg_catalog.count(*)::int`.as('rows'))
    .executeTakeFirstOrThrow();
  if (counted.rows === 0) return { rows: 0, newest: null };
  const newest = await rowsIn(tx, orgId, range)
    .select(['recorded_at', 'id'])
    .orderBy('recorded_at', 'desc')
    .orderBy('id', 'desc')
    .limit(1)
    .executeTakeFirstOrThrow();
  return { rows: counted.rows, newest: { at: newest.recorded_at, id: newest.id } };
}

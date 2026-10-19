// Reading an organisation's activity log (Phase 3 L5, decision 26: admins
// only), for its page, its download and the operator's export for a case
// (L7). Inside the organisation's transaction, so its row-level security
// holds the read too.
//
// - A page is the rows recorded in [from, to), by one person or agent when
//   one is named, newest first by (time, ID), on 0052's two indexes; `next`
//   names the last row's time and ID, where the next page starts before.
// - A range is counted, and its last-written row's ID named, in one
//   statement: a download is refused past its cap before it is recorded,
//   then reads only the rows written by then (`writtenUpTo`). A row's time is
//   when its request arrived but its ID is made as it is written (UUIDv7),
//   so a slow request answered during the download stays out of it (but for
//   one written in the very moment of the count, or under a server's clock
//   a little behind another's).
import { sql, type Transaction } from 'kysely';

import { type ClientClues, TIME_ZONE_SOURCES } from './activity-log.ts';
import type { ActivityTables } from './tables.ts';

/** Who the log's rows can be by: a verified member or agent of the organisation. */
export const ACTIVITY_ACTOR_TYPES = ['user', 'agent'] as const;

/** Who a row is by. */
export interface ActivityActor {
  readonly type: (typeof ACTIVITY_ACTOR_TYPES)[number];
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

/** A page of the log to read: a range, where it starts before (newest when not named), and how many at most. */
export interface ActivityPageToRead extends ActivityRange {
  readonly before?: ActivityCursor | undefined;
  /** A download's rows alone: those written by the time it was counted (activityInRange). */
  readonly writtenUpTo?: string | undefined;
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

/** `value` as one of `known`, or RangeError: 0052 checks each, so another is a bug. */
const oneOf = <Known extends string>(known: readonly Known[], value: string, what: string): Known => {
  const found = known.find((each) => each === value);
  if (found === undefined) throw new RangeError(`an activity log row has ${what} it doesn't know: ${value}`);
  return found;
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
  const { before, writtenUpTo } = asked;
  if (before !== undefined) query = query.where(sql<boolean>`(recorded_at, id) < (${before.at}, ${before.id}::uuid)`);
  if (writtenUpTo !== undefined) query = query.where(sql<boolean>`id <= ${writtenUpTo}::uuid`);
  // One more than the page, to know whether another follows.
  const found = await query
    .orderBy('recorded_at', 'desc')
    .orderBy('id', 'desc')
    .limit(asked.limit + 1)
    .execute();
  const rows = found.slice(0, asked.limit).map((row): ActivityRow => ({
    id: row.id,
    recordedAt: row.recorded_at,
    actor: { type: oneOf(ACTIVITY_ACTOR_TYPES, row.actor_type, 'an actor type'), id: row.actor_id },
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

/** How many rows a range holds, and the ID of its last written (null for none), in one statement. */
export async function activityInRange(
  tx: ActivityTx,
  orgId: string,
  range: ActivityRange,
): Promise<{ readonly rows: number; readonly writtenUpTo: string | null }> {
  // A UUID's text in lower case sorts as the UUID does; Postgres has no max() of uuid itself.
  const counted = await rowsIn(tx, orgId, range)
    .select([
      sql<number>`pg_catalog.count(*)::int`.as('rows'),
      sql<string | null>`pg_catalog.max(id::text)`.as('written_up_to'),
    ])
    .executeTakeFirstOrThrow();
  return { rows: counted.rows, writtenUpTo: counted.written_up_to };
}

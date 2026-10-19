// The activity log's daily seal (Phase 3 L6; partner decision 26; ADR-011
// §7): each UTC day of an organisation's activity log digested and the
// digest sealed into one `access_log.sealed` event on its audit chain, so a
// row changed, deleted or slipped in after the day closed shows.
//
// - A day is the rows *written* in it: their IDs are UUIDv7s, made as each
//   row is written, so day D holds every ID in [floor(D), floor(D+1)), the
//   floor being a UUIDv7 of that instant with every bit after its time zero.
//   A slow request answered after midnight is in the day it was written, and
//   every row lands in one day alone. A day is sealed only once it has been
//   closed a while (SEAL_GRACE_MS), far past any statement's limit.
// - The digest: SHA-256 over one line a row, by ID, each the JSON array of
//   its ID, its time to the microsecond in UTC (as text, so a tampered
//   microsecond shows), its actor, method, route, path IDs, status, reason,
//   correlation ID and duration, then a newline. The organisation is the
//   chain's own. The client's IP address, place and time zone are outside
//   it (ADR-011 §7): clues a lawful erasure may blank, the seal standing.
//   A day with no rows digests the empty text: a quiet day is sealed too, so
//   a day emptied after shows.
// - Read in batches, each in the organisation's transaction (its row-level
//   security holds the read); recorded in one more, after counting the day
//   again with its last ID: a day that moved meanwhile is left for the next
//   run.
import { createHash } from 'node:crypto';

import { sql, type Transaction } from 'kysely';

import type { ActivityTables } from './tables.ts';

type SealTx = Transaction<ActivityTables>;

/** The action an organisation's daily seal records on its own chain. */
export const ACTIVITY_SEALED = 'access_log.sealed';

/** How long after a day ends it is sealed: far past any statement's limit and any server's clock drift. */
export const SEAL_GRACE_MS = 15 * 60_000;

const DAY_MS = 86_400_000;

/** The form of the seal's lines, recorded with each seal so a later form can't be confused with this one. */
export const SEAL_FORM = 1;

/** A day, YYYY-MM-DD, UTC. */
const DAY = /^\d{4}-\d{2}-\d{2}$/;

function startOf(day: string): number {
  if (!DAY.test(day)) throw new RangeError('A day is named YYYY-MM-DD');
  return Date.parse(`${day}T00:00:00.000Z`);
}

/** The day after `day`. */
export const nextDay = (day: string): string => new Date(startOf(day) + DAY_MS).toISOString().slice(0, 10);

/** The lowest UUIDv7 of the instant `ms`: its time, every bit after it zero. */
export function v7Floor(ms: number): string {
  const hex = ms.toString(16).padStart(12, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-0000-0000-000000000000`;
}

/** The UTC day a UUIDv7 was made in. */
export const dayOfId = (id: string): string =>
  new Date(Number.parseInt(id.replaceAll('-', '').slice(0, 12), 16)).toISOString().slice(0, 10);

/** The IDs a day holds: [from, to). */
export const idsOfDay = (day: string): { readonly from: string; readonly to: string } => ({
  from: v7Floor(startOf(day)),
  to: v7Floor(startOf(day) + DAY_MS),
});

/** Whether `day` has been closed long enough, at `now`, to be sealed. */
export const sealable = (day: string, now: Date): boolean => now.getTime() >= startOf(day) + DAY_MS + SEAL_GRACE_MS;

/** A day's digest, its count and its first and last IDs (null when it holds none). */
export interface DayDigest {
  readonly day: string;
  readonly requests: number;
  readonly digest: string;
  readonly idFrom: string | null;
  readonly idTo: string | null;
}

/** The sealed columns of a batch of the day's rows, by ID, after `after` when named. */
const sealedRows = (tx: SealTx, orgId: string, day: string, after: string | undefined, limit: number) => {
  const { from, to } = idsOfDay(day);
  return tx
    .selectFrom('access.requests')
    .select([
      'id',
      sql<string>`pg_catalog.to_char(recorded_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`.as('at'),
      'actor_type',
      'actor_id',
      'method',
      'route',
      'path_ids',
      'status',
      'reason',
      'correlation_id',
      'duration_ms',
    ])
    .where('org_id', '=', orgId)
    .where(sql<boolean>`id >= ${from}::uuid and id < ${to}::uuid`)
    .$if(after !== undefined, (query) => query.where(sql<boolean>`id > ${after}::uuid`))
    .orderBy('id')
    .limit(limit)
    .execute();
};

type SealedRow = Awaited<ReturnType<typeof sealedRows>>[number];

/** One row's line in the digest. */
const lineOf = (row: SealedRow): string =>
  `${JSON.stringify([
    row.id,
    row.at,
    row.actor_type,
    row.actor_id,
    row.method,
    row.route,
    row.path_ids,
    row.status,
    row.reason,
    row.correlation_id,
    row.duration_ms,
  ])}\n`;

/**
 * The day's digest, read `batch` rows at a time, each batch in a transaction
 * `inOrg` opens for the organisation.
 */
export async function digestOfDay(
  inOrg: <T>(work: (tx: SealTx) => Promise<T>) => Promise<T>,
  orgId: string,
  day: string,
  batch: number,
): Promise<DayDigest> {
  const hash = createHash('sha256');
  let requests = 0;
  let idFrom: string | null = null;
  let idTo: string | null = null;
  for (;;) {
    const after: string | undefined = idTo ?? undefined;
    const rows: SealedRow[] = await inOrg((tx) => sealedRows(tx, orgId, day, after, batch));
    for (const row of rows) hash.update(lineOf(row));
    requests += rows.length;
    idFrom ??= rows[0]?.id ?? null;
    idTo = rows.at(-1)?.id ?? idTo;
    if (rows.length < batch) break;
  }
  return { day, requests, digest: hash.digest('hex'), idFrom, idTo };
}

/** The day's count and last ID, read in one statement, to check a digest still stands before it is sealed. */
export async function dayCount(
  tx: SealTx,
  orgId: string,
  day: string,
): Promise<{ readonly requests: number; readonly idTo: string | null }> {
  const { from, to } = idsOfDay(day);
  const counted = await tx
    .selectFrom('access.requests')
    .select([
      sql<number>`pg_catalog.count(*)::int`.as('requests'),
      // A UUID's text in lower case sorts as the UUID does; Postgres has no max() of uuid itself.
      sql<string | null>`pg_catalog.max(id::text)`.as('id_to'),
    ])
    .where('org_id', '=', orgId)
    .where(sql<boolean>`id >= ${from}::uuid and id < ${to}::uuid`)
    .executeTakeFirstOrThrow();
  return { requests: counted.requests, idTo: counted.id_to };
}

/** The day the organisation's first row was written, or undefined for an organisation with none. */
export async function firstDayOf(tx: SealTx, orgId: string): Promise<string | undefined> {
  const first = await tx
    .selectFrom('access.requests')
    .select('id')
    .where('org_id', '=', orgId)
    .orderBy('id')
    .limit(1)
    .executeTakeFirst();
  return first === undefined ? undefined : dayOfId(first.id);
}

/**
 * Whether a seal's details hold the day's digest as it is read now: its day,
 * count, digest, first and last IDs and form. Anything else, a row changed,
 * deleted or slipped in since, or a seal rewritten, is a mismatch.
 */
export function sealHolds(digest: DayDigest, details: Readonly<Record<string, unknown>>): boolean {
  return (
    details.day === digest.day &&
    details.requests === digest.requests &&
    details.digest === digest.digest &&
    details.idFrom === digest.idFrom &&
    details.idTo === digest.idTo &&
    details.form === SEAL_FORM
  );
}

/** Whether any row of the organisation's was written before `day`: one no seal from that day on holds. */
export async function writtenBefore(tx: SealTx, orgId: string, day: string): Promise<boolean> {
  const found = await tx
    .selectFrom('access.requests')
    .select('id')
    .where('org_id', '=', orgId)
    .where(sql<boolean>`id < ${idsOfDay(day).from}::uuid`)
    .limit(1)
    .executeTakeFirst();
  return found !== undefined;
}

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
//   correlation ID and duration, then, on a row that names one, its agent's
//   key (0070), then a newline. A row with none reads as it always did, so
//   every seal made before 0070 still holds, on the same form. The organisation
//   is the chain's own. The client's IP address, place and time zone are outside
//   it (ADR-011 §7): clues a lawful erasure may blank, the seal standing.
//   A day with no rows digests the empty text: a quiet day is sealed too, so
//   a day emptied after shows.
// - A row's ID is made as it is written, just after its request was
//   answered: its ID's time is its `recorded_at` plus its duration, from
//   moments before to hours after (ID_LATE_MS). One further off was written past the app (a fresh ID with
//   an old time, to pass as an old row once sealed): the digest names it
//   (`misdated`), and neither the seal nor its check believes the day (F1, G3).
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

/**
 * The form of the seal's lines, recorded with each seal so a later form can't be confused with this one.
 *
 * Still 1 after 0070: a row with no key reads as it always did, so every seal made before it holds. The price: a
 * day with keyed rows only reads right on code that knows the key. Code from before 0070 would seal such a day, or
 * check its seal, on the shorter line, and an organisation goes on a false hold. So never roll back past 0070 once
 * keyed rows exist, and never release across the seal's run at 00:15 UTC.
 */
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

/** A day's digest, its count, its first and last IDs (null when it holds none), and its first row misdated (null for none). */
export interface DayDigest {
  readonly day: string;
  readonly requests: number;
  readonly digest: string;
  readonly idFrom: string | null;
  readonly idTo: string | null;
  readonly misdated: string | null;
}

/** How long before its answer a row's ID may be made: two clocks on one server, read a moment apart. */
const ID_EARLY_MS = 5_000;

/**
 * How long after its answer. The row is written then, awaited, so only a
 * wait for a connection lies between; but an ID's clock never goes back
 * (uuid v7 keeps its highest time), so a server clock stepped back makes its
 * IDs late by the step until the clock catches up. Hours, then: a fresh ID
 * given an old time to pass as an old row is days off, and an honest clock
 * fault never holds an organisation (F1 G3's review).
 */
const ID_LATE_MS = 6 * 60 * 60_000;

/** The instant a UUIDv7 was made, in milliseconds. */
const msOfId = (id: string): number => Number.parseInt(id.replaceAll('-', '').slice(0, 12), 16);

/** A row's time as the digest reads it: to the microsecond, in UTC, as text, so a tampered microsecond shows. */
export const SEALED_AT = sql<string>`pg_catalog.to_char(recorded_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

/**
 * Which log a seal digests (6E1a): an organisation's rows of `access.requests`, or the person log,
 * `access.person_requests`, every person's rows together.
 */
export type SealedLog = { readonly orgId: string } | 'person';

/** The log's table and the condition that keeps a read to it: an organisation's own rows alone. */
const scopeOf = (log: SealedLog) =>
  log === 'person'
    ? { table: sql.table('access.person_requests'), own: sql<boolean>`true` }
    : { table: sql.table('access.requests'), own: sql<boolean>`org_id = ${log.orgId}::uuid` };

/** What the digest needs of a row: its ID, its time as SEALED_AT reads it, and its duration. */
export interface DigestedRow {
  readonly id: string;
  readonly at: string;
  readonly duration_ms: number;
}

/** Whether the row's ID was made where its time and duration say it was answered, give or take the bounds above. */
const dated = (row: DigestedRow): boolean => {
  const answered = Date.parse(row.at) + row.duration_ms;
  const made = msOfId(row.id);
  return made >= answered - ID_EARLY_MS && made <= answered + ID_LATE_MS;
};

/**
 * A day's digest over the rows `read` gives, `batch` at a time by ID after the last read (undefined first), each row's
 * line the JSON of what `line` makes of it and a newline: an organisation's log's and the person log's alike.
 */
export async function digestRows<Row extends DigestedRow>(
  day: string,
  batch: number,
  read: (after: string | undefined, limit: number) => Promise<readonly Row[]>,
  line: (row: Row) => readonly unknown[],
): Promise<DayDigest> {
  const hash = createHash('sha256');
  let requests = 0;
  let idFrom: string | null = null;
  let idTo: string | null = null;
  let misdated: string | null = null;
  for (;;) {
    const rows = await read(idTo ?? undefined, batch);
    for (const row of rows) {
      hash.update(`${JSON.stringify(line(row))}\n`);
      if (misdated === null && !dated(row)) misdated = row.id;
    }
    requests += rows.length;
    idFrom ??= rows[0]?.id ?? null;
    idTo = rows.at(-1)?.id ?? idTo;
    if (rows.length < batch) break;
  }
  return { day, requests, digest: hash.digest('hex'), idFrom, idTo, misdated };
}

/** The sealed columns of a batch of the day's rows, by ID, after `after` when named. */
const sealedRows = (tx: SealTx, orgId: string, day: string, after: string | undefined, limit: number) => {
  const { from, to } = idsOfDay(day);
  return tx
    .selectFrom('access.requests')
    .select([
      'id',
      SEALED_AT.as('at'),
      'actor_type',
      'actor_id',
      'method',
      'route',
      'path_ids',
      'status',
      'reason',
      'correlation_id',
      'duration_ms',
      'agent_key_id',
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
const lineOf = (row: SealedRow): readonly unknown[] => [
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
  ...(row.agent_key_id === null ? [] : [row.agent_key_id]),
];

/**
 * The day's digest, read `batch` rows at a time, each batch in a transaction
 * `inOrg` opens for the organisation.
 */
export function digestOfDay(
  inOrg: <T>(work: (tx: SealTx) => Promise<T>) => Promise<T>,
  orgId: string,
  day: string,
  batch: number,
): Promise<DayDigest> {
  return digestRows(day, batch, (after, limit) => inOrg((tx) => sealedRows(tx, orgId, day, after, limit)), lineOf);
}

/** The log's day's count and last ID, read in one statement, to check a digest still stands before it is sealed. */
export async function countOfDay(
  tx: SealTx,
  log: SealedLog,
  day: string,
): Promise<{ readonly requests: number; readonly idTo: string | null }> {
  const { from, to } = idsOfDay(day);
  const { table, own } = scopeOf(log);
  // A UUID's text in lower case sorts as the UUID does; Postgres has no max() of uuid itself.
  const { rows } = await sql<{ requests: number; id_to: string | null }>`
    select pg_catalog.count(*)::int as requests, pg_catalog.max(id::text) as id_to from ${table}
    where ${own} and id >= ${from}::uuid and id < ${to}::uuid
  `.execute(tx);
  return { requests: rows[0]?.requests ?? 0, idTo: rows[0]?.id_to ?? null };
}

/** The organisation's day's count and last ID (countOfDay). */
export const dayCount = (tx: SealTx, orgId: string, day: string) => countOfDay(tx, { orgId }, day);

/** The day the log's first row was written, or undefined for a log with none. */
export async function firstDayIn(tx: SealTx, log: SealedLog): Promise<string | undefined> {
  const { table, own } = scopeOf(log);
  const { rows } = await sql<{ id: string }>`select id from ${table} where ${own} order by id limit 1`.execute(tx);
  const first = rows[0];
  return first === undefined ? undefined : dayOfId(first.id);
}

/** The day the organisation's first row was written, or undefined for an organisation with none. */
export const firstDayOf = (tx: SealTx, orgId: string) => firstDayIn(tx, { orgId });

/**
 * Whether a seal's details hold the day's digest as it is read now: its day,
 * count, digest, first and last IDs and form (an organisation's unless named;
 * a person's log has its own, person-seal.ts). Anything else, a row changed,
 * deleted or slipped in since, or a seal rewritten, is a mismatch.
 */
export function sealHolds(
  digest: DayDigest,
  details: Readonly<Record<string, unknown>>,
  form: number = SEAL_FORM,
): boolean {
  return (
    details.day === digest.day &&
    details.requests === digest.requests &&
    details.digest === digest.digest &&
    details.idFrom === digest.idFrom &&
    details.idTo === digest.idTo &&
    details.form === form
  );
}

/** Whether any row of the log was written before `day`: one no seal from that day on holds. */
export async function writtenBeforeIn(tx: SealTx, log: SealedLog, day: string): Promise<boolean> {
  const { table, own } = scopeOf(log);
  const { rows } = await sql`
    select id from ${table} where ${own} and id < ${idsOfDay(day).from}::uuid limit 1
  `.execute(tx);
  return rows.length > 0;
}

/** Whether any row of the organisation's was written before `day`. */
export const writtenBefore = (tx: SealTx, orgId: string, day: string) => writtenBeforeIn(tx, { orgId }, day);

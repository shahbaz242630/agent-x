// The person log's daily seal (Phase 6 6E1a, CO8, PL-48; decision 26's L8):
// each UTC day of `access.person_requests`, every person's rows together,
// digested and the digest sealed into one `access_log.person_sealed` event on
// the platform chain, so a row changed, deleted or slipped in after the day
// closed shows. The rows belong to no organisation, so no organisation's chain
// can hold their seal (3L5c-L7's L6b note).
//
// The organisation's seal's rules and code (activity-seal.ts: digestRows,
// countOfDay, firstDayIn, writtenBeforeIn): a day is the rows *written* in it,
// by their UUIDv7 IDs; sealed only past its grace; read in batches by ID; a
// quiet day sealed too, from the first row's day on; a row whose ID is far
// from its own time (`misdated`) never sealed. Only the line is its own: the
// JSON array of its ID, its time to the microsecond in UTC, its person, the
// organisation its header claimed (null for none), method, route, path IDs,
// status, reason, correlation ID and duration. The client's IP address, place
// and time zone are outside it (ADR-011 §7), so a lawful erasure may blank
// them, the seal standing.
//
// The table is global (0052): no tenant holds the read, and none is needed.
import { sql, type Transaction } from 'kysely';

import { type DayDigest, digestRows, idsOfDay, SEALED_AT } from './activity-seal.ts';
import type { ActivityTables } from './tables.ts';

type SealTx = Transaction<ActivityTables>;

/** The action the person log's daily seal records on the platform chain. */
export const PERSON_SEALED = 'access_log.person_sealed';

/** The form of the person seal's lines, recorded with each seal so a later form can't be confused with this one. */
export const PERSON_SEAL_FORM = 1;

/** The sealed columns of a batch of the day's rows, by ID, after `after` when named. */
const sealedRows = (tx: SealTx, day: string, after: string | undefined, limit: number) => {
  const { from, to } = idsOfDay(day);
  return tx
    .selectFrom('access.person_requests')
    .select([
      'id',
      SEALED_AT.as('at'),
      'user_id',
      'claimed_org',
      'method',
      'route',
      'path_ids',
      'status',
      'reason',
      'correlation_id',
      'duration_ms',
    ])
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
  row.user_id,
  row.claimed_org,
  row.method,
  row.route,
  row.path_ids,
  row.status,
  row.reason,
  row.correlation_id,
  row.duration_ms,
];

/** The person log's digest of `day`, read `batch` rows at a time, each batch in a transaction `read` opens. */
export const personDigestOfDay = (
  read: <T>(work: (tx: SealTx) => Promise<T>) => Promise<T>,
  day: string,
  batch: number,
): Promise<DayDigest> =>
  digestRows(day, batch, (after, limit) => read((tx) => sealedRows(tx, day, after, limit)), lineOf);

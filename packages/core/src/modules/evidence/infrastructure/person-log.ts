// One person's own activity log as they and we are shown it (Phase 6 6E1a,
// CO8, PL-48; decision 26's L8), for the API's page and download and the
// operator's export for a case:
//
// - Each row as an organisation's is shown (activity-shown.ts), but with no
//   actor (it is the person's own) and the organisation its header claimed, if
//   any: their own claim, never shown to that organisation.
// - Whether its day is sealed: written on or before the newest day the person
//   log's seal names on the platform chain (`access_log.person_sealed`).
// - The platform chain's events about the person log, each believed only once
//   its content, MAC and (for an operator's event) signature check
//   (platformEventSealed): a seal or an export record planted or edited past
//   the app reads `unsealed`, and the caller raises the alarm.
import { type Kysely, sql, type Transaction } from 'kysely';

import type { KeyProvider } from '@agentx/platform/keys';

import { PERSON_SEALED, type PersonActivityRow } from '../../activity/index.ts';
import {
  type PlatformControlsTables,
  platformEventSealed,
  platformEventsSigned,
} from '../../platform-controls/index.ts';
import { clientShown, localTimeOf, sealedRow } from './activity-shown.ts';

/** A person's own download of their log, recorded on the platform chain before a row is read (`person` the person). */
export const PERSON_LOG_EXPORTED = 'access_log.person_exported';

/** Our export of a person's log for a case (the operator's command), on the platform chain: what the person is told of. */
export const OPERATOR_PERSON_LOG_EXPORTED = 'operator.person_log_exported';

type PlatformTx = Transaction<PlatformControlsTables>;
type PlatformReader = PlatformTx | Kysely<PlatformControlsTables>;

/** A row as its person is shown it, page or download, sealed or not by `sealedDay`. */
export const personActivityShown = (row: PersonActivityRow, sealedDay: string | null) => {
  const { timeZone } = row.client;
  return {
    id: row.id,
    recordedAt: row.recordedAt.toISOString(),
    localTime: timeZone === undefined ? null : localTimeOf(row.recordedAt, timeZone.name),
    claimedOrganizationId: row.claimedOrg,
    method: row.method,
    route: row.route,
    pathIds: [...row.pathIds],
    status: row.status,
    reason: row.reason,
    correlationId: row.correlationId,
    durationMs: row.durationMs,
    sealed: sealedRow(row.id, sealedDay),
    client: clientShown(row.client),
  };
};

/** A row as an NDJSON download holds it: one line. */
export const personNdjsonLine = (row: PersonActivityRow, sealedDay: string | null): string =>
  JSON.stringify(personActivityShown(row, sealedDay));

/** A platform event about the person log, believed: its place, when, and its details. */
export interface PersonLogEvent {
  readonly seq: bigint;
  readonly id: string;
  readonly action: string;
  /** Who recorded it, as the chain sealed it: `system:operator` for our exports. */
  readonly actor: { readonly type: string; readonly id: string };
  readonly recordedAt: Date;
  readonly details: Readonly<Record<string, unknown>>;
}

type SignedRow = Awaited<ReturnType<ReturnType<typeof platformEventsSigned>['execute']>>[number];

/** The rows as events, every one believed; `unsealed` if any isn't. */
const believed = (keys: KeyProvider, rows: readonly SignedRow[]): readonly PersonLogEvent[] | 'unsealed' => {
  if (!rows.every((row) => platformEventSealed(keys, row))) return 'unsealed';
  return rows.map((row) => ({
    seq: row.seq,
    id: row.id,
    action: row.action,
    actor: { type: row.actor_type, id: row.actor_id },
    recordedAt: row.recorded_at,
    // Read only once believed: the chain sealed them as an event's details, canonical JSON of an object.
    details: JSON.parse(row.details) as Readonly<Record<string, unknown>>,
  }));
};

/** The person log's newest seal's day (null for none yet), or `unsealed` for a newest seal that can't be believed. */
export async function newestPersonSeal(
  tx: PlatformTx,
  keys: KeyProvider,
): Promise<{ readonly day: string | null } | 'unsealed'> {
  const rows = await platformEventsSigned(tx)
    .where('e.action', '=', PERSON_SEALED)
    .orderBy('e.seq', 'desc')
    .limit(1)
    .execute();
  const events = believed(keys, rows);
  if (events === 'unsealed') return events;
  const day = events[0]?.details.day;
  return { day: typeof day === 'string' ? day : null };
}

/**
 * A page of the person log's seals (or another daily seal's, by its `action`), newest first, before `beforeSeq` when
 * named; `next` the seq the next page starts before.
 */
export async function personSealsPage(
  tx: PlatformTx,
  keys: KeyProvider,
  {
    beforeSeq,
    limit,
    action = PERSON_SEALED,
  }: { readonly beforeSeq?: bigint | undefined; readonly limit: number; readonly action?: string },
): Promise<{ readonly events: readonly PersonLogEvent[]; readonly next: bigint | null } | 'unsealed'> {
  let query = platformEventsSigned(tx).where('e.action', '=', action);
  if (beforeSeq !== undefined) query = query.where('e.seq', '<', beforeSeq);
  // One more than the page, to know whether another follows.
  const rows = await query
    .orderBy('e.seq', 'desc')
    .limit(limit + 1)
    .execute();
  const events = believed(keys, rows.slice(0, limit));
  if (events === 'unsealed') return events;
  const last = events.at(-1);
  return { events, next: rows.length > limit && last !== undefined ? last.seq : null };
}

/** The fact 0084 indexes the platform chain's events by, written exactly as its index keys it. */
const PERSON_FACT = sql<string | null>`(details::jsonb ->> 'person')`;

/**
 * Our exports of the person's log (OPERATOR_PERSON_LOG_EXPORTED), newest first, `most` at most, on 0084's index by
 * person; `unsealed` if any can't be believed.
 */
export async function operatorExportsOf(
  tx: PlatformTx,
  keys: KeyProvider,
  userId: string,
  most: number,
): Promise<readonly PersonLogEvent[] | 'unsealed'> {
  const rows = await platformEventsSigned(tx)
    .where('e.action', '=', OPERATOR_PERSON_LOG_EXPORTED)
    .where(sql<boolean>`(e.details::jsonb ->> 'person') = ${userId}`)
    .orderBy('e.seq', 'desc')
    .limit(most)
    .execute();
  return believed(keys, rows);
}

/** How many of its own downloads the person has made since `since`, counted from their records on the platform chain. */
export async function personExportsSince(db: PlatformReader, userId: string, since: Date): Promise<number> {
  const counted = await db
    .selectFrom('platform_controls.audit_events')
    .select(sql<number>`pg_catalog.count(*)::int`.as('made'))
    .where('action', '=', PERSON_LOG_EXPORTED)
    .where(sql<boolean>`${PERSON_FACT} = ${userId}`)
    .where('recorded_at', '>=', since)
    .executeTakeFirstOrThrow();
  return counted.made;
}

/** One platform event by its ID, believed; undefined for none, `unsealed` for one that can't be believed. */
export async function personLogEventOf(
  tx: PlatformTx,
  keys: KeyProvider,
  eventId: string,
): Promise<PersonLogEvent | undefined | 'unsealed'> {
  const rows = await platformEventsSigned(tx).where('e.id', '=', eventId).limit(1).execute();
  const events = believed(keys, rows);
  return events === 'unsealed' ? events : events[0];
}

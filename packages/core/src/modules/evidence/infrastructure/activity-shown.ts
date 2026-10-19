// The activity log as an organisation is shown it (Phase 3 L5, decision 26),
// in one place for the API's page and download and the operator's export for
// a case (L7):
//
// - Each row's actor named beside their ID, as the audit log's (actor-names.ts).
// - Its time exact in UTC, and as the clock read where the row's time zone
//   says (the browser's own report, or the organisation's).
// - Its client's clues labelled as clues: the IP address, and the place it
//   is registered to marked approximate, with the credit DB-IP's licence asks
//   for (CC BY 4.0) wherever a place is shown.
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

import { activityPage, type ActivityPageToRead, type ActivityRow, type ActivityTables } from '../../activity/index.ts';
import type { SignedStates } from '../../audit/index.ts';

import { type ActorName, type ActorsHeld, actorsHeld, nameOf } from './actor-names.ts';
import type { LogReadTables } from './log-shown.ts';

/** The credit DB-IP City Lite's licence asks for wherever a place from it is shown (CC BY 4.0). */
export const PLACES_BY = { by: 'IP Geolocation by DB-IP', link: 'https://db-ip.com' } as const;

/** The tables a batch of the activity log reads: its rows, and what names their actors. */
export type ActivityReadTables = ActivityTables & LogReadTables;

/**
 * `at` as the clock read in `timeZone`, with its offset: `2026-10-19T17:39:12.123+04:00`;
 * null for a zone this runtime doesn't know (0052 checks only a zone's form).
 */
export function localTimeOf(at: Date, timeZone: string): string | null {
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = new Intl.DateTimeFormat('en-GB', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
      timeZoneName: 'longOffset',
    }).formatToParts(at);
  } catch {
    // Intl refuses only a zone it doesn't know: the row is shown without its local time, never another zone's.
    return null;
  }
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((each) => each.type === type)?.value ?? '';
  // `GMT+04:00`, or `GMT` alone for no offset.
  const offset = part('timeZoneName').slice('GMT'.length) || '+00:00';
  const ms = String(at.getUTCMilliseconds()).padStart(3, '0');
  return `${part('year')}-${part('month')}-${part('day')}T${part('hour')}:${part('minute')}:${part('second')}.${ms}${offset}`;
}

/** A row as an organisation is shown it, page or download, its actor named. */
export const activityShown = (row: ActivityRow, names: ReadonlyMap<string, ActorName>) => {
  const { ip, place, timeZone } = row.client;
  return {
    id: row.id,
    recordedAt: row.recordedAt.toISOString(),
    localTime: timeZone === undefined ? null : localTimeOf(row.recordedAt, timeZone.name),
    actor: { ...row.actor, ...nameOf(names, row.actor) },
    method: row.method,
    route: row.route,
    pathIds: [...row.pathIds],
    status: row.status,
    reason: row.reason,
    correlationId: row.correlationId,
    durationMs: row.durationMs,
    client: {
      ip: ip ?? null,
      place:
        place === undefined
          ? null
          : { country: place.country, city: place.city ?? null, approximate: true as const, ...PLACES_BY },
      timeZone: timeZone === undefined ? null : { name: timeZone.name, from: timeZone.from },
    },
  };
};

/** A row as an NDJSON download holds it: one line. */
export const activityNdjsonLine = (row: ActivityRow, names: ReadonlyMap<string, ActorName>): string =>
  JSON.stringify(activityShown(row, names));

/** A batch of the activity log and what Agent X holds to name its actors. */
export interface HeldActivityPage {
  readonly rows: readonly ActivityRow[];
  readonly next: Awaited<ReturnType<typeof activityPage>>['next'];
  readonly held: ActorsHeld;
}

/**
 * A batch of the activity log and what Agent X holds to name its actors, in
 * the organisation's transaction; `tampered` for an agent that can't be believed.
 */
export async function heldActivityPage(
  tx: DatabaseTransaction<ActivityReadTables>,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  asked: ActivityPageToRead,
): Promise<HeldActivityPage | 'tampered'> {
  const page = await activityPage(tx, orgId, asked);
  const held = await actorsHeld(
    tx,
    states,
    keys,
    orgId,
    page.rows.map((row) => row.actor),
  );
  if (held === 'tampered') return 'tampered';
  return { ...page, held };
}

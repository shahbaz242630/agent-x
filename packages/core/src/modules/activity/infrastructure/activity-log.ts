// The activity log (Phase 3 L3, partner decision 26; ADR-005 §6, ADR-011 §7):
// one row for every request a known caller made, the reads and refusals the
// audit chain doesn't hold among them, in the tables 0052 made.
//
// - A request of a verified member or agent of an organisation is written to
//   `access.requests` inside that organisation's transaction (withTenant), so
//   its row-level security holds the write too.
// - A signed-in person's request naming no organisation they are verified in
//   goes to `access.person_requests`, the header's organisation kept only as
//   `claimedOrg`, never as the row's owner.
// - One row a call, in a transaction of its own (the request's own is rolled
//   back on a refusal), each statement limited to 10 seconds.
// - What the API decides must be well formed, or nothing is written and it
//   throws RangeError: a bug, never a row half true.
// - The client's clues (L4): its IP address, the approximate country and city
//   that address is registered to, and a time zone, the browser's own report
//   or the organisation's. Each may be missing; none is proof of anything.
import { limitStatements, withTenant } from '@agentx/platform/db';
import type { Kysely } from 'kysely';

import { type IdGenerator, isIpAddress, plainLine, UUID } from '../../../shared-kernel/index.ts';
import type { ActivityTables } from './tables.ts';

/** The methods a route is served on. */
export const ACTIVITY_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
type Method = (typeof ACTIVITY_METHODS)[number];

/** The most IDs a row keeps from its route's path. */
export const MOST_PATH_IDS = 4;

const ROUTE = /^\/[A-Za-z0-9/:_.-]{0,200}$/;
const REASON = /^[A-Z][A-Z0-9_]{0,63}$/;
/** A country by its ISO 3166 code. */
export const COUNTRY_CODE = /^[A-Z]{2}$/;
/** A time zone's name as 0052 checks it; the API takes only a zone Intl knows (`timeZoneOf`) and this allows. */
export const TIME_ZONE_NAME = /^[A-Za-z][A-Za-z0-9_+/-]{0,63}$/;
/** The longest city kept, in UTF-16 units: never more characters than 0052 allows. */
export const MOST_CITY_LENGTH = 120;

/** Where a row's time zone came from. */
const TIME_ZONE_SOURCES = ['browser', 'organisation'] as const;

/** The approximate place a client's address is registered to. */
export interface ClientPlace {
  readonly country: string;
  readonly city: string | undefined;
}

/** What a request says of where its client may be: clues, never proof (decision 26). */
export interface ClientClues {
  /** Its IP address, as the trusted proxies' rule reads it; undefined when it couldn't be read. */
  readonly ip: string | undefined;
  /** The approximate place that address is registered to; undefined when none is known. */
  readonly place: ClientPlace | undefined;
  /** The browser's own time zone, or else the organisation's; undefined for a person's row with none sent. */
  readonly timeZone: { readonly name: string; readonly from: (typeof TIME_ZONE_SOURCES)[number] } | undefined;
}

/** What every row says of its request, whoever made it. */
interface RequestFacts {
  /** When it arrived. */
  readonly at: Date;
  readonly method: Method;
  /** The route's pattern, never the URL as sent: `/v1/agents/:id/suspend`. */
  readonly route: string;
  /** The UUIDs its path named, in lower case, at most MOST_PATH_IDS. */
  readonly pathIds: readonly string[];
  readonly status: number;
  /** The reason code of a refusal or failure; undefined for an answer that is neither. */
  readonly reason: string | undefined;
  readonly correlationId: string;
  /** How long it took to answer, in whole milliseconds. */
  readonly durationMs: number;
  readonly client: ClientClues;
}

/** A request of a verified member or agent of one organisation. */
export interface OrganisationRequest extends RequestFacts {
  readonly orgId: string;
  readonly actor: { readonly type: 'user' | 'agent'; readonly id: string };
}

/** A signed-in person's request naming no organisation they are verified in. */
export interface PersonRequest extends RequestFacts {
  readonly userId: string;
  /** The organisation the request's header named, when it named one: a claim, never verified. */
  readonly claimedOrg: string | undefined;
}

export interface ActivityLog {
  /** Writes one organisation's row. Throws RangeError for anything malformed, writing nothing. */
  recordForOrganisation(db: Kysely<ActivityTables>, request: OrganisationRequest): Promise<void>;
  /** Writes one person's row. Throws RangeError for anything malformed, writing nothing. */
  recordForPerson(db: Kysely<ActivityTables>, request: PersonRequest): Promise<void>;
}

/** Why a request's clues can't be written, if they can't. */
function clueProblem({ ip, place, timeZone }: ClientClues): string | undefined {
  if (ip !== undefined && !isIpAddress(ip)) return 'its client address is not an IP address';
  if (place !== undefined) {
    if (!COUNTRY_CODE.test(place.country)) return 'its country is not a two-letter code';
    const { city } = place;
    if (city !== undefined && plainLine(city, MOST_CITY_LENGTH) !== city) {
      return `its city is not 1 to ${String(MOST_CITY_LENGTH)} characters of text`;
    }
  }
  if (timeZone !== undefined && (!TIME_ZONE_NAME.test(timeZone.name) || !TIME_ZONE_SOURCES.includes(timeZone.from))) {
    return 'its time zone is not a zone with where it came from';
  }
  return undefined;
}

/** Why a request's facts can't be written, if they can't. */
function problemWith(facts: RequestFacts): string | undefined {
  if (!(facts.at instanceof Date) || Number.isNaN(facts.at.getTime())) return 'it has no time';
  if (!ACTIVITY_METHODS.includes(facts.method)) return 'its method is not one a route is served on';
  if (!ROUTE.test(facts.route)) return 'its route is not a pattern';
  if (facts.pathIds.length > MOST_PATH_IDS || !facts.pathIds.every((id) => UUID.test(id))) {
    return `its path IDs are not at most ${String(MOST_PATH_IDS)} UUIDs`;
  }
  if (!Number.isInteger(facts.status) || facts.status < 100 || facts.status > 599) return 'its status is not HTTP’s';
  if (facts.reason !== undefined && !REASON.test(facts.reason)) return 'its reason is not a reason code';
  if (!UUID.test(facts.correlationId)) return 'its correlation ID is not a UUID';
  if (!Number.isSafeInteger(facts.durationMs) || facts.durationMs < 0) return 'its duration is not whole milliseconds';
  return clueProblem(facts.client);
}

/** The columns both tables share, from facts already checked. */
const columnsOf = (id: string, facts: RequestFacts) => ({
  id,
  recorded_at: facts.at,
  method: facts.method,
  route: facts.route,
  path_ids: facts.pathIds.map((pathId) => pathId.toLowerCase()),
  status: facts.status,
  reason: facts.reason ?? null,
  correlation_id: facts.correlationId.toLowerCase(),
  duration_ms: facts.durationMs,
  ip: facts.client.ip ?? null,
  country: facts.client.place?.country ?? null,
  city: facts.client.place?.city ?? null,
  time_zone: facts.client.timeZone?.name ?? null,
  time_zone_from: facts.client.timeZone?.from ?? null,
});

const refuse = (problem: string): never => {
  throw new RangeError(`an activity log row can't be written: ${problem}`);
};

export function createActivityLog({ ids }: { readonly ids: IdGenerator }): ActivityLog {
  return {
    async recordForOrganisation(db, request) {
      const problem =
        problemWith(request) ??
        (UUID.test(request.orgId) ? undefined : 'its organisation is not a UUID') ??
        (['user', 'agent'].includes(request.actor.type) && UUID.test(request.actor.id)
          ? undefined
          : 'its actor is not a person or an agent by UUID');
      if (problem !== undefined) refuse(problem);
      await withTenant(db, request.orgId, async (tx) => {
        await limitStatements(tx);
        await tx
          .insertInto('access.requests')
          .values({
            ...columnsOf(ids.next(), request),
            org_id: request.orgId.toLowerCase(),
            actor_type: request.actor.type,
            actor_id: request.actor.id.toLowerCase(),
          })
          .execute();
      });
    },

    async recordForPerson(db, request) {
      const problem =
        problemWith(request) ??
        (UUID.test(request.userId) ? undefined : 'its person is not a UUID') ??
        (request.claimedOrg === undefined || UUID.test(request.claimedOrg)
          ? undefined
          : 'its claimed organisation is not a UUID');
      if (problem !== undefined) refuse(problem);
      await db.transaction().execute(async (tx) => {
        await limitStatements(tx);
        await tx
          .insertInto('access.person_requests')
          .values({
            ...columnsOf(ids.next(), request),
            user_id: request.userId.toLowerCase(),
            claimed_org: request.claimedOrg?.toLowerCase() ?? null,
          })
          .execute();
      });
    },
  };
}

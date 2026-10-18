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
//   throws RangeError: a bug, never a row half true. The client's address and
//   its place and time zone are L4's; until then they are left empty.
import { limitStatements, withTenant } from '@agentx/platform/db';
import type { Kysely } from 'kysely';

import { type IdGenerator, UUID } from '../../../shared-kernel/index.ts';
import type { ActivityTables } from './tables.ts';

/** The methods a route is served on. */
export const ACTIVITY_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
type Method = (typeof ACTIVITY_METHODS)[number];

/** The most IDs a row keeps from its route's path. */
export const MOST_PATH_IDS = 4;

const ROUTE = /^\/[A-Za-z0-9/:_.-]{0,200}$/;
const REASON = /^[A-Z][A-Z0-9_]{0,63}$/;

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
  return undefined;
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
  ip: null,
  country: null,
  city: null,
  time_zone: null,
  time_zone_from: null,
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

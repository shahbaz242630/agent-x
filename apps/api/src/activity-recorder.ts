// The activity log's recorder (Phase 3 L3, partner decision 26: "everything
// logged", reads and refusals too; ADR-005 §6, ADR-011 §7): one row for every
// request of a known caller, written as its answer completes.
//
// - Whose: a verified member's request in their organisation (`member`, or
//   `verifiedOrg` for one refused by the role, passkey or second-factor
//   checks: still that organisation's), and an agent's in its own, go to the
//   organisation's log; a signed-in person's naming no organisation they are
//   verified in goes to the person's, the header's organisation kept only as a
//   claim. A request of no known caller (signed out, a key refused) is not
//   logged here: its refusal is a security event or a request line.
// - What: the route's pattern and the UUIDs in its path, never the URL as
//   sent, a query, a header or a body; the status and, for a refusal or
//   failure, the reason code the contract wrote; the correlation ID; the time.
// - Where, as clues (L4): the client's address as the trusted proxies' rule
//   reads it (the rate limit's), the place it is registered to, and the
//   browser's time zone; else, on an organisation's row, the organisation's
//   (Asia/Dubai, as every lineage's default). An agent is no browser: its row
//   always takes the organisation's zone.
// - When: in `onResponse`, one row a request, awaited, never batched. The
//   contract lets no hook run between an answer's check and its leaving
//   (onSend), so this is the nearest point: only a crash in the milliseconds
//   after the answer leaves can lose its row. A row that can't be written is
//   `access_log.write_failed` at error level, which the app-error alert sees
//   (ADR-012 §9): never silent, and never the answer's failure.
// - As the API stops, its close waits for the rows still being written.
import {
  ACTIVITY_METHODS,
  type ActivityLog,
  type ActivityTables,
  type ClientClues,
  MOST_PATH_IDS,
  type OrganisationRequest,
  type PersonRequest,
} from '@agentx/core/modules/activity';
import { DEFAULT_TIME_ZONE, UUID } from '@agentx/core/shared-kernel';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Database } from '@agentx/platform/db';

import { ORGANIZATION_HEADER } from './access.ts';
import { type PlaceOf, TIME_ZONE_HEADER, timeZoneSent } from './client-clues.ts';
import { clientAddress, type ProxyTrust, rawClientIp } from './rate-limit.ts';
import { writtenText } from './written-answers.ts';

/** Where the recorder writes each row: the activity module's writes, bound to the API's database. */
export interface ActivitySink {
  forOrganisation(request: OrganisationRequest): Promise<void>;
  forPerson(request: PersonRequest): Promise<void>;
}

/** The activity module's writes, bound to the API's database. */
export const activitySinkOf = (log: ActivityLog, db: Database<ActivityTables>): ActivitySink => ({
  forOrganisation: (request) => log.recordForOrganisation(db, request),
  forPerson: (request) => log.recordForPerson(db, request),
});

type Method = OrganisationRequest['method'];

const isMethod = (method: string): method is Method => (ACTIVITY_METHODS as readonly string[]).includes(method);

/** The reason code in an error answer the contract wrote; undefined when there is none. */
export function reasonIn(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  try {
    const body: unknown = JSON.parse(text);
    if (typeof body !== 'object' || body === null || !('error' in body)) return undefined;
    const { error } = body;
    if (typeof error !== 'object' || error === null || !('code' in error)) return undefined;
    return typeof error.code === 'string' ? error.code : undefined;
  } catch {
    return undefined;
  }
}

/** The UUIDs a request's path named, in lower case, at most MOST_PATH_IDS. */
export function pathIdsOf(params: unknown): string[] {
  if (typeof params !== 'object' || params === null) return [];
  return Object.values(params)
    .filter((value): value is string => typeof value === 'string' && UUID.test(value))
    .map((value) => value.toLowerCase())
    .slice(0, MOST_PATH_IDS);
}

/** The organisation a request's header named, as a claim: a UUID in lower case, or undefined. */
const claimedOrgOf = (header: string | string[] | undefined): string | undefined =>
  typeof header === 'string' && UUID.test(header) ? header.toLowerCase() : undefined;

/** How the recorder reads a request's clues. */
interface ClueReading {
  readonly trust: ProxyTrust;
  readonly placeOf: PlaceOf | undefined;
}

/** Whose zone a row falls back to, and whether its caller may name its own. */
interface ZoneRule {
  readonly browser: boolean;
  readonly organisation: boolean;
}

const MEMBER_ZONE: ZoneRule = { browser: true, organisation: true };
const AGENT_ZONE: ZoneRule = { browser: false, organisation: true };
const PERSON_ZONE: ZoneRule = { browser: true, organisation: false };

/** Where the request's client may be: clues, never proof. */
function cluesOf(request: FastifyRequest, { trust, placeOf }: ClueReading, zone: ZoneRule): ClientClues {
  const ip = clientAddress(rawClientIp(request, trust));
  const sent = zone.browser ? timeZoneSent(request.headers[TIME_ZONE_HEADER]) : undefined;
  return {
    ip,
    place: ip === undefined ? undefined : placeOf?.(ip),
    timeZone:
      sent !== undefined
        ? { name: sent, from: 'browser' }
        : zone.organisation
          ? { name: DEFAULT_TIME_ZONE, from: 'organisation' }
          : undefined,
  };
}

/** What every row says of the request; undefined for one that isn't a route's, or on a method no route is served on. */
function factsOf(request: FastifyRequest, reply: FastifyReply) {
  const route = request.routeOptions.url;
  if (route === undefined || !isMethod(request.method)) return undefined;
  const durationMs = Math.max(0, Math.round(reply.elapsedTime));
  return {
    at: new Date(Date.now() - durationMs),
    method: request.method,
    route,
    pathIds: pathIdsOf(request.params),
    status: reply.statusCode,
    reason: reply.statusCode >= 400 ? reasonIn(writtenText(reply)) : undefined,
    correlationId: request.id,
    durationMs,
  };
}

/** Writes the request's row, if its caller is known: the organisation's, or the person's. */
function rowFor(
  request: FastifyRequest,
  reply: FastifyReply,
  sink: ActivitySink,
  reading: ClueReading,
): Promise<void> | undefined {
  const { person, member, verifiedOrg, agent } = request;
  const facts = factsOf(request, reply);
  if (facts === undefined) return undefined;
  if (agent !== null) {
    return sink.forOrganisation({
      ...facts,
      client: cluesOf(request, reading, AGENT_ZONE),
      orgId: agent.orgId,
      actor: { type: 'agent', id: agent.agentId },
    });
  }
  if (person === null) return undefined;
  const orgId = member?.orgId ?? verifiedOrg;
  if (orgId !== null) {
    return sink.forOrganisation({
      ...facts,
      client: cluesOf(request, reading, MEMBER_ZONE),
      orgId,
      actor: { type: 'user', id: person.userId },
    });
  }
  const claimedOrg = claimedOrgOf(request.headers[ORGANIZATION_HEADER]);
  return sink.forPerson({
    ...facts,
    client: cluesOf(request, reading, PERSON_ZONE),
    userId: person.userId,
    claimedOrg,
  });
}

/** Records every known caller's request, when there is somewhere to write it. */
export function registerActivityLog(
  app: FastifyInstance,
  { sink, logger, ...reading }: { readonly sink: ActivitySink | undefined; readonly logger: Logger } & ClueReading,
): void {
  if (sink === undefined) return;
  const writing = new Set<Promise<void>>();
  app.addHook('onResponse', async (request, reply) => {
    const written = rowFor(request, reply, sink, reading)?.catch((error: unknown) => {
      // Never the error's text: a database's may quote the row. Its kind and where are enough to look.
      logger.child({ correlationId: request.id }).error('access_log.write_failed', {
        route: request.routeOptions.url,
        status: reply.statusCode,
        malformed: error instanceof RangeError,
      });
    });
    if (written === undefined) return;
    writing.add(written);
    try {
      await written;
    } finally {
      writing.delete(written);
    }
  });
  // Once no request is still being answered: the rows of those just answered.
  app.addHook('onClose', async () => {
    await Promise.allSettled([...writing]);
  });
}

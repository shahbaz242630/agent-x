// The organisation's activity log, for its admins (Phase 3 L5; partner
// decision 26: "everything logged", admins only).
//
// - `GET /v1/access-log?from&to[&actorType&actorId][&before][&limit]`: every
//   request a verified member or agent of the organisation made in
//   [from, to), the reads and refusals the audit log doesn't hold among
//   them, by the one person or agent named, newest first, a page at most
//   MOST_ACTIVITY_A_PAGE. `next` names where the next page starts before.
// - Each row: when (UTC, exact; and the clock where its time zone says), who
//   (named as on the audit log, decision 25), what (method, route pattern and
//   the IDs in its path, status and reason code), its correlation ID (on the
//   audit events it wrote), and its client's clues: the IP address, the place
//   it is registered to (approximate, credited to DB-IP), the time zone and
//   where it came from. Clues, never proof (decision 26). And whether it is
//   sealed (L6): its day closed and sealed on the audit chain, as
//   `sealedThrough`, the newest day sealed, says.
// - An agent on the page whose signed state can't be believed, or a seal, is
//   503 INTEGRITY_FAILED, the alarm raised, as on the audit log.
// Reading a page is itself a row of the log (the activity recorder, L3).
import {
  ACTIVITY_ACTOR_TYPES,
  type ActivityCursor,
  type ActivityPageToRead,
  type ActivityRow,
  TIME_ZONE_SOURCES,
} from '@agentx/core/modules/activity';
import type { SignedStates } from '@agentx/core/modules/audit';
import {
  activityActorsOf,
  type ActivityReadTables,
  type ActorName,
  activityShown,
  createActorNamer,
  heldActivityPage,
  PLACES_BY,
  SHOWN_FROM,
} from '@agentx/core/modules/evidence';
import type { DirectoryNames } from '@agentx/core/modules/identity';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import type { AuditLogTables } from './audit-log.ts';
import { answerRefusal } from './idempotent-writes.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork, UseCaseRefused } from './use-case-work.ts';

/** The most rows a page of the activity log holds. */
const MOST_ACTIVITY_A_PAGE = 100;

export class ActivityLogRefused extends UseCaseRefused {}

/** The tables a page of the activity log reads: its rows, and what names their actors. */
export type ActivityLogTables = AuditLogTables & ActivityReadTables;

export type ActivityPageAnswer =
  | {
      readonly outcome: 'page';
      readonly rows: readonly ActivityRow[];
      readonly next: ActivityCursor | null;
      readonly names: ReadonlyMap<string, ActorName>;
      readonly sealedDay: string | null;
    }
  | Refused;

export interface ActivityPages {
  page(orgId: string, asked: ActivityPageToRead, correlationId: string): Promise<ActivityPageAnswer>;
}

/**
 * A batch of the activity log, what Agent X holds to name its actors and the
 * newest day sealed, in the organisation's transaction, a page or a
 * download's alike; an agent or a seal that can't be believed is
 * ActivityLogRefused INTEGRITY_FAILED.
 */
export async function heldActivity(
  tx: DatabaseTransaction<ActivityLogTables>,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  asked: ActivityPageToRead,
) {
  const page = await heldActivityPage(tx, states, keys, orgId, asked);
  if (page === 'tampered') throw new ActivityLogRefused(503, 'INTEGRITY_FAILED');
  return page;
}

export function createActivityPages({
  database,
  keys,
  ids,
  logger,
  directory,
}: {
  readonly database: Database<ActivityLogTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** The login service's names; undefined when none is set up, and people are named from the kept copy. */
  readonly directory: DirectoryNames | undefined;
}): ActivityPages {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: ActivityLogRefused });
  return {
    async page(orgId, asked, correlationId) {
      const read = await work.answered(orgId, correlationId, async (tx, states) => ({
        outcome: 'page' as const,
        ...(await heldActivity(tx, states, keys, orgId, asked)),
      }));
      if (read.outcome === 'refused') return read;
      const namer = createActorNamer({ directory, logger: logger.child({ correlationId }) });
      return {
        ...read,
        names: await namer.namesOf(activityActorsOf(read.rows), read.held),
      };
    },
  };
}

/** Where a page starts before, as `next` names it: a row's time and ID, `2026-10-19T13:39:12.123Z_<uuid>`. */
const CURSOR =
  /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

const cursorText = ({ at, id }: ActivityCursor): string => `${at.toISOString()}_${id}`;

/** A cursor's time and ID, or undefined for text that isn't one. */
const cursorOf = (text: string): ActivityCursor | undefined => {
  const [, at, id] = CURSOR.exec(text) ?? [];
  if (at === undefined || id === undefined) return undefined;
  const time = new Date(at);
  // A day or hour that doesn't exist reads as another, or as none.
  return Number.isNaN(time.getTime()) || time.toISOString() !== at ? undefined : { at: time, id: id.toLowerCase() };
};

const ACTIVITY_ROW = z
  .object({
    id: z.uuid().describe('The row, by its ID.'),
    recordedAt: z.iso.datetime().describe('When the request arrived, in UTC: exact.'),
    localTime: z
      .string()
      .nullable()
      .describe(
        'The same moment as the clock read in `client.timeZone`, with its offset (`2026-10-19T17:39:12.123+04:00`); null with no time zone.',
      ),
    actor: z
      .object({
        type: z.enum(ACTIVITY_ACTOR_TYPES).describe('A person or an AI agent.'),
        id: z.uuid().describe('Who, by their Agent X ID.'),
        name: z.string().nullable().describe('Their name; null when none is known.'),
        email: z.string().nullable().describe('A person’s verified email address; null for an agent, or none known.'),
        shownFrom: z.enum(SHOWN_FROM).nullable().describe('Where the name was found, as on the audit log.'),
      })
      .describe('Who made the request.'),
    method: z.string().describe('The request’s method, such as `GET`.'),
    route: z.string().describe('The route’s pattern, such as `/v1/agents/:id/suspend`: never the address as sent.'),
    pathIds: z.array(z.uuid()).describe('The IDs its path named, in order.'),
    status: z.int().describe('The answer’s HTTP status.'),
    reason: z.string().nullable().describe('The reason code of a refusal or failure; null for neither.'),
    correlationId: z.uuid().describe('The request’s correlation ID: the same on the audit events it recorded.'),
    durationMs: z.int().min(0).describe('How long it took to answer, in milliseconds.'),
    sealed: z
      .boolean()
      .describe(
        'Whether its day is sealed on the audit chain: written on or before `sealedThrough` (a day is the UTC day a row was written).',
      ),
    client: z
      .object({
        ip: z.string().nullable().describe('The IP address it came from; null when it couldn’t be read.'),
        place: z
          .object({
            country: z.string().describe('The country, by its ISO 3166 code.'),
            city: z.string().nullable().describe('The city; null when none is known.'),
            approximate: z
              .literal(true)
              .describe('Always: a VPN or a company network shows somewhere else than the person is.'),
            by: z.literal(PLACES_BY.by).describe('Where the place comes from (CC BY 4.0).'),
            link: z.literal(PLACES_BY.link).describe('Its source.'),
          })
          .nullable()
          .describe('The approximate place the address is registered to; null when none is known.'),
        timeZone: z
          .object({
            name: z.string().describe('The time zone, such as `Asia/Dubai`.'),
            from: z
              .enum(TIME_ZONE_SOURCES)
              .describe('`browser`: the browser reported it; `organisation`: the organisation’s own, as none was.'),
          })
          .nullable()
          .describe('The time zone the request was made in; null when none is known.'),
      })
      .describe('What the request says of where its client may be: clues, never proof.'),
  })
  .register(API_SCHEMAS, { id: 'ActivityLogRow', description: 'One request in the organisation’s activity log.' });

const PAGE_SCHEMA = {
  summary: 'Your organisation’s activity log: every request its people and agents made, newest first',
  querystring: z
    .strictObject({
      from: z.iso.datetime().describe('Requests made at or after it.'),
      to: z.iso.datetime().describe('Requests made before it.'),
      actorType: z
        .enum(ACTIVITY_ACTOR_TYPES)
        .optional()
        .describe('Only requests by this kind of actor; with `actorId`.'),
      actorId: z.uuid().optional().describe('Only requests by this person or agent, by Agent X ID; with `actorType`.'),
      before: z.string().max(80).optional().describe('The page starts before this row: the page before’s `next`.'),
      limit: z.coerce
        .number()
        .int()
        .min(1)
        .max(MOST_ACTIVITY_A_PAGE)
        .optional()
        .describe(
          `How many at most, 1 to ${String(MOST_ACTIVITY_A_PAGE)}; all ${String(MOST_ACTIVITY_A_PAGE)} unless fewer are asked for.`,
        ),
    })
    .superRefine((query, context) => {
      if (new Date(query.from).getTime() >= new Date(query.to).getTime()) {
        context.addIssue({ code: 'custom', message: 'the range starts before it ends' });
      }
      if ((query.actorType === undefined) !== (query.actorId === undefined)) {
        context.addIssue({ code: 'custom', message: 'an actor is named by actorType and actorId together' });
      }
      if (query.before !== undefined && cursorOf(query.before) === undefined) {
        context.addIssue({ code: 'custom', message: 'before is a page’s `next`' });
      }
    }),
  response: {
    200: z
      .object({
        rows: z.array(ACTIVITY_ROW).describe('The requests, newest first.'),
        next: z.string().nullable().describe('Where the next page starts before (`before`); null at the end.'),
        sealedThrough: z.iso
          .date()
          .nullable()
          .describe(
            'The newest day sealed, UTC: every request written on or before it is sealed. Null while none is (a day is sealed after it closes).',
          ),
      })
      .describe('A page of the activity log.'),
  },
};

/** The activity log's route. Without `log` it is still documented, and no one reaches it. */
export function registerActivityPages(app: FastifyInstance, { log }: { log: ActivityPages | undefined }): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get('/v1/access-log', { schema: PAGE_SCHEMA, config: { access: ['admin'] } }, async (request, reply) => {
    const { orgId } = memberInSessionOf(request);
    const { from, to, actorType, actorId, before, limit } = request.query;
    const page = await need(log).page(
      orgId,
      {
        from: new Date(from),
        to: new Date(to),
        actor:
          actorType === undefined || actorId === undefined ? undefined : { type: actorType, id: actorId.toLowerCase() },
        before: before === undefined ? undefined : cursorOf(before),
        limit: limit ?? MOST_ACTIVITY_A_PAGE,
      },
      request.id,
    );
    if (page.outcome === 'refused') return answerRefusal(page, request, reply);
    return {
      rows: page.rows.map((row) => activityShown(row, page.names, page.sealedDay)),
      next: page.next === null ? null : cursorText(page.next),
      sealedThrough: page.sealedDay,
    };
  });
}

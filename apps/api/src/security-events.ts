// The organisation's security events, for its admins (Phase 6 6E1b, CO7b;
// BR-16, BR-18; partner decision 26: "everything logged", admins only).
//
// - `GET /v1/security-events?from&to[&kind][&before][&limit]`: the counts of
//   rate-limit hits and failed step-ups of the organisation's own people and
//   agents whose minute began in [from, to), of one kind when named, newest
//   first, a page at most MOST_SECURITY_EVENTS_A_PAGE. `next` names where the
//   next page starts before.
// - Only events the API tied to the organisation as it verified them (a
//   member's once their membership there was found active, an agent's by its
//   accepted key; security-recorder.ts) are here, read in the organisation's
//   transaction from its walled table (0091). Failed sign-ins before anyone
//   is known, and the partner's refused messages, are no organisation's.
// - Each row: the kind and reason, the client's IP address (a clue, never
//   proof, decision 26), who it was about named as on the audit log, the
//   minute it was counted in and how many there were.
// - An agent on the page whose signed state can't be believed is 503
//   INTEGRITY_FAILED, the alarm raised, as on the logs.
// Reading a page is itself a row of the activity log (the activity recorder, L3).
import {
  heldSecurityEventsPage,
  type ActorName,
  createActorNamer,
  securityEventActorsOf,
  type SecurityEventsReadTables,
  securityEventShown,
} from '@agentx/core/modules/evidence';
import type { DirectoryNames } from '@agentx/core/modules/identity';
import {
  ORG_EVENT_KINDS,
  type OrgEventCursor,
  type OrgEventsToRead,
  type OrgSecurityEvent,
  macBoundary,
} from '@agentx/core/modules/security-events';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
// A row's place is named as the activity log names its rows: its time (here, the minute's start) and ID.
import { cursorOf, cursorText } from './activity-log.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerRefusal } from './idempotent-writes.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork, UseCaseRefused } from './use-case-work.ts';

/** The most rows a page of security events holds. */
const MOST_SECURITY_EVENTS_A_PAGE = 100;

class SecurityEventsRefused extends UseCaseRefused {}

export type SecurityEventsPageAnswer =
  | {
      readonly outcome: 'page';
      readonly rows: readonly OrgSecurityEvent[];
      readonly next: OrgEventCursor | null;
      readonly names: ReadonlyMap<string, ActorName>;
    }
  | Refused;

export interface SecurityEventPages {
  page(orgId: string, asked: OrgEventsToRead, correlationId: string): Promise<SecurityEventsPageAnswer>;
}

export function createSecurityEventPages({
  database,
  keys,
  ids,
  logger,
  directory,
}: {
  readonly database: Database<SecurityEventsReadTables & PlatformControlsTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** The login service's names; undefined when none is set up, and people are named from the kept copy. */
  readonly directory: DirectoryNames | undefined;
}): SecurityEventPages {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: SecurityEventsRefused });
  // When the rows' MACs began (S206 V6): read once, then kept, so a page costs no more trips.
  const boundary = macBoundary(keys, logger);
  return {
    async page(orgId, asked, correlationId) {
      const macsFrom = await boundary(database);
      const checked = { keys, macsFrom, logger: logger.child({ correlationId }) };
      const read = await work.answered(orgId, correlationId, async (tx, states) => {
        const page = await heldSecurityEventsPage(tx, states, keys, orgId, asked, checked);
        if (page === 'tampered') throw new SecurityEventsRefused(503, 'INTEGRITY_FAILED');
        return { outcome: 'page' as const, ...page };
      });
      if (read.outcome === 'refused') return read;
      const namer = createActorNamer({ directory, logger: logger.child({ correlationId }) });
      return {
        outcome: 'page',
        rows: read.rows,
        next: read.next,
        names: await namer.namesOf(securityEventActorsOf(read.rows), read.held),
      };
    },
  };
}

const SECURITY_EVENT_ROW = z
  .object({
    id: z.uuid().describe('The row, by its ID.'),
    kind: z
      .enum(ORG_EVENT_KINDS)
      .describe('`rate_limited`: a request refused past a limit; `sign_in_failed`: a step-up that failed.'),
    reason: z
      .string()
      .describe(
        'Why, in the kind’s own words: the limit hit (`per_user`, `per_agent`, `per_organisation`), or the step-up’s failed step.',
      ),
    ip: z
      .string()
      .nullable()
      .describe('The IP address it came from: a clue, never proof; null when it couldn’t be read.'),
    actor: z
      .object({
        type: z.enum(['user', 'agent']).describe('A person or an AI agent.'),
        id: z.uuid().describe('Who, by their Agent X ID.'),
        name: z.string().nullable().describe('Their name; null when none is known.'),
      })
      .nullable()
      .describe('Who it was about; null when the count is of no one in particular.'),
    windowStart: z.iso.datetime().describe('The minute it was counted in, in UTC: when that minute began.'),
    count: z.int().min(1).describe('How many times it happened in that minute.'),
  })
  .register(API_SCHEMAS, {
    id: 'SecurityEventRow',
    description: 'A count of one security event of the organisation’s people or agents in one minute.',
  });

const PAGE_SCHEMA = {
  summary: 'Your organisation’s security events: its people’s and agents’ rate-limit hits and failed step-ups',
  querystring: z
    .strictObject({
      from: z.iso.datetime().describe('Events counted in a minute that began at or after it.'),
      to: z.iso.datetime().describe('Events counted in a minute that began before it.'),
      kind: z.enum(ORG_EVENT_KINDS).optional().describe('Only events of this kind.'),
      before: z.string().max(80).optional().describe('The page starts before this row: the page before’s `next`.'),
      limit: z.coerce
        .number()
        .int()
        .min(1)
        .max(MOST_SECURITY_EVENTS_A_PAGE)
        .optional()
        .describe(
          `How many at most, 1 to ${String(MOST_SECURITY_EVENTS_A_PAGE)}; all ${String(MOST_SECURITY_EVENTS_A_PAGE)} unless fewer are asked for.`,
        ),
    })
    .superRefine((query, context) => {
      if (new Date(query.from).getTime() >= new Date(query.to).getTime()) {
        context.addIssue({ code: 'custom', message: 'the range starts before it ends' });
      }
      if (query.before !== undefined && cursorOf(query.before) === undefined) {
        context.addIssue({ code: 'custom', message: 'before is a page’s `next`' });
      }
    }),
  response: {
    200: z
      .object({
        rows: z.array(SECURITY_EVENT_ROW).describe('The events, newest first.'),
        next: z.string().nullable().describe('Where the next page starts before (`before`); null at the end.'),
      })
      .describe('A page of the organisation’s security events.'),
  },
};

/** The security events' route. Without `pages` it is still documented, and no one reaches it. */
export function registerSecurityEvents(
  app: FastifyInstance,
  { pages }: { pages: SecurityEventPages | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get('/v1/security-events', { schema: PAGE_SCHEMA, config: { access: ['admin'] } }, async (request, reply) => {
    const { orgId } = memberInSessionOf(request);
    const { from, to, kind, before, limit } = request.query;
    const page = await need(pages).page(
      orgId,
      {
        from: new Date(from),
        to: new Date(to),
        kind,
        before: before === undefined ? undefined : cursorOf(before),
        limit: limit ?? MOST_SECURITY_EVENTS_A_PAGE,
      },
      request.id,
    );
    if (page.outcome === 'refused') return answerRefusal(page, request, reply);
    return {
      rows: page.rows.map((row) => securityEventShown(row, page.names)),
      next: page.next === null ? null : cursorText(page.next),
    };
  });
}

// The organisation's audit log, for its admins (Phase 3 E10a; partner rule
// S119, "nothing on our platform goes without log; logs available for both
// user and us"; decision 24: admins only).
//
// - `GET /v1/audit-log?from&to[&actions][&actorType&actorId][&before][&limit]`:
//   every signed event of the organisation recorded in [from, to), of the
//   actions named, by the one actor named (decision 26), newest first, a page at most MOST_LOG_EVENTS_A_PAGE: who (the actor), what (the
//   action and its subject) and every fact sealed with it, each choice and
//   confirm with its statement version and step-up evidence among them.
//   `next` names the event the next page starts before.
// - Each event is believed only whole, its seal and the head checked (the
//   audit trail's logPage): any that can't be is 503 INTEGRITY_FAILED, the
//   alarm raised and the organisation held, never a page with it left out.
// - Shown whole but for the seals that are the platform's alone: the MAC and
//   its key's version are never read out; a signed state's keyed fingerprint
//   and its key's version are taken out of the details. The hashes stay, so
//   an admin can see each event's link to the one before.
// - Each actor is named beside their ID (decision 25, the evidence module): a
//   person by name and email, from the login service or the copy Agent X
//   kept; an agent by its name; Agent X's own parts by theirs.
// Reading a page isn't itself logged (decision 24: a download is, E10b).
import type { AgentsTables } from '@agentx/core/modules/agents';
import {
  actorAsKept,
  actorProblems,
  type ActorType,
  type LogEvent,
  type LogPageToRead,
  type SignedStates,
} from '@agentx/core/modules/audit';
import {
  type ActorName,
  actorsOf,
  createActorNamer,
  eventShown,
  factsShown,
  heldLogPage as heldPage,
  SHOWN_FROM,
} from '@agentx/core/modules/evidence';
import type { DirectoryNames } from '@agentx/core/modules/identity';
import { actionProblems, type IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerRefusal } from './idempotent-writes.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork, UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

/** The most events a page of the log holds. */
export const MOST_LOG_EVENTS_A_PAGE = 100;

/** The most actions one page may be filtered to. */
export const MOST_ACTIONS_FILTERED = 20;

export class AuditLogRefused extends UseCaseRefused {}

export type LogPageAnswer =
  | {
      readonly outcome: 'page';
      readonly events: readonly LogEvent[];
      readonly next: bigint | null;
      readonly names: ReadonlyMap<string, ActorName>;
    }
  | Refused;

export interface AuditLog {
  page(orgId: string, asked: LogPageToRead, correlationId: string): Promise<LogPageAnswer>;
}

/** The tables a page of the log reads: its events, and what names their actors. */
export type AuditLogTables = UseCaseTables & AgentsTables;

/**
 * A page of the log and what Agent X holds to name its actors, in the
 * organisation's transaction, a page or a download's batch alike; an event or
 * an agent that can't be believed is AuditLogRefused INTEGRITY_FAILED.
 */
export async function heldLogPage(
  tx: DatabaseTransaction<AuditLogTables>,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  asked: LogPageToRead,
) {
  const page = await heldPage(tx, states, keys, orgId, asked);
  if (page === 'tampered') throw new AuditLogRefused(503, 'INTEGRITY_FAILED');
  return page;
}

export function createAuditLog({
  database,
  keys,
  ids,
  logger,
  directory,
}: {
  readonly database: Database<AuditLogTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** The login service's names; undefined when none is set up, and people are named from the kept copy. */
  readonly directory: DirectoryNames | undefined;
}): AuditLog {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: AuditLogRefused });
  return {
    async page(orgId, asked, correlationId) {
      const read = await work.answered(orgId, correlationId, async (tx, states) => ({
        outcome: 'page' as const,
        ...(await heldLogPage(tx, states, keys, orgId, asked)),
      }));
      if (read.outcome === 'refused') return read;
      const namer = createActorNamer({ directory, logger: logger.child({ correlationId }) });
      return { ...read, names: await namer.namesOf(actorsOf(read.events), read.held) };
    },
  };
}

/** Who the log's events can be by. */
export const ACTOR_TYPES = ['user', 'agent', 'system'] as const satisfies readonly ActorType[];

/** An actor to filter to, as asked: a person's or an agent's UUID, or a part of Agent X by its process name. */
export const ACTOR_ASKED_ID = z.string().max(64);

/** A whole number as the log's sequence names it, in text: JSON numbers can't hold every one. */
export const SEQ = z.string().regex(/^[1-9][0-9]{0,18}$/);

const LOG_EVENT = z
  .object({
    seq: SEQ.describe('Its place in the organisation’s chain, from 1.'),
    id: z.uuid().describe('The event, by its ID.'),
    recordedAt: z.iso.datetime().describe('When it was recorded.'),
    actor: z
      .object({
        type: z.enum(ACTOR_TYPES).describe('A person, an AI agent, or Agent X itself.'),
        id: z.string().describe('Who, by their Agent X ID (or the system part that acted).'),
        name: z
          .string()
          .nullable()
          .describe('Their name: a person’s, an agent’s, or Agent X’s part; null when none is known.'),
        email: z
          .string()
          .nullable()
          .describe('A person’s verified email address; null for anyone else, or when none is known.'),
        shownFrom: z
          .enum(SHOWN_FROM)
          .nullable()
          .describe(
            'Where the name was found: `login_service` (it gave the name or email as they are now; the kept copy fills what it lacks), `kept_copy` (as at their latest sign-in, when the login service couldn’t answer or no longer has them), `agent` or `agent_x`; null for neither.',
          ),
      })
      .describe('Who did it.'),
    action: z.string().describe('What was done, such as `mandate.accepted`.'),
    subject: z
      .object({
        type: z.string().describe('The kind of record it was about.'),
        id: z.string().describe('The record, by its ID.'),
        version: z.int().describe('The record’s version it made or read.'),
      })
      .describe('What it was about.'),
    details: z
      .array(
        z.object({
          name: z.string().describe('The fact’s name, such as `overLimit`.'),
          value: z.union([z.string(), z.number(), z.boolean(), z.null()]).describe('Its value as sealed.'),
        }),
      )
      .describe(
        'Every fact sealed with it, by name: each choice and its statement version, a step-up’s evidence, and more.',
      ),
    hash: z.string().describe('Its hash in the chain, hex.'),
    prevHash: z.string().describe('The hash of the event before it in the chain, hex: what links it there.'),
  })
  .register(API_SCHEMAS, { id: 'AuditLogEvent', description: 'One signed event of the organisation’s audit log.' });

const PAGE_SCHEMA = {
  summary: 'Your organisation’s audit log: every signed event, newest first',
  querystring: z
    .strictObject({
      from: z.iso.datetime().describe('Events recorded at or after it.'),
      to: z.iso.datetime().describe('Events recorded before it.'),
      actions: z
        .string()
        .optional()
        .describe(`Only these actions, comma-separated, at most ${String(MOST_ACTIONS_FILTERED)}.`),
      actorType: z.enum(ACTOR_TYPES).optional().describe('Only events by this kind of actor; with `actorId`.'),
      actorId: ACTOR_ASKED_ID.optional().describe(
        'Only events by this actor: a person’s or an agent’s Agent X ID, or a part of Agent X by name; with `actorType`.',
      ),
      before: SEQ.optional().describe('The page starts before this event: the page before’s `next`.'),
      limit: z.coerce
        .number()
        .int()
        .min(1)
        .max(MOST_LOG_EVENTS_A_PAGE)
        .optional()
        .describe(
          `How many at most, 1 to ${String(MOST_LOG_EVENTS_A_PAGE)}; all ${String(MOST_LOG_EVENTS_A_PAGE)} unless fewer are asked for.`,
        ),
    })
    .superRefine((query, context) => {
      if (new Date(query.from).getTime() >= new Date(query.to).getTime()) {
        context.addIssue({ code: 'custom', message: 'the range starts before it ends' });
      }
      const actions = query.actions?.split(',') ?? [];
      if (actions.length > MOST_ACTIONS_FILTERED || !actions.every((action) => actionProblems(action).length === 0)) {
        context.addIssue({ code: 'custom', message: 'actions are event names, comma-separated, 20 at most' });
      }
      const { actorType, actorId } = query;
      if ((actorType === undefined) !== (actorId === undefined)) {
        context.addIssue({ code: 'custom', message: 'an actor is named by actorType and actorId together' });
      } else if (actorType !== undefined && actorId !== undefined) {
        if (actorProblems({ type: actorType, id: actorId }).length > 0) {
          context.addIssue({ code: 'custom', message: 'actorId is a UUID, or for system a process name' });
        }
      }
    }),
  response: {
    200: z
      .object({
        events: z.array(LOG_EVENT).describe('The events, newest first.'),
        next: SEQ.nullable().describe('The event to start the next page before (`before`); null at the end.'),
      })
      .describe('A page of the log, each event checked whole.'),
  },
};

/** An event as the page shows it: its facts as name/value pairs, the platform's own seals left out. */
const shownOf = (logged: LogEvent, names: ReadonlyMap<string, ActorName>) => ({
  ...eventShown(logged, names),
  details: factsShown(logged.event.details).map(([name, value]) => ({ name, value })),
});

/** The log's route. Without `log` it is still documented, and no one reaches it. */
export function registerAuditLog(app: FastifyInstance, { log }: { log: AuditLog | undefined }): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get('/v1/audit-log', { schema: PAGE_SCHEMA, config: { access: ['admin'] } }, async (request, reply) => {
    const { orgId } = memberInSessionOf(request);
    const { from, to, actions, actorType, actorId, before, limit } = request.query;
    const page = await need(log).page(
      orgId,
      {
        from: new Date(from),
        to: new Date(to),
        actions: actions?.split(','),
        actor:
          actorType === undefined || actorId === undefined ? undefined : actorAsKept({ type: actorType, id: actorId }),
        beforeSeq: before === undefined ? undefined : BigInt(before),
        limit: limit ?? MOST_LOG_EVENTS_A_PAGE,
      },
      request.id,
    );
    if (page.outcome === 'refused') return answerRefusal(page, request, reply);
    return { events: page.events.map((event) => shownOf(event, page.names)), next: page.next?.toString() ?? null };
  });
}

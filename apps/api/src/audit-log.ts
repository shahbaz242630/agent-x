// The organisation's audit log, for its admins (Phase 3 E10a; partner rule
// S119, "nothing on our platform goes without log; logs available for both
// user and us"; decision 24: admins only).
//
// - `GET /v1/audit-log?from&to[&actions][&before][&limit]`: every signed event
//   of the organisation recorded in [from, to), of the actions named, newest
//   first, a page at most MOST_LOG_EVENTS_A_PAGE: who (the actor), what (the
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
// Reading a page isn't itself logged (decision 24: a download is, E10b).
import type { LogEvent, LogPageToRead } from '@agentx/core/modules/audit';
import { actionProblems, type IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
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
const MOST_ACTIONS_FILTERED = 20;

/** The details a signed state's event carries that are the platform's seal, not the organisation's record. */
const SEALS_NOT_SHOWN: ReadonlySet<string> = new Set(['stateFingerprint', 'stateKeyVersion']);

class AuditLogRefused extends UseCaseRefused {}

export type LogPageAnswer =
  { readonly outcome: 'page'; readonly events: readonly LogEvent[]; readonly next: bigint | null } | Refused;

export interface AuditLog {
  page(orgId: string, asked: LogPageToRead, correlationId: string): Promise<LogPageAnswer>;
}

export function createAuditLog({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<UseCaseTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): AuditLog {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: AuditLogRefused });
  return {
    async page(orgId, asked, correlationId) {
      return work.answered(orgId, correlationId, async (tx, states) => {
        const read = await states.logPageOf(tx, orgId, asked);
        if (read.outcome === 'tampered') throw new AuditLogRefused(503, 'INTEGRITY_FAILED');
        return { outcome: 'page' as const, events: read.events, next: read.next };
      });
    },
  };
}

/** A whole number as the log's sequence names it, in text: JSON numbers can't hold every one. */
const SEQ = z.string().regex(/^[1-9][0-9]{0,18}$/);

const LOG_EVENT = z
  .object({
    seq: SEQ.describe('Its place in the organisation’s chain, from 1.'),
    id: z.uuid().describe('The event, by its ID.'),
    recordedAt: z.iso.datetime().describe('When it was recorded.'),
    actor: z
      .object({
        type: z.enum(['user', 'agent', 'system']).describe('A person, an AI agent, or Agent X itself.'),
        id: z.string().describe('Who, by their Agent X ID (or the system part that acted).'),
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

/** An event as the page shows it: the platform's own seals left out. */
const shownOf = ({ seq, id, recordedAt, event, hash, prevHash }: LogEvent) => ({
  seq: seq.toString(),
  id,
  recordedAt: recordedAt.toISOString(),
  actor: event.actor,
  action: event.action,
  subject: event.subject,
  details: Object.entries(event.details)
    .filter(([name]) => !SEALS_NOT_SHOWN.has(name))
    .map(([name, value]) => ({ name, value })),
  hash,
  prevHash,
});

/** The log's route. Without `log` it is still documented, and no one reaches it. */
export function registerAuditLog(app: FastifyInstance, { log }: { log: AuditLog | undefined }): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get('/v1/audit-log', { schema: PAGE_SCHEMA, config: { access: ['admin'] } }, async (request, reply) => {
    const { orgId } = memberInSessionOf(request);
    const { from, to, actions, before, limit } = request.query;
    const page = await need(log).page(
      orgId,
      {
        from: new Date(from),
        to: new Date(to),
        actions: actions?.split(','),
        beforeSeq: before === undefined ? undefined : BigInt(before),
        limit: limit ?? MOST_LOG_EVENTS_A_PAGE,
      },
      request.id,
    );
    if (page.outcome === 'refused') return answerRefusal(page, request, reply);
    return { events: page.events.map(shownOf), next: page.next?.toString() ?? null };
  });
}

// Resets of a member's lost second factor (ADR-003 §4, ADR-012 §8;
// SEC-OPS-04; B6-3b): admins only, in the organisation the request names.
// An admin asks for another member, signs in again with a passkey to send it
// to the organisation's registered contacts that count, one of whom confirms
// it by the link they are emailed (the public route, B6-3b-3); the factor is
// removed after the cooling-off (B6-3c). Any admin may cancel it until then.
//
// 1. `GET /v1/factor-resets`: every reset of the organisation, open or not.
// 2. `POST /v1/members/{id}/factor-reset` keeps it as a DRAFT: 202 with the
//    reset and the step-up to sign in again for, at
//    `GET /v1/auth/step-up?challenge=…`.
// 3. `POST /v1/factor-resets/{id}/confirm`, once signed in again, sends it to
//    the contacts: 200, AWAITING_CONTACT.
// 4. `POST /v1/factor-resets/{id}/cancel`: CANCELLED, with no step-up
//    (stopping is never gated).
// Refusals: 409 OWN_RESET for the admin's own; 409 MEMBER_DEACTIVATED; 409
// MEMBER_ELSEWHERE for a member of another organisation too (the runbook);
// 409 NO_COUNTING_CONTACTS; 409 RESET_OPEN while one is under way; 409
// RESET_CLOSED for a reset sent, ended or lapsed; 409 TOO_MANY_RESETS; 404
// for a member or reset not in the organisation; 403 STEP_UP_FAILED for
// another change than the one signed in again for; 503 INTEGRITY_FAILED when
// a record it rests on can't be verified. The use case is the identity
// module's reset-changes.ts.
import {
  FACTOR_RESET,
  RESET_ASK_CONFIRM_OPERATION,
  RESET_ASK_OPERATION,
  RESET_CANCEL_OPERATION,
  type ResetChanges,
  type ResetChangeWrite,
} from '@agentx/core/modules/identity';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';

/** The most a body that names nothing may be. */
const NOTHING_BODY_LIMIT = 64;

const RESET = z
  .object({
    id: z.uuid().describe('The reset, by its ID.'),
    status: z
      .enum(FACTOR_RESET.states)
      .describe(
        'DRAFT until the admin who asked signs in again and sends it; AWAITING_CONTACT until a registered contact confirms it; COOLING_OFF until the second factor is removed; then COMPLETED. CANCELLED by an admin, or EXPIRED when no contact confirmed it in time.',
      ),
    person: z.uuid().describe('The membership of the person whose second factor it resets.'),
    requestedBy: z.uuid().describe('The membership of the admin who asked for it.'),
    expiresAt: z.iso
      .datetime()
      .describe('When it lapses if no registered contact has confirmed it: 72 hours after it was asked.'),
    confirmedBy: z.uuid().nullable().describe('The registered contact who confirmed it; null until one has.'),
    coolingOffUntil: z.iso
      .datetime()
      .nullable()
      .describe(
        'When the second factor is removed, unless an admin cancels first: 24 hours after a contact confirmed. Null until then.',
      ),
  })
  .register(API_SCHEMAS, { id: 'FactorReset', description: "A reset of a member's lost second factor." });

const ID = z.object({ id: z.uuid().describe('The reset, by its ID.') });
const MEMBER_ID = z.object({ id: z.uuid().describe('The membership of the person whose second factor is lost.') });
const NOTHING = z
  .strictObject({})
  // Fastify gives a request sent with no body a null one.
  .nullish()
  .describe('Nothing. An empty object, or no body at all.');

const CHANGED = z
  .object({ reset: RESET })
  .register(API_SCHEMAS, { id: 'FactorResetChanged', description: 'The reset, as it now stands.' });

const LIST_SCHEMA = {
  summary: "Your organisation's resets of lost second factors",
  response: {
    200: z.object({ resets: z.array(RESET) }).register(API_SCHEMAS, {
      id: 'FactorResets',
      description: "Every reset of the organisation's members' second factors, open or not, in order of ID.",
    }),
  },
};

const ASK_SCHEMA = {
  summary: "Ask to reset a member's lost second factor",
  params: MEMBER_ID,
  body: NOTHING,
  response: {
    202: z
      .object({
        reset: RESET,
        stepUpChallengeId: z
          .uuid()
          .optional()
          .describe(
            'While the reset is a DRAFT: the step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before sending it to the registered contacts.',
          ),
      })
      .register(API_SCHEMAS, {
        id: 'FactorResetDrafted',
        description: 'The reset kept as a draft, waiting for the admin who asked to sign in again and send it.',
      }),
  },
};

const CONFIRM_SCHEMA = {
  summary: 'Send a reset to the registered contacts, once signed in again for it',
  params: ID,
  body: NOTHING,
  response: { 200: CHANGED },
};

const CANCEL_SCHEMA = {
  summary: 'Cancel a reset of a second factor',
  params: ID,
  body: NOTHING,
  response: { 200: CHANGED },
};

type Reset = Extract<ResetChangeWrite, { outcome: 'written' }>['reset'];

/** A reset as the API answers it. */
const resetOf = (reset: Reset) => ({
  id: reset.id,
  status: reset.status,
  person: reset.person,
  requestedBy: reset.requestedBy,
  expiresAt: reset.expiresAt.toISOString(),
  confirmedBy: reset.confirmedBy,
  coolingOffUntil: reset.coolingOffUntil?.toISOString() ?? null,
});

/** The route's own caller: an admin the access hook found, with their session. The hooks let no one else through. */
function adminOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('a factor reset route ran without an admin');
  return { orgId: member.orgId, userId: person.userId, sessionId: person.sessionId };
}

/** Answers a write that wrote nothing: refused, or its key in use for another request or still being done. */
const refusalOf = (
  written: Exclude<ResetChangeWrite, { outcome: 'written' }>,
  request: FastifyRequest,
  reply: FastifyReply,
) =>
  written.outcome === 'refused'
    ? sendErrorBody(reply, written.status, written.code, request.id)
    : answerRefusedWrite(written, request, reply);

/**
 * The resets' routes. `changes` does them; without it the routes are still
 * documented, and no one reaches them, as no one holds a role.
 */
export function registerFactorResets(app: FastifyInstance, changes: ResetChanges | undefined): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const changesOf = (): ResetChanges => {
    if (changes === undefined) throw new Error('the factor reset routes ran without their writes');
    return changes;
  };

  routes.get('/v1/factor-resets', { schema: LIST_SCHEMA, config: { access: ['admin'] } }, async (request, reply) => {
    const admin = adminOf(request);
    const list = await changesOf().list(admin.orgId, request.id);
    if (list.outcome === 'refused') return sendErrorBody(reply, list.status, list.code, request.id);
    return { resets: list.resets.map(resetOf) };
  });

  routes.post(
    '/v1/members/:id/factor-reset',
    {
      schema: ASK_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: ['admin'], operation: RESET_ASK_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await changesOf().ask(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.id,
      );
      if (written.outcome !== 'written') return refusalOf(written, request, reply);
      const { reset, stepUpChallengeId } = written;
      return reply.code(202).send({
        reset: resetOf(reset),
        ...(stepUpChallengeId !== undefined && { stepUpChallengeId }),
      });
    },
  );

  routes.post(
    '/v1/factor-resets/:id/confirm',
    {
      schema: CONFIRM_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: ['admin'], operation: RESET_ASK_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await changesOf().confirm(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.id,
      );
      if (written.outcome !== 'written') return refusalOf(written, request, reply);
      return { reset: resetOf(written.reset) };
    },
  );

  routes.post(
    '/v1/factor-resets/:id/cancel',
    {
      schema: CANCEL_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: ['admin'], operation: RESET_CANCEL_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await changesOf().cancel(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.id,
      );
      if (written.outcome !== 'written') return refusalOf(written, request, reply);
      return { reset: resetOf(written.reset) };
    },
  );
}

// The organisation's integrity hold, for its admin (ADR-012 §2, SEC-DB-10's
// clearing; B3+-2b-2): once anything of the organisation's is found tampered
// with, its hand-offs stop until its admin clears the hold, with step-up,
// after the investigation is recorded (B3+-2b-2; clearing B3+-2c-2).
//
// - `GET /v1/integrity-hold`: the hold, CLEAR or HELD, since when, and for a
//   HELD one the tamper sign and the kind of record it was found on.
// - `POST /v1/integrity-hold/investigations`: records what the investigation
//   concluded (CAUSE_REMOVED or NO_TAMPERING) and the incident's reference,
//   where the account is kept, outside Agent X: an audit row holds short
//   facts, never prose. 201 with the investigation.
// - `POST /v1/integrity-hold/clear`, naming the investigation: opens a step-up
//   bound to clearing exactly this HELD state after exactly that
//   investigation: 202 with its ID, for the console to send the admin to
//   `GET /v1/auth/step-up?challenge=…`.
// - `…/clear/confirm` with the same investigation and the step-up's ID, once
//   the admin has signed in again: every record of the organisation is
//   verified first, then the hold cleared: 200 with the hold as it now is.
// Admins only, in the organisation the request names. Refusals: 409
// NOT_ON_HOLD while the hold is CLEAR; 409 NO_INVESTIGATION without an
// investigation of the hold as it stands; 403 STEP_UP_FAILED for another
// step-up, or one begun for a HELD state the hold has since left (cleared and
// set again); 409 HOLD_CHANGED when it is cleared while this clearing is made;
// 503 INTEGRITY_FAILED when the hold, or any record, can't be verified (the
// hold stays). The use cases are the identity module's hold-investigations.ts
// and hold-clearing.ts; the hold is the audit module's.
import {
  CLEAR_CONFIRM_OPERATION,
  CLEAR_OPERATION,
  type ClearingWrite,
  type HoldClearings,
  type HoldInvestigations,
  type HoldShown,
  INVESTIGATE_OPERATION,
  type InvestigationWrite,
} from '@agentx/core/modules/identity';
import {
  INVESTIGATION_CONCLUSIONS,
  INVESTIGATION_REFERENCE_MAX,
  isIncidentReference,
} from '@agentx/core/modules/audit';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';

/** The most an investigation's body may be: a conclusion and a reference, with room to spare. */
const INVESTIGATION_BODY_LIMIT = 256;

const HOLD = z
  .object({
    status: z.enum(['CLEAR', 'HELD']).describe("CLEAR, or HELD: the organisation's hand-offs are stopped."),
    version: z.int().min(1).describe("The hold's version: each time it is set or cleared, it moves on by one."),
    since: z.iso.datetime().describe('When it became CLEAR or HELD.'),
    reason: z
      .string()
      .nullable()
      .describe('For a HELD one, how the tampering showed (seal, deleted, chain, and so on); otherwise null.'),
    foundOn: z
      .string()
      .nullable()
      .describe('For a HELD one, the kind of record it was found on (membership, audit_chain, …); otherwise null.'),
  })
  .register(API_SCHEMAS, {
    id: 'IntegrityHold',
    description: "The organisation's integrity hold: while HELD, nothing is handed off.",
  });

const INVESTIGATION = z
  .object({
    id: z.uuid().describe('The investigation, by its ID.'),
    holdVersion: z.int().min(1).describe('The version of the HELD hold it investigated.'),
    conclusion: z.enum(INVESTIGATION_CONCLUSIONS).describe('What the investigation concluded.'),
    reference: z.string().describe("The incident's reference, where the account is kept."),
    recordedBy: z.uuid().describe('Who recorded it, by their Agent X ID.'),
    recordedAt: z.iso.datetime().describe('When it was recorded.'),
  })
  .register(API_SCHEMAS, {
    id: 'HoldInvestigation',
    description: 'An investigation of the integrity hold, which clearing it rests on.',
  });

const SHOW_SCHEMA = {
  summary: "Your organisation's integrity hold",
  response: { 200: z.object({ hold: HOLD }).describe('The hold, as its newest record holds it.') },
};

const RECORD_SCHEMA = {
  summary: 'Record the investigation of the integrity hold',
  body: z
    .strictObject({
      conclusion: z
        .enum(INVESTIGATION_CONCLUSIONS)
        .describe('CAUSE_REMOVED: the cause was found and taken away. NO_TAMPERING: a fault raised the alarm.'),
      reference: z
        .string()
        .max(INVESTIGATION_REFERENCE_MAX)
        .refine(isIncidentReference, 'a letter or digit, then letters, digits, ".", "_" or "-", 64 at most')
        .describe("The incident's reference, a ticket's ID: never prose, which stays with the incident."),
    })
    .describe('What the investigation concluded, and where its account is kept.'),
  response: { 201: z.object({ investigation: INVESTIGATION }).describe('The investigation, as recorded.') },
};

/** The most a clearing's body may be: an investigation and a step-up's ID, with room to spare. */
const CLEARING_BODY_LIMIT = 192;

const INVESTIGATION_ID = z.uuid().describe('The investigation of the hold as it now stands, by its ID.');

const ASKED = z
  .object({
    stepUpChallengeId: z
      .uuid()
      .describe('The step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming.'),
  })
  .register(API_SCHEMAS, {
    id: 'HoldClearingAsked',
    description: 'Clearing the integrity hold, waiting for the admin to sign in again.',
  });

const CLEAR_SCHEMA = {
  summary: 'Ask to clear the integrity hold',
  body: z.strictObject({ investigationId: INVESTIGATION_ID }).describe('The investigation the clearing rests on.'),
  response: { 202: ASKED },
};

const CLEAR_CONFIRM_SCHEMA = {
  summary: 'Clear the integrity hold, once signed in again for it',
  body: z
    .strictObject({
      investigationId: INVESTIGATION_ID,
      stepUpChallengeId: z.uuid().describe('The step-up the ask answered with, signed in again for.'),
    })
    .describe('The same investigation as asked with, and the step-up signed in again for.'),
  response: { 200: z.object({ hold: HOLD }).describe('The hold, as the clearing left it.') },
};

/** The route's own caller: an admin the access hook found, with their session. The hooks let no one else through. */
function adminOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('an integrity hold route ran without an admin');
  return { orgId: member.orgId, userId: person.userId, sessionId: person.sessionId };
}

/** The hold as the API answers it. */
const holdOf = (hold: Extract<HoldShown, { outcome: 'shown' }>['hold']) => ({
  status: hold.outcome === 'held' ? ('HELD' as const) : ('CLEAR' as const),
  version: hold.version,
  since: hold.since.toISOString(),
  reason: hold.outcome === 'held' ? hold.reason : null,
  foundOn: hold.outcome === 'held' ? hold.foundOn : null,
});

/** Answers a refusal; undefined for the route to answer. */
const refusalOf = (
  answer: HoldShown | InvestigationWrite | ClearingWrite,
  request: FastifyRequest,
  reply: FastifyReply,
) => {
  if (answer.outcome === 'refused') return sendErrorBody(reply, answer.status, answer.code, request.id);
  if (answer.outcome === 'conflict' || answer.outcome === 'busy') return answerRefusedWrite(answer, request, reply);
  return undefined;
};

/**
 * The integrity hold's routes. `investigations` does them; without it the
 * routes are still documented, and no one reaches them, as no one holds a
 * role.
 */
export function registerIntegrityHold(
  app: FastifyInstance,
  {
    investigations,
    clearings,
  }: { investigations: HoldInvestigations | undefined; clearings: HoldClearings | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const investigationsOf = (): HoldInvestigations => {
    if (investigations === undefined) throw new Error('the integrity hold routes ran without their use case');
    return investigations;
  };
  const clearingsOf = (): HoldClearings => {
    if (clearings === undefined) throw new Error('the integrity hold clearing routes ran without their use case');
    return clearings;
  };

  routes.get('/v1/integrity-hold', { schema: SHOW_SCHEMA, config: { access: ['admin'] } }, async (request, reply) => {
    const { orgId, userId } = adminOf(request);
    const shown = await investigationsOf().show({ orgId, userId }, request.id);
    const refused = refusalOf(shown, request, reply);
    if (refused !== undefined || shown.outcome !== 'shown') return refused;
    return { hold: holdOf(shown.hold) };
  });

  routes.post(
    '/v1/integrity-hold/investigations',
    {
      schema: RECORD_SCHEMA,
      bodyLimit: INVESTIGATION_BODY_LIMIT,
      config: { access: ['admin'], operation: INVESTIGATE_OPERATION },
    },
    async (request, reply) => {
      const { orgId, userId } = adminOf(request);
      const written = await investigationsOf().record(
        { orgId, userId },
        idempotentRequest(request, orgId),
        request.body,
        request.id,
      );
      const refused = refusalOf(written, request, reply);
      if (refused !== undefined || written.outcome !== 'written') return refused;
      const { investigation } = written;
      return reply.code(201).send({
        investigation: {
          id: investigation.id,
          holdVersion: investigation.holdVersion,
          conclusion: investigation.conclusion,
          reference: investigation.reference,
          recordedBy: investigation.recordedBy,
          recordedAt: investigation.recordedAt.toISOString(),
        },
      });
    },
  );

  routes.post(
    '/v1/integrity-hold/clear',
    {
      schema: CLEAR_SCHEMA,
      bodyLimit: CLEARING_BODY_LIMIT,
      config: { access: ['admin'], operation: CLEAR_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await clearingsOf().ask(
        admin,
        idempotentRequest(request, admin.orgId),
        request.body.investigationId,
        request.id,
      );
      const refused = refusalOf(written, request, reply);
      if (refused !== undefined) return refused;
      if (written.outcome !== 'asked') throw new Error('an ask answered without its step-up');
      return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    },
  );

  routes.post(
    '/v1/integrity-hold/clear/confirm',
    {
      schema: CLEAR_CONFIRM_SCHEMA,
      bodyLimit: CLEARING_BODY_LIMIT,
      config: { access: ['admin'], operation: CLEAR_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await clearingsOf().confirm(
        admin,
        idempotentRequest(request, admin.orgId),
        request.body.investigationId,
        request.body.stepUpChallengeId,
        request.id,
      );
      const refused = refusalOf(written, request, reply);
      if (refused !== undefined) return refused;
      if (written.outcome !== 'cleared') throw new Error('a clearing answered without the hold');
      return { hold: holdOf(written.hold) };
    },
  );
}

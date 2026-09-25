// Changing a member's role, or deactivating them (PRD §7.1
// `POST /v1/members/{id}/role`, `POST /v1/members/{id}/deactivate`; B4-5b):
// admins only, each with a step-up (ADR-003 §8), in the organisation the
// request names. Every session the member has ends with the change
// (SEC-HA-10).
//
// 1. `POST /v1/members/{id}/role` with the new role, or
//    `POST /v1/members/{id}/deactivate`, opens a step-up bound to exactly
//    that change on the membership as it is: 202 with its ID, for the
//    console to send the admin to `GET /v1/auth/step-up?challenge=…`.
// 2. `…/role/confirm` with the same role and the step-up's ID, or
//    `…/deactivate/confirm` with the step-up's ID, once the admin has signed
//    in again, makes the change: 200 with the member as they now are.
// Refusals: 409 OWN_MEMBERSHIP for the admin's own membership (another admin
// must, so the organisation always keeps an admin); 409 ROLE_UNCHANGED; 409
// MEMBER_DEACTIVATED; 404 for a membership not in the organisation; 403
// STEP_UP_FAILED for another change than the one signed in again for, or one
// the membership has moved on from since; 503 INTEGRITY_FAILED when a record
// it rests on can't be verified. The use case is the identity module's
// membership-changes.ts.
import {
  DEACTIVATE_CONFIRM_OPERATION,
  DEACTIVATE_OPERATION,
  type MembershipChange,
  type MembershipChanges,
  type MembershipChangeWrite,
  ROLE_CONFIRM_OPERATION,
  ROLE_OPERATION,
} from '@agentx/core/modules/identity';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';
import { MEMBER, memberOf } from './members.ts';

/** The most an ask's body may be: a role, with room to spare. */
const ASK_BODY_LIMIT = 128;
/** The most a confirmation's body may be: a role and a challenge's ID, with room to spare. */
const CONFIRM_BODY_LIMIT = 192;

const ROLE = z.enum(['admin', 'approver', 'developer', 'viewer']).describe('The role the member is to have.');
const MEMBERSHIP_ID = z.object({ id: z.uuid().describe('The membership, by its ID.') });
const STEP_UP = z.uuid().describe('The step-up the ask answered with, signed in again for.');
const NOTHING = z
  .strictObject({})
  // Fastify gives a request sent with no body a null one.
  .nullish()
  .describe('Nothing. An empty object, or no body at all.');

const ASKED = z
  .object({
    stepUpChallengeId: z
      .uuid()
      .describe('The step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming.'),
  })
  .register(API_SCHEMAS, {
    id: 'MemberChangeAsked',
    description:
      "A change to a member, waiting for the admin to sign in again. Every one of the member's sessions ends when it is made.",
  });

const CHANGED = z
  .object({ member: MEMBER })
  .register(API_SCHEMAS, { id: 'MemberChanged', description: 'The member, as the change left them.' });

const ROLE_SCHEMA = {
  summary: "Ask to change a member's role",
  params: MEMBERSHIP_ID,
  body: z.strictObject({ role: ROLE }).describe('The new role.'),
  response: { 202: ASKED },
};

const ROLE_CONFIRM_SCHEMA = {
  summary: "Change a member's role, once signed in again for it",
  params: MEMBERSHIP_ID,
  body: z
    .strictObject({ role: ROLE, stepUpChallengeId: STEP_UP })
    .describe('The same role as asked for, and the step-up signed in again for.'),
  response: { 200: CHANGED },
};

const DEACTIVATE_SCHEMA = {
  summary: 'Ask to deactivate a member',
  params: MEMBERSHIP_ID,
  body: NOTHING,
  response: { 202: ASKED },
};

const DEACTIVATE_CONFIRM_SCHEMA = {
  summary: 'Deactivate a member, once signed in again for it',
  params: MEMBERSHIP_ID,
  body: z.strictObject({ stepUpChallengeId: STEP_UP }).describe('The step-up signed in again for.'),
  response: { 200: CHANGED },
};

/** The route's own caller: an admin the access hook found, with their session. The hooks let no one else through. */
function adminOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('a member change route ran without an admin');
  return { orgId: member.orgId, userId: person.userId, sessionId: person.sessionId };
}

/** Answers a refusal; undefined for the route to answer. */
const refusalOf = (written: MembershipChangeWrite, request: FastifyRequest, reply: FastifyReply) => {
  if (written.outcome === 'refused') return sendErrorBody(reply, written.status, written.code, request.id);
  if (written.outcome === 'conflict' || written.outcome === 'busy') return answerRefusedWrite(written, request, reply);
  return undefined;
};

/**
 * The routes that change a member. `changes` does them; without it the
 * routes are still documented, and no one reaches them, as no one holds a
 * role.
 */
export function registerMemberChanges(app: FastifyInstance, changes: MembershipChanges | undefined): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const changesOf = (): MembershipChanges => {
    if (changes === undefined) throw new Error('the member change routes ran without their writes');
    return changes;
  };

  const ask = async (request: FastifyRequest, reply: FastifyReply, id: string, change: MembershipChange) => {
    const admin = adminOf(request);
    const written = await changesOf().ask(admin, idempotentRequest(request, admin.orgId), id, change, request.id);
    const refused = refusalOf(written, request, reply);
    if (refused !== undefined) return refused;
    if (written.outcome !== 'asked') throw new Error('an ask answered without its challenge');
    return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
  };

  const confirm = async (
    request: FastifyRequest,
    reply: FastifyReply,
    id: string,
    change: MembershipChange,
    stepUpChallengeId: string,
  ) => {
    const admin = adminOf(request);
    const written = await changesOf().confirm(
      admin,
      idempotentRequest(request, admin.orgId),
      id,
      change,
      stepUpChallengeId,
      request.id,
    );
    const refused = refusalOf(written, request, reply);
    if (refused !== undefined) return refused;
    if (written.outcome !== 'written') throw new Error('a confirmation answered without its member');
    return { member: memberOf(written.member) };
  };

  routes.post(
    '/v1/members/:id/role',
    { schema: ROLE_SCHEMA, bodyLimit: ASK_BODY_LIMIT, config: { access: ['admin'], operation: ROLE_OPERATION } },
    (request, reply) => ask(request, reply, request.params.id, { kind: 'role', role: request.body.role }),
  );

  routes.post(
    '/v1/members/:id/role/confirm',
    {
      schema: ROLE_CONFIRM_SCHEMA,
      bodyLimit: CONFIRM_BODY_LIMIT,
      config: { access: ['admin'], operation: ROLE_CONFIRM_OPERATION },
    },
    (request, reply) =>
      confirm(
        request,
        reply,
        request.params.id,
        { kind: 'role', role: request.body.role },
        request.body.stepUpChallengeId,
      ),
  );

  routes.post(
    '/v1/members/:id/deactivate',
    {
      schema: DEACTIVATE_SCHEMA,
      bodyLimit: ASK_BODY_LIMIT,
      config: { access: ['admin'], operation: DEACTIVATE_OPERATION },
    },
    (request, reply) => ask(request, reply, request.params.id, { kind: 'deactivate' }),
  );

  routes.post(
    '/v1/members/:id/deactivate/confirm',
    {
      schema: DEACTIVATE_CONFIRM_SCHEMA,
      bodyLimit: CONFIRM_BODY_LIMIT,
      config: { access: ['admin'], operation: DEACTIVATE_CONFIRM_OPERATION },
    },
    (request, reply) =>
      confirm(request, reply, request.params.id, { kind: 'deactivate' }, request.body.stepUpChallengeId),
  );
}

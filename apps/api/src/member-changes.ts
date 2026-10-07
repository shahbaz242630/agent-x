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
  ROLE_CONFIRM_OPERATION,
  ROLE_OPERATION,
} from '@agentx/core/modules/identity';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { MEMBER, memberOf } from './members.ts';
import { NOTHING, STEP_UP_CONFIRM, STEP_UP_SIGNED_IN, stepUpAsked } from './route-schemas.ts';

/** The most an ask's body may be: a role, with room to spare. */
const ASK_BODY_LIMIT = 128;
/** The most a confirmation's body may be: a role and a challenge's ID, with room to spare. */
const CONFIRM_BODY_LIMIT = 192;

const ROLE = z.enum(['admin', 'approver', 'developer', 'viewer']).describe('The role the member is to have.');
const MEMBERSHIP_ID = z.object({ id: z.uuid().describe('The membership, by its ID.') });

const ASKED = stepUpAsked(
  'MemberChangeAsked',
  "A change to a member, waiting for the admin to sign in again. Every one of the member's sessions ends when it is made.",
);

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
    .strictObject({ role: ROLE, stepUpChallengeId: STEP_UP_SIGNED_IN })
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
  body: STEP_UP_CONFIRM,
  response: { 200: CHANGED },
};

/**
 * The routes that change a member. `changes` does them; without it the
 * routes are still documented, and no one reaches them, as no one holds a
 * role.
 */
export function registerMemberChanges(app: FastifyInstance, changes: MembershipChanges | undefined): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  const ask = async (request: FastifyRequest, reply: FastifyReply, id: string, change: MembershipChange) => {
    const admin = memberInSessionOf(request);
    const written = await need(changes).ask(admin, idempotentRequest(request, admin.orgId), id, change, request.id);
    return answerAsked(written, request, reply);
  };

  const confirm = async (
    request: FastifyRequest,
    reply: FastifyReply,
    id: string,
    change: MembershipChange,
    stepUpChallengeId: string,
  ) => {
    const admin = memberInSessionOf(request);
    const written = await need(changes).confirm(
      admin,
      idempotentRequest(request, admin.orgId),
      id,
      change,
      stepUpChallengeId,
      request.id,
    );
    const refused = answerRefusal(written, request, reply);
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

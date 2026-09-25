// Inviting a member (PRD §7.1 `POST /v1/members/invitations`, B4-3b): the
// first write routes, and the first to use the API's idempotency (B2b) and a
// step-up (B3). Only an admin may invite (ADR-003 §8: inviting needs a
// step-up), in the organisation the request names.
//
// 1. `POST /v1/members/invitations` takes the invited address and role, and
//    keeps the invitation as a DRAFT. It answers 202 with the invitation and
//    the step-up challenge opened for it: the console sends the admin to
//    `GET /v1/auth/step-up?challenge=…` to sign in again.
// 2. `POST /v1/members/invitations/{id}/confirm`, once they have, opens it:
//    200 with the invitation and, this once, the link to send the invited
//    person (B5 sends it by email). A replay of the same request answers the
//    invitation without the link, which is kept nowhere: a lost link is a new
//    invitation.
// Refusals: 403 STEP_UP_FAILED when the admin hasn't signed in again for this
// invitation in this session; 409 INVITATION_CLOSED for one confirmed already
// or past its end; 404 for one not in the organisation; 503 INTEGRITY_FAILED
// when a record it rests on can't be verified. The use case itself is
// the identity module's inviting.ts.
import {
  CONFIRM_OPERATION,
  EMAIL_MAX,
  INVITE_OPERATION,
  type InvitationWrite,
  type InvitationWrites,
} from '@agentx/core/modules/identity';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';

/** The most an invitation's body may be: an address and a role, with room to spare. */
const INVITATION_BODY_LIMIT = 1024;

/** The most a confirmation's body may be: it takes none, or an empty object. */
const CONFIRM_BODY_LIMIT = 64;

const ROLE = z.enum(['admin', 'approver', 'developer', 'viewer']);

const INVITATION = z
  .object({
    id: z.uuid().describe('The invitation, by its ID.'),
    role: ROLE.describe('The role the invited person joins with.'),
    status: z
      .enum(['DRAFT', 'OPEN'])
      .describe('DRAFT until the admin who asked signs in again and confirms it; OPEN once confirmed.'),
    expiresAt: z.iso.datetime().describe('When it ends, 72 hours after it was asked for, whatever its status.'),
  })
  .register(API_SCHEMAS, { id: 'Invitation', description: 'An invitation to join the organisation.' });

const ASK_SCHEMA = {
  summary: 'Invite a person to the organisation',
  body: z
    .strictObject({
      email: z
        .email()
        .max(EMAIL_MAX)
        .describe("The invited person's email address: they accept with a login whose verified address is this one."),
      role: ROLE.describe('The role they join with.'),
    })
    .describe('Who to invite, and with which role.'),
  response: {
    202: z
      .object({
        invitation: INVITATION,
        stepUpChallengeId: z
          .uuid()
          .optional()
          .describe(
            'While the invitation is a DRAFT: the step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming it.',
          ),
      })
      .register(API_SCHEMAS, {
        id: 'InvitationDrafted',
        description: 'The invitation kept as a draft, waiting for the admin who asked to sign in again and confirm it.',
      }),
  },
};

const CONFIRM_SCHEMA = {
  summary: 'Confirm an invitation, once signed in again for it',
  params: z.object({ id: z.uuid().describe('The invitation, by its ID.') }),
  body: z
    .strictObject({})
    // Fastify gives a request sent with no body a null one.
    .nullish()
    .describe('Nothing: the invitation names its own step-up. An empty object, or no body at all.'),
  response: {
    200: z
      .object({
        invitation: INVITATION,
        link: z
          .url()
          .optional()
          .describe(
            'The link to send the invited person, shown only in the answer that confirmed the invitation and kept nowhere. A retry of the same request answers without it.',
          ),
      })
      .register(API_SCHEMAS, {
        id: 'InvitationConfirmed',
        description: 'The invitation, open for the invited person.',
      }),
  },
};

/** Where an invitation is accepted: the token in the fragment, which browsers never send to a server or in a Referer. */
const linkFor = (publicOrigin: string, token: string): string => `${publicOrigin}/invitations/accept#token=${token}`;

/** The route's own caller: an admin the access hook found, with their session. The hooks let no one else through. */
function adminOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('an invitation route ran without an admin');
  return { orgId: member.orgId, userId: person.userId, sessionId: person.sessionId };
}

const answerRefusal = (written: InvitationWrite, request: FastifyRequest, reply: FastifyReply) => {
  if (written.outcome === 'refused') return sendErrorBody(reply, written.status, written.code, request.id);
  if (written.outcome === 'conflict' || written.outcome === 'busy') return answerRefusedWrite(written, request, reply);
  return undefined;
};

const invitationOf = (written: Extract<InvitationWrite, { outcome: 'written' }>) => ({
  id: written.invitation.id,
  role: written.invitation.role,
  status: written.invitation.status,
  expiresAt: written.invitation.expiresAt.toISOString(),
});

/**
 * The invitation routes. `writes` does them; without it the routes are still
 * documented, and no one reaches them, as no one holds a role.
 */
export function registerInvitations(
  app: FastifyInstance,
  { writes, publicOrigin }: { writes: InvitationWrites | undefined; publicOrigin: string },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.post(
    '/v1/members/invitations',
    {
      schema: ASK_SCHEMA,
      bodyLimit: INVITATION_BODY_LIMIT,
      config: { access: ['admin'], operation: INVITE_OPERATION },
    },
    async (request, reply) => {
      if (writes === undefined) throw new Error('the invitation routes ran without their writes');
      const admin = adminOf(request);
      const written = await writes.ask(admin, idempotentRequest(request, admin.orgId), request.body, request.id);
      const refused = answerRefusal(written, request, reply);
      if (refused !== undefined || written.outcome !== 'written') return refused;
      return reply.code(202).send({
        invitation: invitationOf(written),
        ...(written.invitation.status === 'DRAFT' && { stepUpChallengeId: written.invitation.stepUpChallengeId }),
      });
    },
  );

  routes.post(
    '/v1/members/invitations/:id/confirm',
    {
      schema: CONFIRM_SCHEMA,
      bodyLimit: CONFIRM_BODY_LIMIT,
      config: { access: ['admin'], operation: CONFIRM_OPERATION },
    },
    async (request, reply) => {
      if (writes === undefined) throw new Error('the invitation routes ran without their writes');
      const admin = adminOf(request);
      const written = await writes.confirm(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.id,
      );
      const refused = answerRefusal(written, request, reply);
      if (refused !== undefined || written.outcome !== 'written') return refused;
      return reply.code(200).send({
        invitation: invitationOf(written),
        ...(written.token !== undefined && { link: linkFor(publicOrigin, written.token) }),
      });
    },
  );
}

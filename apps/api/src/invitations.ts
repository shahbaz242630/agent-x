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
// 3. `POST /v1/invitations/accept` (B4-4c), for any signed-in person, takes
//    the token from the link: the directory names the organisation, the
//    invitation must still be open, and the person's verified email (B4-4a)
//    must be the invited one. A developer or viewer joins now; an admin or
//    approver waits for an existing admin's confirmation (B4-4d). 200 with the
//    organisation and the invitation; 403 INVITATION_INVALID for a token not
//    known or another address alike, 409 INVITATION_CLOSED, 409
//    ALREADY_A_MEMBER.
// 4. B4-4d: an admin or approver who accepted waits for an existing admin
//    (ADR-005 §6). `POST /v1/members/invitations/{id}/approve` opens a
//    step-up bound to who accepted and the role (202 with its ID);
//    `.../approve/confirm` with that ID, once signed in again, adds the
//    membership (200); `.../decline` refuses them (200, no step-up: it grants
//    nothing). Admins only.
// Refusals: 403 STEP_UP_FAILED when the admin hasn't signed in again for this
// invitation in this session; 409 INVITATION_CLOSED for one confirmed already
// or past its end; 404 for one not in the organisation; 503 INTEGRITY_FAILED
// when a record it rests on can't be verified. The use case itself is
// the identity module's inviting.ts.
import {
  ACCEPT_OPERATION,
  type AcceptanceConfirmations,
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  type ConfirmationWrite,
  DECLINE_OPERATION,
  type InvitationAcceptance,
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

/** The most a confirmation's body may be: a challenge's ID, with room to spare. */
const APPROVE_CONFIRM_BODY_LIMIT = 128;

const ROLE = z.enum(['admin', 'approver', 'developer', 'viewer']);

const INVITATION = z
  .object({
    id: z.uuid().describe('The invitation, by its ID.'),
    role: ROLE.describe('The role the invited person joins with.'),
    status: z
      .enum(['DRAFT', 'OPEN', 'AWAITING_CONFIRMATION', 'ACCEPTED', 'DECLINED'])
      .describe(
        'DRAFT until the admin who asked signs in again and confirms it; OPEN once confirmed; ACCEPTED once the invited person has joined; AWAITING_CONFIRMATION while an accepted admin or approver waits for an admin to confirm them, then ACCEPTED or DECLINED.',
      ),
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

/** An invitation's token, as its link carries it: 32 random bytes in base64url. */
const TOKEN = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .describe('The token from the invitation link, after `#token=`.');

/** The most an acceptance's body may be: a token, with room to spare. */
const ACCEPT_BODY_LIMIT = 256;

const ACCEPT_SCHEMA = {
  summary: 'Accept an invitation, signed in with the invited email address',
  body: z.strictObject({ token: TOKEN }).describe('The invitation to accept, by its token.'),
  response: {
    200: z
      .object({
        organizationId: z.uuid().describe('The organisation the invitation is to.'),
        invitation: INVITATION,
      })
      .register(API_SCHEMAS, {
        id: 'InvitationAccepted',
        description:
          'The invitation accepted: ACCEPTED when the person has joined, AWAITING_CONFIRMATION while an admin or approver waits for an admin to confirm them.',
      }),
  },
};

const DECIDED = z
  .object({ invitation: INVITATION })
  .register(API_SCHEMAS, { id: 'InvitationDecided', description: 'The invitation, confirmed or declined.' });

const APPROVE_SCHEMA = {
  summary: "Ask to confirm who accepted an admin's or approver's invitation",
  params: z.object({ id: z.uuid().describe('The invitation, by its ID.') }),
  body: z
    .strictObject({})
    // Fastify gives a request sent with no body a null one.
    .nullish()
    .describe('Nothing. An empty object, or no body at all.'),
  response: {
    202: z
      .object({
        stepUpChallengeId: z
          .uuid()
          .describe('The step-up to sign in again for, at GET /v1/auth/step-up?challenge=..., before confirming.'),
      })
      .register(API_SCHEMAS, {
        id: 'ConfirmationAsked',
        description: 'A confirmation of who accepted, waiting for the admin to sign in again.',
      }),
  },
};

const APPROVE_CONFIRM_SCHEMA = {
  summary: "Confirm who accepted an admin's or approver's invitation, once signed in again for it",
  params: z.object({ id: z.uuid().describe('The invitation, by its ID.') }),
  body: z
    .strictObject({ stepUpChallengeId: z.uuid().describe('The step-up the ask answered with.') })
    .describe('The step-up signed in again for.'),
  response: { 200: DECIDED },
};

const DECLINE_SCHEMA = {
  summary: "Decline who accepted an admin's or approver's invitation",
  params: z.object({ id: z.uuid().describe('The invitation, by its ID.') }),
  body: z.strictObject({}).nullish().describe('Nothing. An empty object, or no body at all.'),
  response: { 200: DECIDED },
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
  {
    writes,
    acceptance,
    publicOrigin,
    confirmations,
  }: {
    writes: InvitationWrites | undefined;
    acceptance: InvitationAcceptance | undefined;
    confirmations: AcceptanceConfirmations | undefined;
    publicOrigin: string;
  },
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
        ...(written.invitation.status === 'DRAFT' &&
          written.invitation.stepUpChallengeId !== null && { stepUpChallengeId: written.invitation.stepUpChallengeId }),
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
  routes.post(
    '/v1/invitations/accept',
    {
      schema: ACCEPT_SCHEMA,
      bodyLimit: ACCEPT_BODY_LIMIT,
      config: { access: ['person'], operation: ACCEPT_OPERATION },
    },
    async (request, reply) => {
      const { person } = request;
      // The access hook lets no one else through; a route that runs without a person is a bug.
      if (person === null || acceptance === undefined) throw new Error('the acceptance route ran without a person');
      const accepted = await acceptance.accept(
        { userId: person.userId, sessionId: person.sessionId },
        request.body.token,
        (orgId) => idempotentRequest(request, orgId),
        request.id,
      );
      if (accepted.outcome === 'refused') return sendErrorBody(reply, accepted.status, accepted.code, request.id);
      if (accepted.outcome !== 'accepted') return answerRefusedWrite(accepted, request, reply);
      return {
        organizationId: accepted.orgId,
        invitation: {
          id: accepted.invitation.id,
          role: accepted.invitation.role,
          status: accepted.invitation.status,
          expiresAt: accepted.invitation.expiresAt.toISOString(),
        },
      };
    },
  );
  /** Answers a confirmation's refusal; undefined for the route to answer. */
  const refusalOf = (written: ConfirmationWrite, request: FastifyRequest, reply: FastifyReply) => {
    if (written.outcome === 'refused') return sendErrorBody(reply, written.status, written.code, request.id);
    if (written.outcome === 'conflict' || written.outcome === 'busy')
      return answerRefusedWrite(written, request, reply);
    return undefined;
  };
  const confirmationsOf = (): AcceptanceConfirmations => {
    if (confirmations === undefined) throw new Error('the confirmation routes ran without their writes');
    return confirmations;
  };
  const decided = (written: ConfirmationWrite) => {
    if (written.outcome !== 'written') throw new Error('a confirmation answered without its invitation');
    return {
      invitation: {
        id: written.invitation.id,
        role: written.invitation.role,
        status: written.invitation.status,
        expiresAt: written.invitation.expiresAt.toISOString(),
      },
    };
  };

  routes.post(
    '/v1/members/invitations/:id/approve',
    {
      schema: APPROVE_SCHEMA,
      bodyLimit: CONFIRM_BODY_LIMIT,
      config: { access: ['admin'], operation: APPROVE_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await confirmationsOf().ask(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.id,
      );
      const refused = refusalOf(written, request, reply);
      if (refused !== undefined) return refused;
      if (written.outcome !== 'asked') throw new Error('an ask answered without its challenge');
      return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    },
  );

  routes.post(
    '/v1/members/invitations/:id/approve/confirm',
    {
      schema: APPROVE_CONFIRM_SCHEMA,
      bodyLimit: APPROVE_CONFIRM_BODY_LIMIT,
      config: { access: ['admin'], operation: APPROVE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await confirmationsOf().confirm(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.id,
      );
      return refusalOf(written, request, reply) ?? decided(written);
    },
  );

  routes.post(
    '/v1/members/invitations/:id/decline',
    {
      schema: DECLINE_SCHEMA,
      bodyLimit: CONFIRM_BODY_LIMIT,
      config: { access: ['admin'], operation: DECLINE_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await confirmationsOf().decline(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.id,
      );
      return refusalOf(written, request, reply) ?? decided(written);
    },
  );
}

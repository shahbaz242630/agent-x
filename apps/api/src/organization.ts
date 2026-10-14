// The organisation's freeze routes (Phase 3 D1, partner decisions 3, 10 and
// 11; organization-changes.ts), each an admin's:
//
// - `POST /v1/organization/freeze`, the instant brake, with no step-up:
//   `pendingRequests`, `cancel` or `pause`, required (no default), and
//   `confirmed: true`, the console's are-you-sure (decision 11). 200 with
//   the organisation, FROZEN; one frozen already is answered as it is
//   (409 PENDING_REQUESTS_CANCELLED for a pause over a cancel).
// - `POST /v1/organization/unfreeze`, then `…/unfreeze/confirm` with the
//   step-up's ID once signed in again (a passkey), each with the same reason:
//   202 with the step-up, then 200 with the organisation, ACTIVE. 409
//   ORG_NOT_FROZEN otherwise; 409 PENDING_REQUESTS_TOO_MANY while a freeze
//   that cancels still has more to end than one move ends at once.
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import {
  FREEZE_OPERATION,
  FREEZING_ROLES,
  type OrganizationChanges,
  type OrganizationChangeWrite,
  UNFREEZE_CONFIRM_OPERATION,
  UNFREEZE_OPERATION,
  UNFREEZE_REASON_MOST,
  unfreezeReason,
} from './organization-changes.ts';
import { CHALLENGE_BODY_LIMIT, STEP_UP_SIGNED_IN, stepUpAsked } from './route-schemas.ts';
import { FREEZE_BODY } from './suspensions.ts';

/** The most a freeze's body may be: a choice and a confirmation, with room to spare. */
const FREEZE_BODY_LIMIT = 96;

/** The most an unfreeze's body may be: its reason, each of 200 characters up to 4 code points, and a step-up's ID. */
const UNFREEZE_BODY_LIMIT = 10_240;

const ORGANIZATION = z
  .object({
    id: z.uuid().describe('The organisation, by its ID.'),
    status: z
      .enum(['ACTIVE', 'FROZEN'])
      .describe('ACTIVE, or FROZEN: no spend request is decided or approved; rejecting and cancelling go on.'),
  })
  .register(API_SCHEMAS, {
    id: 'OrganizationFreeze',
    description: 'The organisation, as a freeze or unfreeze left it.',
  });

const CHANGED = z.object({ organization: ORGANIZATION }).describe('The organisation as it now stands.');

/** An unfreeze's reason, checked as it is kept (unfreezeReason). */
const REASON = z
  .string()
  // UTF-16 units: each of its 200 characters sent as up to 4 code points, each astral (UNFREEZE_BODY_LIMIT).
  .max(UNFREEZE_REASON_MOST * 8)
  .superRefine((reason, context) => {
    for (const problem of unfreezeReason(reason).problems) context.addIssue({ code: 'custom', message: problem });
  })
  .describe(
    `Why you unfreeze it: 1 to ${String(UNFREEZE_REASON_MOST)} characters on one line, with no phone or account numbers (it is kept for good).`,
  );

const FREEZE_SCHEMA = {
  summary: 'Freeze your organisation: the brake, at once and with no step-up, its pending requests cancelled or held',
  body: FREEZE_BODY,
  response: { 200: CHANGED },
};

const UNFREEZE_SCHEMA = {
  summary: 'Ask to unfreeze your organisation, with your reason',
  body: z.strictObject({ reason: REASON }).describe('Why it is unfrozen.'),
  response: {
    202: stepUpAsked(
      'OrganizationUnfreezeAsked',
      'Unfreezing the organisation, waiting for the admin to sign in again.',
    ),
  },
};

const UNFREEZE_CONFIRM_SCHEMA = {
  summary: 'Unfreeze your organisation, once signed in again for it',
  body: z
    .strictObject({ reason: REASON, stepUpChallengeId: STEP_UP_SIGNED_IN })
    .describe('The same reason as asked with, and the step-up signed in again for.'),
  response: { 200: CHANGED },
};

/**
 * The organisation's freeze routes. `changes` does them; without it the
 * routes are still documented, and no one reaches them.
 */
export function registerOrganization(app: FastifyInstance, { changes }: { changes: OrganizationChanges | undefined }) {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  /** A write's answer: 200 with the organisation, 202 with a step-up, or its refusal. */
  const answer = (
    written: OrganizationChangeWrite,
    request: Parameters<typeof answerRefusal>[1],
    reply: Parameters<typeof answerRefusal>[2],
  ) => {
    if (written.outcome === 'changed') return reply.code(200).send({ organization: written.organization });
    if (written.outcome === 'asked') return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    return answerRefusal(written, request, reply);
  };

  routes.post(
    '/v1/organization/freeze',
    {
      schema: FREEZE_SCHEMA,
      bodyLimit: FREEZE_BODY_LIMIT,
      config: { access: [...FREEZING_ROLES], operation: FREEZE_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(changes).freeze(
        member,
        idempotentRequest(request, member.orgId),
        request.body.pendingRequests,
        request.id,
      );
      return answer(written, request, reply);
    },
  );

  routes.post(
    '/v1/organization/unfreeze',
    {
      schema: UNFREEZE_SCHEMA,
      bodyLimit: UNFREEZE_BODY_LIMIT,
      config: { access: [...FREEZING_ROLES], operation: UNFREEZE_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(changes).unfreeze(
        member,
        idempotentRequest(request, member.orgId),
        unfreezeReason(request.body.reason).note,
        request.id,
      );
      return answer(written, request, reply);
    },
  );

  routes.post(
    '/v1/organization/unfreeze/confirm',
    {
      schema: UNFREEZE_CONFIRM_SCHEMA,
      bodyLimit: UNFREEZE_BODY_LIMIT + CHALLENGE_BODY_LIMIT,
      config: { access: [...FREEZING_ROLES], operation: UNFREEZE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(changes).unfreezeConfirm(
        member,
        idempotentRequest(request, member.orgId),
        { stepUpChallengeId: request.body.stepUpChallengeId, reason: unfreezeReason(request.body.reason).note },
        request.id,
      );
      return answer(written, request, reply);
    },
  );
}

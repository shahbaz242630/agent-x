// A payment's routes (Phase 4 gate H10; partner decision 38 and its S145
// heads-up): two admins mark an UNKNOWN payment failed on their bank's
// written word (payment-marks.ts), each step asked, then confirmed with a
// passkey. The payment is named by its ID, as the admins' emails and the
// audit log name it.
//
// - `POST /v1/payments/{id}/failure-proposal`, with the bank's evidence
//   reference and the consequence confirmed: 202 with the step-up; `…/confirm`:
//   201, the proposal OPEN, the payment as it was.
// - `…/failure-proposal/approve`, with the consequence confirmed: 202 with the
//   step-up and the proposal it confirms; `…/approve/confirm`: 200, the
//   payment FAILED.
// - `…/failure-proposal/withdraw`: 202 with the step-up; `…/withdraw/confirm`:
//   200, the proposal WITHDRAWN.
// 409 PAYMENT_NOT_UNKNOWN, PAYMENT_TOO_RECENT, FAILURE_PROPOSAL_OPEN,
// NO_FAILURE_PROPOSAL, FAILURE_PROPOSAL_TOO_RECENT; 403 FAILURE_PROPOSAL_YOURS;
// 404 for none of the organisation's.
import { FAILURE_PROPOSAL, type FailureProposalRecord } from '@agentx/core/modules/transactions';
import { isUnwritten } from '@agentx/platform/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import {
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  EVIDENCE_REFERENCE,
  MARK_FAILED_CONFIRMED,
  MARK_FAILED_STATEMENT,
  MARKING_ROLES,
  type PaymentMarks,
  PROPOSE_CONFIRM_OPERATION,
  PROPOSE_OPERATION,
  WITHDRAW_CONFIRM_OPERATION,
  WITHDRAW_OPERATION,
} from './payment-marks.ts';
import {
  CHALLENGE_BODY_LIMIT,
  NOTHING,
  NOTHING_BODY_LIMIT,
  STEP_UP_CONFIRM,
  STEP_UP_SIGNED_IN,
  stepUpAsked,
  stepUpAskedWith,
} from './route-schemas.ts';

const PAYMENT_ID = z.object({
  id: z.uuid().describe('The payment, by its ID, as its emails and the audit log name it.'),
});

/** The most a step's body may be: a reference of 64, the confirmation, a challenge's ID, with room to spare. */
const MARK_BODY_LIMIT = 512;

const EVIDENCE = z
  .string()
  .regex(
    EVIDENCE_REFERENCE,
    'The bank’s reference is 3 to 64 letters, digits and . _ / -, starting with a letter or digit.',
  )
  .describe(
    'Your bank’s reference for its written statement that it never accepted the payment: 3 to 64 letters, digits and . _ / -. Agent X can’t check it; it is kept in the audit log.',
  );

const CONFIRMED = z.literal(MARK_FAILED_CONFIRMED).describe(`What you confirm: ${MARK_FAILED_STATEMENT}`);

const PROPOSAL = z
  .object({
    id: z.uuid().describe('The proposal.'),
    paymentId: z.uuid().describe('The payment it is for.'),
    evidenceRef: z.string().describe('The bank’s reference the proposing admin gave.'),
    proposedBy: z.uuid().describe('The proposing admin, by their user ID.'),
    status: z
      .enum(FAILURE_PROPOSAL.states)
      .describe(
        'OPEN, waiting for a second admin; WITHDRAWN; CONFIRMED, the payment FAILED; or ENDED, the bank’s answer came first.',
      ),
    proposedAt: z.iso.datetime().describe('When it was proposed.'),
  })
  .register(API_SCHEMAS, { id: 'FailureProposal', description: 'An admin’s proposal to mark a payment failed.' });

const shown = (proposal: FailureProposalRecord) => ({
  id: proposal.id,
  paymentId: proposal.transactionId,
  evidenceRef: proposal.evidenceRef,
  proposedBy: proposal.proposedBy,
  status: proposal.status,
  proposedAt: proposal.createdAt.toISOString(),
});

const PROPOSE_SCHEMA = {
  summary: 'Ask to propose marking a payment failed, once your bank has confirmed in writing it never accepted it',
  params: PAYMENT_ID,
  body: z
    .strictObject({ evidenceRef: EVIDENCE, confirmed: CONFIRMED })
    .describe('The bank’s reference, and the consequence confirmed.'),
  response: {
    202: stepUpAsked('FailureProposalAsked', 'Proposing a payment be marked failed, waiting for you to sign in again.'),
  },
};

const PROPOSE_CONFIRM_SCHEMA = {
  summary: 'Propose marking a payment failed, once signed in again for it: a second admin must confirm it',
  params: PAYMENT_ID,
  body: z
    .strictObject({ evidenceRef: EVIDENCE, confirmed: CONFIRMED, stepUpChallengeId: STEP_UP_SIGNED_IN })
    .describe('The same reference and confirmation as the ask, and the step-up signed in again for.'),
  response: { 201: PROPOSAL.describe('The proposal, OPEN; the payment stays as it was.') },
};

const APPROVE_SCHEMA = {
  summary: 'Ask to confirm another admin’s proposal to mark a payment failed',
  params: PAYMENT_ID,
  body: z.strictObject({ confirmed: CONFIRMED }).describe('The consequence confirmed.'),
  response: {
    202: stepUpAskedWith(
      'FailureProposalApproveAsked',
      'Confirming a proposal to mark a payment failed, waiting for you to sign in again; the proposal you confirm.',
      { proposal: PROPOSAL },
    ),
  },
};

const APPROVE_CONFIRM_SCHEMA = {
  summary: 'Mark a payment failed, confirming another admin’s proposal, once signed in again for it',
  params: PAYMENT_ID,
  body: z
    .strictObject({ confirmed: CONFIRMED, stepUpChallengeId: STEP_UP_SIGNED_IN })
    .describe('The same confirmation as the ask, and the step-up signed in again for.'),
  response: {
    200: z
      .object({
        id: z.uuid().describe('The payment.'),
        status: z.literal('FAILED').describe('FAILED: its money and its invoice are free again.'),
      })
      .register(API_SCHEMAS, { id: 'PaymentMarkedFailed', description: 'The payment, marked failed.' }),
  },
};

const WITHDRAW_SCHEMA = {
  summary: 'Ask to withdraw the proposal to mark a payment failed',
  params: PAYMENT_ID,
  body: NOTHING,
  response: {
    202: stepUpAsked('FailureProposalWithdrawAsked', 'Withdrawing a proposal, waiting for you to sign in again.'),
  },
};

const WITHDRAW_CONFIRM_SCHEMA = {
  summary: 'Withdraw the proposal to mark a payment failed, once signed in again for it',
  params: PAYMENT_ID,
  body: STEP_UP_CONFIRM,
  response: { 200: PROPOSAL.describe('The proposal, WITHDRAWN; the payment stays as it was.') },
};

export function registerPayments(app: FastifyInstance, { marks }: { marks: PaymentMarks | undefined }): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const access = [...MARKING_ROLES];

  routes.post(
    '/v1/payments/:id/failure-proposal',
    { schema: PROPOSE_SCHEMA, bodyLimit: MARK_BODY_LIMIT, config: { access, operation: PROPOSE_OPERATION } },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const asked = await need(marks).propose(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.evidenceRef,
        request.id,
      );
      return answerAsked(asked, request, reply);
    },
  );

  routes.post(
    '/v1/payments/:id/failure-proposal/confirm',
    {
      schema: PROPOSE_CONFIRM_SCHEMA,
      bodyLimit: MARK_BODY_LIMIT,
      config: { access, operation: PROPOSE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const { evidenceRef, stepUpChallengeId } = request.body;
      const proposed = await need(marks).confirmProposal(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        { evidenceRef, stepUpChallengeId },
        request.id,
      );
      if (isUnwritten(proposed)) return answerRefusal(proposed, request, reply);
      return reply.code(201).send(shown(proposed.proposal));
    },
  );

  routes.post(
    '/v1/payments/:id/failure-proposal/approve',
    { schema: APPROVE_SCHEMA, bodyLimit: MARK_BODY_LIMIT, config: { access, operation: APPROVE_OPERATION } },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const asked = await need(marks).approve(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      if (isUnwritten(asked)) return answerRefusal(asked, request, reply);
      return reply.code(202).send({ stepUpChallengeId: asked.stepUpChallengeId, proposal: shown(asked.proposal) });
    },
  );

  routes.post(
    '/v1/payments/:id/failure-proposal/approve/confirm',
    {
      schema: APPROVE_CONFIRM_SCHEMA,
      bodyLimit: MARK_BODY_LIMIT,
      config: { access, operation: APPROVE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const marked = await need(marks).confirmApproval(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.id,
      );
      if (isUnwritten(marked)) return answerRefusal(marked, request, reply);
      return reply.code(200).send({ id: marked.paymentId, status: 'FAILED' });
    },
  );

  routes.post(
    '/v1/payments/:id/failure-proposal/withdraw',
    { schema: WITHDRAW_SCHEMA, bodyLimit: NOTHING_BODY_LIMIT, config: { access, operation: WITHDRAW_OPERATION } },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const asked = await need(marks).withdraw(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerAsked(asked, request, reply);
    },
  );

  routes.post(
    '/v1/payments/:id/failure-proposal/withdraw/confirm',
    {
      schema: WITHDRAW_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access, operation: WITHDRAW_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const withdrawn = await need(marks).confirmWithdrawal(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.id,
      );
      if (isUnwritten(withdrawn)) return answerRefusal(withdrawn, request, reply);
      return reply.code(200).send(shown(withdrawn.proposal));
    },
  );
}

// A payment's routes (Phase 4 gate H10; partner decision 38): an admin marks
// an UNKNOWN payment failed on their bank's written word, asked, then
// confirmed with a passkey (payment-marks.ts). The payment is named by its ID,
// as the admins' emails and the audit log name it.
//
// - `POST /v1/payments/{id}/mark-failed`, with the bank's evidence reference
//   and the consequence confirmed: 202 with the step-up to sign in again for.
// - `POST /v1/payments/{id}/mark-failed/confirm`, with the same and the
//   step-up: 200, the payment FAILED.
// 409 PAYMENT_NOT_UNKNOWN for one not waiting for the bank's final answer,
// PAYMENT_TOO_RECENT within a day of its hand-off; 404 for none of the
// organisation's.
import { isUnwritten } from '@agentx/platform/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import {
  EVIDENCE_REFERENCE,
  MARK_FAILED_CONFIRM_OPERATION,
  MARK_FAILED_CONFIRMED,
  MARK_FAILED_OPERATION,
  MARK_FAILED_STATEMENT,
  MARKING_ROLES,
  type PaymentMarks,
} from './payment-marks.ts';
import { STEP_UP_SIGNED_IN, stepUpAsked } from './route-schemas.ts';

const PAYMENT_ID = z.object({
  id: z.uuid().describe('The payment, by its ID, as its emails and the audit log name it.'),
});

/** The most a mark's body may be: a reference of 64, the confirmation, a challenge's ID, with room to spare. */
const MARK_BODY_LIMIT = 512;

const MARK = {
  evidenceRef: z
    .string()
    .regex(
      EVIDENCE_REFERENCE,
      'The bank’s reference is 3 to 64 letters, digits and . _ / -, starting with a letter or digit.',
    )
    .describe(
      'Your bank’s reference for its written statement that it never accepted the payment: 3 to 64 letters, digits and . _ / -. It is kept in the audit log.',
    ),
  confirmed: z.literal(MARK_FAILED_CONFIRMED).describe(`What you confirm: ${MARK_FAILED_STATEMENT}`),
};

const MARK_SCHEMA = {
  summary: 'Ask to mark a payment failed, once your bank has confirmed in writing it never accepted it',
  params: PAYMENT_ID,
  body: z.strictObject(MARK).describe('The bank’s evidence reference, and the consequence confirmed.'),
  response: {
    202: stepUpAsked('PaymentMarkFailedAsked', 'Marking a payment failed, waiting for you to sign in again.'),
  },
};

const MARK_CONFIRM_SCHEMA = {
  summary: 'Mark a payment failed, once signed in again for it',
  params: PAYMENT_ID,
  body: z
    .strictObject({ ...MARK, stepUpChallengeId: STEP_UP_SIGNED_IN })
    .describe('The same reference and confirmation as the ask, and the step-up signed in again for.'),
  response: {
    200: z
      .object({
        id: z.uuid().describe('The payment.'),
        status: z.literal('FAILED').describe('FAILED: its money and its invoice are free again.'),
      })
      .register(API_SCHEMAS, { id: 'PaymentMarkedFailed', description: 'The payment, marked failed.' }),
  },
};

export function registerPayments(app: FastifyInstance, { marks }: { marks: PaymentMarks | undefined }): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.post(
    '/v1/payments/:id/mark-failed',
    {
      schema: MARK_SCHEMA,
      bodyLimit: MARK_BODY_LIMIT,
      config: { access: [...MARKING_ROLES], operation: MARK_FAILED_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const asked = await need(marks).ask(
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
    '/v1/payments/:id/mark-failed/confirm',
    {
      schema: MARK_CONFIRM_SCHEMA,
      bodyLimit: MARK_BODY_LIMIT,
      config: { access: [...MARKING_ROLES], operation: MARK_FAILED_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const { evidenceRef, stepUpChallengeId } = request.body;
      const marked = await need(marks).confirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        { evidenceRef, stepUpChallengeId },
        request.id,
      );
      if (isUnwritten(marked)) return answerRefusal(marked, request, reply);
      return reply.code(200).send({ id: marked.paymentId, status: 'FAILED' });
    },
  );
}

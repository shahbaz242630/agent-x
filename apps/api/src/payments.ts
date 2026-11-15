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
//
// The team's reads (Phase 6 C1; payment-reads.ts), for every role, no step-up:
// `GET /v1/payments` newest first, all or one group (`status`);
// `GET /v1/payments/exceptions` the exception list (BR-17): every UNKNOWN
// payment, and every settled one the bank's word on it still contradicts; and
// `GET /v1/payments/{id}` in full, with where marking it failed stands and its
// history. Each names the supplier it was handed off to pay by ID and the name
// those details gave it, and never the payee's reference or the consent.
import { MOST_PAYMENTS_A_PAGE } from '@agentx/core/modules/outcomes';
import { FAILURE_PROPOSAL, type FailureProposalRecord, TRANSACTION } from '@agentx/core/modules/transactions';
import { isUnwritten } from '@agentx/platform/db';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { EVERY_MEMBER, memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { confirmedWith, statementVersion } from './statements.ts';
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
  PAYMENT_GROUPS,
  type PaymentFound,
  type PaymentGroup,
  type PaymentReads,
  type PaymentShown,
  TIMELINE_MOST,
} from './payment-reads.ts';
import {
  CHALLENGE_BODY_LIMIT,
  NEXT,
  NOTHING,
  NOTHING_BODY_LIMIT,
  pageQuery,
  STEP_UP_CONFIRM,
  STEP_UP_SIGNED_IN,
  stepUpAsked,
  stepUpAskedWith,
  UNCHECKED,
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

/** The version of the words a confirm was shown (CO3), sent back with the step-up. */
const MARK_WORDS = statementVersion('mark_failed');

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
    .strictObject({
      evidenceRef: EVIDENCE,
      confirmed: CONFIRMED,
      stepUpChallengeId: STEP_UP_SIGNED_IN,
      statementVersion: MARK_WORDS,
    })
    .describe(
      'The same reference and confirmation as the ask, the step-up signed in again for, and the words’ version.',
    ),
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
    .strictObject({ confirmed: CONFIRMED, stepUpChallengeId: STEP_UP_SIGNED_IN, statementVersion: MARK_WORDS })
    .describe('The same confirmation as the ask, the step-up signed in again for, and the words’ version.'),
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

const PAYMENT_LISTED = z
  .object({
    id: z.uuid().describe('The payment, by its ID, as its emails and the audit log name it.'),
    spendRequestId: z.uuid().describe('The spend request it pays.'),
    status: z
      .enum(TRANSACTION.states)
      .describe(
        'Where it stands: SUBMISSION_PENDING, SUBMITTED or PROCESSING while under way; SUCCEEDED (paid), FAILED, CANCELLED or REVERSED; UNKNOWN while its outcome can’t be known: follow it up with your bank.',
      ),
    amountMinor: z.number().describe('Whole minor units.'),
    currency: z.string(),
    supplier: z
      .object({ id: z.uuid(), name: z.string() })
      .describe('The supplier paid: its ID, and the name its details carried when the payment was handed off.'),
    bankReference: z.string().describe('The payment reference the bank received with it.'),
    partnerReference: z
      .string()
      .nullable()
      .describe('The payment partner’s reference for it, or null until the partner has given one.'),
    bankStatus: z
      .string()
      .nullable()
      .describe('The payment partner’s own word for where it stands, as it gave it, or null until it has spoken.'),
    rejectCode: z.string().nullable().describe('The reject code the partner gave, as it gave it, or null.'),
    createdAt: z.iso.datetime().describe('When it was handed off.'),
    changedAt: z.iso.datetime().describe('When it last moved, as its signed record says.'),
    contradicted: z
      .boolean()
      .describe(
        'Settled, and the bank went back on it (paid, then rejected; or failed, then paid or under way): Agent X said so to your admins when it first did, leaves the payment as it is, and its latest word still says otherwise; take it up with your bank. False again once the bank agrees.',
      ),
  })
  .register(API_SCHEMAS, { id: 'PaymentListed', description: 'A payment, as the team sees it in a list.' });

const TIMELINE_ENTRY = z
  .object({
    at: z.iso.datetime().describe('When, as the audit log seals it.'),
    what: z
      .string()
      .describe('What happened, as the audit log names it: `transaction.succeed`, `payment.contradicted`.'),
    status: z
      .enum(TRANSACTION.states)
      .nullable()
      .describe('The status the payment moved to, for its own moves; null for any other event.'),
    by: z
      .object({ type: z.enum(['user', 'agent', 'system']), id: z.string() })
      .describe('Who: a person by their user ID, an AI agent by its ID, or Agent X itself by its process’s name.'),
    via: z.string().nullable().describe('How it came, where the event says (`bank_check`, `admin`); else null.'),
    evidenceRef: z
      .string()
      .nullable()
      .describe(
        'The evidence it rests on, where the event names it: the bank’s reference an admin gave, or the bank’s status.',
      ),
  })
  .describe('One event of the payment’s history.');

const PAYMENT_DETAILS = PAYMENT_LISTED.extend({
  markFailed: z
    .object({
      markableFrom: z.iso
        .datetime()
        .describe('After this an admin may propose marking it failed, once their bank confirms it in writing.'),
      openProposal: PROPOSAL.nullable().describe('The proposal waiting for a second admin, or null.'),
    })
    .nullable()
    .describe('For an UNKNOWN payment: where marking it failed stands. Null for any other.'),
  timeline: z
    .array(TIMELINE_ENTRY)
    .describe(`Its history, oldest first: its newest events, at most ${String(TIMELINE_MOST)}.`),
  earlier: z.boolean().describe('Whether older events were left out of `timeline`.'),
}).register(API_SCHEMAS, { id: 'PaymentDetails', description: 'A payment in full, as the team sees it.' });

const PAYMENTS_PAGE = z.object({ payments: z.array(PAYMENT_LISTED), next: NEXT, unchecked: UNCHECKED });

const GROUPS = Object.keys(PAYMENT_GROUPS) as [PaymentGroup, ...PaymentGroup[]];

const LIST_SCHEMA = {
  summary: "The organisation's payments, newest first",
  querystring: pageQuery(MOST_PAYMENTS_A_PAGE).extend({
    status: z
      .enum(GROUPS)
      .optional()
      .describe(
        'Only one group: pending (SUBMISSION_PENDING, SUBMITTED, PROCESSING), paid (SUCCEEDED), failed, cancelled, unknown or reversed. Every payment when left out.',
      ),
  }),
  response: { 200: PAYMENTS_PAGE },
};

const EXCEPTIONS_SCHEMA = {
  summary:
    'The payments to follow up with your bank, newest first: every UNKNOWN one, and every settled one the bank now contradicts',
  querystring: pageQuery(MOST_PAYMENTS_A_PAGE),
  response: { 200: PAYMENTS_PAGE },
};

const SHOW_SCHEMA = {
  summary: 'One payment in full, with its history',
  params: PAYMENT_ID,
  response: { 200: PAYMENT_DETAILS },
};

/** A payment as a list shows it to the team: never its payee's reference or its consent. */
const listed = ({ payment, supplierId, supplierName }: PaymentShown) => ({
  id: payment.transaction.id,
  spendRequestId: payment.spendRequestId,
  status: payment.transaction.status,
  amountMinor: Number(payment.amount.minor),
  currency: payment.amount.currency,
  supplier: { id: supplierId, name: supplierName },
  bankReference: payment.paymentReference,
  partnerReference: payment.transaction.paymentInstructionRef,
  bankStatus: payment.transaction.providerStatus,
  rejectCode: payment.transaction.rejectCode,
  createdAt: payment.transaction.createdAt.toISOString(),
  changedAt: payment.changedAt.toISOString(),
  contradicted: payment.contradicted,
});

/** A payment in full: as listed, with where marking it failed stands and its history. */
const detailed = ({ shown: one, markFailed, timeline, earlier }: Extract<PaymentFound, { outcome: 'found' }>) => ({
  ...listed(one),
  markFailed:
    markFailed === null
      ? null
      : {
          markableFrom: markFailed.markableFrom.toISOString(),
          openProposal: markFailed.openProposal === null ? null : shown(markFailed.openProposal),
        },
  timeline: timeline.map((entry) => ({ ...entry, at: entry.at.toISOString() })),
  earlier,
});

export function registerPayments(
  app: FastifyInstance,
  { marks, reads }: { marks: PaymentMarks | undefined; reads: PaymentReads | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const access = [...MARKING_ROLES];
  const members = { access: [...EVERY_MEMBER] };

  /** A page of payments, all, one group's or the exceptions, as both lists answer it. */
  const pageOf = async (
    request: FastifyRequest,
    reply: FastifyReply,
    { after, limit }: { readonly after?: string | undefined; readonly limit?: number | undefined },
    which: PaymentGroup | 'all' | 'exceptions',
  ) => {
    const { orgId } = memberInSessionOf(request);
    const page = { after: after ?? null, limit: limit ?? MOST_PAYMENTS_A_PAGE };
    const found = await need(reads).list(orgId, page, which, request.id);
    if (found.outcome === 'refused') return answerRefusal(found, request, reply);
    return { payments: found.payments.map(listed), next: found.next, unchecked: [...found.unchecked] };
  };

  routes.get('/v1/payments', { schema: LIST_SCHEMA, config: members }, (request, reply) =>
    pageOf(request, reply, request.query, request.query.status ?? 'all'),
  );

  // Its own route, before `/v1/payments/:id`: the exception list (BR-17).
  routes.get('/v1/payments/exceptions', { schema: EXCEPTIONS_SCHEMA, config: members }, (request, reply) =>
    pageOf(request, reply, request.query, 'exceptions'),
  );

  routes.get('/v1/payments/:id', { schema: SHOW_SCHEMA, config: members }, async (request, reply) => {
    const { orgId } = memberInSessionOf(request);
    const found = await need(reads).show(orgId, request.params.id, request.id);
    if (found.outcome === 'refused') return answerRefusal(found, request, reply);
    return detailed(found);
  });

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
      config: { access, operation: PROPOSE_CONFIRM_OPERATION, statements: confirmedWith('mark_failed') },
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
      config: { access, operation: APPROVE_CONFIRM_OPERATION, statements: confirmedWith('mark_failed') },
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

// The agent's spend-request route (PRD §4.2, §7.1; BR-06–BR-09, BR-22;
// partner decisions 2, 6 and 8; Phase 2 D4r): `POST /v1/spend-requests`, with
// `requests:write`, asks to pay one of the organisation's suppliers from a
// funding source, for one order. The body is checked at the edge as 0039
// checks it (an amount in whole minor units, the purpose and the supplier's
// own order reference in any script); decideAndReserve then weighs it, records
// it with its decision and, for ALLOW or REQUIRE_APPROVAL, holds its capacity
// (spend-request-decisions.ts).
//
// Every request recorded answers 201 with its decision and the reasons, a
// denied one too: the agent learns why, and the evidence keeps it. A refusal
// shows the agent only the reasons that made it (partner decision 11c), so a
// request refused for nothing it holds never maps its hidden approval line;
// one sent for approval past its mandate's own limits (decision 23) never
// names them. Only what can't be recorded is refused: CURRENCY_NOT_ALLOWED
// (422), ORG_FROZEN (409), a key no longer live (401), INTEGRITY_FAILED
// (503), and the idempotency key's own answers. The answer shows the bank reference the order reference
// becomes on the rail when that differs from it (decision 8): the same
// mapping as hand-off's.
//
// Cancelling before hand-off (partner decision 10; Phase 2 D8;
// spend-request-cancels.ts), one click and no step-up: an admin or finance
// approver at `POST /v1/spend-requests/{id}/cancel`, the agent its own at
// `POST /v1/agent/spend-requests/{id}/cancel` (agents have routes of their
// own, SEC-AG-05). Both answer 200 with the request as it now stands, its
// reservation and order claim released.
//
// The team's reads (Phase 3 B3; spend-request-reads.ts), for every role:
// `GET /v1/spend-requests` newest first, `GET /v1/approvals` those waiting
// oldest first, and `GET /v1/spend-requests/{id}` in full. Each names the
// agent and supplier by ID and name, and only the full one carries the
// agent's own words, apart and labelled as its (SEC-AG-08, -10), and, for
// one rejected, the reject: who, when and why; for one voided, the void:
// when, and its causes (C2b).
//
// Rejecting one waiting for approval (Phase 3 B4a; partner decisions 1, 3, 6;
// spend-request-rejects.ts): an admin or finance approver asks at
// `POST /v1/spend-requests/{id}/reject` with a short reason (202, a step-up),
// signs in again with a passkey, and confirms at `…/reject/confirm` with the
// same reason: 200, the request DENIED, its reservation and order claim
// released. No agent key reaches either.
//
// Approving one (Phase 3 B4b; partner decisions 1 and 3;
// spend-request-approvals.ts): an admin or finance approver asks at
// `POST /v1/spend-requests/{id}/approve` (202, a step-up, once the request is
// weighed again and found unchanged), signs in again with a passkey, and
// confirms at `…/approve/confirm`: 200, the request APPROVED, weighed again
// as it then stands, keeping its reservation and order claim. No agent key
// reaches either (SEC-AG-07).
//
// The agent reads one of its own (B4c, partner S106) at
// `GET /v1/agent/spend-requests/{id}`, with `requests:read`: as it stands
// now, so it learns of an approval, a reject, a cancel or an expiry. One a
// person rejected shows the one reason APPROVAL_REJECTED, never their words;
// one voided shows REQUEST_VOIDED, then each cause (C2b).
import { DECISIONS, reasonsShownToAgent } from '@agentx/core/modules/policies';
import {
  askedText,
  bankReferenceOf,
  MOST_REQUESTS_A_PAGE,
  ORDER_REFERENCE_MOST,
  REJECT_REASON_MOST,
  rejectReason,
  REQUEST_PURPOSE_MOST,
  SPEND_REQUEST,
  SpendAskRefused,
  type SpendRequestRecord,
} from '@agentx/core/modules/spend-requests';
import { moneyFromJson } from '@agentx/core/shared-kernel';
import { isUnwritten } from '@agentx/platform/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { agentOf, memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import type { RuleDenial } from './approval-rejections.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import {
  AMOUNT,
  CHALLENGE_BODY_LIMIT,
  issuesOf,
  NEXT,
  NOTHING,
  NOTHING_BODY_LIMIT,
  pageQuery,
  REASONS,
  reasonsOf,
  RULE_DENIAL_SHOWN,
  shownRules,
  STEP_UP_CONFIRM,
  STEP_UP_SIGNED_IN,
  stepUpAsked,
  stepUpAskedWith,
  UNCHECKED,
} from './route-schemas.ts';
import {
  AGENT_CANCEL_OPERATION,
  CANCEL_OPERATION,
  CANCELLING_ROLES,
  type SpendRequestCancels,
} from './spend-request-cancels.ts';
import {
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  RECHECK_STATEMENT,
  type RecheckShown,
  type SpendRequestApprovals,
} from './spend-request-approvals.ts';
import { DECIDE_OPERATION, type SpendRequestDecisions } from './spend-request-decisions.ts';
import type { RequestShown, SpendRequestReads } from './spend-request-reads.ts';
import {
  DECIDING_ROLES,
  REJECT_CONFIRM_OPERATION,
  REJECT_OPERATION,
  type SpendRequestRejects,
} from './spend-request-rejects.ts';

/**
 * The most a request's body may be: a purpose of 200 code points and an order
 * reference of 100, each sent decomposed as at most 4 code points, astral at
 * worst, each UTF-16 unit as a `\uXXXX` escape (300 × 4 × 2 × 6 bytes); the
 * IDs, the amount and the currency with room to spare (the B8-3 lesson: it
 * must fit every body the schema allows).
 */
const REQUEST_BODY_LIMIT = 16_384;

const ASKED = z
  .strictObject({
    amountMinor: AMOUNT.describe('The amount to pay, in whole minor units (fils for AED).'),
    currency: z.string().describe('The amount’s currency: your mandate’s, AED in the Pilot. Never converted.'),
    supplierId: z.uuid().describe('The supplier to pay, by ID: one your mandate names.'),
    fundingSourceId: z.uuid().describe('The bank account to pay from, by ID: your mandate’s.'),
    orderReference: z
      .string()
      .describe(
        `The supplier’s own invoice or order number, as written, in any script: 1 to ${String(ORDER_REFERENCE_MOST)} visible characters. One order is paid once.`,
      ),
    purpose: z.string().describe(`What it is for: 1 to ${String(REQUEST_PURPOSE_MOST)} visible characters.`),
  })
  .superRefine((body, context) => {
    issuesOf(() => moneyFromJson(body.amountMinor, body.currency), SpendAskRefused, context);
    issuesOf(() => askedText(body), SpendAskRefused, context);
  })
  .describe('The payment to ask for.');

const SPEND_REQUEST_SHOWN = z
  .object({
    id: z.uuid().describe('The request, by its ID.'),
    status: z
      .enum(SPEND_REQUEST.states)
      .describe(
        'Where it stands: APPROVED (allowed), APPROVAL_REQUIRED (waiting for a person) or DENIED; later EXPIRED (its wait for approval ended: 24, 48 or 72 hours, as its organisation chose when it was asked) or CANCELLED.',
      ),
    decision: z
      .enum(DECISIONS)
      .describe(
        'ALLOW; REQUIRE_APPROVAL: a person must approve it; REQUIRE_NEW_MANDATE: it is past what your mandate allows; DENY.',
      ),
    reasons: REASONS,
    amountMinor: z.number().describe('Whole minor units.'),
    currency: z.string(),
    supplierId: z.uuid(),
    fundingSourceId: z.uuid(),
    mandateId: z.uuid().nullable().describe('The mandate it was weighed against, or null: you had none in force.'),
    orderReference: z.string().describe('The order reference, as kept.'),
    bankReference: z
      .string()
      .nullable()
      .describe(
        "What the bank’s payment reference will read, when it differs from the order reference: the rail carries 1 to 35 ASCII letters, digits, spaces and /?:().,'+- only. Null when it reads the same.",
      ),
  })
  .register(API_SCHEMAS, { id: 'SpendRequest', description: 'A spend request, with its decision.' });

const ASK_SCHEMA = {
  summary: 'Ask to pay a supplier for one order',
  body: ASKED,
  response: {
    201: SPEND_REQUEST_SHOWN.describe(
      'The request, recorded with its decision: allowed, waiting for approval, or denied with its reasons.',
    ),
  },
};

const SPEND_REQUEST_ID = z.object({ id: z.uuid().describe('The spend request, by its ID.') });

const CANCELLED = SPEND_REQUEST_SHOWN.describe(
  'The request as it now stands: CANCELLED, its reservation and order claim released (or cancelled already).',
);

const CANCEL_SCHEMA = {
  summary: 'Cancel a spend request before hand-off: at once, no step-up',
  params: SPEND_REQUEST_ID,
  body: NOTHING,
  response: { 200: CANCELLED },
};

const AGENT_CANCEL_SCHEMA = {
  summary: 'Cancel one of your own spend requests before hand-off',
  params: SPEND_REQUEST_ID,
  body: NOTHING,
  response: { 200: CANCELLED },
};

const AGENT_SHOW_SCHEMA = {
  summary: 'One of your own spend requests, as it stands now',
  params: SPEND_REQUEST_ID,
  response: {
    200: SPEND_REQUEST_SHOWN.describe(
      'The request now: still waiting, approved, or ended (DENIED, EXPIRED, CANCELLED). One a person rejected is DENIED with the reason APPROVAL_REJECTED alone. One voided (what it was decided under stopped before it was paid) is DENIED with REQUEST_VOIDED, then each cause.',
    ),
  },
};

/** Every role reads the organisation's requests (Phase 3 B3), as its mandates and suppliers. */
const READING_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;

const SPEND_REQUEST_LISTED = z
  .object({
    id: z.uuid().describe('The request, by its ID.'),
    status: z.enum(SPEND_REQUEST.states).describe('Where it stands now.'),
    decision: z.enum(DECISIONS).describe('What its decision was when the agent asked.'),
    reasons: REASONS,
    amountMinor: z.number().describe('Whole minor units.'),
    currency: z.string(),
    agent: z
      .object({ id: z.uuid(), name: z.string() })
      .describe('The AI agent that asked: its ID, and the name the team gave it.'),
    supplier: z
      .object({ id: z.uuid(), name: z.string() })
      .describe('The supplier to pay: its ID, and the name its current verified details give it.'),
    fundingSourceId: z.uuid(),
    mandateId: z
      .uuid()
      .nullable()
      .describe('The mandate it was weighed against, or null: the agent had none in force.'),
    bankReference: z
      .string()
      .describe(
        "What the bank's payment reference will read: the order reference in the 1 to 35 ASCII letters, digits, spaces and /?:().,'+- the rail carries. Made from the agent's own words, so show it as text the agent wrote, never as Agent X's.",
      ),
    changedAt: z.iso.datetime().describe('When it last moved, as its signed record says.'),
    expiresAt: z.iso
      .datetime()
      .nullable()
      .describe(
        'While it waits for approval: when it expires, its decision’s time plus the wait its organisation had chosen then (24, 48 or 72 hours). Otherwise null.',
      ),
    needsRecheck: z
      .boolean()
      .describe(
        'Waiting, and its supplier’s details changed since it was decided (an admin chose to pause it): approve it ' +
          'with `recheck`, once the new details are verified, to see how it is weighed under them.',
      ),
  })
  .register(API_SCHEMAS, { id: 'SpendRequestListed', description: 'A spend request, as the team sees it in a list.' });

const SPEND_REQUEST_DETAILS = SPEND_REQUEST_LISTED.extend({
  agentWrote: z
    .object({
      purpose: z.string().describe(`What the agent says it is for: 1 to ${String(REQUEST_PURPOSE_MOST)} characters.`),
      orderReference: z
        .string()
        .describe(
          `The supplier's order or invoice number, as the agent gave it: 1 to ${String(ORDER_REFERENCE_MOST)} characters.`,
        ),
    })
    .describe(
      "The agent's own words, as it wrote them. Agent X checks only that they are visible text of a set length, never what they say: show them as plain text, labelled as the agent's, never as markup or a link.",
    ),
  rejection: z
    .object({
      byUserId: z.uuid().describe('The member who rejected it.'),
      at: z.iso.datetime().describe('When, as its signed record says.'),
      reason: z.string().describe('Their reason, as they wrote it. The agent never sees it.'),
    })
    .nullable()
    .describe('For one a person rejected: who, when and why. Otherwise null.'),
  voiding: z
    .object({
      at: z.iso.datetime().describe('When, as its signed record says.'),
      reasons: REASONS.describe(
        'Why: what it was decided under that stopped (its agent, mandate, funding source or supplier).',
      ),
    })
    .nullable()
    .describe(
      'For one voided, its holdings released, because what it was decided under stopped before it was paid: when and why. Otherwise null.',
    ),
}).register(API_SCHEMAS, { id: 'SpendRequestDetails', description: 'A spend request in full, as the team sees it.' });

const LIST_SCHEMA = {
  summary: "The organisation's spend requests, newest first",
  querystring: pageQuery(MOST_REQUESTS_A_PAGE),
  response: {
    200: z.object({ spendRequests: z.array(SPEND_REQUEST_LISTED), next: NEXT, unchecked: UNCHECKED }),
  },
};

const APPROVALS_SCHEMA = {
  summary: 'The spend requests waiting for approval, oldest first: the soonest to expire at the top',
  querystring: pageQuery(MOST_REQUESTS_A_PAGE),
  response: {
    200: z.object({ waiting: z.array(SPEND_REQUEST_LISTED), next: NEXT, unchecked: UNCHECKED }),
  },
};

const SHOW_SCHEMA = {
  summary: 'One spend request in full',
  params: SPEND_REQUEST_ID,
  response: { 200: SPEND_REQUEST_DETAILS },
};

/**
 * The most a reject's body may be: a reason of 200 code points, each sent
 * decomposed as at most 4 code points, astral at worst, each UTF-16 unit as a
 * `\uXXXX` escape (200 × 4 × 2 × 6 bytes), and a challenge's ID.
 */
const REJECT_BODY_LIMIT = 10_240;

/** The reject's reason (decision 6), checked as it is kept (rejectReason). */
const REASON = z
  .string()
  // UTF-16 units: each of its 200 characters sent as up to 4 code points, each astral (REJECT_BODY_LIMIT).
  .max(REJECT_REASON_MOST * 8)
  .superRefine((reason, context) => {
    for (const problem of rejectReason(reason).problems) context.addIssue({ code: 'custom', message: problem });
  })
  .describe(
    `Why you reject it: 1 to ${String(REJECT_REASON_MOST)} characters on one line, with no phone or account numbers (it is kept for good). Your team sees it; the agent never does.`,
  );

const REJECT_SCHEMA = {
  summary: 'Ask to reject a spend request waiting for approval, with your reason',
  params: SPEND_REQUEST_ID,
  body: z.strictObject({ reason: REASON }).describe('Why you reject it.'),
  response: {
    202: stepUpAsked('SpendRequestRejectAsked', 'Rejecting a spend request, waiting for you to sign in again.'),
  },
};

const REJECT_CONFIRM_SCHEMA = {
  summary: 'Reject a spend request, once signed in again for it',
  params: SPEND_REQUEST_ID,
  body: z
    .strictObject({ stepUpChallengeId: STEP_UP_SIGNED_IN, reason: REASON })
    .describe('The step-up signed in again for, with the same reason as the ask.'),
  response: {
    200: SPEND_REQUEST_SHOWN.describe(
      'The request as it now stands: DENIED, its reservation and order claim released.',
    ),
  },
};

/** A request as a list shows it to the team. */
const listed = ({ request, changedAt, expiresAt, agentName, supplierName, needsRecheck }: RequestShown) => ({
  id: request.id,
  status: request.status,
  decision: request.decision,
  reasons: reasonsOf(request.reasons),
  amountMinor: Number(request.amount.minor),
  currency: request.amount.currency,
  agent: { id: request.agentId, name: agentName },
  supplier: { id: request.supplierId, name: supplierName },
  fundingSourceId: request.fundingSourceId,
  mandateId: request.mandateId,
  bankReference: bankReferenceOf(request.orderReference, request.id),
  changedAt: changedAt.toISOString(),
  expiresAt: expiresAt?.toISOString() ?? null,
  needsRecheck,
});

/** The request as answered: to its agent, a refusal's own reasons alone (reasonsShownToAgent); to a person, all. */
const shown = (request: SpendRequestRecord, to: 'agent' | 'member') => {
  const bankReference = bankReferenceOf(request.orderReference, request.id);
  return {
    id: request.id,
    status: request.status,
    decision: request.decision,
    reasons: reasonsOf(to === 'agent' ? reasonsShownToAgent(request.decision, request.reasons) : request.reasons),
    amountMinor: Number(request.amount.minor),
    currency: request.amount.currency,
    supplierId: request.supplierId,
    fundingSourceId: request.fundingSourceId,
    mandateId: request.mandateId,
    orderReference: request.orderReference,
    bankReference: bankReference === request.orderReference ? null : bankReference,
  };
};

/** The approver's ask to re-check one whose supplier's details changed (E5a), in both bodies. */
const RECHECK = {
  recheck: z
    .literal(true)
    .optional()
    .describe(
      'Only for a request whose supplier’s details changed after it was decided and were verified again (asked ' +
        `for with RECHECK_REQUIRED): approve it checked again under the new details. ${RECHECK_STATEMENT}`,
    ),
};

/** A re-check as the ask shows it (E5a): what changed, and how it is weighed now. */
const RECHECK_SHOWN = z
  .object({
    fromSupplierVersionId: z.uuid().describe('The supplier’s details it was decided under.'),
    supplierVersionId: z.uuid().describe('The supplier’s details, verified again, it is approved under.'),
    decidedAs: z.enum(DECISIONS).describe('What its decision was when the agent asked.'),
    decidedReasons: REASONS.describe('Why it was decided so then.'),
    decision: z.enum(DECISIONS).describe('How it is weighed now, under the new details and today’s policies.'),
    reasons: REASONS.describe('Why it is weighed so now.'),
  })
  .nullable()
  .describe(
    'With `recheck`: what changed and how it is weighed now. Confirming approves exactly this; if anything changes ' +
      'first, the confirm is refused and you ask again. Null otherwise.',
  );

/** A rejection as the ask shows it (decision 18; E5b): each rule that now refuses it, its words and what to do. */
const REJECTION_SHOWN = z
  .array(RULE_DENIAL_SHOWN)
  .nullable()
  .describe(
    'When today’s check refuses it under rules your team set (a limit or cap lowered, a supplier taken off a ' +
      'policy): confirming **rejects** it, its money freed, with these kept on its record; the agent learns only ' +
      'that a person rejected it. Null when confirming approves it.',
  );

const shownRejection = (rules: readonly RuleDenial[] | null) => (rules === null ? null : shownRules(rules));

const shownRecheck = (view: RecheckShown | null) =>
  view === null
    ? null
    : {
        ...view,
        decidedReasons: reasonsOf(view.decidedReasons),
        reasons: reasonsOf(view.reasons),
      };

const APPROVE_SCHEMA = {
  summary: 'Ask to approve a spend request waiting for approval',
  params: SPEND_REQUEST_ID,
  body: z
    .strictObject(RECHECK)
    // Fastify gives a request sent with no body a null one.
    .nullish()
    .describe('Nothing, or `recheck` for one whose supplier’s details changed.'),
  response: {
    202: stepUpAskedWith(
      'SpendRequestApproveAsked',
      'Approving a spend request, waiting for you to sign in again; with `recheck`, how it is weighed now.',
      { recheck: RECHECK_SHOWN, rejection: REJECTION_SHOWN },
    ),
  },
};

const APPROVE_CONFIRM_SCHEMA = {
  summary: 'Approve a spend request, once signed in again for it',
  params: SPEND_REQUEST_ID,
  body: STEP_UP_CONFIRM.extend(RECHECK).describe(
    'The step-up signed in again for, and any `recheck` it was asked with.',
  ),
  response: {
    200: SPEND_REQUEST_SHOWN.describe(
      'The request as it now stands: APPROVED, weighed again as everything now stands, keeping its reservation and order claim; or DENIED, rejected under your team’s rules as the ask showed, its money freed.',
    ),
  },
};

export function registerSpendRequests(
  app: FastifyInstance,
  {
    decisions,
    cancels,
    reads,
    rejects,
    approvals,
  }: {
    decisions: SpendRequestDecisions | undefined;
    cancels: SpendRequestCancels | undefined;
    reads: SpendRequestReads | undefined;
    rejects: SpendRequestRejects | undefined;
    approvals: SpendRequestApprovals | undefined;
  },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get(
    '/v1/spend-requests',
    { schema: LIST_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberInSessionOf(request);
      const page = { after: request.query.after ?? null, limit: request.query.limit ?? MOST_REQUESTS_A_PAGE };
      const found = await need(reads).list(orgId, page, 'all', request.id);
      if (found.outcome === 'refused') return answerRefusal(found, request, reply);
      return { spendRequests: found.requests.map(listed), next: found.next, unchecked: [...found.unchecked] };
    },
  );

  routes.get(
    '/v1/approvals',
    { schema: APPROVALS_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberInSessionOf(request);
      const page = { after: request.query.after ?? null, limit: request.query.limit ?? MOST_REQUESTS_A_PAGE };
      const found = await need(reads).list(orgId, page, 'waiting', request.id);
      if (found.outcome === 'refused') return answerRefusal(found, request, reply);
      return { waiting: found.requests.map(listed), next: found.next, unchecked: [...found.unchecked] };
    },
  );

  routes.get(
    '/v1/spend-requests/:id',
    { schema: SHOW_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberInSessionOf(request);
      const found = await need(reads).show(orgId, request.params.id, request.id);
      if (found.outcome === 'refused') return answerRefusal(found, request, reply);
      const { purpose, orderReference } = found.shown.request;
      const { rejection, voiding } = found;
      return {
        ...listed(found.shown),
        agentWrote: { purpose, orderReference },
        rejection: rejection === null ? null : { ...rejection, at: rejection.at.toISOString() },
        voiding: voiding === null ? null : { at: voiding.at.toISOString(), reasons: reasonsOf(voiding.causes) },
      };
    },
  );

  routes.post(
    '/v1/spend-requests',
    {
      schema: ASK_SCHEMA,
      bodyLimit: REQUEST_BODY_LIMIT,
      config: { access: ['agent'], agentScopes: ['requests:write'], operation: DECIDE_OPERATION },
    },
    async (request, reply) => {
      const { orgId, agentId, keyId } = agentOf(request);
      const { body } = request;
      const asked = {
        // The schema has checked both.
        amount: moneyFromJson(body.amountMinor, body.currency),
        supplierId: body.supplierId,
        fundingSourceId: body.fundingSourceId,
        ...askedText(body),
      };
      const decided = await need(decisions).decideAndReserve(
        { orgId, agentId, keyId },
        idempotentRequest(request, orgId),
        asked,
        request.id,
      );
      if (isUnwritten(decided)) return answerRefusal(decided, request, reply);
      return reply.code(201).send(shown(decided.request, 'agent'));
    },
  );

  routes.post(
    '/v1/spend-requests/:id/cancel',
    {
      schema: CANCEL_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...CANCELLING_ROLES], operation: CANCEL_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const cancelled = await need(cancels).byMember(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      if (isUnwritten(cancelled)) return answerRefusal(cancelled, request, reply);
      return reply.code(200).send(shown(cancelled.request, 'member'));
    },
  );

  routes.post(
    '/v1/spend-requests/:id/reject',
    {
      schema: REJECT_SCHEMA,
      bodyLimit: REJECT_BODY_LIMIT,
      config: { access: [...DECIDING_ROLES], operation: REJECT_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const asked = await need(rejects).ask(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        // The schema has checked it.
        rejectReason(request.body.reason).note,
        request.id,
      );
      return answerAsked(asked, request, reply);
    },
  );

  routes.post(
    '/v1/spend-requests/:id/reject/confirm',
    {
      schema: REJECT_CONFIRM_SCHEMA,
      bodyLimit: REJECT_BODY_LIMIT,
      config: { access: [...DECIDING_ROLES], operation: REJECT_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const { stepUpChallengeId, reason } = request.body;
      const rejected = await need(rejects).confirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        { stepUpChallengeId, reason: rejectReason(reason).note },
        request.id,
      );
      if (isUnwritten(rejected)) return answerRefusal(rejected, request, reply);
      return reply.code(200).send(shown(rejected.request, 'member'));
    },
  );

  routes.post(
    '/v1/spend-requests/:id/approve',
    {
      schema: APPROVE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...DECIDING_ROLES], operation: APPROVE_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const asked = await need(approvals).ask(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body?.recheck === true,
        request.id,
      );
      if (asked.outcome !== 'asked') return answerAsked(asked, request, reply);
      return reply.code(202).send({
        stepUpChallengeId: asked.stepUpChallengeId,
        recheck: shownRecheck(asked.recheck),
        rejection: shownRejection(asked.rejection),
      });
    },
  );

  routes.post(
    '/v1/spend-requests/:id/approve/confirm',
    {
      schema: APPROVE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...DECIDING_ROLES], operation: APPROVE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const approved = await need(approvals).confirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.body.recheck === true,
        request.id,
      );
      if (isUnwritten(approved)) return answerRefusal(approved, request, reply);
      return reply.code(200).send(shown(approved.request, 'member'));
    },
  );

  routes.get(
    '/v1/agent/spend-requests/:id',
    { schema: AGENT_SHOW_SCHEMA, config: { access: ['agent'], agentScopes: ['requests:read'] } },
    async (request, reply) => {
      const { orgId, agentId } = agentOf(request);
      const found = await need(reads).ofAgent(orgId, agentId, request.params.id, request.id);
      if (found.outcome === 'refused') return answerRefusal(found, request, reply);
      const shownToAgent = shown(found.request, 'agent');
      // Ended by a person or a brake: the reasons the decision gave no longer explain where it stands.
      return found.endedBecause === null ? shownToAgent : { ...shownToAgent, reasons: reasonsOf(found.endedBecause) };
    },
  );

  routes.post(
    '/v1/agent/spend-requests/:id/cancel',
    {
      schema: AGENT_CANCEL_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: ['agent'], agentScopes: ['requests:write'], operation: AGENT_CANCEL_OPERATION },
    },
    async (request, reply) => {
      const { orgId, agentId, keyId } = agentOf(request);
      const cancelled = await need(cancels).byAgent(
        { orgId, agentId, keyId },
        idempotentRequest(request, orgId),
        request.params.id,
        request.id,
      );
      if (isUnwritten(cancelled)) return answerRefusal(cancelled, request, reply);
      return reply.code(200).send(shown(cancelled.request, 'agent'));
    },
  );
}

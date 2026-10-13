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
// request refused for nothing it holds never maps its hidden approval line. Only what
// can't be recorded is refused: CURRENCY_NOT_ALLOWED (422), ORG_FROZEN (409),
// a key no longer live (401), INTEGRITY_FAILED (503), and the idempotency
// key's own answers. The answer shows the bank reference the order reference
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
// agent's own words, apart and labelled as its (SEC-AG-08, -10).
import { DECISIONS, reasonsShownToAgent } from '@agentx/core/modules/policies';
import {
  askedText,
  bankReferenceOf,
  MOST_REQUESTS_A_PAGE,
  ORDER_REFERENCE_MOST,
  REQUEST_PURPOSE_MOST,
  SPEND_REQUEST,
  SpendAskRefused,
  type SpendRequestRecord,
  WAITS_FOR_APPROVAL_MS,
} from '@agentx/core/modules/spend-requests';
import { moneyFromJson } from '@agentx/core/shared-kernel';
import { isUnwritten } from '@agentx/platform/db';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { agentOf, memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import {
  AMOUNT,
  issuesOf,
  NEXT,
  NOTHING,
  NOTHING_BODY_LIMIT,
  pageQuery,
  REASONS,
  reasonsOf,
  UNCHECKED,
} from './route-schemas.ts';
import {
  AGENT_CANCEL_OPERATION,
  CANCEL_OPERATION,
  CANCELLING_ROLES,
  type SpendRequestCancels,
} from './spend-request-cancels.ts';
import { DECIDE_OPERATION, type SpendRequestDecisions } from './spend-request-decisions.ts';
import type { RequestShown, SpendRequestReads } from './spend-request-reads.ts';

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
        'Where it stands: APPROVED (allowed), APPROVAL_REQUIRED (waiting for a person) or DENIED; later EXPIRED (waited 72 hours) or CANCELLED.',
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
        "What the bank's payment reference will read: the order reference in the 1 to 35 ASCII letters, digits, spaces and /?:().,'+- the rail carries.",
      ),
    changedAt: z.iso.datetime().describe('When it last moved, as its signed record says.'),
    expiresAt: z.iso
      .datetime()
      .nullable()
      .describe('While it waits for approval: when it expires, 72 hours from its decision. Otherwise null.'),
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

/** A request as a list shows it to the team. */
const listed = ({ request, changedAt, agentName, supplierName }: RequestShown) => ({
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
  // Its decision is its latest move while it waits, so its 72 hours run from changedAt (D7).
  expiresAt:
    request.status === 'APPROVAL_REQUIRED' ? new Date(changedAt.getTime() + WAITS_FOR_APPROVAL_MS).toISOString() : null,
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

export function registerSpendRequests(
  app: FastifyInstance,
  {
    decisions,
    cancels,
    reads,
  }: {
    decisions: SpendRequestDecisions | undefined;
    cancels: SpendRequestCancels | undefined;
    reads: SpendRequestReads | undefined;
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
      return { ...listed(found.shown), agentWrote: { purpose, orderReference } };
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

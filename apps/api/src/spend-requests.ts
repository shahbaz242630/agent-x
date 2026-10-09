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
// denied one too: the agent learns why, and the evidence keeps it. Only what
// can't be recorded is refused: CURRENCY_NOT_ALLOWED (422), ORG_FROZEN (409),
// a key no longer live (401), INTEGRITY_FAILED (503), and the idempotency
// key's own answers. The answer shows the bank reference the order reference
// becomes on the rail when that differs from it (decision 8): the same
// mapping as hand-off's.
import { DECISIONS } from '@agentx/core/modules/policies';
import {
  askedText,
  bankReferenceOf,
  ORDER_REFERENCE_MOST,
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

import { agentOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { AMOUNT, issuesOf, REASONS, reasonsOf } from './route-schemas.ts';
import { DECIDE_OPERATION, type SpendRequestDecisions } from './spend-request-decisions.ts';

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
      .describe('Where it stands: APPROVED (allowed), APPROVAL_REQUIRED (waiting for a person), or DENIED.'),
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

const shown = (request: SpendRequestRecord) => {
  const bankReference = bankReferenceOf(request.orderReference, request.id);
  return {
    id: request.id,
    status: request.status,
    decision: request.decision,
    reasons: reasonsOf(request.reasons),
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
  { decisions }: { decisions: SpendRequestDecisions | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

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
      return reply.code(201).send(shown(decided.request));
    },
  );
}

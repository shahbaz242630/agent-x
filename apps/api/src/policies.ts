// The policy routes (PRD §5, §7.1; BR-06; partner decision 5; Phase 2 C3):
// the organisation's own policy, every agent's defaults, and each mandate's
// own, which narrows it for that mandate's agent. An admin changes either,
// asking then confirming with a passkey, the rules sent with both; it is in
// force at once. Every member reads them. Amounts are whole minor units
// (fils), as integers (ADR-006 §1), checked at the edge as safe integers.
//
// The simulator (C4, partner decision 9): `POST /v1/mandates/{id}/policy/simulate`,
// for admins, approvers and developers, answers what a request by the
// mandate's agent would get now, with the rules in force or proposed ones in
// their place, writing nothing (policy-simulations.ts).
import { DECISIONS, DEFAULT_MONTHLY_CAP } from '@agentx/core/modules/policies';
import { orderReferenceOf, SpendAskRefused } from '@agentx/core/modules/spend-requests';
import {
  MOST_ALLOWED_SUPPLIERS,
  OVER_CAP,
  type PolicyRules,
  PolicyRulesRefused,
  policyRules,
  type PolicyVersionRecord,
} from '@agentx/core/modules/mandates';
import { moneyFromJson } from '@agentx/core/shared-kernel';
import { isUnwritten } from '@agentx/platform/db';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import {
  CHANGING_ROLES,
  POLICY_OPERATIONS,
  type PolicyChanges,
  type PolicyTarget,
  type PolicyView,
} from './policy-changes.ts';
import { type PolicySimulations, SIMULATING_ROLES, type Simulated } from './policy-simulations.ts';
import { AMOUNT, issuesOf, MANDATE_ID, REASONS, reasonsOf, STEP_UP_SIGNED_IN, stepUpAsked } from './route-schemas.ts';

/** Every member may see the organisation's policies, as its mandates. */
const READING_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;

/**
 * The most a change's body may be: 100 supplier IDs written as the longest
 * JSON can (each character a `\uXXXX` escape: 219 bytes with its quotes and
 * comma), the amounts, the currency and a challenge's ID, with room to spare
 * (the B8-3 lesson: it must fit every body the schema allows).
 */
const RULES_BODY_LIMIT = 32_768;

/** A policy's rules as a body sends them: each left out, or null, where the policy sets none. */
const RULE_FIELDS = {
  currency: z
    .string()
    .regex(/^[A-Z]{3}$/)
    .describe('The rules’ currency, an ISO 4217 code: AED in the Pilot, a mandate’s own for its policy.'),
  perOrderCap: z
    .strictObject({
      capMinor: AMOUNT.describe('The most one request may be under this policy.'),
      over: z.enum(OVER_CAP).describe('What a request above it gets: DENY, or REQUIRE_APPROVAL by a person.'),
    })
    .nullish()
    .describe('A per-order cap, or none.'),
  monthlyCapMinor: AMOUNT.nullish().describe(
    'The most each agent may spend in its month (every mandate of its counted): above it, DENY. None: the organisation’s policy’s, else AED 20,000; a mandate’s own replaces the organisation’s for its agent, higher or lower.',
  ),
  approvalThresholdMinor: AMOUNT.nullish().describe(
    'Above it, a person must approve the request: the lowest of the mandate’s and its policies’ applies.',
  ),
  supplierIds: z
    .array(z.uuid())
    .min(1)
    .max(MOST_ALLOWED_SUPPLIERS)
    .nullish()
    .describe(
      `The only suppliers that may be paid, by ID: 1 to ${String(MOST_ALLOWED_SUPPLIERS)}, each once; none: no list of its own.`,
    ),
};

type RuleFields = z.infer<z.ZodObject<typeof RULE_FIELDS>>;

/**
 * The most a simulation's body may be: two proposed policies of 100 supplier
 * IDs each written as the longest JSON can (as RULES_BODY_LIMIT, twice), the
 * request's fields and an order reference of 100 characters sent decomposed
 * and escaped, with room to spare (the B8-3 lesson).
 */
const SIMULATE_BODY_LIMIT = 49_152;

/** The rules a body gives, as a version keeps them; or `MoneyRefused` / `PolicyRulesRefused`. */
const rulesOf = (body: RuleFields): PolicyRules => {
  // Left out or null alike: the policy sets none.
  const amount = (minor: number | null | undefined) =>
    minor === null || minor === undefined ? null : moneyFromJson(minor, body.currency);
  const cap = body.perOrderCap ?? null;
  return policyRules({
    currency: body.currency,
    perOrderCap: cap === null ? null : { cap: moneyFromJson(cap.capMinor, body.currency), over: cap.over },
    monthlyCap: amount(body.monthlyCapMinor),
    approvalThreshold: amount(body.approvalThresholdMinor),
    supplierIds: body.supplierIds ?? null,
  });
};

/** Each problem that keeps the body's rules from being a policy's, as a refinement. */
const rulesChecked = (body: RuleFields, context: z.RefinementCtx): void => {
  issuesOf(() => rulesOf(body), PolicyRulesRefused, context);
};

/** Proposed rules for a policy: weighed in place of those in force, never kept. */
const PROPOSED_RULES = z.strictObject(RULE_FIELDS).superRefine(rulesChecked);

const SIMULATE_SCHEMA = {
  summary: 'What a request by the mandate’s agent would get now, with the rules in force or proposed ones',
  params: MANDATE_ID,
  body: z
    .strictObject({
      amountMinor: AMOUNT.describe('The amount, in whole minor units (fils for AED).'),
      currency: z.string().describe('The amount’s currency: the mandate’s, AED in the Pilot. Never converted.'),
      supplierId: z.uuid().describe('The supplier to pay, by ID.'),
      fundingSourceId: z.uuid().describe('The bank account to pay from, by ID.'),
      orderReference: z
        .string()
        .optional()
        .describe('The supplier’s order number, to check for a duplicate as a request would; none: not checked.'),
      whatIf: z
        .strictObject({
          organizationPolicy: PROPOSED_RULES.optional().describe(
            'Rules weighed in place of the organisation’s policy.',
          ),
          mandatePolicy: PROPOSED_RULES.optional().describe(
            'Rules weighed in place of this mandate’s policy: within its terms, as a change must be.',
          ),
        })
        .optional()
        .describe('Proposed rules, weighed in place of those in force and never kept; none: the rules in force.'),
    })
    .superRefine((body, context) => {
      issuesOf(() => moneyFromJson(body.amountMinor, body.currency), SpendAskRefused, context);
      if (body.orderReference !== undefined) {
        issuesOf(() => orderReferenceOf(body.orderReference ?? ''), SpendAskRefused, context);
      }
    })
    .describe('The request to weigh, and any proposed rules.'),
  response: {
    200: z
      .object({
        decision: z.enum(DECISIONS).describe('What the request would get now: nothing was made or reserved.'),
        reasons: REASONS,
        mandateId: z.uuid().nullable().describe('The agent’s mandate in force weighed, or null: it has none.'),
        versions: z
          .object({
            mandate: z.uuid().nullable(),
            organizationPolicy: z.uuid().nullable().describe('Null: none set, or the proposed rules weighed.'),
            mandatePolicy: z.uuid().nullable().describe('Null: none set, or the proposed rules weighed.'),
          })
          .describe('The versions in force weighed.'),
        proposed: z
          .object({ organizationPolicy: z.boolean(), mandatePolicy: z.boolean() })
          .describe('Which policies were weighed as proposed, in place of those in force.'),
        monthlyCapFrom: z
          .enum(['mandate-policy', 'organization-policy', 'default'])
          .describe('Where the agent’s monthly cap came from.'),
        month: z.string().nullable().describe('The agent’s month (YYYY-MM) in its zone, or null without a mandate.'),
        monthSpentMinor: z
          .number()
          .describe('What the agent holds or spent in that month, under every mandate of its, in whole minor units.'),
      })
      .register(API_SCHEMAS, {
        id: 'PolicySimulation',
        description: 'What a request would get now, weighed by the same engine and totals; nothing made.',
      }),
  },
};

/** A version weighed as the answer shows it: a proposed policy's is none. */
const versionShown = (versionId: string | null, proposed: boolean) => (proposed ? null : versionId);

const simulationBody = ({ made, mandateId, month, monthSpent, proposed }: Simulated) => ({
  decision: made.decision,
  reasons: reasonsOf(made.reasons),
  mandateId,
  versions: {
    mandate: made.versions.mandate,
    organizationPolicy: versionShown(made.versions.organizationPolicy, proposed.organizationPolicy),
    mandatePolicy: versionShown(made.versions.mandatePolicy, proposed.mandatePolicy),
  },
  proposed,
  monthlyCapFrom: made.monthlyCapFrom,
  month,
  monthSpentMinor: Number(monthSpent.minor),
});

const POLICY_VERSION = z
  .object({
    id: z.uuid().describe('The version, by its ID.'),
    version: z.int().describe('Its number, from 1.'),
    currency: z.string(),
    perOrderCap: z
      .object({ capMinor: z.number().describe('Whole minor units.'), over: z.enum(OVER_CAP) })
      .nullable()
      .describe('Its per-order cap, or null for none.'),
    monthlyCapMinor: z.number().nullable().describe('Whole minor units, or null for none.'),
    approvalThresholdMinor: z.number().nullable().describe('Whole minor units, or null for none.'),
    supplierIds: z.array(z.uuid()).nullable().describe('Its supplier list in order of ID, or null for none.'),
    rulesHash: z.string().describe('SHA-256 of these rules: what the change’s step-up was bound to.'),
    madeBy: z.uuid().describe('The membership of the admin who made it.'),
    madeAt: z.iso.datetime(),
  })
  .register(API_SCHEMAS, { id: 'PolicyVersion', description: 'One version of a policy’s rules, made once.' });

const POLICY = z
  .object({
    scope: z.enum(['organization', 'mandate']).describe('The organisation’s own policy, or a mandate’s.'),
    id: z.uuid().describe('The policy: the organisation’s ID for its own, the mandate’s for a mandate’s.'),
    mandateId: z.uuid().nullable().describe('The mandate, for a mandate’s policy.'),
    current: POLICY_VERSION.nullable().describe('The rules in force, or null: none was ever set.'),
    defaultMonthlyCapMinor: z
      .number()
      .describe('Each agent’s monthly cap when no policy sets one (AED 20,000), in whole minor units.'),
  })
  .register(API_SCHEMAS, { id: 'Policy', description: 'A policy and the rules in force.' });

/** Each kind's words, params and paths. */
const KINDS = {
  organization: {
    path: '/v1/policies/organization',
    params: undefined,
    asked: [
      'OrganizationPolicyChangeAsked',
      'Changing the organisation’s policy, waiting for the admin to sign in again.',
    ],
    show: 'Your organisation’s own policy: every agent’s defaults',
    ask: 'Ask to change the organisation’s policy, signing in again with a passkey',
    confirm: 'Change the organisation’s policy, once signed in again for it with a passkey',
  },
  mandate: {
    path: '/v1/mandates/:id/policy',
    params: MANDATE_ID,
    asked: ['MandatePolicyChangeAsked', 'Changing a mandate’s policy, waiting for the admin to sign in again.'],
    show: 'A mandate’s own policy, narrowing it for its agent',
    ask: 'Ask to change a mandate’s policy, within its terms, signing in again with a passkey',
    confirm: 'Change the mandate’s policy, once signed in again for it with a passkey',
  },
} as const;

type Kind = keyof typeof KINDS;

const schemasOf = (kind: Kind) => {
  const words = KINDS[kind];
  const params = words.params === undefined ? {} : { params: words.params };
  return {
    show: { summary: words.show, ...params, response: { 200: POLICY } },
    ask: {
      summary: words.ask,
      ...params,
      body: z.strictObject(RULE_FIELDS).superRefine(rulesChecked).describe('Every rule of the new version.'),
      response: { 202: stepUpAsked(words.asked[0], words.asked[1]) },
    },
    confirm: {
      summary: words.confirm,
      ...params,
      body: z
        .strictObject({ ...RULE_FIELDS, stepUpChallengeId: STEP_UP_SIGNED_IN })
        .superRefine(rulesChecked)
        .describe('The same rules as the ask, with the step-up it answered, signed in again for.'),
      response: { 200: POLICY.describe('The policy with the new rules in force.') },
    },
  };
};

const versionOf = (v: PolicyVersionRecord) => ({
  id: v.id,
  version: v.version,
  currency: v.currency,
  perOrderCap: v.perOrderCap === null ? null : { capMinor: Number(v.perOrderCap.cap.minor), over: v.perOrderCap.over },
  monthlyCapMinor: v.monthlyCap === null ? null : Number(v.monthlyCap.minor),
  approvalThresholdMinor: v.approvalThreshold === null ? null : Number(v.approvalThreshold.minor),
  supplierIds: v.supplierIds === null ? null : [...v.supplierIds],
  rulesHash: v.rulesHash,
  madeBy: v.madeBy,
  madeAt: v.madeAt.toISOString(),
});

const policyBody = ({ scope, id, mandateId, current }: PolicyView) => ({
  scope,
  id,
  mandateId,
  current: current === null ? null : versionOf(current),
  defaultMonthlyCapMinor: Number(DEFAULT_MONTHLY_CAP.minor),
});

const targetOf = (kind: Kind, request: FastifyRequest): PolicyTarget => {
  if (kind === 'organization') return { scope: 'organization' };
  const { id } = MANDATE_ID.parse(request.params);
  return { scope: 'mandate', mandateId: id };
};

export function registerPolicies(
  app: FastifyInstance,
  { changes, simulations }: { changes: PolicyChanges | undefined; simulations: PolicySimulations | undefined },
) {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.post(
    '/v1/mandates/:id/policy/simulate',
    {
      schema: SIMULATE_SCHEMA,
      bodyLimit: SIMULATE_BODY_LIMIT,
      config: { access: [...SIMULATING_ROLES], writesNothing: true },
    },
    async (request, reply) => {
      const { orgId } = memberInSessionOf(request);
      const { body } = request;
      const { organizationPolicy, mandatePolicy } = body.whatIf ?? {};
      const simulated = await need(simulations).simulate(
        orgId,
        request.params.id,
        {
          // The schema has checked both.
          amount: moneyFromJson(body.amountMinor, body.currency),
          supplierId: body.supplierId,
          fundingSourceId: body.fundingSourceId,
          orderReference: body.orderReference === undefined ? null : orderReferenceOf(body.orderReference),
        },
        {
          organizationPolicy: organizationPolicy && rulesOf(organizationPolicy),
          mandatePolicy: mandatePolicy && rulesOf(mandatePolicy),
        },
        request.id,
      );
      if (simulated.outcome === 'refused') return answerRefusal(simulated, request, reply);
      return simulationBody(simulated);
    },
  );

  for (const kind of ['organization', 'mandate'] as const) {
    const schemas = schemasOf(kind);
    const { path } = KINDS[kind];

    routes.get(path, { schema: schemas.show, config: { access: [...READING_ROLES] } }, async (request, reply) => {
      const { orgId } = memberInSessionOf(request);
      const found = await need(changes).show(orgId, targetOf(kind, request), request.id);
      if (found.outcome === 'refused') return answerRefusal(found, request, reply);
      return policyBody(found);
    });

    routes.post(
      `${path}/change`,
      {
        schema: schemas.ask,
        bodyLimit: RULES_BODY_LIMIT,
        config: { access: [...CHANGING_ROLES], operation: POLICY_OPERATIONS[kind].ask },
      },
      async (request, reply) => {
        const member = memberInSessionOf(request);
        const asked = await need(changes).ask(
          member,
          idempotentRequest(request, member.orgId),
          targetOf(kind, request),
          rulesOf(request.body),
          request.id,
        );
        return answerAsked(asked, request, reply);
      },
    );

    routes.post(
      `${path}/change/confirm`,
      {
        schema: schemas.confirm,
        bodyLimit: RULES_BODY_LIMIT,
        config: { access: [...CHANGING_ROLES], operation: POLICY_OPERATIONS[kind].confirm },
      },
      async (request, reply) => {
        const member = memberInSessionOf(request);
        const changed = await need(changes).confirm(
          member,
          idempotentRequest(request, member.orgId),
          targetOf(kind, request),
          rulesOf(request.body),
          request.body.stepUpChallengeId,
          request.id,
        );
        if (isUnwritten(changed)) return answerRefusal(changed, request, reply);
        return reply.code(200).send(policyBody(changed));
      },
    );
  }
}

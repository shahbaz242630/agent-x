// The policy routes (PRD §5, §7.1; BR-06; partner decision 5; Phase 2 C3):
// the organisation's own policy, every agent's defaults, and each mandate's
// own, which narrows it for that mandate's agent. An admin changes either,
// asking then confirming with a passkey, the rules sent with both; it is in
// force at once. Every member reads them. Amounts are whole minor units
// (fils), as integers (ADR-006 §1), checked at the edge as safe integers.
import { DEFAULT_MONTHLY_CAP } from '@agentx/core/modules/policies';
import {
  MOST_ALLOWED_SUPPLIERS,
  OVER_CAP,
  type PolicyRules,
  PolicyRulesRefused,
  policyRules,
  type PolicyVersionRecord,
} from '@agentx/core/modules/mandates';
import { MoneyRefused, moneyFromJson } from '@agentx/core/shared-kernel';
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
import { STEP_UP_SIGNED_IN, stepUpAsked } from './route-schemas.ts';

/** Every member may see the organisation's policies, as its mandates. */
const READING_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;

/**
 * The most a change's body may be: 100 supplier IDs of 38 bytes with their
 * quotes and commas, the amounts, the currency and a challenge's ID, with room
 * to spare (the B8-3 lesson: it must fit every body the schema allows).
 */
const RULES_BODY_LIMIT = 8_192;

const AMOUNT = z
  .number()
  .describe('Whole minor units (fils for AED): an integer from 1 to 2^53 − 1, never a string or a fraction.');

/** A policy's rules as a body sends them: each left out, or null, where the policy sets none. */
const RULE_FIELDS = {
  currency: z.string().describe('The rules’ currency: AED in the Pilot, a mandate’s own for its policy.'),
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

/**
 * Each problem that keeps the body's rules from being a policy's, as a
 * refinement: the body stays the JSON it came as, since the idempotency key's
 * fingerprint has no form for Money's bigints (S89).
 */
const rulesChecked = (body: RuleFields, context: z.RefinementCtx): void => {
  try {
    rulesOf(body);
  } catch (error) {
    if (error instanceof MoneyRefused) context.addIssue({ code: 'custom', message: error.message });
    else if (error instanceof PolicyRulesRefused) {
      for (const problem of error.problems) context.addIssue({ code: 'custom', message: problem });
    } else throw error;
  }
};

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

const MANDATE_ID = z.object({ id: z.uuid().describe('The mandate, by its ID.') });

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

export function registerPolicies(app: FastifyInstance, { changes }: { changes: PolicyChanges | undefined }) {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  for (const kind of ['organization', 'mandate'] as const) {
    const schemas = schemasOf(kind);
    const { path } = KINDS[kind];

    routes.get(path, { schema: schemas.show, config: { access: [...READING_ROLES] } }, async (request, reply) => {
      const { member } = request;
      if (member === null) throw new Error('a policies route ran without a member');
      const found = await need(changes).show(member.orgId, targetOf(kind, request), request.id);
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

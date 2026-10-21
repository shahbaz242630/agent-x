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
//
// The organisation's change names its monthly cap choice (decision 15, E2):
// `amount` with a monthly cap, `none` without; no agent spends until one is
// chosen (monthly-cap-choice.ts).
//
// The preview (E5d, decision 19): `POST …/change/preview`, an admin's, with
// the ask's body, answers which requests waiting for approval the rules
// would reject and why, writing nothing (policy-waiting.ts).
import { DECISIONS, MONTHLY_CAP_FROM } from '@agentx/core/modules/policies';
import {
  type ApprovalWaitHours,
  LONGEST_APPROVAL_WAIT,
  orderReferenceOf,
  SpendAskRefused,
} from '@agentx/core/modules/spend-requests';
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
import { APPROVAL_WAIT_HOURS } from './approval-wait-choice.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import {
  MONTHLY_CAP_CHOICE,
  MONTHLY_CAP_CHOICES,
  type MonthlyCapChoice,
  SUGGESTED_MONTHLY_CAP_MINOR,
} from './monthly-cap-choice.ts';
import {
  CHANGING_ROLES,
  POLICY_OPERATIONS,
  type PolicyChanges,
  type PolicyTarget,
  type PolicyView,
} from './policy-changes.ts';
import { type PolicySimulations, SIMULATING_ROLES, type Simulated } from './policy-simulations.ts';
import { WAITING_REQUESTS, type WaitingChoice, type WaitingPlan } from './policy-waiting.ts';
import {
  AMOUNT,
  issuesOf,
  MANDATE_ID,
  REASONS,
  reasonsOf,
  RULE_DENIAL_SHOWN,
  shownRules,
  STEP_UP_SIGNED_IN,
  stepUpAskedWith,
} from './route-schemas.ts';

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
    'The most each agent may spend in its month (every mandate of its counted): above it, DENY. A mandate’s own replaces the organisation’s for its agent, higher or lower; none in a mandate’s: the organisation’s. The organisation’s is given with monthlyCapChoice `amount`, left out with `none`.',
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

/** A change's body: the organisation's names its monthly cap choice (E2) and its approval wait (E6). */
type ChangeBody = RuleFields & {
  readonly monthlyCapChoice?: MonthlyCapChoice | undefined;
  readonly approvalWaitHours?: ApprovalWaitHours | undefined;
  readonly waitingRequests?: WaitingChoice | undefined;
};

/** A change's choice for the waiting requests it would reject (E5d, decision 19): never the preview's. */
const WAITING_FIELD = { waitingRequests: WAITING_REQUESTS.optional() };

/**
 * The organisation's rules with its choices: the cap's, which must say what
 * they do (an amount with a monthly cap, none without), and the wait, always.
 */
const ORGANIZATION_FIELDS = {
  ...RULE_FIELDS,
  monthlyCapChoice: MONTHLY_CAP_CHOICE,
  approvalWaitHours: APPROVAL_WAIT_HOURS,
};

const choiceChecked = (body: ChangeBody, context: z.RefinementCtx): void => {
  rulesChecked(body, context);
  const capped = body.monthlyCapMinor !== null && body.monthlyCapMinor !== undefined;
  if ((body.monthlyCapChoice === 'amount') !== capped) {
    context.addIssue({
      code: 'custom',
      path: ['monthlyCapChoice'],
      message: '`amount` must come with monthlyCapMinor, and `none` without it',
    });
  }
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
      const { orderReference } = body;
      if (orderReference !== undefined) issuesOf(() => orderReferenceOf(orderReference), SpendAskRefused, context);
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
          .enum(MONTHLY_CAP_FROM)
          .describe(
            'Where the agent’s monthly cap came from: `none`, the organisation chose none; `not-set`, its admin hasn’t chosen yet, so every request is denied (ORG_MONTHLY_CAP_NOT_SET).',
          ),
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
    monthlyCapChoice: z
      .enum(MONTHLY_CAP_CHOICES)
      .nullable()
      .describe(
        'The organisation’s monthly cap per agent as its admin chose it: `amount` (current.monthlyCapMinor) or `none`; null: not chosen yet, so no agent may spend (ORG_MONTHLY_CAP_NOT_SET). Always null for a mandate’s policy.',
      ),
    approvalWaitHours: z
      .number()
      .nullable()
      .describe(
        'How many hours the organisation’s requests wait for approval as its admin chose it: 24, 48 or 72; null: not chosen yet (72 in force), or a mandate’s policy.',
      ),
    approvalWaitInForceHours: z
      .number()
      .nullable()
      .describe(
        'The wait new requests get now: the one chosen, else 72. Each request keeps the wait it was asked under. Null for a mandate’s policy.',
      ),
    suggestedMonthlyCapMinor: z
      .number()
      .describe(
        'The amount the console suggests for the organisation’s monthly cap (AED 20,000), in whole minor units: never applied until an admin chooses it.',
      ),
  })
  .register(API_SCHEMAS, { id: 'Policy', description: 'A policy and the rules in force.' });

const WAITING_PREVIEW = z
  .object({
    rejected: z
      .array(
        z.object({
          id: z.uuid().describe('The spend request.'),
          agentId: z.uuid().describe('The agent that asked.'),
          amountMinor: z.number().describe('Whole minor units.'),
          currency: z.string(),
          reasons: z.array(RULE_DENIAL_SHOWN).describe('The rules that would reject it, with what to do.'),
        }),
      )
      .describe(
        'Oldest first, at most 20: each request waiting for approval that these rules would reject, though the ' +
          'rules in force don’t. One the rules in force refuse already, one whose supplier or mandate changed since, ' +
          'and one past its wait stay with their approvers and aren’t listed.',
      ),
    more: z
      .boolean()
      .describe(
        'True when there are others not listed: more than 20 would be rejected, or more than 100 are waiting and ' +
          'the younger weren’t weighed yet. `reject` rejects all the others these rules would within minutes.',
      ),
  })
  .register(API_SCHEMAS, {
    id: 'PolicyWaitingPreview',
    description: 'The requests waiting for approval a policy change would reject, written nothing.',
  });

const previewBody = ({ rejected, more }: WaitingPlan) => ({
  rejected: rejected.map(({ id, agentId, amount, reasons }) => ({
    id,
    agentId,
    amountMinor: Number(amount.minor),
    currency: amount.currency,
    reasons: shownRules(reasons),
  })),
  more,
});

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
    preview: 'See which requests waiting for approval a change of the organisation’s policy would reject',
  },
  mandate: {
    path: '/v1/mandates/:id/policy',
    params: MANDATE_ID,
    asked: ['MandatePolicyChangeAsked', 'Changing a mandate’s policy, waiting for the admin to sign in again.'],
    show: 'A mandate’s own policy, narrowing it for its agent',
    ask: 'Ask to change a mandate’s policy, within its terms, signing in again with a passkey',
    confirm: 'Change the mandate’s policy, once signed in again for it with a passkey',
    preview: 'See which requests waiting for approval a change of a mandate’s policy would reject',
  },
} as const;

type Kind = keyof typeof KINDS;

const ASK_WORDS = 'Every rule of the new version, and what happens to the waiting requests they would reject.';
const PREVIEW_WORDS = 'Every rule of the new version, as the ask sends them.';
const CONFIRM_WORDS = 'The same rules as the ask, with the step-up it answered, signed in again for.';

/** Each kind's ask and confirm bodies: only the organisation's names its monthly cap choice. */
const BODIES = {
  organization: {
    preview: z.strictObject(ORGANIZATION_FIELDS).superRefine(choiceChecked).describe(PREVIEW_WORDS),
    ask: z
      .strictObject({ ...ORGANIZATION_FIELDS, ...WAITING_FIELD })
      .superRefine(choiceChecked)
      .describe(ASK_WORDS),
    confirm: z
      .strictObject({ ...ORGANIZATION_FIELDS, ...WAITING_FIELD, stepUpChallengeId: STEP_UP_SIGNED_IN })
      .superRefine(choiceChecked)
      .describe(CONFIRM_WORDS),
  },
  mandate: {
    preview: z.strictObject(RULE_FIELDS).superRefine(rulesChecked).describe(PREVIEW_WORDS),
    ask: z
      .strictObject({ ...RULE_FIELDS, ...WAITING_FIELD })
      .superRefine(rulesChecked)
      .describe(ASK_WORDS),
    confirm: z
      .strictObject({ ...RULE_FIELDS, ...WAITING_FIELD, stepUpChallengeId: STEP_UP_SIGNED_IN })
      .superRefine(rulesChecked)
      .describe(CONFIRM_WORDS),
  },
};

const schemasOf = (kind: Kind) => {
  const words = KINDS[kind];
  const params = words.params === undefined ? {} : { params: words.params };
  // Either kind's, as the handlers read them alike.
  const preview: z.ZodType<ChangeBody> = BODIES[kind].preview;
  const ask: z.ZodType<ChangeBody> = BODIES[kind].ask;
  const confirm: z.ZodType<ChangeBody & { readonly stepUpChallengeId: string }> = BODIES[kind].confirm;
  return {
    show: { summary: words.show, ...params, response: { 200: POLICY } },
    ask: {
      summary: words.ask,
      ...params,
      body: ask,
      response: {
        202: stepUpAskedWith(words.asked[0], words.asked[1], {
          waiting: WAITING_PREVIEW.describe(
            'The requests waiting for approval these rules would reject, as the preview lists them: what ' +
              '`waitingRequests` applies to. Confirming applies exactly this; if anything changes first, the ' +
              'confirm is refused and you ask again.',
          ),
        }),
      },
    },
    confirm: {
      summary: words.confirm,
      ...params,
      body: confirm,
      response: { 200: POLICY.describe('The policy with the new rules in force.') },
    },
    preview: { summary: words.preview, ...params, body: preview, response: { 200: WAITING_PREVIEW } },
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

const policyBody = ({ scope, id, mandateId, current, monthlyCapChoice, approvalWait }: PolicyView) => ({
  scope,
  id,
  mandateId,
  current: current === null ? null : versionOf(current),
  monthlyCapChoice,
  approvalWaitHours: approvalWait,
  approvalWaitInForceHours: scope === 'organization' ? (approvalWait ?? LONGEST_APPROVAL_WAIT) : null,
  suggestedMonthlyCapMinor: SUGGESTED_MONTHLY_CAP_MINOR,
});

/** The body's rules, with its choices: none sent (a mandate's) is null. */
const askedOf = (body: ChangeBody) => ({
  rules: rulesOf(body),
  capChoice: body.monthlyCapChoice ?? null,
  approvalWait: body.approvalWaitHours ?? null,
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
          askedOf(request.body),
          request.body.waitingRequests,
          request.id,
        );
        if (asked.outcome !== 'asked') return answerAsked(asked, request, reply);
        return reply
          .code(202)
          .send({ stepUpChallengeId: asked.stepUpChallengeId, waiting: previewBody(asked.waiting) });
      },
    );

    routes.post(
      `${path}/change/preview`,
      {
        schema: schemas.preview,
        bodyLimit: RULES_BODY_LIMIT,
        config: { access: [...CHANGING_ROLES], writesNothing: true },
      },
      async (request, reply) => {
        const previewed = await need(changes).preview(
          memberInSessionOf(request),
          targetOf(kind, request),
          askedOf(request.body),
          request.id,
        );
        if (previewed.outcome === 'refused') return answerRefusal(previewed, request, reply);
        return previewBody(previewed);
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
          askedOf(request.body),
          request.body.waitingRequests,
          request.body.stepUpChallengeId,
          request.id,
        );
        if (isUnwritten(changed)) return answerRefusal(changed, request, reply);
        return reply.code(200).send(policyBody(changed));
      },
    );
  }
}

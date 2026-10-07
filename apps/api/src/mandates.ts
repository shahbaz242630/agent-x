// The mandate routes (PRD §7.1, BR-05, BR-06; Phase 2 B2): an admin drafts a
// mandate for one of the organisation's agents, and later versions of it;
// every member reads them. A draft grants nothing until an admin accepts it
// with a passkey (B3). An admin suspends, resumes or revokes one the same way,
// asking then confirming with a passkey (B4). Amounts are whole minor units (fils), as integers
// (ADR-006 §1), checked at the edge as safe integers and kept as bigints.
import {
  CONSENT_LIMITS,
  DEFAULT_CONSENT_LIMITS,
  MANDATE,
  type MandateRecord,
  type MandateTerms,
  MandateTermsRefused,
  mandateTerms,
  MOST_ALLOWED_SUPPLIERS,
  MOST_MANDATES_A_PAGE,
  PURPOSE_MOST,
  SPLIT_WINDOW_HOURS,
} from '@agentx/core/modules/mandates';
import { MoneyRefused, moneyFromJson, timeZoneOf } from '@agentx/core/shared-kernel';
import { isUnwritten } from '@agentx/platform/db';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import {
  DRAFT_OPERATION,
  DRAFTING_ROLES,
  type MandateRegistry,
  type MandateWrite,
  REDRAFT_OPERATION,
} from './mandate-registry.ts';
import {
  ACCEPT_CONFIRM_OPERATION,
  ACCEPT_OPERATION,
  ACCEPTING_ROLES,
  type MandateAcceptance,
} from './mandate-acceptance.ts';
import { MANDATE_MOVES, type MandateMove, type MandateMoves, MOVE_OPERATIONS, MOVING_ROLES } from './mandate-moves.ts';
import type { MandateView, VersionShown } from './mandate-reads.ts';
import {
  CHALLENGE_BODY_LIMIT,
  NEXT,
  NOTHING,
  NOTHING_BODY_LIMIT,
  pageQuery,
  STEP_UP_CONFIRM,
  stepUpAsked,
} from './route-schemas.ts';

/** Every member may see the organisation's mandates. */
const READING_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;

/**
 * The most a draft's body may be: a purpose of at most 200 code points once
 * composed, sent decomposed as at most 4 each, astral at worst, each UTF-16
 * unit as a `\uXXXX` escape (200 × 4 × 2 × 6 bytes); 100 supplier IDs of 38
 * bytes with their quotes and commas; the agent, the source, the zone, the
 * amounts and the settings, with room to spare (the B8-3 lesson: it must fit
 * every body the schema allows).
 */
const DRAFT_BODY_LIMIT = 16_384;

const AMOUNT = z
  .number()
  .describe('Whole minor units (fils for AED): an integer from 1 to 2^53 − 1, never a string or a fraction.');

/** A version's terms as a body sends them. */
const TERM_FIELDS = {
  purpose: z.string().describe(`What the agent may spend on: 1 to ${String(PURPOSE_MOST)} visible characters.`),
  currency: z.string().describe('The mandate’s currency, its funding source’s: AED in the Pilot.'),
  perOrderLimitMinor: AMOUNT.describe('The most one request may be. Above it: REQUIRE_NEW_MANDATE.'),
  monthlyLimitMinor: AMOUNT.describe('The most the agent may spend in a month, every mandate of its counted.'),
  approvalThresholdMinor: AMOUNT.describe('Above it, a person must approve the request. At most the per-order limit.'),
  supplierIds: z
    .array(z.uuid())
    .min(1)
    .max(MOST_ALLOWED_SUPPLIERS)
    .describe(`The suppliers it may pay, by ID: 1 to ${String(MOST_ALLOWED_SUPPLIERS)}, each once.`),
  fundingSourceId: z.uuid().describe('The funding source it draws on: one of the organisation’s, able to fund now.'),
  splitCheck: z
    .boolean()
    .optional()
    .describe('Whether a split order counts toward the approval threshold (ADR-014 §5): on unless switched off.'),
  consentLimits: z
    .enum(CONSENT_LIMITS)
    .optional()
    .describe(
      'Above the bank consent’s limits: strict (the default) refuses the mandate; flexible keeps it, with a warning that the bank may refuse a payment.',
    ),
  endsAt: z.iso.datetime().nullish().describe('When it ends, in the future; none: until revoked.'),
};

type TermFields = z.infer<z.ZodObject<typeof TERM_FIELDS>>;

/** The terms as a version keeps them, an end checked against `now`; or `MoneyRefused` / `MandateTermsRefused`. */
const termsOf = (body: TermFields, now: Date): MandateTerms =>
  mandateTerms(
    {
      purpose: body.purpose,
      perOrderLimit: moneyFromJson(body.perOrderLimitMinor, body.currency),
      monthlyLimit: moneyFromJson(body.monthlyLimitMinor, body.currency),
      approvalThreshold: moneyFromJson(body.approvalThresholdMinor, body.currency),
      supplierIds: body.supplierIds,
      fundingSourceId: body.fundingSourceId,
      splitCheck: body.splitCheck ?? true,
      consentLimits: body.consentLimits ?? DEFAULT_CONSENT_LIMITS,
      endsAt: body.endsAt ? new Date(body.endsAt) : null,
    },
    now,
  );

/**
 * Each problem that keeps the body's terms from being a version's, as a
 * refinement: the body stays the JSON it came as, since the idempotency key's
 * fingerprint (canonicalJson) has no form for Money's bigints.
 */
const termsChecked = (body: TermFields, context: z.RefinementCtx): void => {
  try {
    // The edge has no clock of its own; the registry checks the end again on its clock (termsChecked).
    termsOf(body, new Date());
  } catch (error) {
    if (error instanceof MoneyRefused) context.addIssue({ code: 'custom', message: error.message });
    else if (error instanceof MandateTermsRefused) {
      for (const problem of error.problems) context.addIssue({ code: 'custom', message: problem });
    } else throw error;
  }
};

/** Before any end: the handler's terms, the schema having checked them, leave a passed end to the use case's clock. */
const ANY_END = new Date(0);

/** The terms of a body its schema has passed. */
const termsKept = (body: TermFields): MandateTerms => termsOf(body, ANY_END);

const VERSION = z
  .object({
    id: z.uuid().describe('The version, by its ID.'),
    version: z.int().describe('Its number, from 1.'),
    purpose: z.string(),
    currency: z.string(),
    perOrderLimitMinor: z.number().describe('Whole minor units.'),
    monthlyLimitMinor: z.number().describe('Whole minor units.'),
    approvalThresholdMinor: z.number().describe('Whole minor units.'),
    supplierIds: z.array(z.uuid()).describe('The suppliers it may pay, in order of ID.'),
    fundingSourceId: z.uuid(),
    splitCheck: z.boolean(),
    consentLimits: z.enum(CONSENT_LIMITS),
    endsAt: z.iso.datetime().nullable().describe('When it ends, or null: until revoked.'),
    termsHash: z
      .string()
      .describe('SHA-256 of these terms with the mandate they bind: what an acceptance is bound to.'),
    draftedBy: z.uuid().describe('The membership of the admin who drafted it.'),
    draftedAt: z.iso.datetime(),
    consentWarnings: z
      .array(z.string())
      .describe(
        'Where these terms now go past the funding source’s bank consent: the bank may refuse such a payment. Empty when they fit.',
      ),
  })
  .register(API_SCHEMAS, { id: 'MandateVersion', description: 'One version of a mandate’s terms, made once.' });

const STATUS = z
  .enum(MANDATE.states)
  .describe(
    'PENDING_ACCEPTANCE until an admin accepts it with a passkey; ACTIVE; SUSPENDED (the brake); REVOKED or EXPIRED end it.',
  );

const MANDATE_FIELDS = {
  id: z.uuid().describe('The mandate, by its ID: the same across its versions.'),
  agentId: z.uuid().describe('The agent it gives authority to.'),
  timeZone: z.string().describe('The IANA time zone its months are counted in, fixed when it was drafted.'),
  splitWindowHours: z.int().describe('The split check’s rolling window, in hours, fixed when it was drafted.'),
  status: STATUS,
};

const MANDATE_LISTED = z
  .object({
    ...MANDATE_FIELDS,
    purpose: z.string().describe('The purpose of the version in force, or else the draft’s.'),
  })
  .register(API_SCHEMAS, { id: 'Mandate', description: 'A mandate of the organisation, as Agent X holds it.' });

const MANDATE_DETAILS = z
  .object({
    ...MANDATE_FIELDS,
    acceptedBy: z.uuid().nullable().describe('The membership of the admin who accepted the version in force, or null.'),
    acceptedAt: z.iso.datetime().nullable(),
    current: VERSION.nullable().describe('The version in force, or null until one is accepted.'),
    pending: VERSION.nullable().describe('A draft waiting for acceptance, or null.'),
  })
  .register(API_SCHEMAS, {
    id: 'MandateDetails',
    description: 'A mandate with its version in force and the draft waiting.',
  });

const DRAFT_SCHEMA = {
  summary: 'Draft a mandate for an agent, waiting for acceptance',
  body: z
    .strictObject({
      agentId: z.uuid().describe('The agent: active, with no mandate waiting or in force.'),
      timeZone: z
        .string()
        .max(64)
        .optional()
        .describe('The IANA time zone its months are counted in (Asia/Dubai unless given): fixed for good.'),
      splitWindowHours: z
        .int()
        .min(SPLIT_WINDOW_HOURS.least)
        .max(SPLIT_WINDOW_HOURS.most)
        .optional()
        .describe('The split check’s rolling window in hours (24 unless given): fixed for good.'),
      ...TERM_FIELDS,
    })
    .superRefine((body, context) => {
      if (body.timeZone !== undefined && timeZoneOf(body.timeZone) === undefined) {
        context.addIssue({ code: 'custom', message: 'the time zone is not one the IANA database names' });
      }
      termsChecked(body, context);
    })
    .describe('The mandate to draft, with its first terms.'),
  response: { 201: MANDATE_DETAILS.describe('The mandate, waiting for an admin to accept it.') },
};

const MANDATE_ID = z.object({ id: z.uuid().describe('The mandate, by its ID.') });

const REDRAFT_SCHEMA = {
  summary: 'Draft a new version of a mandate, waiting for acceptance',
  params: MANDATE_ID,
  body: z
    .strictObject(TERM_FIELDS)
    .superRefine(termsChecked)
    .describe('Every term of the new version: the agent, zone and window stay as they are.'),
  response: {
    200: MANDATE_DETAILS.describe(
      'The mandate with the new draft waiting in place of any that waited; the version in force is unchanged until accepted.',
    ),
  },
};

/** The most an accept's body may be: a version's ID, with room to spare. */
const ACCEPT_BODY_LIMIT = 128;

const ACCEPT_SCHEMA = {
  summary: 'Ask to accept the draft waiting, signing in again with a passkey',
  params: MANDATE_ID,
  body: z
    .strictObject({ versionId: z.uuid().describe('The draft waiting, as you read it: its terms are what you accept.') })
    .describe('The draft to accept.'),
  response: {
    202: stepUpAsked('MandateAcceptanceAsked', 'Accepting a mandate’s draft, waiting for the admin to sign in again.'),
  },
};

const ACCEPT_CONFIRM_SCHEMA = {
  summary: 'Accept the draft, once signed in again for it with a passkey',
  params: MANDATE_ID,
  body: STEP_UP_CONFIRM,
  response: {
    200: MANDATE_DETAILS.describe(
      'The mandate with the draft in force (ACTIVE, if it was its first), the version it replaced superseded.',
    ),
  },
};

/** Each move's words in its routes' schemas. */
const MOVE_WORDS = {
  suspend: {
    asked: ['MandateSuspensionAsked', 'Suspending a mandate, waiting for the admin to sign in again.'],
    ask: 'Ask to suspend a mandate in force (the brake), signing in again with a passkey',
    confirm: 'Suspend the mandate, once signed in again for it with a passkey',
    moved: 'The mandate, SUSPENDED: its agent can spend nothing under it until it is resumed.',
  },
  resume: {
    asked: ['MandateResumptionAsked', 'Resuming a suspended mandate, waiting for the admin to sign in again.'],
    ask: 'Ask to resume a suspended mandate, signing in again with a passkey',
    confirm: 'Resume the mandate, once signed in again for it with a passkey',
    moved: 'The mandate, ACTIVE again, with its version in force as it was.',
  },
  revoke: {
    asked: ['MandateRevocationAsked', 'Revoking a mandate, waiting for the admin to sign in again.'],
    ask: 'Ask to revoke a mandate, waiting or in force, signing in again with a passkey',
    confirm: 'Revoke the mandate for good, once signed in again for it with a passkey',
    moved: 'The mandate, REVOKED: it ends for good, and the agent may be given a new one.',
  },
} as const satisfies Record<MandateMove, unknown>;

const moveSchemas = (move: MandateMove) => {
  const words = MOVE_WORDS[move];
  return {
    ask: {
      summary: words.ask,
      params: MANDATE_ID,
      body: NOTHING,
      response: { 202: stepUpAsked(words.asked[0], words.asked[1]) },
    },
    confirm: {
      summary: words.confirm,
      params: MANDATE_ID,
      body: STEP_UP_CONFIRM,
      response: { 200: MANDATE_DETAILS.describe(words.moved) },
    },
  };
};

const LIST_SCHEMA = {
  summary: "Your organisation's mandates",
  querystring: pageQuery(MOST_MANDATES_A_PAGE),
  response: {
    200: z
      .object({ mandates: z.array(MANDATE_LISTED).describe('The mandates, in order of ID.'), next: NEXT })
      .describe('A page of mandates, each as its signed state says.'),
  },
};

const SHOW_SCHEMA = {
  summary: 'One of your organisation’s mandates, with its versions',
  params: MANDATE_ID,
  response: { 200: MANDATE_DETAILS },
};

function memberOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('a mandates route ran without a member');
  return { orgId: member.orgId, userId: person.userId };
}

const mandateBody = (mandate: MandateRecord) => ({
  id: mandate.id,
  agentId: mandate.agentId,
  timeZone: mandate.timeZone,
  splitWindowHours: mandate.splitWindowHours,
  status: mandate.status,
});

const versionOf = ({ version: v, consentWarnings }: VersionShown) => ({
  id: v.id,
  version: v.version,
  purpose: v.purpose,
  currency: v.perOrderLimit.currency,
  perOrderLimitMinor: Number(v.perOrderLimit.minor),
  monthlyLimitMinor: Number(v.monthlyLimit.minor),
  approvalThresholdMinor: Number(v.approvalThreshold.minor),
  supplierIds: [...v.supplierIds],
  fundingSourceId: v.fundingSourceId,
  splitCheck: v.splitCheck,
  consentLimits: v.consentLimits,
  endsAt: v.endsAt?.toISOString() ?? null,
  termsHash: v.termsHash,
  draftedBy: v.draftedBy,
  draftedAt: v.draftedAt.toISOString(),
  consentWarnings: [...consentWarnings],
});

const detailsOf = ({ mandate, current, pending }: MandateView) => ({
  ...mandateBody(mandate),
  acceptedBy: mandate.acceptedBy,
  acceptedAt: mandate.acceptedAt?.toISOString() ?? null,
  current: current === null ? null : versionOf(current),
  pending: pending === null ? null : versionOf(pending),
});

export function registerMandates(
  app: FastifyInstance,
  {
    registry,
    acceptance,
    moves,
  }: {
    registry: MandateRegistry | undefined;
    acceptance: MandateAcceptance | undefined;
    moves: MandateMoves | undefined;
  },
) {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  /** Answers a draft: the mandate as it now stands, or a refusal. */
  const answer = (written: MandateWrite, status: 200 | 201, request: FastifyRequest, reply: FastifyReply) => {
    if (isUnwritten(written)) return answerRefusal(written, request, reply);
    return reply.code(status).send(detailsOf(written));
  };

  routes.post(
    '/v1/mandates',
    {
      schema: DRAFT_SCHEMA,
      bodyLimit: DRAFT_BODY_LIMIT,
      config: { access: [...DRAFTING_ROLES], operation: DRAFT_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const { body } = request;
      const draft = {
        agentId: body.agentId,
        timeZone: body.timeZone === undefined ? null : (timeZoneOf(body.timeZone) ?? null),
        splitWindowHours: body.splitWindowHours ?? null,
        terms: termsKept(body),
      };
      const written = await need(registry).draft(member, idempotentRequest(request, member.orgId), draft, request.id);
      return answer(written, 201, request, reply);
    },
  );

  routes.post(
    '/v1/mandates/:id/supersede',
    {
      schema: REDRAFT_SCHEMA,
      bodyLimit: DRAFT_BODY_LIMIT,
      config: { access: [...DRAFTING_ROLES], operation: REDRAFT_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(registry).redraft(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        termsKept(request.body),
        request.id,
      );
      return answer(written, 200, request, reply);
    },
  );

  routes.post(
    '/v1/mandates/:id/accept',
    {
      schema: ACCEPT_SCHEMA,
      bodyLimit: ACCEPT_BODY_LIMIT,
      config: { access: [...ACCEPTING_ROLES], operation: ACCEPT_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const asked = await need(acceptance).accept(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.versionId,
        request.id,
      );
      return answerAsked(asked, request, reply);
    },
  );

  routes.post(
    '/v1/mandates/:id/accept/confirm',
    {
      schema: ACCEPT_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...ACCEPTING_ROLES], operation: ACCEPT_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const accepted = await need(acceptance).acceptConfirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.id,
      );
      if (isUnwritten(accepted)) return answerRefusal(accepted, request, reply);
      return reply.code(200).send(detailsOf(accepted));
    },
  );

  for (const move of MANDATE_MOVES) {
    const schemas = moveSchemas(move);
    routes.post(
      `/v1/mandates/:id/${move}`,
      {
        schema: schemas.ask,
        bodyLimit: NOTHING_BODY_LIMIT,
        config: { access: [...MOVING_ROLES], operation: MOVE_OPERATIONS[move].ask },
      },
      async (request, reply) => {
        const member = memberInSessionOf(request);
        const asked = await need(moves).ask(
          member,
          idempotentRequest(request, member.orgId),
          request.params.id,
          move,
          request.id,
        );
        return answerAsked(asked, request, reply);
      },
    );

    routes.post(
      `/v1/mandates/:id/${move}/confirm`,
      {
        schema: schemas.confirm,
        bodyLimit: CHALLENGE_BODY_LIMIT,
        config: { access: [...MOVING_ROLES], operation: MOVE_OPERATIONS[move].confirm },
      },
      async (request, reply) => {
        const member = memberInSessionOf(request);
        const moved = await need(moves).confirm(
          member,
          idempotentRequest(request, member.orgId),
          request.params.id,
          move,
          request.body.stepUpChallengeId,
          request.id,
        );
        if (isUnwritten(moved)) return answerRefusal(moved, request, reply);
        return reply.code(200).send(detailsOf(moved));
      },
    );
  }

  routes.get(
    '/v1/mandates',
    { schema: LIST_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberOf(request);
      const page = { after: request.query.after ?? null, limit: request.query.limit ?? MOST_MANDATES_A_PAGE };
      const listed = await need(registry).list(orgId, page, request.id);
      if (listed.outcome === 'refused') return answerRefusal(listed, request, reply);
      return {
        mandates: listed.mandates.map((mandate) => ({ ...mandateBody(mandate), purpose: mandate.purpose })),
        next: listed.next,
      };
    },
  );

  routes.get(
    '/v1/mandates/:id',
    { schema: SHOW_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberOf(request);
      const found = await need(registry).show(orgId, request.params.id, request.id);
      if (found.outcome === 'refused') return answerRefusal(found, request, reply);
      return detailsOf(found);
    },
  );
}

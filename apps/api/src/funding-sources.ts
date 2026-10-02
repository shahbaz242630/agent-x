// The organisation's bank account, linked through the payment partner (PRD
// §2.3, §7.1, SEC-PTR-08; Phase 1 D2-3b).
//
// - `POST /v1/funding-sources/link-sessions`: starts a link at the partner:
//   201 with the link and `authoriseUrl`, the partner's page that takes the
//   admin on to their bank. Admins.
// - `POST /v1/funding-sources/link-sessions/:linkId/confirm`, once back from
//   the bank: asks the partner, server to server, how the link ended. 202 with
//   the link while the business hasn't finished at its bank; 200 with the
//   link, settled, and the source it made, if it made one. Admins.
// - `GET /v1/funding-sources?after=&limit=` and `/v1/funding-sources/:id`
//   (D2-4a): the sources as Agent X holds them, ENDED ones too, each verified
//   against its signed state. Every member.
// - `POST /v1/funding-sources/:id/refresh` (D2-4a): asks the partner, server
//   to server, how the source stands now, and answers it brought up to that.
//   Admins.
// - `POST /v1/funding-sources/:id/suspend` (D2-4b): the brake, at once and
//   with no step-up: 200 with the source, SUSPENDED; one suspended or ended
//   already is answered as it is. Admins and finance approvers.
// - `POST /v1/funding-sources/:id/reactivate`, then `…/reactivate/confirm`
//   with the step-up's ID once signed in again (a passkey) (D2-4b): 202 with
//   the step-up, then 200 with the source, ACTIVE. 409 SOURCE_NOT_SUSPENDED
//   for one that isn't suspended. Admins.
// - `GET /v1/agent/funding-sources?after=&limit=` (D2-4a, SEC-AG-05): for an
//   agent's key with `sources:read`, the sources that may fund a request now,
//   each as the safe summary alone: its ID, currency, kind and hint. Never
//   the holder, the partner's references, the consent or the bank's limits.
// Refusals: 503 PARTNER_UNAVAILABLE when the partner didn't answer (nothing
// was done; send it again) or none is set up; 409 LINK_STARTS_SPENT past the
// day's budget; 404 NOT_FOUND for a link or source not the organisation's;
// 503 INTEGRITY_FAILED when the caller's membership or a source can't be
// verified. The use cases are funding-source-links.ts, funding-source-reads.ts
// and funding-source-changes.ts.
import { type LinkRecord, MOST_SOURCES_A_PAGE, type SourceRecord } from '@agentx/core/modules/funding-sources';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { agentOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import {
  type FundingSourceChanges,
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  REACTIVATING_ROLES,
  REFRESH_OPERATION,
  REFRESHING_ROLES,
  type SourceChangeWrite,
  SUSPEND_OPERATION,
  SUSPENDING_ROLES,
} from './funding-source-changes.ts';
import {
  type FundingSourceLinks,
  LINK_CONFIRM_OPERATION,
  LINK_START_OPERATION,
  LINKING_ROLES,
} from './funding-source-links.ts';
import type { FundingSourceReads } from './funding-source-reads.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';
import {
  CHALLENGE_BODY_LIMIT,
  NEXT,
  NOTHING,
  NOTHING_BODY_LIMIT,
  pageQuery,
  STEP_UP_SIGNED_IN,
  STEP_UP_TO_SIGN_IN,
} from './route-schemas.ts';

/** Every member may see the organisation's sources. */
const READING_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;

const LINK = z
  .object({
    id: z.uuid().describe('The link, by its ID.'),
    status: z
      .enum(['open', 'linked', 'rejected', 'expired', 'unknown'])
      .describe(
        'open until the partner says how it ended: linked, rejected at the bank, expired before it was approved, or unknown to the partner.',
      ),
    expiresAt: z.iso.datetime().describe('When the partner stops waiting for the bank.'),
    createdAt: z.iso.datetime().describe('When it was started.'),
    settledAt: z.iso.datetime().nullable().describe('When Agent X learnt how it ended; null while open.'),
    sourceId: z.uuid().nullable().describe('The source it made, once linked.'),
  })
  .register(API_SCHEMAS, { id: 'FundingSourceLink', description: 'A link to the organisation’s bank account.' });

const MINOR_UNITS = z.string().regex(/^[1-9][0-9]*$/);

const SOURCE = z
  .object({
    id: z.uuid().describe('The source, by its ID.'),
    status: z
      .enum(['ACTIVE', 'SUSPENDED', 'ENDED'])
      .describe('Agent X’s own: ACTIVE, SUSPENDED by the business, or ENDED once the partner says it is gone.'),
    availability: z
      .enum(['PENDING', 'ACTIVE', 'SUSPENDED', 'UNAVAILABLE'])
      .describe('The partner’s latest word: only an ACTIVE source, ACTIVE here too, may fund a request.'),
    consentStatus: z.string().describe('The partner’s own word for the bank’s consent, kept as evidence.'),
    consentExpiresAt: z.iso.datetime().describe('When the bank’s consent runs out.'),
    holderName: z.string().describe('The account holder, as the bank names it.'),
    accountType: z.enum(['retail', 'sme', 'corporate']).describe('What kind of account it is.'),
    hint: z.string().describe('The country and the last four characters of the account number, such as AE…6026.'),
    controls: z
      .object({
        currency: z.string().describe('The currency the limits are in.'),
        period: z.enum(['day', 'week', 'month', 'year']).describe('The period the bank counts over.'),
        maxPaymentMinor: MINOR_UNITS.describe('The most one payment may be, in minor units.'),
        maxPeriodMinor: MINOR_UNITS.describe('The most a period’s payments may add up to, in minor units.'),
        maxPeriodPayments: z.int().describe('The most payments a period may hold.'),
      })
      .describe('The limits the bank holds the consent to, whatever Agent X’s mandates say.'),
  })
  .register(API_SCHEMAS, {
    id: 'FundingSource',
    description: 'The organisation’s bank account as Agent X holds it: never an account number or a balance.',
  });

const START_SCHEMA = {
  summary: 'Start linking the organisation’s bank account',
  body: NOTHING,
  response: {
    201: z
      .object({
        link: LINK,
        authoriseUrl: z.url().describe('The partner’s page, which takes you on to your bank to approve the link.'),
      })
      .describe('The link, waiting for you at your bank.'),
  },
};

const LINK_WITH_SOURCE = z.object({
  link: LINK,
  source: SOURCE.nullable().describe('The source the link made; null unless it is linked.'),
});

const CONFIRM_SCHEMA = {
  summary: 'Ask the partner how the link ended, once back from the bank',
  params: z.object({ linkId: z.uuid().describe('The link, by its ID.') }),
  body: NOTHING,
  response: {
    200: LINK_WITH_SOURCE.describe('The link, settled, and the source it made, if it made one.'),
    202: LINK_WITH_SOURCE.describe('The link, still waiting for the business at its bank: ask again later.'),
  },
};

/** The route's own caller: a member the access hook found. The hooks let no one else through. */
function memberOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('a funding-sources route ran without a member');
  return { orgId: member.orgId, userId: person.userId };
}

/** The route's caller in the session a step-up challenge is bound to. */
function inSessionOf(request: FastifyRequest) {
  const { person } = request;
  if (person === null) throw new Error('a funding-sources route ran without a person');
  return { ...memberOf(request), sessionId: person.sessionId };
}

const linkOf = (link: LinkRecord) => ({
  id: link.id,
  status: link.outcome,
  expiresAt: link.expiresAt.toISOString(),
  createdAt: link.createdAt.toISOString(),
  settledAt: link.settledAt === null ? null : link.settledAt.toISOString(),
  sourceId: link.sourceId,
});

const sourceOf = (source: SourceRecord) => ({
  id: source.id,
  status: source.status,
  availability: source.availability,
  consentStatus: source.consentStatus,
  consentExpiresAt: source.consentExpiresAt.toISOString(),
  holderName: source.summary.holderName,
  accountType: source.summary.accountType,
  hint: source.summary.hint,
  controls: {
    currency: source.controls.currency,
    period: source.controls.period,
    maxPaymentMinor: source.controls.maxPaymentMinor.toString(),
    maxPeriodMinor: source.controls.maxPeriodMinor.toString(),
    maxPeriodPayments: source.controls.maxPeriodPayments,
  },
});

const PAGE = pageQuery(MOST_SOURCES_A_PAGE);

const LIST_SCHEMA = {
  summary: "Your organisation's bank accounts",
  querystring: PAGE,
  response: {
    200: z
      .object({ sources: z.array(SOURCE).describe('The sources, in order of ID.'), next: NEXT })
      .describe('A page of sources, each as its signed state says.'),
  },
};

const SOURCE_ID = z.object({ id: z.uuid().describe('The source, by its ID.') });

const SHOW_SCHEMA = {
  summary: 'One of your organisation’s bank accounts',
  params: SOURCE_ID,
  response: { 200: SOURCE },
};

const REFRESH_SCHEMA = {
  summary: 'Ask the partner how a bank account stands now',
  params: SOURCE_ID,
  body: NOTHING,
  response: { 200: SOURCE.describe('The source, brought up to the partner’s answer.') },
};

const SOURCE_CHANGED = SOURCE.describe('The source, as the change left it.');

const SUSPEND_SCHEMA = {
  summary: 'Suspend a bank account: the brake, at once and with no step-up',
  params: SOURCE_ID,
  body: NOTHING,
  response: { 200: SOURCE_CHANGED },
};

const REACTIVATION_ASKED = z
  .object({
    stepUpChallengeId: STEP_UP_TO_SIGN_IN,
  })
  .register(API_SCHEMAS, {
    id: 'FundingSourceReactivationAsked',
    description: 'Reactivating a bank account, waiting for the admin to sign in again.',
  });

const REACTIVATE_SCHEMA = {
  summary: 'Ask to reactivate a suspended bank account',
  params: SOURCE_ID,
  body: NOTHING,
  response: { 202: REACTIVATION_ASKED },
};

const REACTIVATE_CONFIRM_SCHEMA = {
  summary: 'Reactivate the bank account, once signed in again for it',
  params: SOURCE_ID,
  body: z.strictObject({ stepUpChallengeId: STEP_UP_SIGNED_IN }).describe('The step-up signed in again for.'),
  response: { 200: SOURCE_CHANGED },
};

const AGENT_SOURCE = z
  .object({
    id: z.uuid().describe('The source, by its ID.'),
    currency: z.string().describe('The currency the bank’s limits are in.'),
    accountType: z.enum(['retail', 'sme', 'corporate']).describe('What kind of account it is.'),
    hint: z.string().describe('The country and the last four characters of the account number, such as AE…6026.'),
  })
  .register(API_SCHEMAS, {
    id: 'AgentFundingSource',
    description: 'A bank account the agent’s organisation may pay from now: the safe summary alone (SEC-AG-05).',
  });

const AGENT_LIST_SCHEMA = {
  summary: 'The bank accounts your organisation may pay from now',
  querystring: PAGE,
  response: {
    200: z
      .object({
        sources: z.array(AGENT_SOURCE).describe('Those of this page that may fund a request now, in order of ID.'),
        next: NEXT,
      })
      .describe('A page of sources: it may hold fewer than asked for, and `next` still leads on.'),
  },
};

/** The routes. Each use case does its own; without one they are still documented, and no one reaches them. */
export function registerFundingSources(
  app: FastifyInstance,
  {
    links,
    reads,
    changes,
  }: {
    links: FundingSourceLinks | undefined;
    reads: FundingSourceReads | undefined;
    changes: FundingSourceChanges | undefined;
  },
) {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const refused = (
    answer: { outcome: 'refused'; status: number; code: Parameters<typeof sendErrorBody>[2] },
    request: FastifyRequest,
    reply: FastifyReply,
  ) => sendErrorBody(reply, answer.status, answer.code, request.id);

  /** Answers a change: the source as it now stands, a step-up asked, or a refusal. */
  const answerChange = (written: SourceChangeWrite, request: FastifyRequest, reply: FastifyReply) => {
    if (written.outcome === 'changed') return reply.code(200).send(sourceOf(written.source));
    if (written.outcome === 'asked') return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    if (written.outcome === 'refused') return refused(written, request, reply);
    return answerRefusedWrite(written, request, reply);
  };

  routes.post(
    '/v1/funding-sources/link-sessions',
    {
      schema: START_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...LINKING_ROLES], operation: LINK_START_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(links).start(member, idempotentRequest(request, member.orgId), request.id);
      if (written.outcome === 'refused') return refused(written, request, reply);
      if (written.outcome === 'conflict' || written.outcome === 'busy') {
        return answerRefusedWrite(written, request, reply);
      }
      return reply.code(201).send({ link: linkOf(written.link), authoriseUrl: written.authoriseUrl });
    },
  );

  routes.post(
    '/v1/funding-sources/link-sessions/:linkId/confirm',
    {
      schema: CONFIRM_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...LINKING_ROLES], operation: LINK_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(links).confirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.linkId,
        request.id,
      );
      if (written.outcome === 'refused') return refused(written, request, reply);
      if (written.outcome === 'conflict' || written.outcome === 'busy') {
        return answerRefusedWrite(written, request, reply);
      }
      return reply
        .code(written.link.outcome === 'open' ? 202 : 200)
        .send({ link: linkOf(written.link), source: written.source === null ? null : sourceOf(written.source) });
    },
  );
  routes.get(
    '/v1/funding-sources',
    { schema: LIST_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberOf(request);
      const listed = await need(reads).list(
        orgId,
        { after: request.query.after ?? null, limit: request.query.limit ?? MOST_SOURCES_A_PAGE },
        request.id,
      );
      if (listed.outcome === 'refused') return refused(listed, request, reply);
      return { sources: listed.sources.map(sourceOf), next: listed.next };
    },
  );

  routes.get(
    '/v1/funding-sources/:id',
    { schema: SHOW_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberOf(request);
      const found = await need(reads).show(orgId, request.params.id, request.id);
      if (found.outcome === 'refused') return refused(found, request, reply);
      return sourceOf(found.source);
    },
  );

  routes.post(
    '/v1/funding-sources/:id/refresh',
    {
      schema: REFRESH_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...REFRESHING_ROLES], operation: REFRESH_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(changes).refresh(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.get(
    '/v1/agent/funding-sources',
    { schema: AGENT_LIST_SCHEMA, config: { access: ['agent'], agentScopes: ['sources:read'] } },
    async (request, reply) => {
      const { orgId } = agentOf(request);
      const listed = await need(reads).usableByAgent(
        orgId,
        { after: request.query.after ?? null, limit: request.query.limit ?? MOST_SOURCES_A_PAGE },
        request.id,
      );
      if (listed.outcome === 'refused') return refused(listed, request, reply);
      // The safe summary alone, field by field: nothing else of the source can reach an agent.
      return {
        sources: listed.sources.map((source) => ({
          id: source.id,
          currency: source.controls.currency,
          accountType: source.summary.accountType,
          hint: source.summary.hint,
        })),
        next: listed.next,
      };
    },
  );
  routes.post(
    '/v1/funding-sources/:id/suspend',
    {
      schema: SUSPEND_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...SUSPENDING_ROLES], operation: SUSPEND_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(changes).suspend(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/funding-sources/:id/reactivate',
    {
      schema: REACTIVATE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...REACTIVATING_ROLES], operation: REACTIVATE_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(changes).reactivate(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/funding-sources/:id/reactivate/confirm',
    {
      schema: REACTIVATE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...REACTIVATING_ROLES], operation: REACTIVATE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(changes).reactivateConfirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );
}

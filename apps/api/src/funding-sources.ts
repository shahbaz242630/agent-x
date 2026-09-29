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
// Refusals: 503 PARTNER_UNAVAILABLE when the partner didn't answer (nothing
// was done; send it again) or none is set up; 409 LINK_STARTS_SPENT past the
// day's budget; 404 NOT_FOUND for a link the organisation didn't start; 503
// INTEGRITY_FAILED when the caller's membership or the source can't be
// verified. The use case is funding-source-links.ts.
import type { LinkRecord, SourceRecord } from '@agentx/core/modules/funding-sources';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import {
  type FundingSourceLinks,
  LINK_CONFIRM_OPERATION,
  LINK_START_OPERATION,
  LINKING_ROLES,
} from './funding-source-links.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';

/** The most a bodyless write may be sent with: an empty object, with room to spare. */
const NOTHING_BODY_LIMIT = 64;

const NOTHING = z
  .strictObject({})
  // Fastify gives a request sent with no body a null one.
  .nullish()
  .describe('Nothing. An empty object, or no body at all.');

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

/** The routes. `links` does them; without it they are still documented, and no one reaches them. */
export function registerFundingSources(app: FastifyInstance, { links }: { links: FundingSourceLinks | undefined }) {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const linksOf = (): FundingSourceLinks => {
    if (links === undefined) throw new Error('the funding-sources routes ran without their use case');
    return links;
  };
  const refused = (
    answer: { outcome: 'refused'; status: number; code: Parameters<typeof sendErrorBody>[2] },
    request: FastifyRequest,
    reply: FastifyReply,
  ) => sendErrorBody(reply, answer.status, answer.code, request.id);

  routes.post(
    '/v1/funding-sources/link-sessions',
    {
      schema: START_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...LINKING_ROLES], operation: LINK_START_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await linksOf().start(member, idempotentRequest(request, member.orgId), request.id);
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
      const written = await linksOf().confirm(
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
}

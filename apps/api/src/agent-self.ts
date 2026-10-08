// The agent's own routes (ADR-011 §1, BR-03, BR-05; Phase 1 C2-1, D2-4a;
// Phase 2 B5), each with its key, each answering only what an agent may see
// (SEC-AG-05).
//
// - `GET /v1/agent`: which agent the key is, in which organisation, the key's
//   ID, the scopes the request may use (those both the key and its agent
//   hold) and when the key stops working, so the agent can have it rotated in
//   time. Any accepted key, whatever its scopes. Everything here is what the
//   key check found, in the same request: nothing is read again. The agent's
//   name isn't told: it is for the organisation's members (C1-2).
// - `GET /v1/agent/mandate` (B5): with `requests:write`, the mandate it acts
//   under, ACTIVE or SUSPENDED, and its version in force: purpose, currency,
//   per-order and monthly limits, suppliers by ID (their names are
//   `GET /v1/agent/suppliers`), the source by ID, its zone and end. Not the
//   approval threshold (the answer to a request says when approval is
//   needed; knowing the line invites orders sized just under it), the bank
//   consent setting, the terms hash or who drafted and accepted it. 404
//   NOT_FOUND without one in force.
// - `GET /v1/agent/funding-sources?after=&limit=` (D2-4a, narrowed in B5):
//   with `sources:read`, the source its ACTIVE mandate names while it may
//   fund a request, as the safe summary alone: its ID, currency, kind and
//   hint. Never the holder, the partner's references, the consent or the
//   bank's limits. None without such a mandate.
// 503 INTEGRITY_FAILED when the mandate, its version or the source can't be
// believed. The use case is agent-mandate.ts.
import { SCOPES } from '@agentx/core/modules/agents';
import { MANDATE } from '@agentx/core/modules/mandates';
import { MOST_SOURCES_A_PAGE } from '@agentx/core/modules/funding-sources';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { agentOf, need } from './access.ts';
import type { AgentMandates } from './agent-mandate.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { NEXT, pageQuery } from './route-schemas.ts';

const SELF_SCHEMA = {
  summary: 'The agent your key is',
  response: {
    200: z
      .object({
        agentId: z.uuid().describe('The agent, by its ID.'),
        organizationId: z.uuid().describe('The organisation it acts for, by its ID.'),
        keyId: z.uuid().describe('The key the request was sent with, by its ID.'),
        scopes: z.array(z.enum(SCOPES)).describe('What requests with this key may do: its scopes, within its agent’s.'),
        keyExpiresAt: z.iso.datetime().describe('When the key stops working: ask for it to be rotated before then.'),
      })
      .register(API_SCHEMAS, { id: 'AgentSelf', description: 'The agent a key is, as the key check found it.' }),
  },
};

const MANDATE_SCHEMA = {
  summary: 'The mandate you act under',
  response: {
    200: z
      .object({
        mandateId: z.uuid().describe('The mandate, by its ID.'),
        status: z
          .enum(MANDATE.states)
          .extract(['ACTIVE', 'SUSPENDED'])
          .describe('ACTIVE; SUSPENDED: no request is allowed until an admin resumes it.'),
        versionId: z.uuid().describe('The version in force, by its ID.'),
        version: z.int().describe('Its number, from 1.'),
        purpose: z.string().describe('What you may spend on.'),
        currency: z.string(),
        perOrderLimitMinor: z.number().describe('The most one request may be, in whole minor units (fils for AED).'),
        monthlyLimitMinor: z
          .number()
          .describe('The most you may spend in a month, in whole minor units, every mandate of yours counted.'),
        monthlyCapMinor: z
          .number()
          .describe(
            'The most the organisation’s policies let you spend in a month, in whole minor units: the lower of this and monthlyLimitMinor applies.',
          ),
        supplierIds: z.array(z.uuid()).describe('The suppliers you may pay, by ID, in order of ID.'),
        fundingSourceId: z.uuid().describe('The bank account you pay from, by ID.'),
        timeZone: z.string().describe('The IANA time zone your months are counted in.'),
        endsAt: z.iso.datetime().nullable().describe('When it ends, or null: until revoked.'),
      })
      .register(API_SCHEMAS, {
        id: 'AgentMandate',
        description: 'The mandate an agent acts under, as far as an agent may see it (SEC-AG-05).',
      }),
  },
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
    description: 'A bank account the agent may pay from now: the safe summary alone (SEC-AG-05).',
  });

const SOURCES_SCHEMA = {
  summary: 'The bank accounts your mandate lets you pay from now',
  querystring: pageQuery(MOST_SOURCES_A_PAGE),
  response: {
    200: z
      .object({
        sources: z.array(AGENT_SOURCE).describe('The source your active mandate names, while it may fund a request.'),
        next: NEXT,
      })
      .describe('A page of sources, in order of ID.'),
  },
};

export function registerAgentSelf(app: FastifyInstance, { mandates }: { mandates: AgentMandates | undefined }): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get('/v1/agent', { schema: SELF_SCHEMA, config: { access: ['agent'], agentScopes: [] } }, (request) => {
    const { orgId, agentId, keyId, scopes, expiresAt } = agentOf(request);
    return { agentId, organizationId: orgId, keyId, scopes: [...scopes], keyExpiresAt: expiresAt.toISOString() };
  });

  routes.get(
    '/v1/agent/mandate',
    { schema: MANDATE_SCHEMA, config: { access: ['agent'], agentScopes: ['requests:write'] } },
    async (request, reply) => {
      const { orgId, agentId } = agentOf(request);
      const found = await need(mandates).inForce(orgId, agentId, request.id);
      if (found.outcome === 'refused') return sendErrorBody(reply, found.status, found.code, request.id);
      const { mandate, version: v, monthlyCap } = found;
      // Field by field: nothing else of the mandate can reach an agent.
      return {
        mandateId: mandate.id,
        status: mandate.status,
        versionId: v.id,
        version: v.version,
        purpose: v.purpose,
        currency: v.perOrderLimit.currency,
        perOrderLimitMinor: Number(v.perOrderLimit.minor),
        monthlyLimitMinor: Number(v.monthlyLimit.minor),
        monthlyCapMinor: Number(monthlyCap.minor),
        supplierIds: [...v.supplierIds],
        fundingSourceId: v.fundingSourceId,
        timeZone: mandate.timeZone,
        endsAt: v.endsAt?.toISOString() ?? null,
      };
    },
  );

  routes.get(
    '/v1/agent/funding-sources',
    { schema: SOURCES_SCHEMA, config: { access: ['agent'], agentScopes: ['sources:read'] } },
    async (request, reply) => {
      const { orgId, agentId } = agentOf(request);
      // `limit` stays in the query for the paging contract (D2-4a): one source at most fits any page.
      const listed = await need(mandates).sources(orgId, agentId, request.query.after ?? null, request.id);
      if (listed.outcome === 'refused') return sendErrorBody(reply, listed.status, listed.code, request.id);
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
}

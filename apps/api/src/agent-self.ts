// The agent's own route (ADR-011 §1, BR-03; Phase 1 C2-1): the first an AI
// agent calls, with its key.
//
// - `GET /v1/agent`: which agent the key is, in which organisation, the key's
//   ID, the scopes the request may use (those both the key and its agent
//   hold) and when the key stops working, so the agent can have it rotated in
//   time. Any accepted key, whatever its scopes. Everything here is what the
//   key check found, in the same request: nothing is read again. The agent's
//   name isn't told: it is for the organisation's members (C1-2).
import { SCOPES } from '@agentx/core/modules/agents';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { agentOf } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';

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

export function registerAgentSelf(app: FastifyInstance): void {
  app
    .withTypeProvider<ZodTypeProvider>()
    .get('/v1/agent', { schema: SELF_SCHEMA, config: { access: ['agent'], agentScopes: [] } }, (request) => {
      const { orgId, agentId, keyId, scopes, expiresAt } = agentOf(request);
      return { agentId, organizationId: orgId, keyId, scopes: [...scopes], keyExpiresAt: expiresAt.toISOString() };
    });
}

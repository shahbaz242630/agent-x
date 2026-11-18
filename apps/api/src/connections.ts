// An agent's MCP connections, on its page in the console (6E3b, ADR-016;
// SEC-OAUTH-07, -10). The use case is connection-changes.ts.
//
// - `GET /v1/agents/:id/connections`: the agent's connections, newest first,
//   at most 50: every live one and those ended in the last 30 days, each
//   verified against its signed state and its key's. Any member.
// - `POST /v1/agents/:id/connections/:keyId/revoke`, then `…/revoke/confirm`
//   with the step-up's ID: the connection stops at once, every token it was
//   given refused at its next use: 202 with the step-up, then 200 with the
//   agent's connections. Admins and developers, a developer only for an agent
//   they own. 409 CONNECTION_REVOKED for one revoked already.
// Refusals: 404 NOT_FOUND for an agent the organisation doesn't have, or a key
// that is no connection of the agent's (its own keys are revoked at
// `…/keys/:keyId/revoke`, which answers 404 for a connection's); 403
// STEP_UP_FAILED for another step-up; 503 INTEGRITY_FAILED when a connection,
// its key, the agent or the caller's membership can't be verified. Not behind
// AGENTX_MCP_OAUTH: a connection made while it was on can still be revoked
// once it is off.
import { SCOPES } from '@agentx/core/modules/agents';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { EVERY_MEMBER, memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import {
  CONNECTION_REVOKE_CONFIRM_OPERATION,
  CONNECTION_REVOKE_OPERATION,
  CONNECTION_REVOKING_ROLES,
  type ConnectionChanges,
  type ConnectionChangeWrite,
  type ConnectionShown,
} from './connection-changes.ts';
import { answerAsked, answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { CHALLENGE_BODY_LIMIT, NOTHING, NOTHING_BODY_LIMIT, STEP_UP_CONFIRM, stepUpAsked } from './route-schemas.ts';

const CONNECTION = z
  .object({
    keyId: z.uuid().describe('The connection, by its key’s ID: the one its tokens name.'),
    clientId: z.string().describe('The app’s client ID.'),
    clientName: z.string().describe('What the app said it is when it was connected: never proof of who it is.'),
    redirectHost: z
      .string()
      .nullable()
      .describe('The host (and port) the person’s browser was sent back to when it was made; null for a device’s.'),
    via: z.enum(['code', 'device']).describe('Made in a browser (`code`), or on a device by its code (`device`).'),
    scopes: z.array(z.enum(SCOPES)).describe('What its tokens may do, within its agent’s scopes.'),
    madeBy: z.uuid().describe('The membership of the member who connected it.'),
    createdAt: z.iso.datetime().describe('When it was made.'),
    expiresAt: z.iso.datetime().describe('When it stops working, and the app must be connected again.'),
    lastConnectedAt: z.iso.datetime().nullable().describe('When the app was last given tokens for it; null if never.'),
    status: z
      .enum(['ACTIVE', 'REVOKED', 'EXPIRED'])
      .describe('ACTIVE while it works; REVOKED once revoked, by a person, a hand-over or the app; EXPIRED once past.'),
  })
  .register(API_SCHEMAS, {
    id: 'Connection',
    description: "An app connected as one of the organisation's agents by OAuth: never a token.",
  });

const CONNECTIONS = z
  .object({
    connections: z
      .array(CONNECTION)
      .describe('Newest first, at most 50: every live one, and those ended in the last 30 days.'),
  })
  .register(API_SCHEMAS, { id: 'Connections', description: "An agent's app connections." });

const AGENT_ID = z.object({ id: z.uuid().describe('The agent, by its ID.') });

const CONNECTION_NAMED = z.object({
  id: z.uuid().describe('The agent, by its ID.'),
  keyId: z.uuid().describe('Its connection, by its key’s ID.'),
});

const LIST_SCHEMA = {
  summary: "An agent's app connections",
  params: AGENT_ID,
  response: { 200: CONNECTIONS.describe('The agent’s connections, each as its signed state says.') },
};

const REVOKE_SCHEMA = {
  summary: "Ask to revoke an agent's app connection: it stops at once",
  params: CONNECTION_NAMED,
  body: NOTHING,
  response: {
    202: stepUpAsked('ConnectionRevokeAsked', "Revoking an agent's app connection, waiting for you to sign in again."),
  },
};

const REVOKE_CONFIRM_SCHEMA = {
  summary: 'Revoke the connection, once signed in again for it',
  params: CONNECTION_NAMED,
  body: STEP_UP_CONFIRM,
  response: { 200: CONNECTIONS.describe('The agent’s connections, the one revoked among them.') },
};

const connectionOf = (shown: ConnectionShown) => ({
  ...shown,
  scopes: [...shown.scopes],
  createdAt: shown.createdAt.toISOString(),
  expiresAt: shown.expiresAt.toISOString(),
  lastConnectedAt: shown.lastConnectedAt?.toISOString() ?? null,
});

/** Answers a revocation: the connections as they now stand, a step-up asked, or a refusal. */
function answerRevocation(written: ConnectionChangeWrite, request: FastifyRequest, reply: FastifyReply): FastifyReply {
  if (written.outcome === 'revoked') {
    return reply.code(200).send({ connections: written.connections.map(connectionOf) });
  }
  return answerAsked(written, request, reply);
}

/**
 * The connections' routes. `changes` does them; without it the routes are still documented, and no one reaches them, as
 * no one holds a role.
 */
export function registerConnections(
  app: FastifyInstance,
  { changes }: { readonly changes: ConnectionChanges | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get(
    '/v1/agents/:id/connections',
    { schema: LIST_SCHEMA, config: { access: [...EVERY_MEMBER] } },
    async (request, reply) => {
      const { orgId } = memberInSessionOf(request);
      const listed = await need(changes).list(orgId, request.params.id, request.id);
      if ('outcome' in listed) return answerRefusal(listed, request, reply);
      return { connections: listed.connections.map(connectionOf) };
    },
  );

  const named = (params: { id: string; keyId: string }) => ({ agentId: params.id, keyId: params.keyId });

  routes.post(
    '/v1/agents/:id/connections/:keyId/revoke',
    {
      schema: REVOKE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...CONNECTION_REVOKING_ROLES], operation: CONNECTION_REVOKE_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(changes).revoke(
        member,
        idempotentRequest(request, member.orgId),
        named(request.params),
        request.id,
      );
      return answerRevocation(written, request, reply);
    },
  );

  routes.post(
    '/v1/agents/:id/connections/:keyId/revoke/confirm',
    {
      schema: REVOKE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...CONNECTION_REVOKING_ROLES], operation: CONNECTION_REVOKE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(changes).revokeConfirm(
        member,
        idempotentRequest(request, member.orgId),
        named(request.params),
        request.body.stepUpChallengeId,
        request.id,
      );
      return answerRevocation(written, request, reply);
    },
  );
}

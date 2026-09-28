// The organisation's AI agents (ADR-011 §1, ADR-012 §5, BR-03; Phase 1 C1-2, C1-3).
//
// - `GET /v1/agents?after=&limit=`: a page of the agents, in order of ID,
//   each verified against its signed state, with `next` to ask the page after
//   (null at the end). Any member.
// - `GET /v1/agents/:id`: the agent with its keys (their IDs, statuses,
//   scopes and expiries; never a secret or its MAC). Any member.
// - `POST /v1/agents`, a name and scopes: opens a step-up bound to registering
//   exactly that agent, owned by the caller: 202 with its ID, for the console
//   to send them to `GET /v1/auth/step-up?challenge=…`.
// - `POST /v1/agents/confirm`, the same name and scopes and the step-up's ID,
//   once signed in again: 201 with the agent, its first key's record, and the
//   key itself, `axk_<keyId>_<secret>`, shown this once (null on a retry of the
//   same write: only its MAC is kept).
// - `POST /v1/agents/:id/suspend`: the kill switch (C1-3), at once and with no
//   step-up: 200 with the agent, SUSPENDED; one suspended already is answered
//   as it is. Admins and developers.
// - `POST /v1/agents/:id/reactivate`, then `…/reactivate/confirm` with the
//   step-up's ID (C1-3): an admin gives a suspended agent its authority back,
//   signing in again with a passkey: 202 with the step-up, then 200 with the
//   agent, ACTIVE. 409 AGENT_NOT_SUSPENDED for one that isn't suspended.
// The two registration writes: admins and developers, in the organisation the request
// names. Refusals: 409 AGENT_ADDS_SPENT past the day's budget; 403
// STEP_UP_FAILED for another step-up, or other name or scopes than asked; 404
// NOT_FOUND for an agent the organisation doesn't have; 503 INTEGRITY_FAILED
// when an agent, a key or the caller's membership can't be verified. The use
// cases are agent-registering.ts and agent-changes.ts.
import { isAgentName, MOST_AGENTS_A_PAGE, SCOPES } from '@agentx/core/modules/agents';
import type { AgentKeyRecord, AgentShown } from '@agentx/core/modules/agents';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import {
  type AgentRegistrations,
  REGISTER_CONFIRM_OPERATION,
  REGISTER_OPERATION,
  REGISTERING_ROLES,
} from './agent-registering.ts';
import type { AgentWithKeys } from './agent-writes.ts';
import {
  type AgentChanges,
  type AgentChangeWrite,
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  REACTIVATING_ROLES,
  SUSPEND_OPERATION,
  SUSPENDING_ROLES,
} from './agent-changes.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';

/**
 * The most a registration's body may be: a name of 100 characters, each
 * sent as the longest JSON can write one (two `\uXXXX` escapes, 12 bytes),
 * every scope and a step-up's ID, with room to spare. Fastify refuses a body
 * past it before the schema is read (the B8-3 lesson), so it must fit every
 * body the schema allows.
 */
const REGISTER_BODY_LIMIT = 2048;

const AGENT = z
  .object({
    id: z.uuid().describe('The agent, by its ID.'),
    name: z.string().describe('What people call it.'),
    owner: z.uuid().describe('The membership of the member who owns it.'),
    status: z.enum(['ACTIVE', 'SUSPENDED']).describe('ACTIVE, or SUSPENDED: none of its keys works.'),
    scopes: z.array(z.enum(SCOPES)).describe('The most any of its keys may be given.'),
    createdAt: z.iso.datetime().describe('When it was registered.'),
  })
  .register(API_SCHEMAS, { id: 'Agent', description: 'An AI agent of the organisation.' });

const AGENT_KEY = z
  .object({
    id: z.uuid().describe("The key, by its ID: the one in the key the agent sends, without the uuid's dashes."),
    status: z.enum(['ACTIVE', 'REVOKED']).describe('ACTIVE until it is revoked, once.'),
    scopes: z.array(z.enum(SCOPES)).describe('What a request with it may do, within its agent’s scopes.'),
    expiresAt: z.iso.datetime().describe('When it stops working.'),
  })
  .register(API_SCHEMAS, { id: 'AgentKey', description: "An agent's key: never its secret." });

const AGENT_WITH_KEYS = z.object({ agent: AGENT, keys: z.array(AGENT_KEY).describe('Its keys, in order of ID.') });

const NAME = z
  .string()
  .refine(isAgentName, 'a visible name of 1 to 100 characters, with a letter or digit')
  .describe('What people will call it: shown to the organisation’s members, never to the agent.');

const ASKED = z
  .array(z.enum(SCOPES))
  .min(1)
  .max(SCOPES.length)
  .refine((scopes) => new Set(scopes).size === scopes.length, 'each scope once')
  .describe('The most any of its keys may be given; its first key gets them all.');

const LIST_SCHEMA = {
  summary: "Your organisation's agents",
  querystring: z.strictObject({
    after: z.uuid().optional().describe('The ID the page starts after: the last page’s `next`.'),
    limit: z.coerce
      .number()
      .int()
      .min(1)
      .max(MOST_AGENTS_A_PAGE)
      .optional()
      .describe(`How many at most, ${String(MOST_AGENTS_A_PAGE)} unless fewer are asked for.`),
  }),
  response: {
    200: z
      .object({
        agents: z.array(AGENT).describe('The agents, in order of ID.'),
        next: z.uuid().nullable().describe('The ID to ask the next page after; null at the end.'),
      })
      .describe('A page of agents, each as its signed state says.'),
  },
};

const SHOW_SCHEMA = {
  summary: 'An agent, with its keys',
  params: z.object({ id: z.uuid().describe('The agent, by its ID.') }),
  response: { 200: AGENT_WITH_KEYS.describe('The agent and its keys, each as its signed state says.') },
};

const REGISTER_SCHEMA = {
  summary: 'Ask to register an agent',
  body: z.strictObject({ name: NAME, scopes: ASKED }).describe('The agent to register, owned by you.'),
  response: {
    202: z
      .object({
        stepUpChallengeId: z
          .uuid()
          .describe('The step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming.'),
      })
      .register(API_SCHEMAS, {
        id: 'AgentRegistrationAsked',
        description: 'Registering an agent, waiting for you to sign in again.',
      }),
  },
};

const CONFIRM_SCHEMA = {
  summary: 'Register the agent, once signed in again for it',
  body: z
    .strictObject({
      name: NAME,
      scopes: ASKED,
      stepUpChallengeId: z.uuid().describe('The step-up the ask answered with, signed in again for.'),
    })
    .describe('The same name and scopes as asked, and the step-up signed in again for.'),
  response: {
    201: AGENT_WITH_KEYS.extend({
      key: z
        .string()
        .nullable()
        .describe(
          'The key, `axk_<keyId>_<secret>`, shown this once: keep it where the agent reads it. Null on a retry of the same request.',
        ),
    }).describe('The agent, registered, with its first key.'),
  },
};

/** The most a bodyless change may be sent with: an empty object, with room to spare. */
const NOTHING_BODY_LIMIT = 64;
/** The most a reactivation's confirm may be: a step-up's ID, with room to spare. */
const CHALLENGE_BODY_LIMIT = 128;

const AGENT_ID = z.object({ id: z.uuid().describe('The agent, by its ID.') });

const NOTHING = z
  .strictObject({})
  // Fastify gives a request sent with no body a null one.
  .nullish()
  .describe('Nothing. An empty object, or no body at all.');

const AGENT_CHANGED = AGENT_WITH_KEYS.describe('The agent and its keys, as the change left them.');

const STEP_UP_ASKED = z
  .object({
    stepUpChallengeId: z
      .uuid()
      .describe('The step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming.'),
  })
  .register(API_SCHEMAS, {
    id: 'AgentReactivationAsked',
    description: 'Reactivating an agent, waiting for the admin to sign in again.',
  });

const SUSPEND_SCHEMA = {
  summary: 'Suspend an agent: the kill switch, at once and with no step-up',
  params: AGENT_ID,
  body: NOTHING,
  response: { 200: AGENT_CHANGED },
};

const REACTIVATE_SCHEMA = {
  summary: 'Ask to reactivate a suspended agent',
  params: AGENT_ID,
  body: NOTHING,
  response: { 202: STEP_UP_ASKED },
};

const REACTIVATE_CONFIRM_SCHEMA = {
  summary: 'Reactivate the agent, once signed in again for it',
  params: AGENT_ID,
  body: z
    .strictObject({ stepUpChallengeId: z.uuid().describe('The step-up the ask answered with, signed in again for.') })
    .describe('The step-up signed in again for.'),
  response: { 200: AGENT_CHANGED },
};

/** The route's own caller: a member the access hook found, with their session. The hooks let no one else through. */
function memberOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('an agents route ran without a member');
  return { orgId: member.orgId, userId: person.userId, sessionId: person.sessionId };
}

const agentOf = (agent: AgentShown) => ({
  id: agent.id,
  name: agent.name,
  owner: agent.owner,
  status: agent.status,
  scopes: [...agent.scopes],
  createdAt: agent.createdAt.toISOString(),
});

const keyOf = (key: AgentKeyRecord) => ({
  id: key.id,
  status: key.status,
  scopes: [...key.scopes],
  expiresAt: key.expiresAt.toISOString(),
});

const withKeysOf = ({ agent, keys }: AgentWithKeys) => ({ agent: agentOf(agent), keys: keys.map(keyOf) });

/**
 * The agents' routes. `registrations` and `changes` do them; without them the
 * routes are still documented, and no one reaches them, as no one holds a role.
 */
export function registerAgents(
  app: FastifyInstance,
  { registrations, changes }: { registrations: AgentRegistrations | undefined; changes: AgentChanges | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const registrationsOf = (): AgentRegistrations => {
    if (registrations === undefined) throw new Error('the agents routes ran without their use case');
    return registrations;
  };
  const changesOf = (): AgentChanges => {
    if (changes === undefined) throw new Error('the agents change routes ran without their use case');
    return changes;
  };
  const refused = (
    answer: { outcome: 'refused'; status: number; code: Parameters<typeof sendErrorBody>[2] },
    request: FastifyRequest,
    reply: FastifyReply,
  ) => sendErrorBody(reply, answer.status, answer.code, request.id);

  routes.get(
    '/v1/agents',
    { schema: LIST_SCHEMA, config: { access: ['admin', 'approver', 'developer', 'viewer'] } },
    async (request, reply) => {
      const { orgId } = memberOf(request);
      const listed = await registrationsOf().list(
        orgId,
        { after: request.query.after ?? null, limit: request.query.limit ?? MOST_AGENTS_A_PAGE },
        request.id,
      );
      if (listed.outcome === 'refused') return refused(listed, request, reply);
      return { agents: listed.agents.map(agentOf), next: listed.next };
    },
  );

  routes.get(
    '/v1/agents/:id',
    { schema: SHOW_SCHEMA, config: { access: ['admin', 'approver', 'developer', 'viewer'] } },
    async (request, reply) => {
      const { orgId } = memberOf(request);
      const found = await registrationsOf().show(orgId, request.params.id, request.id);
      if (found.outcome === 'refused') return refused(found, request, reply);
      return withKeysOf(found);
    },
  );

  routes.post(
    '/v1/agents',
    {
      schema: REGISTER_SCHEMA,
      bodyLimit: REGISTER_BODY_LIMIT,
      config: { access: [...REGISTERING_ROLES], operation: REGISTER_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await registrationsOf().ask(
        member,
        idempotentRequest(request, member.orgId),
        request.body,
        request.id,
      );
      if (written.outcome === 'refused') return refused(written, request, reply);
      if (written.outcome === 'conflict' || written.outcome === 'busy') {
        return answerRefusedWrite(written, request, reply);
      }
      if (written.outcome !== 'asked') throw new Error('an ask answered without its step-up');
      return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    },
  );

  routes.post(
    '/v1/agents/confirm',
    {
      schema: CONFIRM_SCHEMA,
      bodyLimit: REGISTER_BODY_LIMIT,
      config: { access: [...REGISTERING_ROLES], operation: REGISTER_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const { stepUpChallengeId, ...asked } = request.body;
      const written = await registrationsOf().confirm(
        member,
        idempotentRequest(request, member.orgId),
        asked,
        stepUpChallengeId,
        request.id,
      );
      if (written.outcome === 'refused') return refused(written, request, reply);
      if (written.outcome === 'conflict' || written.outcome === 'busy') {
        return answerRefusedWrite(written, request, reply);
      }
      if (written.outcome !== 'registered') throw new Error('a registration answered without its agent');
      return reply.code(201).send({ ...withKeysOf(written.agent), key: written.key });
    },
  );

  /** Answers a change: the agent as it now stands, a step-up asked, or a refusal. */
  const answerChange = (written: AgentChangeWrite, request: FastifyRequest, reply: FastifyReply) => {
    if (written.outcome === 'changed') return reply.code(200).send(withKeysOf(written.agent));
    if (written.outcome === 'asked') return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    if (written.outcome === 'refused') return refused(written, request, reply);
    return answerRefusedWrite(written, request, reply);
  };

  routes.post(
    '/v1/agents/:id/suspend',
    {
      schema: SUSPEND_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...SUSPENDING_ROLES], operation: SUSPEND_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await changesOf().suspend(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/agents/:id/reactivate',
    {
      schema: REACTIVATE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...REACTIVATING_ROLES], operation: REACTIVATE_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await changesOf().reactivate(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/agents/:id/reactivate/confirm',
    {
      schema: REACTIVATE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...REACTIVATING_ROLES], operation: REACTIVATE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await changesOf().reactivateConfirm(
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

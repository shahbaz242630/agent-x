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
// - `POST /v1/agents/:id/owner` with the new owner's membership, then
//   `…/owner/confirm` with it and the step-up's ID (the S68 audit's question
//   A): an admin hands the agent to another member, signing in again with a
//   passkey, and its keys are replaced: 202 with the step-up, then 201 with
//   the agent, its keys (every one before it revoked) and its new key, shown
//   this once. 409 AGENT_OWNER_NOT_ELIGIBLE unless the member is an active
//   admin or developer of the organisation, AGENT_OWNER_UNCHANGED for the
//   agent's owner already, AGENT_KEYS_SPENT past the day's key budget.
// - `POST /v1/agents/:id/keys/:keyId/rotate`, then `…/rotate/confirm` with the
//   step-up's ID (C1-4b): a new key, shown this once, and the old one kept
//   working for the overlap (24 hours): 202 with the step-up, then 201 with
//   the agent, its keys and the new key. 409 AGENT_KEY_NOT_LIVE for a key
//   revoked or expired, AGENT_KEYS_FULL while a rotation's overlap runs,
//   AGENT_KEYS_SPENT past the day's budget. Admins and developers.
// - `POST /v1/agents/:id/keys/:keyId/revoke`, then `…/revoke/confirm` (C1-4b):
//   the key stops at once: 202, then 200 with the agent and its keys. 409
//   AGENT_KEY_REVOKED for one revoked already. Admins and developers.
// The two registration writes: admins and developers, in the organisation the request
// names. Refusals: 409 AGENT_ADDS_SPENT past the day's budget; 403
// STEP_UP_FAILED for another step-up, or other name or scopes than asked; 404
// NOT_FOUND for an agent the organisation doesn't have; 503 INTEGRITY_FAILED
// when an agent, a key or the caller's membership can't be verified. The use
// cases are agent-registering.ts, agent-changes.ts and agent-key-changes.ts.
import { isAgentName, MOST_AGENTS_A_PAGE, SCOPES } from '@agentx/core/modules/agents';
import type { AgentKeyRecord, AgentShown } from '@agentx/core/modules/agents';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
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
  HAND_OVER_CONFIRM_OPERATION,
  HAND_OVER_OPERATION,
  HANDING_OVER_ROLES,
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  REACTIVATING_ROLES,
  SUSPEND_OPERATION,
  SUSPENDING_ROLES,
} from './agent-changes.ts';
import {
  type AgentKeyChanges,
  type AgentKeyChangeWrite,
  KEY_CHANGING_ROLES,
  type KeyNamed,
  REVOKE_CONFIRM_OPERATION,
  REVOKE_OPERATION,
  ROTATE_CONFIRM_OPERATION,
  ROTATE_OPERATION,
} from './agent-key-changes.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
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
  querystring: pageQuery(MOST_AGENTS_A_PAGE),
  response: {
    200: z
      .object({
        agents: z.array(AGENT).describe('The agents, in order of ID.'),
        next: NEXT,
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
        stepUpChallengeId: STEP_UP_TO_SIGN_IN,
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
      stepUpChallengeId: STEP_UP_SIGNED_IN,
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

/** The most a handover's ask or confirm may be: a membership's ID and a step-up's, with room to spare. */
const HAND_OVER_BODY_LIMIT = 256;

const AGENT_ID = z.object({ id: z.uuid().describe('The agent, by its ID.') });

const AGENT_CHANGED = AGENT_WITH_KEYS.describe('The agent and its keys, as the change left them.');

const STEP_UP_ASKED = z
  .object({
    stepUpChallengeId: STEP_UP_TO_SIGN_IN,
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
  body: z.strictObject({ stepUpChallengeId: STEP_UP_SIGNED_IN }).describe('The step-up signed in again for.'),
  response: { 200: AGENT_CHANGED },
};

const NEW_OWNER = z
  .uuid()
  .describe('The membership of the member taking the agent over: an active admin or developer.');

const HAND_OVER_ASKED = z
  .object({
    stepUpChallengeId: STEP_UP_TO_SIGN_IN,
  })
  .register(API_SCHEMAS, {
    id: 'AgentHandOverAsked',
    description: 'Handing an agent to another owner, waiting for the admin to sign in again.',
  });

const HAND_OVER_SCHEMA = {
  summary: 'Ask to hand an agent to another owner',
  params: AGENT_ID,
  body: z.strictObject({ owner: NEW_OWNER }).describe('The member taking the agent over.'),
  response: { 202: HAND_OVER_ASKED },
};

const HAND_OVER_CONFIRM_SCHEMA = {
  summary: 'Hand the agent over, once signed in again for it',
  params: AGENT_ID,
  body: z
    .strictObject({
      owner: NEW_OWNER,
      stepUpChallengeId: STEP_UP_SIGNED_IN,
    })
    .describe('The same member as asked, and the step-up signed in again for.'),
  response: {
    201: AGENT_WITH_KEYS.extend({
      key: z
        .string()
        .nullable()
        .describe(
          'The agent’s new key, `axk_<keyId>_<secret>`, shown this once: give it to the agent, as every key before it is revoked. Null on a retry of the same request.',
        ),
    }).describe('The agent, handed over: its keys, every one before the handover revoked, and its new key.'),
  },
};

const KEY_NAMED = z.object({
  id: z.uuid().describe('The agent, by its ID.'),
  keyId: z.uuid().describe('Its key, by its ID.'),
});

const KEY_CHANGE_ASKED = z
  .object({
    stepUpChallengeId: STEP_UP_TO_SIGN_IN,
  })
  .register(API_SCHEMAS, {
    id: 'AgentKeyChangeAsked',
    description: "Rotating or revoking an agent's key, waiting for you to sign in again.",
  });

const STEP_UP_CONFIRM = z
  .strictObject({ stepUpChallengeId: STEP_UP_SIGNED_IN })
  .describe('The step-up signed in again for.');

const ROTATE_SCHEMA = {
  summary: "Ask to rotate an agent's key: a new one, the old one kept working for the overlap",
  params: KEY_NAMED,
  body: NOTHING,
  response: { 202: KEY_CHANGE_ASKED },
};

const ROTATE_CONFIRM_SCHEMA = {
  summary: 'Rotate the key, once signed in again for it',
  params: KEY_NAMED,
  body: STEP_UP_CONFIRM,
  response: {
    201: AGENT_WITH_KEYS.extend({
      key: z
        .string()
        .nullable()
        .describe(
          'The new key, `axk_<keyId>_<secret>`, shown this once: give it to the agent before the old one expires. Null on a retry of the same request.',
        ),
    }).describe('The agent and its keys: the new one, and the old one expiring at the end of the overlap.'),
  },
};

const REVOKE_SCHEMA = {
  summary: "Ask to revoke an agent's key: it stops at once, with no overlap",
  params: KEY_NAMED,
  body: NOTHING,
  response: { 202: KEY_CHANGE_ASKED },
};

const REVOKE_CONFIRM_SCHEMA = {
  summary: 'Revoke the key, once signed in again for it',
  params: KEY_NAMED,
  body: STEP_UP_CONFIRM,
  response: { 200: AGENT_CHANGED },
};

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
  {
    registrations,
    changes,
    keyChanges,
  }: {
    registrations: AgentRegistrations | undefined;
    changes: AgentChanges | undefined;
    keyChanges: AgentKeyChanges | undefined;
  },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const refused = (
    answer: { outcome: 'refused'; status: number; code: Parameters<typeof sendErrorBody>[2] },
    request: FastifyRequest,
    reply: FastifyReply,
  ) => sendErrorBody(reply, answer.status, answer.code, request.id);

  routes.get(
    '/v1/agents',
    { schema: LIST_SCHEMA, config: { access: ['admin', 'approver', 'developer', 'viewer'] } },
    async (request, reply) => {
      const { orgId } = memberInSessionOf(request);
      const listed = await need(registrations).list(
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
      const { orgId } = memberInSessionOf(request);
      const found = await need(registrations).show(orgId, request.params.id, request.id);
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
      const member = memberInSessionOf(request);
      const written = await need(registrations).ask(
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
      const member = memberInSessionOf(request);
      const { stepUpChallengeId, ...asked } = request.body;
      const written = await need(registrations).confirm(
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
    if (written.outcome === 'handedOver') {
      return reply.code(201).send({ ...withKeysOf(written.agent), key: written.key });
    }
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
      const member = memberInSessionOf(request);
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
    '/v1/agents/:id/reactivate',
    {
      schema: REACTIVATE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...REACTIVATING_ROLES], operation: REACTIVATE_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
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
    '/v1/agents/:id/reactivate/confirm',
    {
      schema: REACTIVATE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...REACTIVATING_ROLES], operation: REACTIVATE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
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

  routes.post(
    '/v1/agents/:id/owner',
    {
      schema: HAND_OVER_SCHEMA,
      bodyLimit: HAND_OVER_BODY_LIMIT,
      config: { access: [...HANDING_OVER_ROLES], operation: HAND_OVER_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(changes).handOver(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.owner,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/agents/:id/owner/confirm',
    {
      schema: HAND_OVER_CONFIRM_SCHEMA,
      bodyLimit: HAND_OVER_BODY_LIMIT,
      config: { access: [...HANDING_OVER_ROLES], operation: HAND_OVER_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(changes).handOverConfirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.owner,
        request.body.stepUpChallengeId,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  /** Answers a key change: the agent as it now stands (with the new key, once), a step-up asked, or a refusal. */
  const answerKeyChange = (written: AgentKeyChangeWrite, request: FastifyRequest, reply: FastifyReply) => {
    if (written.outcome === 'rotated') {
      return reply.code(201).send({ ...withKeysOf(written.agent), key: written.key });
    }
    if (written.outcome === 'revoked') return reply.code(200).send(withKeysOf(written.agent));
    if (written.outcome === 'asked') return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    if (written.outcome === 'refused') return refused(written, request, reply);
    return answerRefusedWrite(written, request, reply);
  };

  const named = (params: { id: string; keyId: string }): KeyNamed => ({ agentId: params.id, keyId: params.keyId });

  routes.post(
    '/v1/agents/:id/keys/:keyId/rotate',
    {
      schema: ROTATE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...KEY_CHANGING_ROLES], operation: ROTATE_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(keyChanges).rotate(
        member,
        idempotentRequest(request, member.orgId),
        named(request.params),
        request.id,
      );
      return answerKeyChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/agents/:id/keys/:keyId/rotate/confirm',
    {
      schema: ROTATE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...KEY_CHANGING_ROLES], operation: ROTATE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(keyChanges).rotateConfirm(
        member,
        idempotentRequest(request, member.orgId),
        named(request.params),
        request.body.stepUpChallengeId,
        request.id,
      );
      return answerKeyChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/agents/:id/keys/:keyId/revoke',
    {
      schema: REVOKE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...KEY_CHANGING_ROLES], operation: REVOKE_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(keyChanges).revoke(
        member,
        idempotentRequest(request, member.orgId),
        named(request.params),
        request.id,
      );
      return answerKeyChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/agents/:id/keys/:keyId/revoke/confirm',
    {
      schema: REVOKE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...KEY_CHANGING_ROLES], operation: REVOKE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(keyChanges).revokeConfirm(
        member,
        idempotentRequest(request, member.orgId),
        named(request.params),
        request.body.stepUpChallengeId,
        request.id,
      );
      return answerKeyChange(written, request, reply);
    },
  );
}

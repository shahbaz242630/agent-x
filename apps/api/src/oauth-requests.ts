// The consent page's addresses (6E3a, ADR-016; SEC-OAUTH-10): what the
// console's `/connect` screen (6E3b) reads and sends for a flow an MCP client
// opened. Only the browser that opened the flow (its `__Host-agentx-connect`
// cookie) reaches it; anyone else, or a flow decided or ended, is a 404.
//
// - `GET /v1/oauth/requests/:id`: the client, by what it says it is, the host
//   it sends the person back to, what it asks for. Any signed-in person.
// - `POST /v1/oauth/requests/:id/consent`, then `…/consent/confirm`: the
//   agent picked and the scopes ticked, with step-up (connection-consents.ts).
//   Admins and developers of the organisation the header names. The confirm
//   answers where the browser goes next, with the code, this once.
// - `POST /v1/oauth/requests/:id/deny`: the client told no.
// - `POST /v1/oauth/device/lookup` (6E3c, RFC 8628 §3.3): the user code a
//   device showed, typed by a signed-in person on the console's `/device`
//   page, claims that device's request for this browser and this person
//   (oauth-device.ts, AG8); the request is then read and decided as above, by
//   that person alone. Five tries a minute a person, beside every other
//   limit, and a network's every lookup held for a minute (429) once too
//   many failed from it: the code is all that guards it.
import { SCOPES } from '@agentx/core/modules/agents';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need, personOf } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import {
  CONNECTING_ROLES,
  type ConnectionConsents,
  CONSENT_CONFIRM_OPERATION,
  CONSENT_OPERATION,
  type ConsentWrite,
  DENY_OPERATION,
  type FlowNamed,
} from './connection-consents.ts';
import { sendErrorBody } from './errors.ts';
import { answerAsked, idempotentRequest } from './idempotent-writes.ts';
import type { OauthDevice } from './oauth-device.ts';
import { CONNECT_COOKIE, connectCookie, OAUTH_PATHS } from './oauth-wire.ts';
import { createRoutePersonCounter, type ProxyTrust, rawClientIp } from './rate-limit.ts';
import { NOTHING, NOTHING_BODY_LIMIT, STEP_UP_SIGNED_IN, stepUpAsked } from './route-schemas.ts';
import { cookieValue } from './sign-in.ts';

/** The most a consent's body may be: an agent's ID, every scope and a step-up's ID, with room to spare. */
const CONSENT_BODY_LIMIT = 512;

const FLOW = z.object({ id: z.uuid().describe('The request, by the ID its address named.') });

const SCOPE_LIST = z.array(z.enum(SCOPES)).describe('The scopes, in the order Agent X lists them.');

const REQUEST_SHOWN = z
  .object({
    id: z.uuid(),
    via: z.enum(['code', 'device']).describe('A browser’s sign-in, or a device’s (RFC 8628), which sends no one back.'),
    client: z
      .object({
        id: z.string().describe('The client’s ID.'),
        name: z.string().describe('What the client says it is: never proof of who it is.'),
        verifiedBy: z
          .string()
          .nullable()
          .describe('The host whose metadata document named the client; null for one that registered itself.'),
      })
      .describe('The app asking.'),
    redirectUri: z.string().nullable().describe('Where the person is sent back to, with the code; none for a device.'),
    redirectHost: z
      .string()
      .nullable()
      .describe('That address’s host: show it in bold, it is what the name can’t hide. None for a device.'),
    loopback: z.boolean().describe('Sent back to an app on the person’s own computer.'),
    scopesAsked: SCOPE_LIST.describe('What the app asks to do: tick among these, and those the agent holds.'),
    resource: z.string().describe('The MCP endpoint the connection is for.'),
    endsAt: z.iso.datetime().describe('When the request ends, unanswered.'),
  })
  .register(API_SCHEMAS, { id: 'ConnectionRequest', description: 'An MCP client asking to be connected.' });

const CONSENT = z
  .strictObject({
    agentId: z.uuid().describe('The agent the connection acts as.'),
    scopes: SCOPE_LIST.min(1).max(SCOPES.length).describe('The scopes ticked: among those asked and the agent holds.'),
  })
  .describe('The agent picked and the scopes ticked.');

const CONSENT_CONFIRM = CONSENT.extend({ stepUpChallengeId: STEP_UP_SIGNED_IN }).describe(
  'The same agent and scopes, and the step-up signed in again for.',
);

const CONNECTED = z
  .object({
    redirectTo: z
      .string()
      .nullable()
      .describe('Where to send the browser now, with the code: this once. Null on a retry of the same request.'),
    connection: z
      .object({
        via: z.enum(['code', 'device']).describe('Made for a browser’s sign-in, or a device’s: then go back to it.'),
        keyId: z.uuid().describe('The connection, by its key’s ID.'),
        agentId: z.uuid(),
        clientId: z.string(),
        scopes: SCOPE_LIST,
        expiresAt: z.iso.datetime().describe('When it ends, and the person must connect the app again.'),
      })
      .describe('The connection made.'),
  })
  .register(API_SCHEMAS, { id: 'ConnectionMade', description: 'The app connected as the agent.' });

const DENIED = z
  .object({
    redirectTo: z
      .string()
      .nullable()
      .describe('Where to send the browser now: the app is told no. None for a device, which learns it by polling.'),
  })
  .register(API_SCHEMAS, { id: 'ConnectionDenied', description: 'The app told no.' });

const OAUTH_MEMBER_ROUTE = { access: [...CONNECTING_ROLES], oauth: true } as const;

/** Claiming a device's request by its user code: its operation. */
const DEVICE_LOOKUP_OPERATION = 'connections.device-lookup';

/** A person's tries at a user code (6E3 plan §1): 5 a minute, so 20^8 codes can't be walked. */
const LOOKUP_LIMIT = { most: 5, windowMs: 60_000 } as const;

/** How long to wait when a network's lookups are held (AG8): at most the rest of the failed lookups' minute. */
const LOOKUP_HELD_SECONDS = 60;

const LOOKUP = z
  .strictObject({ userCode: z.string().min(1).max(32).describe('The code the device shows, as typed: `BCDF-GHJK`.') })
  .describe('A device’s user code.');

const LOOKED_UP = z
  .object({
    requestId: z.uuid().describe('The device’s request, now this browser’s: read and decide it as any other.'),
  })
  .register(API_SCHEMAS, { id: 'DeviceRequestFound', description: 'The device’s request, claimed for this browser.' });

/** The most a lookup's body may be: the code, with room to spare. */
const LOOKUP_BODY_LIMIT = 256;

/** The flow named, and the cookie of the browser asking. */
const namedBy = (request: FastifyRequest<{ Params: { id: string } }>): FlowNamed => ({
  flowId: request.params.id,
  cookie: cookieValue(request.headers.cookie, CONNECT_COOKIE),
});

/** Answers a consent's write: connected, denied, a step-up asked, or a refusal. */
function answerConsent(written: ConsentWrite, request: FastifyRequest, reply: FastifyReply): FastifyReply {
  if (written.outcome === 'connected') {
    const { connection } = written;
    return reply.code(201).send({
      redirectTo: written.redirectTo,
      connection: { ...connection, scopes: [...connection.scopes], expiresAt: connection.expiresAt.toISOString() },
    });
  }
  if (written.outcome === 'denied') return reply.code(200).send({ redirectTo: written.redirectTo });
  return answerAsked(written, request, reply);
}

export function registerOauthRequests(
  app: FastifyInstance,
  {
    consents,
    device,
    trust,
  }: {
    readonly consents: ConnectionConsents | undefined;
    readonly device: OauthDevice | undefined;
    /** The trust rule for the client's address (rate-limit.ts): a lookup's failures are held per network (AG8). */
    readonly trust: ProxyTrust;
  },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.post(
    OAUTH_PATHS.deviceLookup,
    {
      schema: {
        summary: 'Find the device asking to be connected, by the code it shows',
        description:
          'The request becomes this browser’s and this person’s: read it, then allow or deny it, as a browser’s. A ' +
          'code typed wrong, ended, decided or already claimed by anyone else is a 404, which says nothing of which; ' +
          'once too many lookups failed from one network this minute, its every lookup is a 429 with Retry-After.',
        body: LOOKUP,
        response: { 200: LOOKED_UP },
      },
      bodyLimit: LOOKUP_BODY_LIMIT,
      preHandler: createRoutePersonCounter(app, LOOKUP_LIMIT),
      config: { access: ['person'], oauth: true, operation: DEVICE_LOOKUP_OPERATION },
    },
    async (request, reply) => {
      const found = await need(device).lookup(
        request.body.userCode,
        cookieValue(request.headers.cookie, CONNECT_COOKIE),
        personOf(request),
        rawClientIp(request, trust),
      );
      if (found.outcome === 'not_found') return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      // AG8: too many lookups failed from this network this minute; the person tries again in a minute.
      if (found.outcome === 'held') {
        return sendErrorBody(reply.header('retry-after', LOOKUP_HELD_SECONDS), 429, 'RATE_LIMITED', request.id);
      }
      // Set again every time, its day starting now, as the authorize endpoint does.
      void reply.header('set-cookie', connectCookie(found.cookie));
      return { requestId: found.requestId };
    },
  );

  routes.get(
    '/v1/oauth/requests/:id',
    {
      schema: { summary: 'An MCP client asking to be connected', params: FLOW, response: { 200: REQUEST_SHOWN } },
      config: { access: ['person'], oauth: true },
    },
    async (request, reply) => {
      const shown = await need(consents).request(namedBy(request), personOf(request));
      if (shown === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      return { ...shown, scopesAsked: [...shown.scopesAsked], endsAt: shown.endsAt.toISOString() };
    },
  );

  routes.post(
    '/v1/oauth/requests/:id/consent',
    {
      schema: {
        summary: 'Allow an MCP client to act as one of your agents: sign in again to confirm',
        params: FLOW,
        body: CONSENT,
        response: { 202: stepUpAsked('ConnectionAsked', 'Connecting the app, waiting for you to sign in again.') },
      },
      bodyLimit: CONSENT_BODY_LIMIT,
      config: { ...OAUTH_MEMBER_ROUTE, operation: CONSENT_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(consents).consent(
        member,
        idempotentRequest(request, member.orgId),
        namedBy(request),
        request.body,
        request.id,
      );
      return answerConsent(written, request, reply);
    },
  );

  routes.post(
    '/v1/oauth/requests/:id/consent/confirm',
    {
      schema: {
        summary: 'Connect the app, once signed in again for it',
        params: FLOW,
        body: CONSENT_CONFIRM,
        response: { 201: CONNECTED },
      },
      bodyLimit: CONSENT_BODY_LIMIT,
      config: { ...OAUTH_MEMBER_ROUTE, operation: CONSENT_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const { stepUpChallengeId, ...asked } = request.body;
      const written = await need(consents).confirm(
        member,
        idempotentRequest(request, member.orgId),
        namedBy(request),
        asked,
        stepUpChallengeId,
        request.id,
      );
      return answerConsent(written, request, reply);
    },
  );

  routes.post(
    '/v1/oauth/requests/:id/deny',
    {
      schema: { summary: 'Tell the app no', params: FLOW, body: NOTHING, response: { 200: DENIED } },
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { ...OAUTH_MEMBER_ROUTE, operation: DENY_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const written = await need(consents).deny(
        member,
        idempotentRequest(request, member.orgId),
        namedBy(request),
        request.id,
      );
      return answerConsent(written, request, reply);
    },
  );
}

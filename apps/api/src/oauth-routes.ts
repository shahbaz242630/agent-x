// The OAuth server's public addresses (6E3a, ADR-016; MCP-Guide M5): what an
// MCP client calls before, and to get, a connection. Every one a 404 while
// AGENTX_MCP_OAUTH is off (registerOauthSwitch, before anyone is asked who
// they are).
//
// - `GET /.well-known/oauth-protected-resource` (and `…/v1/mcp`, RFC 9728's
//   path form): the MCP endpoint's metadata, naming us as its one
//   authorization server.
// - `GET /.well-known/oauth-authorization-server` (RFC 8414) and
//   `/.well-known/openid-configuration` (decision 1): the same document, from
//   the one capabilities object; nothing in it claims OIDC.
// - `GET /v1/oauth/authorize`: a flow opened for the person's browser, and the
//   browser sent to the console's consent page (oauth-authorizing.ts).
// - `POST /v1/oauth/token` and `POST /v1/oauth/revoke`: forms, each field
//   once, at most 4 KB, never cached; OAuth's own error bodies
//   (oauth-grants.ts).
// - `POST /v1/oauth/register` (RFC 7591): a public client registered.
//
// Each counts against a limit of its own per client address, beside the one
// every route has: registering 10 an hour, authorizing 30 a minute, the token
// and revocation endpoints 60 a minute. None of them reads a cookie but the
// authorize endpoint's own flow cookie, so the token, revocation and
// registration endpoints take writes from any origin (`oauthClient`), as
// OAuth clients send them; none answers a browser's cross-origin read (no
// CORS, decision 10).
import { ACCESS_TOKEN_SECONDS } from '@agentx/core/modules/agents';
import type { Clock } from '@agentx/core/shared-kernel';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import type { OauthAuthorizing } from './oauth-authorizing.ts';
import type { GrantAnswer, OauthGrants } from './oauth-grants.ts';
import {
  type Capabilities,
  CONNECT_PATH,
  FORM_BODY_LIMIT,
  noStore,
  OAUTH_COOKIE,
  OAUTH_ERROR_RESPONSES,
  OAUTH_PATHS,
  oauthCookie,
  resourceMetadataOf,
  sendOauthError,
  serverMetadataOf,
} from './oauth-wire.ts';
import { MCP_PATH } from './mcp.ts';
import { type CountRequest, createAddressCounter, type ProxyTrust } from './rate-limit.ts';
import { cookieValue } from './sign-in.ts';

const MINUTE_MS = 60_000;

/** Each endpoint's own limit per client address (plan §1). */
const LIMITS = {
  register: { most: 10, windowMs: 60 * MINUTE_MS },
  authorize: { most: 30, windowMs: MINUTE_MS },
  token: { most: 60, windowMs: MINUTE_MS },
} as const;

/** The most a registration's body may be: five addresses of 2 KB each and the rest, with room to spare. */
const REGISTER_BODY_LIMIT = 16_384;

const OAUTH_ROUTE = { access: ['public'], oauth: true } as const;
const OAUTH_CLIENT_ROUTE = { ...OAUTH_ROUTE, oauthClient: true, oauthWire: true } as const;

const words = z.array(z.string());

const RESOURCE_METADATA = z
  .object({
    resource: z.string().describe('The MCP endpoint, the one resource a connection’s tokens are for.'),
    authorization_servers: words.describe('Agent X itself, the one server that issues them.'),
    scopes_supported: words,
    bearer_methods_supported: words,
    resource_name: z.string(),
    resource_documentation: z.string(),
  })
  .register(API_SCHEMAS, {
    id: 'ProtectedResourceMetadata',
    description: 'The MCP endpoint, as RFC 9728 describes it.',
  });

const SERVER_METADATA = z
  .object({
    issuer: z.string(),
    authorization_endpoint: z.string(),
    token_endpoint: z.string(),
    revocation_endpoint: z.string(),
    registration_endpoint: z.string(),
    scopes_supported: words,
    response_types_supported: words,
    response_modes_supported: words,
    grant_types_supported: words,
    code_challenge_methods_supported: words,
    token_endpoint_auth_methods_supported: words,
    revocation_endpoint_auth_methods_supported: words,
    authorization_response_iss_parameter_supported: z.boolean(),
  })
  .register(API_SCHEMAS, {
    id: 'AuthorizationServerMetadata',
    description: 'Agent X’s authorization server, as RFC 8414 describes it: public clients, PKCE S256, no OIDC.',
  });

const REDIRECT = z.object({}).describe('Sent on: the Location header names where; the body is an empty object.');

const text = (most: number) => z.string().max(most).optional();

const AUTHORIZE_QUERY = z.object({
  response_type: text(64).describe('code: the only flow offered.'),
  client_id: text(2048).describe('The client, as it registered.'),
  redirect_uri: text(2048).describe('One of its registered addresses, exactly (a loopback address on any port).'),
  scope: text(256).describe('The scopes asked for, space-delimited; none asks for all, the person ticks which.'),
  state: text(2048).describe('Sent back unchanged: at most 512 characters.'),
  code_challenge: text(128).describe('PKCE: BASE64URL(SHA-256(code_verifier)).'),
  code_challenge_method: text(16).describe('S256, the only method taken.'),
  resource: text(2048).describe('The MCP endpoint (RFC 8707), if named.'),
});

const TOKEN_FORM = z.object({
  grant_type: text(64).describe('authorization_code or refresh_token.'),
  client_id: text(2048),
  code: text(128),
  redirect_uri: text(2048),
  code_verifier: text(128),
  refresh_token: text(256),
  scope: text(256).describe('On a refresh: the scopes to keep, which may only narrow.'),
  resource: text(2048),
});

const TOKENS = z
  .object({
    access_token: z.string().describe('`axa_…`: sent as a bearer token to the MCP endpoint alone, for an hour.'),
    token_type: z.literal('Bearer'),
    expires_in: z.int().describe('Seconds the access token works.'),
    refresh_token: z.string().describe('`axr_…`: used once, for a new pair; unused for 30 days, it ends.'),
    scope: z.string().describe('The scopes the tokens hold, space-delimited.'),
  })
  .register(API_SCHEMAS, { id: 'OauthTokens', description: 'A connection’s new pair of tokens (RFC 6749 §5.1).' });

const REVOKE_FORM = z.object({
  token: text(256).describe('Either of the connection’s tokens: the connection is revoked.'),
  token_type_hint: text(64),
  client_id: text(2048),
});

const REVOKED = z.object({}).describe('Taken, whatever the token was (RFC 7009 §2.2).');

const REGISTRATION = z.object({
  redirect_uris: z.array(z.string().max(2048)).max(16).optional(),
  client_name: text(400),
  grant_types: z.array(z.string().max(64)).max(8).optional(),
  response_types: z.array(z.string().max(64)).max(8).optional(),
  token_endpoint_auth_method: text(64),
  scope: text(256),
  software_id: text(1024),
  software_version: text(1024),
});

const REGISTERED = z
  .object({
    client_id: z.string(),
    client_id_issued_at: z.int(),
    client_name: z.string().describe('What it said it is, as kept: shown to people as such, never as proof.'),
    redirect_uris: words,
    grant_types: words,
    response_types: words,
    token_endpoint_auth_method: z.literal('none'),
    application_type: z.enum(['web', 'native']),
  })
  .register(API_SCHEMAS, { id: 'OauthClient', description: 'A client, registered (RFC 7591 §3.2.1).' });

/**
 * Every route with `config.oauth` is a 404 while the OAuth server is off, before anyone is asked who they are. Add it
 * before the access hook.
 */
export function registerOauthSwitch(app: FastifyInstance, on: boolean): void {
  app.addHook('onRequest', (request, reply, done) => {
    if (on || request.routeOptions.config.oauth !== true) {
      done();
      return;
    }
    void sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
  });
}

/** The OAuth server's public addresses but its forms'; without their use cases, each answers 404 as when it is off. */
export function registerOauth(
  app: FastifyInstance,
  {
    capabilities,
    authorizing,
    trust,
  }: {
    readonly capabilities: Capabilities;
    readonly authorizing: OauthAuthorizing | undefined;
    readonly trust: ProxyTrust;
  },
): void {
  app.decorateRequest('formRepeated', false);
  const counted = (limit: { readonly most: number; readonly windowMs: number }): CountRequest =>
    createAddressCounter(app, limit, trust);
  const routes = app.withTypeProvider<ZodTypeProvider>();

  for (const path of [OAUTH_PATHS.resourceMetadata, `${OAUTH_PATHS.resourceMetadata}${MCP_PATH}`]) {
    routes.get(
      path,
      {
        schema: { summary: 'The MCP endpoint’s OAuth metadata (RFC 9728)', response: { 200: RESOURCE_METADATA } },
        config: OAUTH_ROUTE,
      },
      () => resourceMetadataOf(capabilities),
    );
  }
  for (const path of [OAUTH_PATHS.serverMetadata, OAUTH_PATHS.openIdConfiguration]) {
    routes.get(
      path,
      {
        schema: { summary: 'Agent X’s OAuth server metadata (RFC 8414)', response: { 200: SERVER_METADATA } },
        config: OAUTH_ROUTE,
      },
      () => serverMetadataOf(capabilities),
    );
  }

  const authorizeLimit = counted(LIMITS.authorize);
  routes.get(
    OAUTH_PATHS.authorize,
    {
      schema: {
        summary: 'Start connecting an MCP client as one of your agents',
        description:
          'OAuth 2.1’s authorization endpoint: the browser goes on to Agent X’s consent page, or back to the client ' +
          'with an error, its state and our issuer (RFC 9207). An unknown client or redirect address is never sent back to.',
        querystring: AUTHORIZE_QUERY,
        response: { 302: REDIRECT },
      },
      onRequest: authorizeLimit,
      config: OAUTH_ROUTE,
    },
    async (request, reply) => {
      if (authorizing === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      const answer = await authorizing.authorize(request.query, cookieValue(request.headers.cookie, OAUTH_COOKIE));
      if (answer.outcome === 'not_redirectable') {
        return reply.code(302).header('location', `${CONNECT_PATH}?problem=${answer.problem}`).send({});
      }
      if (answer.outcome === 'refused') return reply.code(302).header('location', answer.redirectTo).send({});
      // Set again every time, its day starting now: a flow opened near the cookie's end is never stranded.
      void reply.header('set-cookie', oauthCookie(answer.cookie));
      return reply.code(302).header('location', `${CONNECT_PATH}?request=${answer.flowId}`).send({});
    },
  );

  const registerLimit = counted(LIMITS.register);
  routes.post(
    OAUTH_PATHS.register,
    {
      schema: {
        summary: 'Register an MCP client (RFC 7591)',
        description: 'A public client alone: no secret, PKCE on every request. Its logo and pages are never fetched.',
        body: REGISTRATION,
        response: { 201: REGISTERED, ...OAUTH_ERROR_RESPONSES },
      },
      bodyLimit: REGISTER_BODY_LIMIT,
      onRequest: registerLimit,
      config: OAUTH_CLIENT_ROUTE,
    },
    async (request, reply) => {
      if (authorizing === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      const answer = await authorizing.register(request.body, request.id);
      if (answer.outcome === 'invalid') return sendOauthError(reply, 400, answer.error, answer.description);
      if (answer.outcome === 'capped') return sendErrorBody(reply, 429, 'RATE_LIMITED', request.id);
      const { client } = answer;
      return reply.code(201).send({
        client_id: client.clientId,
        client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
        client_name: client.name,
        redirect_uris: [...client.redirectUris],
        grant_types: [...client.grantTypes],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        application_type: client.applicationType,
      });
    },
  );
}

/**
 * The token and revocation endpoints, in `scope`: server.ts's scope of their own whose one parser reads a form
 * (formFields), as JSON is no token request. Without their use case each answers 404, as when it is off.
 */
export function registerOauthForms(
  scope: FastifyInstance,
  {
    grants,
    clock,
    trust,
  }: { readonly grants: OauthGrants | undefined; readonly clock: Clock; readonly trust: ProxyTrust },
): void {
  const tokenLimit = createAddressCounter(scope, LIMITS.token, trust);
  const forms = scope.withTypeProvider<ZodTypeProvider>();
  forms.post(
    OAUTH_PATHS.exchange,
    {
      schema: {
        summary: 'Exchange a code, or a refresh token, for a connection’s tokens',
        description:
          'OAuth 2.1’s token endpoint, as an application/x-www-form-urlencoded form, each field once. A code is used ' +
          'once, within 60 seconds, with its PKCE verifier; a refresh token is used once, and a second use revokes ' +
          'the connection.',
        consumes: ['application/x-www-form-urlencoded'],
        body: TOKEN_FORM,
        response: { 200: TOKENS, ...OAUTH_ERROR_RESPONSES },
      },
      bodyLimit: FORM_BODY_LIMIT,
      onRequest: tokenLimit,
      config: OAUTH_CLIENT_ROUTE,
    },
    async (request, reply) => {
      if (grants === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      if (request.formRepeated) return sendOauthError(reply, 400, 'invalid_request', 'A field was sent twice.');
      const form = request.body;
      const caller = { correlationId: request.id, ip: request.ip };
      if (form.client_id === undefined) {
        return sendOauthError(reply, 401, 'invalid_client', 'Name the client, as it registered: client_id.');
      }
      let answer: GrantAnswer;
      if (form.grant_type === 'authorization_code') {
        const { code, redirect_uri: redirectUri, code_verifier: codeVerifier } = form;
        if (code === undefined || redirectUri === undefined || codeVerifier === undefined) {
          return sendOauthError(reply, 400, 'invalid_request', 'Send code, redirect_uri and code_verifier.');
        }
        answer = await grants.exchangeCode(
          { code, clientId: form.client_id, redirectUri, codeVerifier, resource: form.resource },
          caller,
        );
      } else if (form.grant_type === 'refresh_token') {
        if (form.refresh_token === undefined) {
          return sendOauthError(reply, 400, 'invalid_request', 'Send refresh_token.');
        }
        answer = await grants.refresh(
          { refreshToken: form.refresh_token, clientId: form.client_id, scope: form.scope, resource: form.resource },
          caller,
        );
      } else {
        return sendOauthError(reply, 400, 'unsupported_grant_type', 'Use authorization_code or refresh_token.');
      }
      if (answer.outcome === 'refused') return sendOauthError(reply, answer.status, answer.error, answer.description);
      // The connection verified: its request is the agent's own in the activity log (decision 26).
      request.agent = answer.agent;
      const { tokens } = answer;
      const left = Math.ceil((tokens.accessExpiresAt.getTime() - clock.now().getTime()) / 1000);
      return noStore(reply)
        .code(200)
        .send({
          access_token: tokens.accessToken,
          token_type: 'Bearer',
          expires_in: Math.max(1, Math.min(ACCESS_TOKEN_SECONDS, left)),
          refresh_token: tokens.refreshToken,
          scope: tokens.scopes.join(' '),
        });
    },
  );
  forms.post(
    OAUTH_PATHS.revoke,
    {
      schema: {
        summary: 'Revoke a connection by either of its tokens (RFC 7009)',
        consumes: ['application/x-www-form-urlencoded'],
        body: REVOKE_FORM,
        response: { 200: REVOKED, ...OAUTH_ERROR_RESPONSES },
      },
      bodyLimit: FORM_BODY_LIMIT,
      onRequest: tokenLimit,
      config: OAUTH_CLIENT_ROUTE,
    },
    async (request, reply) => {
      if (grants === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      if (request.formRepeated) return sendOauthError(reply, 400, 'invalid_request', 'A field was sent twice.');
      const { token, client_id: clientId } = request.body;
      if (token === undefined) return sendOauthError(reply, 400, 'invalid_request', 'Send token.');
      const taken = await grants.revoke({ token, clientId }, { correlationId: request.id, ip: request.ip });
      if (taken.outcome === 'refused') return sendOauthError(reply, taken.status, taken.error, taken.description);
      return noStore(reply).code(200).send({});
    },
  );
}

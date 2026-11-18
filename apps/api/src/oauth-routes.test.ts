// 6E3a (ADR-016; SEC-OAUTH-01, -11, -12, -13): the OAuth server's addresses
// over HTTP, with stand-in use cases. Off (the default), every one is a 404
// and the MCP endpoint's 401 names no metadata; on, the metadata documents
// come from the one capabilities object, the authorize endpoint never sends an
// unproven client anywhere, and the token, revocation and registration
// endpoints answer OAuth's own error bodies. What the use cases do in the
// database is oauth-connections.db.test.ts.
import type { AcceptedKey, IssuedTokens } from '@agentx/core/modules/agents';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { createCredentialCheck } from './credentials.ts';
import type { AuthorizeAnswer, OauthAuthorizing, RegistrationAnswer } from './oauth-authorizing.ts';
import type { GrantAnswer, OauthGrants } from './oauth-grants.ts';
import { capabilitiesOf, OAUTH_COOKIE } from './oauth-wire.ts';

import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { testLogger } from '@agentx/testing';

afterEach(closeServers);

const capabilities = capabilitiesOf(PUBLIC_ORIGIN);
const FLOW = '0199a0f0-0000-7000-8000-0000000e3a11';
const KEY = '0199a0f0-0000-7000-8000-0000000e3a12';
const AGENT = '0199a0f0-0000-7000-8000-0000000e3a13';
const BROWSER = 'B'.repeat(43);
const CLIENT = 'axcl_0123456789abcdef0123456789abcdef';
const ACCESS_TEXT = `axa_${'1'.repeat(32)}_${'2'.repeat(32)}_${'a'.repeat(43)}`;

const ACCEPTED: AcceptedKey = {
  orgId: ORG,
  agentId: AGENT,
  keyId: KEY,
  scopes: ['requests:read'],
  expiresAt: new Date('2099-12-28T09:00:00Z'),
  credential: 'connection',
};

const TOKENS: IssuedTokens = {
  accessToken: ACCESS_TEXT,
  refreshToken: `axr_${'1'.repeat(32)}_${'3'.repeat(32)}_${'b'.repeat(43)}`,
  accessTokenId: '0199a0f0-0000-7000-8000-0000000e3a14',
  // Far ahead: the answer counts at most an hour.
  accessExpiresAt: new Date('2099-12-28T09:00:00Z'),
  scopes: ['requests:read', 'suppliers:read'],
};

interface Stand {
  readonly authorize?: AuthorizeAnswer;
  readonly register?: RegistrationAnswer;
  readonly grant?: GrantAnswer;
}

/** A server with stand-in OAuth use cases answering as `stand` says, and what each was asked. */
async function oauthServer(oauthOn: boolean, stand: Stand = {}) {
  const asked: unknown[] = [];
  const authorizing: OauthAuthorizing = {
    authorize: (query, cookie) => {
      asked.push({ query, cookie });
      return Promise.resolve(stand.authorize ?? { outcome: 'opened', flowId: FLOW, cookie: BROWSER, set: true });
    },
    register: (body) => {
      asked.push(body);
      return Promise.resolve(stand.register ?? { outcome: 'capped' });
    },
  };
  const grants: OauthGrants = {
    exchangeCode: (exchange) => {
      asked.push(exchange);
      return Promise.resolve(stand.grant ?? { outcome: 'issued', tokens: TOKENS, agent: ACCEPTED });
    },
    refresh: (refresh) => {
      asked.push(refresh);
      return Promise.resolve(stand.grant ?? { outcome: 'issued', tokens: TOKENS, agent: ACCEPTED });
    },
    revoke: (revoke) => {
      asked.push(revoke);
      return Promise.resolve();
    },
  };
  const app = await routeServer({
    oauthOn,
    oauth: {
      authorizing,
      grants,
      consents: {
        request: () => Promise.resolve(undefined),
        consent: () => Promise.reject(new Error('not here')),
        confirm: () => Promise.reject(new Error('not here')),
        deny: () => Promise.reject(new Error('not here')),
      },
      clock: { now: () => new Date('2099-12-28T08:00:00Z') },
    },
  });
  return { app, asked };
}

const form = (url: string, body: string): InjectOptions & { readonly url: string } => ({
  method: 'POST',
  url,
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  payload: body,
});

const json = (url: string, body: unknown): InjectOptions & { readonly url: string } => ({
  method: 'POST',
  url,
  headers: { 'content-type': 'application/json' },
  payload: JSON.stringify(body),
});

const ADDRESSES: readonly (InjectOptions & { readonly url: string })[] = [
  { method: 'GET', url: '/.well-known/oauth-protected-resource' },
  { method: 'GET', url: '/.well-known/oauth-protected-resource/v1/mcp' },
  { method: 'GET', url: '/.well-known/oauth-authorization-server' },
  { method: 'GET', url: '/.well-known/openid-configuration' },
  { method: 'GET', url: '/v1/oauth/authorize?client_id=x' },
  form('/v1/oauth/token', 'grant_type=refresh_token'),
  form('/v1/oauth/revoke', 'token=x'),
  json('/v1/oauth/register', { redirect_uris: ['https://a.example/cb'] }),
  { method: 'GET', url: `/v1/oauth/requests/${FLOW}` },
  {
    method: 'POST',
    url: `/v1/oauth/requests/${FLOW}/consent`,
    headers: {
      cookie: `${SESSION_COOKIE}=${COOKIE}`,
      [ORGANIZATION_HEADER]: ORG,
      origin: PUBLIC_ORIGIN,
      'idempotency-key': 'k-1',
      'content-type': 'application/json',
    },
    payload: JSON.stringify({ agentId: AGENT, scopes: ['requests:read'] }),
  },
];

describe('AGENTX_MCP_OAUTH off (the default): nothing of the OAuth server answers or is advertised', () => {
  it.each(ADDRESSES.map((options) => [`${options.method ?? 'GET'} ${options.url}`, options] as const))(
    'answers %s 404, before anyone is asked who they are',
    async (_, options) => {
      const { app, asked } = await oauthServer(false);
      const response = await app.inject(options);
      expect(response.statusCode).toBe(404);
      expect(response.json()).toMatchObject({ error: { code: 'NOT_FOUND' } });
      expect(asked).toEqual([]);
    },
  );

  it('answers the MCP endpoint’s 401 with no metadata named', async () => {
    const { app } = await oauthServer(false);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/mcp',
      headers: { 'content-type': 'application/json' },
      payload: '{}',
    });
    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe('Bearer realm="Agent X", error="invalid_token"');
  });

  it('answers 404 with no use cases, flag on or not', async () => {
    const app = await routeServer({ oauthOn: true });
    for (const options of ADDRESSES.slice(4, 8)) {
      expect((await app.inject(options)).statusCode).toBe(404);
    }
  });
});

describe('the metadata documents (RFC 9728, RFC 8414): one capabilities object, nothing claiming OIDC', () => {
  it('names the MCP endpoint and our issuer, exactly, at both resource paths', async () => {
    const { app } = await oauthServer(true);
    for (const url of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/v1/mcp']) {
      const response = await app.inject({ method: 'GET', url });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        resource: `${PUBLIC_ORIGIN}/v1/mcp`,
        authorization_servers: [PUBLIC_ORIGIN],
        scopes_supported: ['requests:read', 'requests:write', 'sources:read', 'suppliers:read'],
        bearer_methods_supported: ['header'],
        resource_name: 'Agent X',
        resource_documentation: `${PUBLIC_ORIGIN}/docs/api`,
      });
    }
  });

  it('serves the same server document at RFC 8414’s address and OIDC discovery’s', async () => {
    const { app } = await oauthServer(true);
    const one = await app.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' });
    const other = await app.inject({ method: 'GET', url: '/.well-known/openid-configuration' });
    expect(one.json()).toEqual(other.json());
    expect(one.json()).toEqual({
      issuer: PUBLIC_ORIGIN,
      authorization_endpoint: `${PUBLIC_ORIGIN}/v1/oauth/authorize`,
      token_endpoint: `${PUBLIC_ORIGIN}/v1/oauth/token`,
      revocation_endpoint: `${PUBLIC_ORIGIN}/v1/oauth/revoke`,
      registration_endpoint: `${PUBLIC_ORIGIN}/v1/oauth/register`,
      scopes_supported: ['requests:read', 'requests:write', 'sources:read', 'suppliers:read', 'offline_access'],
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      revocation_endpoint_auth_methods_supported: ['none'],
      authorization_response_iss_parameter_supported: true,
    });
    expect(JSON.stringify(one.json())).not.toMatch(/jwks|id_token|userinfo|openid"/);
  });

  it('names the metadata on the MCP endpoint’s 401, and an issuer from an origin with no trailing slash', async () => {
    const { app } = await oauthServer(true);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/mcp',
      headers: { 'content-type': 'application/json' },
      payload: '{}',
    });
    expect(response.headers['www-authenticate']).toBe(
      `Bearer realm="Agent X", resource_metadata="${PUBLIC_ORIGIN}/.well-known/oauth-protected-resource/v1/mcp", error="invalid_token"`,
    );
    expect(capabilitiesOf(`${PUBLIC_ORIGIN}/`).issuer).toBe(PUBLIC_ORIGIN);
  });
});

describe('SEC-OAUTH-11 the authorize endpoint', () => {
  it('opens a flow, sets the browser’s cookie and sends it to the consent page', async () => {
    const { app, asked } = await oauthServer(true);
    const response = await app.inject({
      method: 'GET',
      url: `/v1/oauth/authorize?response_type=code&client_id=${CLIENT}&state=xyz`,
      headers: { cookie: `${OAUTH_COOKIE}=${BROWSER}` },
    });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`/connect?request=${FLOW}`);
    expect(response.headers['set-cookie']).toBe(
      `${OAUTH_COOKIE}=${BROWSER}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=86400`,
    );
    expect(asked).toEqual([{ query: { response_type: 'code', client_id: CLIENT, state: 'xyz' }, cookie: BROWSER }]);
  });

  it('keeps the browser’s own cookie, and never sends an unknown client anywhere but our own page', async () => {
    const kept = await oauthServer(true, {
      authorize: { outcome: 'opened', flowId: FLOW, cookie: BROWSER, set: false },
    });
    const response = await kept.app.inject({ method: 'GET', url: '/v1/oauth/authorize' });
    expect(response.headers['set-cookie']).toBeUndefined();
    const unknown = await oauthServer(true, { authorize: { outcome: 'not_redirectable', problem: 'unknown_client' } });
    expect((await unknown.app.inject({ method: 'GET', url: '/v1/oauth/authorize' })).headers.location).toBe(
      '/connect?problem=unknown_client',
    );
    const back = 'https://claude.ai/cb?error=invalid_scope&state=xyz&iss=https%3A%2F%2Fapp.agentx.example';
    const refused = await oauthServer(true, { authorize: { outcome: 'refused', redirectTo: back } });
    expect((await refused.app.inject({ method: 'GET', url: '/v1/oauth/authorize' })).headers.location).toBe(back);
  });
});

describe('the token endpoint: forms, each field once, OAuth’s own errors, never cached', () => {
  it('exchanges a code for a pair, its access token’s life at most an hour', async () => {
    const { app, asked } = await oauthServer(true);
    const response = await app.inject(
      form(
        '/v1/oauth/token',
        `grant_type=authorization_code&code=axc_c&redirect_uri=https%3A%2F%2Fa.example%2Fcb&code_verifier=${'v'.repeat(43)}&client_id=${CLIENT}`,
      ),
    );
    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.json()).toEqual({
      access_token: TOKENS.accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: TOKENS.refreshToken,
      scope: 'requests:read suppliers:read',
    });
    expect(asked).toEqual([
      {
        code: 'axc_c',
        clientId: CLIENT,
        redirectUri: 'https://a.example/cb',
        codeVerifier: 'v'.repeat(43),
        resource: undefined,
      },
    ]);
  });

  it('rotates a refresh token', async () => {
    const { app, asked } = await oauthServer(true);
    const response = await app.inject(
      form('/v1/oauth/token', `grant_type=refresh_token&refresh_token=axr_r&client_id=${CLIENT}&scope=requests%3Aread`),
    );
    expect(response.statusCode).toBe(200);
    expect(asked).toEqual([{ refreshToken: 'axr_r', clientId: CLIENT, scope: 'requests:read', resource: undefined }]);
  });

  it.each([
    [
      'a field twice',
      `grant_type=refresh_token&refresh_token=a&refresh_token=b&client_id=${CLIENT}`,
      400,
      'invalid_request',
    ],
    ['no client', 'grant_type=refresh_token&refresh_token=a', 401, 'invalid_client'],
    ['another grant', `grant_type=password&client_id=${CLIENT}`, 400, 'unsupported_grant_type'],
    [
      'a code without its verifier',
      `grant_type=authorization_code&code=c&redirect_uri=r&client_id=${CLIENT}`,
      400,
      'invalid_request',
    ],
    ['a refresh without its token', `grant_type=refresh_token&client_id=${CLIENT}`, 400, 'invalid_request'],
  ])('refuses %s', async (_, body, status, error) => {
    const { app, asked } = await oauthServer(true);
    const response = await app.inject(form('/v1/oauth/token', body));
    expect(response.statusCode).toBe(status);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.json()).toEqual({ error, error_description: expect.any(String) as unknown });
    expect(asked).toEqual([]);
  });

  it('answers a grant refused as the use case says, and takes no JSON', async () => {
    const { app } = await oauthServer(true, {
      grant: { outcome: 'refused', status: 400, error: 'invalid_grant', description: 'No.' },
    });
    const response = await app.inject(
      form('/v1/oauth/token', `grant_type=refresh_token&refresh_token=a&client_id=${CLIENT}`),
    );
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: 'invalid_grant', error_description: 'No.' });
    expect((await app.inject(json('/v1/oauth/token', { grant_type: 'refresh_token' }))).statusCode).toBe(415);
  });

  it('takes a client’s write from any origin: OAuth clients send them from anywhere', async () => {
    const { app } = await oauthServer(true);
    const response = await app.inject({
      ...form('/v1/oauth/token', `grant_type=refresh_token&refresh_token=a&client_id=${CLIENT}`),
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://chatgpt.com' },
    });
    expect(response.statusCode).toBe(200);
  });
});

describe('the revocation endpoint (RFC 7009)', () => {
  it('takes either token and answers the same whatever it was', async () => {
    const { app, asked } = await oauthServer(true);
    const response = await app.inject(form('/v1/oauth/revoke', `token=axa_x&client_id=${CLIENT}`));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({});
    expect(asked).toEqual([{ token: 'axa_x', clientId: CLIENT }]);
    expect((await app.inject(form('/v1/oauth/revoke', 'client_id=x'))).json()).toMatchObject({
      error: 'invalid_request',
    });
    expect((await app.inject(form('/v1/oauth/revoke', 'token=a&token=b'))).json()).toMatchObject({
      error: 'invalid_request',
    });
  });
});

describe('SEC-OAUTH-13 the registration endpoint (RFC 7591)', () => {
  const REGISTERED: RegistrationAnswer = {
    outcome: 'registered',
    client: {
      clientId: CLIENT,
      name: 'ChatGPT',
      redirectUris: ['https://chatgpt.com/cb'],
      applicationType: 'web',
      grantTypes: ['authorization_code', 'refresh_token'],
      softwareId: null,
      softwareVersion: null,
      createdAt: new Date('2026-11-18T09:00:00Z'),
    },
  };

  it('registers a public client, ignoring metadata it never uses', async () => {
    const { app, asked } = await oauthServer(true, { register: REGISTERED });
    const response = await app.inject(
      json('/v1/oauth/register', {
        redirect_uris: ['https://chatgpt.com/cb'],
        client_name: 'ChatGPT',
        logo_uri: 'https://x',
      }),
    );
    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      client_id: CLIENT,
      client_id_issued_at: 1_794_992_400,
      client_name: 'ChatGPT',
      redirect_uris: ['https://chatgpt.com/cb'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      application_type: 'web',
    });
    expect(asked).toEqual([{ redirect_uris: ['https://chatgpt.com/cb'], client_name: 'ChatGPT' }]);
  });

  it('answers a registration refused with RFC 7591’s error, and the day’s cap as a rate limit', async () => {
    const invalid = await oauthServer(true, {
      register: { outcome: 'invalid', error: 'invalid_redirect_uri', description: 'Why.' },
    });
    const response = await invalid.app.inject(json('/v1/oauth/register', { redirect_uris: ['http://a.example/cb'] }));
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: 'invalid_redirect_uri', error_description: 'Why.' });
    const capped = await oauthServer(true, { register: { outcome: 'capped' } });
    expect((await capped.app.inject(json('/v1/oauth/register', {}))).statusCode).toBe(429);
  });

  it('holds each address to 10 registrations an hour', async () => {
    const { app } = await oauthServer(true, { register: REGISTERED });
    const answers: number[] = [];
    for (let sent = 0; sent < 11; sent += 1) {
      answers.push(
        (await app.inject(json('/v1/oauth/register', { redirect_uris: ['https://chatgpt.com/cb'] }))).statusCode,
      );
    }
    expect(answers).toEqual([...Array.from({ length: 10 }, () => 201), 429]);
  });
});

describe('SEC-OAUTH-01 a connection’s access token, at the MCP endpoint alone', () => {
  const keys = { check: () => Promise.resolve({ outcome: 'refused' as const }) };
  const connections = { check: () => Promise.resolve({ outcome: 'accepted' as const, key: ACCEPTED }) };

  it('is checked as a connection on the MCP endpoint, and refused anywhere else before any lookup', async () => {
    const check = createCredentialCheck({ keys, connections, resource: capabilities.resource, logger: testLogger() });
    expect(await check(ACCESS_TEXT, FLOW, true)).toEqual({ outcome: 'accepted', key: ACCEPTED });
    expect(await check(ACCESS_TEXT, FLOW, false)).toEqual({ outcome: 'refused' });
    expect(await check('axk_x', FLOW, true)).toEqual({ outcome: 'refused' });
    const off = createCredentialCheck({
      keys,
      connections: undefined,
      resource: capabilities.resource,
      logger: testLogger(),
    });
    expect(await off(ACCESS_TEXT, FLOW, true)).toEqual({ outcome: 'refused' });
  });

  it('is the same 401 as any key refused on an agent’s REST route', async () => {
    const app = await routeServer({
      oauthOn: true,
      checkAgentKey: createCredentialCheck({
        keys,
        connections,
        resource: capabilities.resource,
        logger: testLogger(),
      }),
    });
    const response = await app.inject({
      method: 'GET',
      url: '/v1/agent',
      headers: { authorization: `Bearer ${ACCESS_TEXT}` },
    });
    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe('Bearer realm="Agent X", error="invalid_token"');
  });
});

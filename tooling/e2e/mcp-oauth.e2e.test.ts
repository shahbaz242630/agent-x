// SEC-OAUTH-01, -02, -05, -07, -10, -12, -13 end to end (6E3b): a real MCP
// client connects to the compose stack's API by OAuth, as claude.ai or
// ChatGPT would. The official MCP TypeScript SDK's own OAuth client
// (@modelcontextprotocol/client, the canaries' pin) discovers the server from
// the MCP endpoint's 401, registers itself (RFC 7591) and builds the
// authorization request with PKCE; a real person, signed in through the login
// service in a real Chrome, consents through the consent API as the console's
// /connect page does, steps up and confirms; the SDK exchanges the code,
// lists the tools, refreshes its tokens when its access token is refused, and
// revokes its connection (RFC 7009), after which its token is a 401.
//
// The person is a developer of a new organisation, connecting an agent they
// own: a developer steps up with their authenticator app (an admin would need
// a passkey, which the tamper pass covers). The browser never loads the
// console's page: the authorize request's flow cookie is carried by hand, as
// the browser that opened the flow would carry it.
//
// 6E3c: a device with no browser (RFC 8628), driven by hand as the SDK has no
// device flow: it registers, asks for its codes and polls; the person types
// its user code (the console's /device lookup), consents and steps up as
// above; the device's next poll gets its pair, which lists the tools.
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';

import {
  Client,
  type OAuthClientInformationMixed,
  type OAuthClientMetadata,
  type OAuthClientProvider,
  type OAuthTokens,
  StreamableHTTPClientTransport,
  UnauthorizedError,
} from '@modelcontextprotocol/client';
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { addAgent } from '../../packages/core/src/modules/agents/index.ts';
import { withSignedStates } from '../../packages/core/src/modules/audit/index.ts';
import {
  addMembership,
  createSessions,
  createStepUpChallenges,
  userForSubject,
} from '../../packages/core/src/modules/identity/index.ts';
import { createOrganization } from '../../packages/core/src/modules/organizations/index.ts';
import { uuidV7Ids } from '../../packages/core/src/shared-kernel/index.ts';
import { createDatabase } from '../../packages/platform/src/db/index.ts';
import { API_PURPOSES, loadKeys, OPERATOR_ONLY } from '../../packages/platform/src/keys/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { APP_KEYS } from '../../deploy/compose/prepare.ts';
import { API_ORIGIN, localLogin, SECRETS_DIR } from './compose.ts';
import { loginDriver, where } from './login-pages.ts';

const { password, users } = inject('e2e');
const RETURN_TO = '/mcp-oauth-signed-in';
const person = loginDriver({ password, callback: new RegExp(`^${API_ORIGIN.replaceAll('.', '[.]')}${RETURN_TO}$`) });
const MCP_URL = new URL(`${API_ORIGIN}/v1/mcp`);
/** An app on the person's own computer: a loopback address, any port (RFC 8252); nothing listens on it here. */
const REDIRECT = 'http://127.0.0.1:53682/callback';
const SCOPES = ['requests:read', 'suppliers:read'] as const;
const SESSION = '__Host-agentx-session';
const FLOW_COOKIE = '__Host-agentx-connect';

const database = createDatabase<MandateWorldTables>(
  {
    host: '127.0.0.1',
    port: 56541,
    database: 'agentx',
    user: 'agentx_app',
    password: localLogin('AGENTX_LOCAL_DB_APP_PASSWORD'),
    tls: 'disable',
    applicationName: 'agentx-mcp-oauth-e2e',
  },
  testLogger(),
);
/** The API's keys, as its process holds them, so the stack believes what this file signs. */
const keys = loadKeys({ directory: path.join(SECRETS_DIR, APP_KEYS), current: {} }, API_PURPOSES, OPERATOR_ONLY);
const quiet = () => ({ keys, ids: uuidV7Ids, logger: testLogger() });
const OPERATOR = { type: 'system' as const, id: 'mcp-oauth-e2e' };
const PASSKEY = ['pwd', 'user', 'mfa'] as const;

/**
 * The SDK's client side of OAuth, kept in memory, as a desktop app keeps it in its own store: the registration, the
 * tokens, the PKCE verifier, and the address it would open the person's browser at.
 */
class MemoryProvider implements OAuthClientProvider {
  information: OAuthClientInformationMixed | undefined;
  stored: OAuthTokens | undefined;
  verifier = '';
  opened: URL | undefined;

  get redirectUrl(): string {
    return REDIRECT;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: 'Agent X e2e client',
      redirect_uris: [REDIRECT],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: SCOPES.join(' '),
    };
  }

  clientInformation() {
    return this.information;
  }

  saveClientInformation(information: OAuthClientInformationMixed) {
    this.information = information;
  }

  tokens() {
    return this.stored;
  }

  saveTokens(tokens: OAuthTokens) {
    this.stored = tokens;
  }

  redirectToAuthorization(url: URL) {
    this.opened = url;
  }

  saveCodeVerifier(verifier: string) {
    this.verifier = verifier;
  }

  codeVerifier() {
    return this.verifier;
  }
}

let browser: Browser | undefined;
let context: BrowserContext;
let page: Page;
let org: string;
let agentId: string;
/** The developer's membership, which an admin removes in the last case. */
let membershipId: string;

/** The person's live session cookie: a step-up gives the session a new one. */
async function sessionCookie(): Promise<string> {
  const cookie = (await context.cookies(API_ORIGIN)).find((one) => one.name === SESSION);
  if (cookie === undefined) throw new Error('the person is not signed in');
  return cookie.value;
}

/** A write of the consent API's, as the console sends it: the session, the flow's cookie, the organisation. */
async function consentWrite(url: string, flowCookie: string, body: unknown): Promise<Response> {
  return fetch(`${API_ORIGIN}${url}`, {
    method: 'POST',
    headers: {
      cookie: `${SESSION}=${await sessionCookie()}; ${FLOW_COOKIE}=${flowCookie}`,
      'agentx-organization': org,
      origin: API_ORIGIN,
      'idempotency-key': randomUUID(),
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

/** An MCP client of the SDK's, connected with `provider`. */
async function connected(provider: MemoryProvider): Promise<Client> {
  const client = new Client({ name: 'agentx-e2e', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(MCP_URL, { authProvider: provider }));
  return client;
}

/** A tools/list sent with this access token alone, by hand: its HTTP status. */
async function toolsListWith(accessToken: string): Promise<number> {
  const answer = await fetch(MCP_URL, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-06-18',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  });
  return answer.status;
}

/**
 * The SDK's discovery, registration and authorization request, then the person's consent with step-up, as the
 * console's /connect page sends it: the address the browser is sent back to, with the code, and the connection made.
 */
async function authorised(provider: MemoryProvider): Promise<{ back: URL; connection: { keyId: string } }> {
  // Discovery from the MCP endpoint's 401, registration (RFC 7591) and the authorization request, by the SDK.
  await expect(connected(provider)).rejects.toBeInstanceOf(UnauthorizedError);
  expect(provider.information?.client_id).toMatch(/^axcl_[0-9a-f]{32}$/);
  const authorization = provider.opened;
  if (authorization === undefined) throw new Error('the SDK opened no authorization request');
  expect(authorization.origin + authorization.pathname).toBe(`${API_ORIGIN}/v1/oauth/authorize`);
  expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
  expect(authorization.searchParams.get('resource')).toBe(MCP_URL.href);

  // The person's browser opens it: the API keeps the flow, sets its cookie and sends the browser to /connect.
  const opened = await fetch(authorization, { redirect: 'manual' });
  expect(opened.status).toBe(302);
  const connect = new URL(opened.headers.get('location') ?? '', API_ORIGIN);
  expect(connect.pathname).toBe('/connect');
  const flowId = connect.searchParams.get('request') ?? '';
  const flowCookie = opened.headers
    .getSetCookie()
    .map((cookie) => cookie.split(';')[0] ?? '')
    .find((cookie) => cookie.startsWith(`${FLOW_COOKIE}=`))
    ?.slice(FLOW_COOKIE.length + 1);
  if (flowCookie === undefined) throw new Error('the authorize request set no flow cookie');

  // What the consent page shows: the client by what it says it is, and where it sends the person (bold).
  const shown = await fetch(`${API_ORIGIN}/v1/oauth/requests/${flowId}`, {
    headers: { cookie: `${SESSION}=${await sessionCookie()}; ${FLOW_COOKIE}=${flowCookie}` },
  });
  expect(shown.status).toBe(200);
  expect(await shown.json()).toMatchObject({
    client: { name: 'Agent X e2e client' },
    redirectHost: '127.0.0.1:53682',
    loopback: true,
    // The SDK asks for what the server's metadata offers; the person ticks fewer (SEC-OAUTH-08).
    scopesAsked: expect.arrayContaining([...SCOPES]) as unknown,
  });

  // SEC-OAUTH-10: the person allows it, signs in again, and confirms.
  const allowed = { agentId, scopes: [...SCOPES] };
  const asked = await consentWrite(`/v1/oauth/requests/${flowId}/consent`, flowCookie, allowed);
  expect(asked.status).toBe(202);
  const { stepUpChallengeId } = (await asked.json()) as { stepUpChallengeId: string };
  await page.goto(`${API_ORIGIN}/v1/auth/step-up?challenge=${stepUpChallengeId}&returnTo=${RETURN_TO}`);
  expect((await person.drive(page, users.oauth, [])).stoppedAt, where(page)).toBe('callback');
  const confirmed = await consentWrite(`/v1/oauth/requests/${flowId}/consent/confirm`, flowCookie, {
    ...allowed,
    stepUpChallengeId,
  });
  expect(confirmed.status).toBe(201);
  const { redirectTo, connection } = (await confirmed.json()) as {
    redirectTo: string;
    connection: { keyId: string };
  };
  const back = new URL(redirectTo);
  expect(back.origin + back.pathname).toBe(REDIRECT);
  // SEC-OAUTH-12: the issuer named on the answer.
  expect(back.searchParams.get('iss')).toBe(API_ORIGIN);
  return { back, connection };
}

beforeAll(async () => {
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  context = await browser.newContext();
  page = await context.newPage();
  await page.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=${RETURN_TO}`);
  expect((await person.drive(page, users.oauth, [])).stoppedAt, where(page)).toBe('callback');
  const session = await context.request.get(`${API_ORIGIN}/v1/auth/session`);
  expect(session.status()).toBe(200);
  const { userId } = (await session.json()) as { userId: string };

  // A new organisation, the person a developer of it, and an agent of theirs.
  org = uuidV7Ids.next();
  agentId = uuidV7Ids.next();
  membershipId = uuidV7Ids.next();
  const now = new Date();
  await withSignedStates(database, org, quiet(), async (tx, states) => {
    await createOrganization(tx, states, { id: org, name: 'OAuth e2e LLC', actor: OPERATOR });
    await addMembership(tx, states, {
      orgId: org,
      id: membershipId,
      userId,
      role: 'developer',
      joinedAt: now,
      actor: OPERATOR,
    });
    await addAgent(tx, states, {
      orgId: org,
      id: agentId,
      name: 'Claude connector',
      owner: membershipId,
      scopes: ['requests:read', 'requests:write', 'suppliers:read'],
      createdAt: now,
      actor: OPERATOR,
    });
  });
});

afterAll(async () => {
  await browser?.close();
  await database.destroy();
});

describe('SEC-OAUTH-01, -02, -05, -07, -10, -12, -13 a real MCP client connected by OAuth', () => {
  it('registers, is authorised by a person, lists the tools, refreshes, and is revoked', async () => {
    const provider = new MemoryProvider();

    const { back, connection } = await authorised(provider);

    // The SDK exchanges the code with its PKCE verifier (SEC-OAUTH-02), then lists the tools with its access token.
    await new StreamableHTTPClientTransport(MCP_URL, { authProvider: provider }).finishAuth(back.searchParams);
    const first = provider.stored;
    expect(first?.access_token).toMatch(/^axa_/);
    expect(first?.refresh_token).toMatch(/^axr_/);
    const client = await connected(provider);
    const { tools } = await client.listTools();
    expect(tools.map(({ name }) => name)).toContain('get_agent');

    // SEC-OAUTH-05: its access token refused, the SDK refreshes, and the rotated pair works (a reuse is connections.db's).
    if (first === undefined) throw new Error('no tokens were issued');
    provider.saveTokens({ ...first, access_token: `axa_${'0'.repeat(32)}_${'0'.repeat(32)}_${'x'.repeat(43)}` });
    expect((await client.listTools()).tools).toHaveLength(tools.length);
    const second = provider.stored;
    expect(second?.refresh_token).toMatch(/^axr_/);
    expect(second?.refresh_token).not.toBe(first.refresh_token);
    await client.close();

    // The agent's page lists the connection, as its member sees it.
    const listed = await fetch(`${API_ORIGIN}/v1/agents/${agentId}/connections`, {
      headers: { cookie: `${SESSION}=${await sessionCookie()}`, 'agentx-organization': org },
    });
    expect(listed.status).toBe(200);
    expect(await listed.json()).toMatchObject({
      connections: [
        {
          keyId: connection.keyId,
          clientId: provider.information?.client_id,
          clientName: 'Agent X e2e client',
          redirectHost: '127.0.0.1:53682',
          via: 'code',
          scopes: [...SCOPES],
          status: 'ACTIVE',
        },
      ],
    });

    // SEC-OAUTH-07: the app revokes its connection (RFC 7009); its access token is then a 401 at once.
    const accessToken = second?.access_token ?? '';
    expect(await toolsListWith(accessToken)).toBe(200);
    const revoked = await fetch(`${API_ORIGIN}/v1/oauth/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: second?.refresh_token ?? '',
        client_id: provider.information?.client_id ?? '',
      }),
    });
    expect(revoked.status).toBe(200);
    expect(await toolsListWith(accessToken)).toBe(401);
  });
  it('6E3c a device connects by its user code: pending until the person allows it, then its pair', async () => {
    const form = (url: string, fields: Record<string, string>) =>
      fetch(`${API_ORIGIN}${url}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(fields),
      });
    const registered = await fetch(`${API_ORIGIN}/v1/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Agent X e2e device',
        redirect_uris: [REDIRECT],
        grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
      }),
    });
    expect(registered.status).toBe(201);
    const { client_id: clientId } = (await registered.json()) as { client_id: string };
    const codes = await form('/v1/oauth/device_authorization', { client_id: clientId, scope: SCOPES.join(' ') });
    expect(codes.status).toBe(200);
    const given = (await codes.json()) as {
      device_code: string;
      user_code: string;
      verification_uri: string;
      interval: number;
    };
    expect(given.verification_uri).toBe(`${API_ORIGIN}/device`);
    const poll = () =>
      form('/v1/oauth/token', {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: given.device_code,
        client_id: clientId,
      });
    expect(await (await poll()).json()).toMatchObject({ error: 'authorization_pending' });

    // The person types the code on /device: the request becomes this browser's, by the flow cookie set.
    const found = await fetch(`${API_ORIGIN}/v1/oauth/device/lookup`, {
      method: 'POST',
      headers: {
        cookie: `${SESSION}=${await sessionCookie()}`,
        origin: API_ORIGIN,
        'idempotency-key': randomUUID(),
        'content-type': 'application/json',
      },
      body: JSON.stringify({ userCode: given.user_code.toLowerCase() }),
    });
    expect(found.status).toBe(200);
    const { requestId } = (await found.json()) as { requestId: string };
    const flowCookie = found.headers
      .getSetCookie()
      .map((cookie) => cookie.split(';')[0] ?? '')
      .find((cookie) => cookie.startsWith(`${FLOW_COOKIE}=`))
      ?.slice(FLOW_COOKIE.length + 1);
    if (flowCookie === undefined) throw new Error('the lookup set no flow cookie');
    const shown = await fetch(`${API_ORIGIN}/v1/oauth/requests/${requestId}`, {
      headers: { cookie: `${SESSION}=${await sessionCookie()}; ${FLOW_COOKIE}=${flowCookie}` },
    });
    expect(await shown.json()).toMatchObject({ via: 'device', redirectHost: null, client: { id: clientId } });

    const allowed = { agentId, scopes: [...SCOPES] };
    const asked = await consentWrite(`/v1/oauth/requests/${requestId}/consent`, flowCookie, allowed);
    expect(asked.status).toBe(202);
    const { stepUpChallengeId } = (await asked.json()) as { stepUpChallengeId: string };
    await page.goto(`${API_ORIGIN}/v1/auth/step-up?challenge=${stepUpChallengeId}&returnTo=${RETURN_TO}`);
    expect((await person.drive(page, users.oauth, [])).stoppedAt, where(page)).toBe('callback');
    const confirmed = await consentWrite(`/v1/oauth/requests/${requestId}/consent/confirm`, flowCookie, {
      ...allowed,
      stepUpChallengeId,
    });
    expect(confirmed.status).toBe(201);
    expect(await confirmed.json()).toMatchObject({ redirectTo: null, connection: { via: 'device' } });

    // The device's next poll, after its interval, gets its pair; a poll after it, nothing more.
    await new Promise((resolve) => setTimeout(resolve, given.interval * 1000));
    const tokens = await poll();
    expect(tokens.status).toBe(200);
    const { access_token: accessToken } = (await tokens.json()) as { access_token: string };
    expect(accessToken).toMatch(/^axa_/);
    expect(await toolsListWith(accessToken)).toBe(200);
    expect(await (await poll()).json()).toMatchObject({ error: 'invalid_grant' });
  });

  it('M40: removing the member who made a connection revokes it: its access token is a 401 at once', async () => {
    const provider = new MemoryProvider();
    const { back } = await authorised(provider);
    await new StreamableHTTPClientTransport(MCP_URL, { authProvider: provider }).finishAuth(back.searchParams);
    const accessToken = provider.stored?.access_token ?? '';
    expect(await toolsListWith(accessToken)).toBe(200);

    // An admin of the organisation, signed in with a passkey, removes the developer, signing in again for it. Their
    // step-up's evidence is recorded as the API's step-up return records it: the passkey sign-in itself is the tamper
    // pass's (a real WebAuthn key), not this file's.
    const clock = { now: () => new Date() };
    const adminUser = await userForSubject(
      database,
      { issuer: 'https://auth.example.test', subject: `mcp-oauth-admin-${randomUUID()}` },
      { ids: uuidV7Ids, clock, keys, logger: testLogger() },
    );
    const opened = await createSessions({
      ids: uuidV7Ids,
      clock,
      timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
      keys,
      logger: testLogger(),
    }).open(database, adminUser, { idpSessionId: 'V1_1', authTime: new Date(), amr: [...PASSKEY] });
    await withSignedStates(database, org, quiet(), (tx, states) =>
      addMembership(tx, states, {
        orgId: org,
        id: uuidV7Ids.next(),
        userId: adminUser,
        role: 'admin',
        joinedAt: new Date(),
        actor: OPERATOR,
      }),
    );
    const asAdmin = (path: string, body: unknown) =>
      fetch(`${API_ORIGIN}/v1/members/${membershipId}${path}`, {
        method: 'POST',
        headers: {
          cookie: `${SESSION}=${opened.cookie}`,
          'agentx-organization': org,
          origin: API_ORIGIN,
          'idempotency-key': randomUUID(),
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      });
    const asked = await asAdmin('/deactivate', {});
    expect(asked.status).toBe(202);
    const { stepUpChallengeId } = (await asked.json()) as { stepUpChallengeId: string };
    expect(
      await createStepUpChallenges({ ids: uuidV7Ids, clock, keys, logger: testLogger() }).recordEvidence(
        database,
        stepUpChallengeId,
        opened.sessionId,
        {
          authTime: new Date(),
          amr: [...PASSKEY],
          idpSessionId: 'V1_2',
          idTokenHash: createHash('sha256').update('an ID token').digest(),
        },
      ),
    ).toBe(true);
    const removed = await asAdmin('/deactivate/confirm', { stepUpChallengeId });
    expect(removed.status).toBe(200);
    expect(await removed.json()).toMatchObject({ member: { status: 'DEACTIVATED' } });

    expect(await toolsListWith(accessToken)).toBe(401);
  });
});

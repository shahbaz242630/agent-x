// 6E3a (SEC-OAUTH-10): the consent page's addresses over HTTP, with a
// stand-in use case: what the browser that opened a flow is shown, and each
// write's answer, the flow's cookie passed on as the browser sent it. Who
// reaches them is the access hook's (role-matrix.test.ts); what the use case
// does in the database is oauth-connections.db.test.ts.
import type { MembershipCheck } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { ConnectionConsents, ConsentWrite, RequestShown } from './connection-consents.ts';
import { liveSession } from './live-session.helper.test.ts';
import { OAUTH_COOKIE } from './oauth-wire.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

afterEach(closeServers);

const FLOW = '0199a0f0-0000-7000-8000-0000000e3b01';
const AGENT = '0199a0f0-0000-7000-8000-0000000e3b02';
const KEY = '0199a0f0-0000-7000-8000-0000000e3b03';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000e3b04';
const BROWSER = 'B'.repeat(43);
const LIVE = liveSession('2026-09-28T09:00:00.000Z', { endless: true });
const ADMIN = {
  outcome: 'active',
  id: '0199a0f0-0000-7000-8000-0000000e3b05',
  role: 'admin',
} as const satisfies MembershipCheck;

const SHOWN: RequestShown = {
  id: FLOW,
  client: { id: 'axcl_0123456789abcdef0123456789abcdef', name: 'ChatGPT' },
  redirectUri: 'https://chatgpt.com/cb',
  redirectHost: 'chatgpt.com',
  loopback: false,
  scopesAsked: ['requests:read', 'suppliers:read'],
  resource: `${PUBLIC_ORIGIN}/v1/mcp`,
  endsAt: new Date('2026-09-28T09:15:00.000Z'),
};

/** A server whose consent use case answers `write` (or `shown`), and what it was called with. */
async function consentServer(write: ConsentWrite, shown: RequestShown | null = SHOWN) {
  const calls: unknown[] = [];
  const consents: ConnectionConsents = {
    request: (named) => {
      calls.push(named);
      return Promise.resolve(shown ?? undefined);
    },
    consent: (member, idempotent, named, asked) => {
      calls.push({ member, operation: idempotent.operation, named, asked });
      return Promise.resolve(write);
    },
    confirm: (member, idempotent, named, asked, challengeId) => {
      calls.push({ member, operation: idempotent.operation, named, asked, challengeId });
      return Promise.resolve(write);
    },
    deny: (member, idempotent, named) => {
      calls.push({ member, operation: idempotent.operation, named });
      return Promise.resolve(write);
    },
  };
  const app = await routeServer({
    oauthOn: true,
    live: LIVE,
    member: ADMIN,
    oauth: {
      authorizing: {
        authorize: () => Promise.reject(new Error('no')),
        register: () => Promise.reject(new Error('no')),
      },
      grants: {
        exchangeCode: () => Promise.reject(new Error('no')),
        refresh: () => Promise.reject(new Error('no')),
        revoke: () => Promise.reject(new Error('no')),
      },
      consents,
      clock: { now: () => new Date('2026-09-28T09:00:00.000Z') },
    },
  });
  return { app, calls };
}

const cookies = `${SESSION_COOKIE}=${COOKIE}; ${OAUTH_COOKIE}=${BROWSER}`;

const write = (path: string, body: unknown): InjectOptions => ({
  method: 'POST',
  url: `/v1/oauth/requests/${FLOW}${path}`,
  headers: {
    cookie: cookies,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': 'k-1',
    'content-type': 'application/json',
  },
  payload: JSON.stringify(body),
});

const MEMBER = { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId };
const NAMED = { flowId: FLOW, cookie: BROWSER };
const ASKED = { agentId: AGENT, scopes: ['requests:read'] };

describe('the request, as its browser is shown it', () => {
  it('shows the client by what it says it is, and where it sends the person', async () => {
    const { app, calls } = await consentServer({ outcome: 'conflict' });
    const response = await app.inject({
      method: 'GET',
      url: `/v1/oauth/requests/${FLOW}`,
      headers: { cookie: cookies },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ...SHOWN, endsAt: '2026-09-28T09:15:00.000Z' });
    expect(calls).toEqual([NAMED]);
  });

  it('answers 404 for a flow its browser did not open, or one decided or ended', async () => {
    const { app } = await consentServer({ outcome: 'conflict' }, null);
    const response = await app.inject({
      method: 'GET',
      url: `/v1/oauth/requests/${FLOW}`,
      headers: { cookie: cookies },
    });
    expect(response.statusCode).toBe(404);
  });
});

describe('the consent and its confirm', () => {
  it('asks for a step-up for the agent and scopes', async () => {
    const { app, calls } = await consentServer({ outcome: 'asked', stepUpChallengeId: CHALLENGE });
    const response = await app.inject(write('/consent', ASKED));
    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(calls).toEqual([{ member: MEMBER, operation: 'connections.make', named: NAMED, asked: ASKED }]);
  });

  it('answers the confirm with where the browser goes, this once', async () => {
    const connected: ConsentWrite = {
      outcome: 'connected',
      redirectTo: 'https://chatgpt.com/cb?code=axc_x&state=s&iss=https%3A%2F%2Fapp.agentx.example',
      connection: {
        keyId: KEY,
        agentId: AGENT,
        clientId: SHOWN.client.id,
        scopes: ['requests:read'],
        expiresAt: new Date('2026-12-27T09:00:00.000Z'),
      },
    };
    const { app, calls } = await consentServer(connected);
    const response = await app.inject(write('/consent/confirm', { ...ASKED, stepUpChallengeId: CHALLENGE }));
    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      redirectTo: connected.redirectTo,
      connection: { ...connected.connection, expiresAt: '2026-12-27T09:00:00.000Z' },
    });
    expect(calls).toEqual([
      { member: MEMBER, operation: 'connections.make.confirm', named: NAMED, asked: ASKED, challengeId: CHALLENGE },
    ]);
  });

  it('refuses a body with no scope or a scope there is not, before the use case', async () => {
    const { app, calls } = await consentServer({ outcome: 'asked', stepUpChallengeId: CHALLENGE });
    expect((await app.inject(write('/consent', { agentId: AGENT, scopes: [] }))).statusCode).toBe(400);
    expect((await app.inject(write('/consent', { agentId: AGENT, scopes: ['openid'] }))).statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'CONNECTIONS_FULL' } as const, 409, 'CONNECTIONS_FULL'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
  ])('answers a refusal as its code says', async (answer, status, code) => {
    const { app } = await consentServer(answer);
    const response = await app.inject(write('/consent', ASKED));
    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });
});

describe('the deny', () => {
  it('answers where the browser goes, the client told no', async () => {
    const redirectTo = 'https://chatgpt.com/cb?error=access_denied&state=s';
    const { app, calls } = await consentServer({ outcome: 'denied', redirectTo });
    const response = await app.inject(write('/deny', {}));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ redirectTo });
    expect(calls).toEqual([{ member: MEMBER, operation: 'connections.deny', named: NAMED }]);
  });
});

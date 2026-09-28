// C1-2: the agents' routes, answering a member with each outcome of the
// registration and the reads. Who reaches them is the access hook's
// (role-matrix.test.ts); what the use case does in the database is
// agent-registering.db.test.ts.
import type { AgentKeyRecord, AgentShown } from '@agentx/core/modules/agents';
import type { LiveSession, MembershipCheck, Role, SignIn } from '@agentx/core/modules/identity';
import type { IdempotentRequest } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type {
  AgentAsked,
  AgentFound,
  AgentRegistrations,
  AgentsListed,
  RegisteringMember,
  RegistrationWrite,
} from './agent-registering.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY_ID = '0199a0f0-0000-7000-8000-0000000000b1';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c6';
const OWNER = '0199a0f0-0000-7000-8000-000000000033';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-28T09:00:00.000Z'),
  amr: ['pwd', 'otp', 'mfa'],
  createdAt: new Date('2026-09-28T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-28T09:10:00.000Z'),
  endsAt: new Date('2099-09-28T21:00:05.000Z'),
  idleEndsAt: new Date('2099-09-28T09:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const MEMBER: MembershipCheck = { outcome: 'active', id: OWNER, role: 'developer' };
const REGISTERING: RegisteringMember = { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId };

const AGENT: AgentShown = {
  id: AGENT_ID,
  name: 'Purchasing bot',
  owner: OWNER,
  status: 'ACTIVE',
  scopes: ['requests:read', 'requests:write'],
  createdAt: new Date('2026-09-28T09:15:00.000Z'),
};

const KEY: AgentKeyRecord = {
  id: KEY_ID,
  agentId: AGENT_ID,
  status: 'ACTIVE',
  scopes: ['requests:read', 'requests:write'],
  secretMac: Buffer.alloc(32, 0x5a),
  secretKeyVersion: 1,
  expiresAt: new Date('2026-12-27T09:15:00.000Z'),
};

const THE_KEY = `axk_${KEY_ID.replaceAll('-', '')}_${'s'.repeat(43)}`;

/** The agent and its key as the routes answer them: never the key's MAC or version. */
const AGENT_ANSWERED = {
  agent: {
    id: AGENT_ID,
    name: 'Purchasing bot',
    owner: OWNER,
    status: 'ACTIVE',
    scopes: ['requests:read', 'requests:write'],
    createdAt: '2026-09-28T09:15:00.000Z',
  },
  keys: [
    {
      id: KEY_ID,
      status: 'ACTIVE',
      scopes: ['requests:read', 'requests:write'],
      expiresAt: '2026-12-27T09:15:00.000Z',
    },
  ],
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface Call {
  readonly kind: 'ask' | 'confirm' | 'list' | 'show';
  readonly member?: RegisteringMember;
  readonly keyed?: IdempotentRequest;
  readonly asked?: AgentAsked;
  readonly subject?: unknown;
}

interface Answers {
  readonly write?: RegistrationWrite | Error;
  readonly listed?: AgentsListed;
  readonly found?: AgentFound;
}

/** A server whose use case answers `answers`, the caller holding `role`. */
async function withAgents(answers: Answers, role: Role = 'developer') {
  const calls: Call[] = [];
  const written = () =>
    answers.write instanceof Error
      ? Promise.reject(answers.write)
      : Promise.resolve(answers.write ?? { outcome: 'busy' as const });
  const registrations: AgentRegistrations = {
    ask: (member, keyed, asked) => {
      calls.push({ kind: 'ask', member, keyed, asked });
      return written();
    },
    confirm: (member, keyed, asked, challengeId) => {
      calls.push({ kind: 'confirm', member, keyed, asked, subject: challengeId });
      return written();
    },
    list: (orgId, page) => {
      calls.push({ kind: 'list', subject: { orgId, ...page } });
      return Promise.resolve(answers.listed ?? { outcome: 'listed', agents: [], next: null });
    },
    show: (orgId, agentId) => {
      calls.push({ kind: 'show', subject: { orgId, agentId } });
      return Promise.resolve(answers.found ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
  };
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: 1000,
      rateLimitPerUserPerMinute: 1000,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const app = await buildServer({
    config,
    logger: createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', ...config },
      destination: new LogCapture(),
    }),
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: { service: SIGN_IN, sessionSeconds: 43_200 },
    restrictedUntil: () => Promise.resolve(undefined),
    findMembership: (orgId) =>
      Promise.resolve(orgId.toLowerCase() === ORG ? { ...MEMBER, role } : ({ outcome: 'none' } as const)),
    agentRegistrations: registrations,
  });
  servers.push(app);
  await app.ready();
  return { app, calls };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const post = (path: string, payload: unknown, key = 'k-1'): InjectOptions => ({
  method: 'POST',
  url: `/v1/agents${path}`,
  headers: { ...headers, 'idempotency-key': key, 'content-type': 'application/json' },
  payload: JSON.stringify(payload),
});

const ASKED = { name: 'Purchasing bot', scopes: ['requests:write', 'requests:read'] };

describe('POST /v1/agents asks a step-up to register an agent (C1-2)', () => {
  it('answers 202 with the step-up, passing the member, the key and what was asked', async () => {
    const { app, calls } = await withAgents({ write: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });

    const response = await app.inject(post('', ASKED));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(calls).toEqual([
      {
        kind: 'ask',
        member: REGISTERING,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'agents.register', key: 'k-1' }) as unknown,
        asked: ASKED,
      },
    ]);
  });

  it.each<[string, unknown]>([
    ['no name', { scopes: ['requests:read'] }],
    ['an empty name', { name: '', scopes: ['requests:read'] }],
    ['a name with a control character', { name: 'Bot\u0007', scopes: ['requests:read'] }],
    ['a name with a space at its end', { name: 'Bot ', scopes: ['requests:read'] }],
    ['a name of 101 characters', { name: 'b'.repeat(101), scopes: ['requests:read'] }],
    ['no scopes', { name: 'Bot', scopes: [] }],
    ['a scope there is not', { name: 'Bot', scopes: ['requests:delete'] }],
    ['a scope twice', { name: 'Bot', scopes: ['requests:read', 'requests:read'] }],
    ['a field it does not know', { name: 'Bot', scopes: ['requests:read'], owner: OWNER }],
  ])('refuses %s with 400, never reaching the use case', async (_, body) => {
    const { app, calls } = await withAgents({ write: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });

    const response = await app.inject(post('', body));

    expect(response.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it('takes a name of 100 characters sent as the longest JSON can write them: the body limit fits it (B8-3)', async () => {
    const { app } = await withAgents({ write: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });
    // 100 characters outside the basic plane, each written as two escapes: 12 bytes each.
    const name = '\u{1D400}'.repeat(100);
    const escaped = `{"name":"${'\\ud835\\udc00'.repeat(100)}","scopes":["requests:read","requests:write","sources:read","suppliers:read"]}`;
    expect(JSON.parse(escaped)).toMatchObject({ name });

    const response = await app.inject({ ...post('', {}), payload: escaped });

    expect(response.statusCode).toBe(202);
  });

  it.each<[RegistrationWrite, number, string]>([
    [{ outcome: 'refused', status: 403, code: 'FORBIDDEN' }, 403, 'FORBIDDEN'],
    [{ outcome: 'refused', status: 401, code: 'UNAUTHENTICATED' }, 401, 'UNAUTHENTICATED'],
    [{ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' }, 503, 'INTEGRITY_FAILED'],
    [{ outcome: 'conflict' }, 409, 'IDEMPOTENCY_KEY_REUSED'],
  ])('answers a refusal as its status and code: %j', async (write, status, code) => {
    const { app } = await withAgents({ write });

    const response = await app.inject(post('', ASKED));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });
});

describe('POST /v1/agents/confirm registers the agent once signed in again (C1-2)', () => {
  it('answers 201 with the agent, its key’s record and the key, passing the step-up apart from what was asked', async () => {
    const { app, calls } = await withAgents({
      write: { outcome: 'registered', agent: { agent: AGENT, keys: [KEY] }, key: THE_KEY },
    });

    const response = await app.inject(post('/confirm', { ...ASKED, stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({ ...AGENT_ANSWERED, key: THE_KEY });
    expect(response.body).not.toContain(KEY.secretMac.toString('hex'));
    expect(calls).toEqual([
      {
        kind: 'confirm',
        member: REGISTERING,
        keyed: expect.objectContaining({ operation: 'agents.register.confirm' }) as unknown,
        asked: ASKED,
        subject: CHALLENGE,
      },
    ]);
  });

  it('answers a retry with the key null', async () => {
    const { app } = await withAgents({
      write: { outcome: 'registered', agent: { agent: AGENT, keys: [KEY] }, key: null },
    });

    const response = await app.inject(post('/confirm', { ...ASKED, stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({ ...AGENT_ANSWERED, key: null });
  });

  it('refuses a confirm without the step-up’s ID with 400', async () => {
    const { app, calls } = await withAgents({ write: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });

    expect((await app.inject(post('/confirm', ASKED))).statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each<[RegistrationWrite, number, string]>([
    [{ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' }, 403, 'STEP_UP_FAILED'],
    [{ outcome: 'refused', status: 409, code: 'AGENT_ADDS_SPENT' }, 409, 'AGENT_ADDS_SPENT'],
    [{ outcome: 'busy' }, 409, 'IDEMPOTENCY_KEY_BUSY'],
  ])('answers a refusal as its status and code: %j', async (write, status, code) => {
    const { app } = await withAgents({ write });

    const response = await app.inject(post('/confirm', { ...ASKED, stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('answers 500 when the use case fails, never an agent', async () => {
    const { app } = await withAgents({ write: new Error('the database went away') });

    const response = await app.inject(post('/confirm', { ...ASKED, stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(500);
  });
});

describe('GET /v1/agents and /v1/agents/:id read the organisation’s agents (C1-2)', () => {
  it('lists a page, asking the use case for the page named, 50 unless fewer are asked for', async () => {
    const { app, calls } = await withAgents(
      { listed: { outcome: 'listed', agents: [AGENT], next: AGENT_ID } },
      'viewer',
    );

    const first = await app.inject({ method: 'GET', url: '/v1/agents', headers });
    const next = await app.inject({ method: 'GET', url: `/v1/agents?after=${AGENT_ID}&limit=2`, headers });

    expect(first.statusCode).toBe(200);
    expect(first.json()).toEqual({ agents: [AGENT_ANSWERED.agent], next: AGENT_ID });
    expect(next.statusCode).toBe(200);
    expect(calls.map((call) => call.subject)).toEqual([
      { orgId: ORG, after: null, limit: 50 },
      { orgId: ORG, after: AGENT_ID, limit: 2 },
    ]);
  });

  it.each(['?limit=0', '?limit=51', '?limit=two', '?after=not-an-id', '?page=2'])(
    'refuses a query of %s with 400',
    async (query) => {
      const { app, calls } = await withAgents({});

      expect((await app.inject({ method: 'GET', url: `/v1/agents${query}`, headers })).statusCode).toBe(400);
      expect(calls).toEqual([]);
    },
  );

  it('shows an agent with its keys, never a key’s MAC', async () => {
    const { app, calls } = await withAgents({ found: { outcome: 'found', agent: AGENT, keys: [KEY] } }, 'approver');

    const response = await app.inject({ method: 'GET', url: `/v1/agents/${AGENT_ID}`, headers });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(AGENT_ANSWERED);
    expect(response.body).not.toContain(KEY.secretMac.toString('hex'));
    expect(calls).toEqual([{ kind: 'show', subject: { orgId: ORG, agentId: AGENT_ID } }]);
  });

  it('answers 404 for an agent the organisation doesn’t have, and 503 for one tampered with', async () => {
    const missing = await withAgents({ found: { outcome: 'refused', status: 404, code: 'NOT_FOUND' } });
    const tampered = await withAgents({ listed: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });

    expect((await missing.app.inject({ method: 'GET', url: `/v1/agents/${AGENT_ID}`, headers })).statusCode).toBe(404);
    expect((await tampered.app.inject({ method: 'GET', url: '/v1/agents', headers })).json()).toMatchObject({
      error: { code: 'INTEGRITY_FAILED' },
    });
  });
});

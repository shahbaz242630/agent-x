// 6E3b (SEC-OAUTH-07, -10): an agent's MCP connections over HTTP, with a
// stand-in use case: the list as the console reads it, and the revocation's
// ask and confirm, each refusal answered as its status and code. Who reaches
// them is the access hook's (role-matrix.test.ts); what the use case does in
// the database is oauth-connections.db.test.ts.
import type { MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { KeyNamed } from './agent-key-changes.ts';
import type { ConnectionChanges, ConnectionChangeWrite, ConnectionShown } from './connection-changes.ts';
import { liveSession } from './live-session.helper.test.ts';
import type { Refused } from './refused.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

afterEach(closeServers);

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000e3b11';
const KEY_ID = '0199a0f0-0000-7000-8000-0000000e3b12';
const MADE_BY = '0199a0f0-0000-7000-8000-0000000e3b13';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000e3b14';
const LIVE = liveSession('2026-09-28T09:00:00.000Z', { endless: true });
const MEMBER = { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId };
const NAMED: KeyNamed = { agentId: AGENT_ID, keyId: KEY_ID };

const SHOWN: ConnectionShown = {
  keyId: KEY_ID,
  clientId: 'axcl_0123456789abcdef0123456789abcdef',
  clientName: 'ChatGPT',
  redirectHost: 'chatgpt.com',
  via: 'code',
  scopes: ['requests:read', 'suppliers:read'],
  madeBy: MADE_BY,
  createdAt: new Date('2026-09-28T09:00:00.000Z'),
  expiresAt: new Date('2026-12-27T09:00:00.000Z'),
  lastConnectedAt: new Date('2026-09-28T10:00:00.000Z'),
  status: 'ACTIVE',
};

const ANSWERED = {
  ...SHOWN,
  createdAt: '2026-09-28T09:00:00.000Z',
  expiresAt: '2026-12-27T09:00:00.000Z',
  lastConnectedAt: '2026-09-28T10:00:00.000Z',
};

interface Call {
  readonly kind: string;
  readonly subject: unknown;
  readonly keyed?: IdempotentRequest;
}

/** A server whose use case answers `listed` and `written`, as `role`, and what it was called with. */
async function connectionServer(
  { listed, written }: { listed?: readonly ConnectionShown[] | Refused; written?: ConnectionChangeWrite },
  role: Role = 'admin',
) {
  const calls: Call[] = [];
  const changes: ConnectionChanges = {
    list: (orgId, agentId) => {
      calls.push({ kind: 'list', subject: [orgId, agentId] });
      const answer = listed ?? [];
      return Promise.resolve('outcome' in answer ? answer : { connections: answer });
    },
    revoke: (member, keyed, named) => {
      calls.push({ kind: 'revoke', subject: [member, named], keyed });
      return Promise.resolve(written ?? { outcome: 'busy' });
    },
    revokeConfirm: (member, keyed, named, challengeId) => {
      calls.push({ kind: 'revokeConfirm', subject: [member, named, challengeId], keyed });
      return Promise.resolve(written ?? { outcome: 'busy' });
    },
  };
  const member = { outcome: 'active', id: MADE_BY, role } as const satisfies MembershipCheck;
  const app = await routeServer({ live: LIVE, member, connectionChanges: changes });
  return { app, calls };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const revocation = (path: string, payload?: unknown): InjectOptions => ({
  method: 'POST',
  url: `/v1/agents/${AGENT_ID}/connections/${KEY_ID}${path}`,
  headers: {
    ...headers,
    'idempotency-key': 'k-1',
    ...(payload !== undefined && { 'content-type': 'application/json' }),
  },
  ...(payload !== undefined && { payload: JSON.stringify(payload) }),
});

describe('GET /v1/agents/:id/connections', () => {
  it.each<Role>(['admin', 'approver', 'developer', 'viewer'])(
    'answers a %s the agent’s connections, never a token',
    async (role) => {
      const ended: ConnectionShown = {
        ...SHOWN,
        keyId: CHALLENGE,
        redirectHost: null,
        via: 'device',
        lastConnectedAt: null,
        status: 'REVOKED',
      };
      const { app, calls } = await connectionServer({ listed: [SHOWN, ended] }, role);

      const response = await app.inject({ method: 'GET', url: `/v1/agents/${AGENT_ID}/connections`, headers });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        connections: [
          ANSWERED,
          {
            ...ANSWERED,
            keyId: CHALLENGE,
            redirectHost: null,
            via: 'device',
            lastConnectedAt: null,
            status: 'REVOKED',
          },
        ],
      });
      expect(calls).toEqual([{ kind: 'list', subject: [ORG, AGENT_ID] }]);
    },
  );

  it.each<[Refused, number]>([
    [{ outcome: 'refused', status: 404, code: 'NOT_FOUND' }, 404],
    [{ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' }, 503],
  ])('answers a refusal as its status and code: %j', async (refusal, status) => {
    const { app } = await connectionServer({ listed: refusal });

    const response = await app.inject({ method: 'GET', url: `/v1/agents/${AGENT_ID}/connections`, headers });

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code: refusal.code } });
  });

  it('refuses an agent that isn’t an ID with 400, never reaching the use case', async () => {
    const { app, calls } = await connectionServer({});

    expect((await app.inject({ method: 'GET', url: '/v1/agents/not-an-id/connections', headers })).statusCode).toBe(
      400,
    );
    expect(calls).toEqual([]);
  });
});

describe('SEC-OAUTH-10 POST /v1/agents/:id/connections/:keyId/revoke, with its step-up', () => {
  it.each<Role>(['admin', 'developer'])('asks a %s for a step-up: 202 with it', async (role) => {
    const { app, calls } = await connectionServer(
      { written: { outcome: 'asked', stepUpChallengeId: CHALLENGE } },
      role,
    );

    const response = await app.inject(revocation('/revoke'));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(calls).toEqual([
      {
        kind: 'revoke',
        subject: [MEMBER, NAMED],
        keyed: expect.objectContaining({ orgId: ORG, operation: 'connections.revoke', key: 'k-1' }) as unknown,
      },
    ]);
  });

  it('revokes once stepped up: 200 with the agent’s connections, as the key revoke’s confirm takes it', async () => {
    const { app, calls } = await connectionServer({
      written: { outcome: 'revoked', connections: [{ ...SHOWN, status: 'REVOKED' }] },
    });

    const response = await app.inject(revocation('/revoke/confirm', { stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ connections: [{ ...ANSWERED, status: 'REVOKED' }] });
    expect(calls.map(({ kind, subject, keyed }) => [kind, subject, keyed?.operation])).toEqual([
      ['revokeConfirm', [MEMBER, NAMED, CHALLENGE], 'connections.revoke.confirm'],
    ]);
  });

  it.each<[Role, string, unknown]>([
    ['approver', '/revoke', undefined],
    ['viewer', '/revoke', undefined],
    ['approver', '/revoke/confirm', { stepUpChallengeId: CHALLENGE }],
    ['viewer', '/revoke/confirm', { stepUpChallengeId: CHALLENGE }],
  ])('refuses a %s at %s: 403, never reaching the use case', async (role, path, body) => {
    const { app, calls } = await connectionServer({ written: { outcome: 'busy' } }, role);

    expect((await app.inject(revocation(path, body))).statusCode).toBe(403);
    expect(calls).toEqual([]);
  });

  it.each<[string, InjectOptions]>([
    ['an ask with a body', revocation('/revoke', { reason: 'leaked' })],
    ['a confirm with no step-up', revocation('/revoke/confirm', {})],
    ['a confirm naming the step-up otherwise', revocation('/revoke/confirm', { stepUpId: CHALLENGE })],
    ['a confirm with a step-up that isn’t an ID', revocation('/revoke/confirm', { stepUpChallengeId: 'c-1' })],
    ['a key that isn’t an ID', { ...revocation('/revoke'), url: `/v1/agents/${AGENT_ID}/connections/k/revoke` }],
  ])('refuses %s with 400, never reaching the use case', async (_, request) => {
    const { app, calls } = await connectionServer({ written: { outcome: 'busy' } });

    expect((await app.inject(request)).statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each<[ConnectionChangeWrite, number, string]>([
    [{ outcome: 'refused', status: 409, code: 'CONNECTION_REVOKED' }, 409, 'CONNECTION_REVOKED'],
    [{ outcome: 'refused', status: 404, code: 'NOT_FOUND' }, 404, 'NOT_FOUND'],
    [{ outcome: 'refused', status: 403, code: 'FORBIDDEN' }, 403, 'FORBIDDEN'],
    [{ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' }, 403, 'STEP_UP_FAILED'],
    [{ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' }, 503, 'INTEGRITY_FAILED'],
    [{ outcome: 'conflict' }, 409, 'IDEMPOTENCY_KEY_REUSED'],
    [{ outcome: 'busy' }, 409, 'IDEMPOTENCY_KEY_BUSY'],
  ])('answers a refusal as its status and code: %j', async (written, status, code) => {
    const { app } = await connectionServer({ written });

    const response = await app.inject(revocation('/revoke/confirm', { stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });
});

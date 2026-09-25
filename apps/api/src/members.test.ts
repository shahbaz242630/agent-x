// B4-2b: GET /v1/members, the first route naming roles. Who reaches it is the
// access hook's (access-roles.test.ts, role-matrix.test.ts); here, what it
// answers a member with each outcome of the list. The list's own reading and
// verifying is the identity module's (memberships.db.test.ts).
import type { LiveSession, MembersList, MembershipCheck, SignIn } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { errorBody } from './errors.ts';
import type { ListMembers } from './members.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-24T09:00:00.000Z'),
  amr: ['pwd', 'otp', 'mfa'],
  createdAt: new Date('2026-09-24T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-24T09:10:00.000Z'),
  endsAt: new Date('2026-09-24T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-24T09:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const ACTIVE_VIEWER: MembershipCheck = {
  outcome: 'active',
  id: '0199a0f0-0000-7000-8000-000000000033',
  role: 'viewer',
};

const LISTED: MembersList = {
  outcome: 'listed',
  members: [
    {
      id: '0199a0f0-0000-7000-8000-000000000033',
      userId: LIVE.userId,
      role: 'viewer',
      status: 'ACTIVE',
      joinedAt: new Date('2026-09-25T09:00:00.123Z'),
    },
    {
      id: '0199a0f0-0000-7000-8000-000000000044',
      userId: '0199a0f0-0000-7000-8000-000000000055',
      role: 'admin',
      status: 'DEACTIVATED',
      joinedAt: new Date('2026-09-20T08:00:00.000Z'),
    },
  ],
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function withMembers(list: MembersList | Error, options: { listed?: boolean } = {}) {
  const asked: [orgId: string, correlationId: string][] = [];
  const listMembers: ListMembers = (orgId, correlationId) => {
    asked.push([orgId, correlationId]);
    return list instanceof Error ? Promise.reject(list) : Promise.resolve(list);
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
    findMembership: (orgId) =>
      Promise.resolve(orgId.toLowerCase() === ORG ? ACTIVE_VIEWER : ({ outcome: 'none' } as const)),
    ...((options.listed ?? true) && { listMembers }),
  });
  servers.push(app);
  await app.ready();
  return { app, asked };
}

const request = (org = ORG): InjectOptions => ({
  method: 'GET',
  url: '/v1/members',
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: org },
});

describe('GET /v1/members answers a member with their organisation’s members', () => {
  it('lists each member, deactivated ones included, for the organisation the request names, in lower case', async () => {
    const { app, asked } = await withMembers(LISTED);

    const response = await app.inject(request(ORG.toUpperCase()));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      members: [
        {
          id: '0199a0f0-0000-7000-8000-000000000033',
          userId: LIVE.userId,
          role: 'viewer',
          status: 'ACTIVE',
          joinedAt: '2026-09-25T09:00:00.123Z',
        },
        {
          id: '0199a0f0-0000-7000-8000-000000000044',
          userId: '0199a0f0-0000-7000-8000-000000000055',
          role: 'admin',
          status: 'DEACTIVATED',
          joinedAt: '2026-09-20T08:00:00.000Z',
        },
      ],
    });
    expect(asked).toEqual([[ORG, FIRST_ID]]);
  });

  it('withholds the whole list as 503 INTEGRITY_FAILED when a membership in it was tampered with', async () => {
    const { app } = await withMembers({ outcome: 'tampered', sign: 'seal' });

    const response = await app.inject(request());

    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual(errorBody('INTEGRITY_FAILED', FIRST_ID));
  });

  it('fails as INTERNAL_ERROR when the list can’t be read, or when no reader was given', async () => {
    for (const { app } of [
      await withMembers(new Error('the database is away')),
      await withMembers(LISTED, { listed: false }),
    ]) {
      const response = await app.inject(request());

      expect(response.statusCode).toBe(500);
      expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    }
  });

  it('asks nothing of the list for someone not a member there', async () => {
    const { app, asked } = await withMembers(LISTED);

    const response = await app.inject(request('0199a0f0-0000-7000-8000-00000000ffff'));

    expect(response.statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

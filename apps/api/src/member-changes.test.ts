// B4-5b: the routes that change a member's role or deactivate them,
// answering an admin with each outcome of the writes. Who reaches them is the
// access hook's (role-matrix.test.ts); what the writes do in the database is
// the identity module's membership-changes.db.test.ts.
import type {
  InvitingAdmin,
  LiveSession,
  MemberRecord,
  MembershipChange,
  MembershipChanges,
  MembershipChangeWrite,
  MembershipCheck,
  Role,
  SignIn,
} from '@agentx/core/modules/identity';
import type { IdempotentRequest } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const MEMBERSHIP = '0199a0f0-0000-7000-8000-0000000000e5';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c5';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-25T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-09-25T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-25T09:10:00.000Z'),
  endsAt: new Date('2026-09-25T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-25T09:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const ADMIN: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role: 'admin' };
const ADMIN_WRITING: InvitingAdmin = { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId };

const CHANGED: MemberRecord = {
  id: MEMBERSHIP,
  userId: '0199a0f0-0000-7000-8000-000000000044',
  role: 'developer',
  status: 'ACTIVE',
  joinedAt: new Date('2026-09-20T08:00:00.123Z'),
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface Call {
  readonly kind: 'ask' | 'confirm';
  readonly admin: InvitingAdmin;
  readonly keyed: IdempotentRequest;
  readonly id: string;
  readonly change: MembershipChange;
  readonly challengeId?: string;
}

/** A server whose writes answer `answer` (none given the server when undefined), the caller holding `role`. */
async function withChanges(answer: MembershipChangeWrite | Error | undefined, role: Role = 'admin') {
  const asked: Call[] = [];
  const answered = () => (answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer));
  const changes: MembershipChanges = {
    ask: (admin, keyed, id, change) => {
      asked.push({ kind: 'ask', admin, keyed, id, change });
      return answered() as Promise<MembershipChangeWrite>;
    },
    confirm: (admin, keyed, id, change, challengeId) => {
      asked.push({ kind: 'confirm', admin, keyed, id, change, challengeId });
      return answered() as Promise<MembershipChangeWrite>;
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
    findMembership: (orgId) =>
      Promise.resolve(orgId.toLowerCase() === ORG ? { ...ADMIN, role } : ({ outcome: 'none' } as const)),
    ...(answer !== undefined && { membershipChanges: changes }),
  });
  servers.push(app);
  await app.ready();
  return { app, asked };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const post = (path: string, payload?: Record<string, unknown>, key = 'k-1', id = MEMBERSHIP): InjectOptions => ({
  method: 'POST',
  url: `/v1/members/${id}${path}`,
  headers: { ...headers, 'idempotency-key': key },
  ...(payload !== undefined && { payload }),
});

/** The four requests, each well formed. */
const ALL = (): InjectOptions[] => [
  post('/role', { role: 'developer' }),
  post('/role/confirm', { role: 'developer', stepUpChallengeId: CHALLENGE }),
  post('/deactivate'),
  post('/deactivate/confirm', { stepUpChallengeId: CHALLENGE }),
];

describe('POST /v1/members/{id}/role changes a member’s role, once the admin has signed in again (B4-5b)', () => {
  it('asks: 202 with the step-up, for the admin’s own session and exactly this change', async () => {
    const { app, asked } = await withChanges({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    const response = await app.inject(post('/role', { role: 'developer' }));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(asked).toEqual([
      {
        kind: 'ask',
        admin: ADMIN_WRITING,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'members.role', key: 'k-1' }) as unknown,
        id: MEMBERSHIP,
        change: { kind: 'role', role: 'developer' },
      },
    ]);
  });

  it('confirms with the role and the step-up it names: 200 with the member as they now are', async () => {
    const { app, asked } = await withChanges({ outcome: 'written', member: CHANGED });

    const response = await app.inject(post('/role/confirm', { role: 'developer', stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      member: {
        id: MEMBERSHIP,
        userId: CHANGED.userId,
        role: 'developer',
        status: 'ACTIVE',
        joinedAt: '2026-09-20T08:00:00.123Z',
      },
    });
    expect(asked).toEqual([
      {
        kind: 'confirm',
        admin: ADMIN_WRITING,
        keyed: expect.objectContaining({ operation: 'members.role.confirm' }) as unknown,
        id: MEMBERSHIP,
        change: { kind: 'role', role: 'developer' },
        challengeId: CHALLENGE,
      },
    ]);
  });

  it.each([
    ['no role', {}],
    ['a role that isn’t one', { role: 'owner' }],
    ['a field it doesn’t take', { role: 'viewer', stepUpChallengeId: CHALLENGE }],
  ])('refuses an ask with %s as BAD_REQUEST', async (_what, body) => {
    const { app, asked } = await withChanges({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    expect((await app.inject(post('/role', body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    ['no role', { stepUpChallengeId: CHALLENGE }],
    ['no step-up', { role: 'viewer' }],
    ['a step-up that isn’t an ID', { role: 'viewer', stepUpChallengeId: 'not-an-id' }],
    ['a field it doesn’t take', { role: 'viewer', stepUpChallengeId: CHALLENGE, note: 'x' }],
  ])('refuses a confirmation with %s as BAD_REQUEST', async (_what, body) => {
    const { app, asked } = await withChanges({ outcome: 'written', member: CHANGED });

    expect((await app.inject(post('/role/confirm', body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('POST /v1/members/{id}/deactivate deactivates a member, once the admin has signed in again (B4-5b)', () => {
  it('asks: 202 with the step-up, with no body or an empty one', async () => {
    const { app, asked } = await withChanges({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    const bare = await app.inject(post('/deactivate'));
    const empty = await app.inject(post('/deactivate', {}, 'k-2'));

    expect([bare.statusCode, empty.statusCode]).toEqual([202, 202]);
    expect(bare.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(asked).toMatchObject([
      { kind: 'ask', admin: ADMIN_WRITING, keyed: { operation: 'members.deactivate' }, change: { kind: 'deactivate' } },
      { kind: 'ask', keyed: { key: 'k-2' } },
    ]);
  });

  it('confirms with the step-up it names: 200 with the member, deactivated', async () => {
    const { app, asked } = await withChanges({ outcome: 'written', member: { ...CHANGED, status: 'DEACTIVATED' } });

    const response = await app.inject(post('/deactivate/confirm', { stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ member: { id: MEMBERSHIP, status: 'DEACTIVATED' } });
    expect(asked).toEqual([
      {
        kind: 'confirm',
        admin: ADMIN_WRITING,
        keyed: expect.objectContaining({ operation: 'members.deactivate.confirm' }) as unknown,
        id: MEMBERSHIP,
        change: { kind: 'deactivate' },
        challengeId: CHALLENGE,
      },
    ]);
  });

  it('refuses anything in an ask’s body, and a confirmation without a step-up or with more', async () => {
    const { app, asked } = await withChanges({ outcome: 'written', member: CHANGED });

    expect((await app.inject(post('/deactivate', { role: 'viewer' }))).statusCode).toBe(400);
    expect((await app.inject(post('/deactivate/confirm', {}))).statusCode).toBe(400);
    expect(
      (await app.inject(post('/deactivate/confirm', { stepUpChallengeId: CHALLENGE, role: 'viewer' }))).statusCode,
    ).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('all four member change routes (B4-5b)', () => {
  it('refuse a membership that isn’t an ID as BAD_REQUEST', async () => {
    const { app, asked } = await withChanges({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    for (const request of [
      post('/role', { role: 'viewer' }, 'k-1', 'not-an-id'),
      post('/deactivate', undefined, 'k-1', 'not-an-id'),
    ]) {
      expect((await app.inject(request)).statusCode).toBe(400);
    }
    expect(asked).toEqual([]);
  });

  it('refuse a body over their limit: 128 bytes for an ask, 192 for a confirmation', async () => {
    const { app, asked } = await withChanges({ outcome: 'written', member: CHANGED });

    expect((await app.inject(post('/role', { role: 'viewer', pad: 'x'.repeat(128) }))).statusCode).toBe(413);
    expect(
      (await app.inject(post('/role/confirm', { role: 'viewer', stepUpChallengeId: CHALLENGE, pad: 'x'.repeat(192) })))
        .statusCode,
    ).toBe(413);
    // Just under: read, and refused only for the field they don't take.
    expect((await app.inject(post('/role', { role: 'viewer', pad: 'x'.repeat(90) }))).statusCode).toBe(400);
    expect(
      (await app.inject(post('/role/confirm', { role: 'viewer', stepUpChallengeId: CHALLENGE, pad: 'x'.repeat(100) })))
        .statusCode,
    ).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuse a %s at all four', async (role) => {
    const { app, asked } = await withChanges({ outcome: 'written', member: CHANGED }, role);

    for (const request of ALL()) {
      expect((await app.inject(request)).statusCode).toBe(403);
    }
    expect(asked).toEqual([]);
  });

  it.each([
    [409, 'OWN_MEMBERSHIP'],
    [409, 'ROLE_UNCHANGED'],
    [409, 'MEMBER_DEACTIVATED'],
    [403, 'STEP_UP_FAILED'],
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
    [403, 'FORBIDDEN'],
    [401, 'UNAUTHENTICATED'],
  ] as const)('answer the refusal %i %s at all four', async (status, code) => {
    const { app } = await withChanges({ outcome: 'refused', status, code });

    for (const request of ALL()) {
      const response = await app.inject(request);

      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('answer a key used for another request, or still being done, at all four', async () => {
    for (const [outcome, code] of [
      ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
      ['busy', 'IDEMPOTENCY_KEY_BUSY'],
    ] as const) {
      const { app } = await withChanges({ outcome });

      for (const request of ALL()) {
        const response = await app.inject(request);

        expect(response.statusCode).toBe(409);
        expect(response.json()).toMatchObject({ error: { code } });
      }
    }
  });

  it('fail as INTERNAL_ERROR when the writes fail, when none were given, or when one answers out of turn', async () => {
    const failing = (await withChanges(new Error('the database is away'))).app;
    const none = (await withChanges(undefined)).app;
    const asked = (await withChanges({ outcome: 'asked', stepUpChallengeId: CHALLENGE })).app;
    const written = (await withChanges({ outcome: 'written', member: CHANGED })).app;
    const [role, roleConfirm, deactivate, deactivateConfirm] = ALL() as [
      InjectOptions,
      InjectOptions,
      InjectOptions,
      InjectOptions,
    ];

    for (const [app, request] of [
      [failing, role],
      [failing, deactivateConfirm],
      ...ALL().map((request) => [none, request] as const),
      [asked, roleConfirm],
      [asked, deactivateConfirm],
      [written, role],
      [written, deactivate],
    ] as const) {
      expect((await app.inject(request)).statusCode).toBe(500);
    }
  });
});

// B4-3b: the invitation routes, answering an admin with each outcome of the
// writes. Who reaches them is the access hook's (role-matrix.test.ts); what
// the writes do in the database is the identity module's inviting.db.test.ts.
import type {
  InvitationRecord,
  InvitationWrite,
  InvitationWrites,
  InvitingAdmin,
  LiveSession,
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
import { errorBody } from './errors.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const INVITATION_ID = '0199a0f0-0000-7000-8000-0000000000e1';
const CHALLENGE_ID = '0199a0f0-0000-7000-8000-0000000000c1';
const TOKEN = 'T'.repeat(43);
/** A well-formed address of 254 characters, the longest there is. */
const ADDRESS_254 = `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(57)}.tes`;

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

const ADMIN: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role: 'admin' };

const DRAFT: InvitationRecord = {
  id: INVITATION_ID,
  role: 'developer',
  status: 'DRAFT',
  expiresAt: new Date('2026-09-28T09:00:00.123Z'),
  stepUpChallengeId: CHALLENGE_ID,
};
const OPEN: InvitationRecord = { ...DRAFT, status: 'OPEN' };

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

type Asked =
  | {
      readonly kind: 'ask';
      readonly admin: InvitingAdmin;
      readonly idempotent: IdempotentRequest;
      readonly invited: unknown;
    }
  | {
      readonly kind: 'confirm';
      readonly admin: InvitingAdmin;
      readonly idempotent: IdempotentRequest;
      readonly id: string;
    };

async function withWrites(answer: InvitationWrite | Error | undefined, role: Role = 'admin') {
  const asked: Asked[] = [];
  // Without an answer, no writes are given the server, so none is asked for.
  const answered = (): Promise<InvitationWrite> =>
    answer === undefined || answer instanceof Error
      ? Promise.reject(answer ?? new Error('no writes'))
      : Promise.resolve(answer);
  const writes: InvitationWrites = {
    ask: (admin, idempotent, invited) => {
      asked.push({ kind: 'ask', admin, idempotent, invited });
      return answered();
    },
    confirm: (admin, idempotent, id) => {
      asked.push({ kind: 'confirm', admin, idempotent, id });
      return answered();
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
    ...(answer !== undefined && { invitationWrites: writes }),
  });
  servers.push(app);
  await app.ready();
  return { app, asked };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const ask = (body: unknown = { email: 'Sara@Example.test', role: 'developer' }, key = 'ask-1'): InjectOptions => ({
  method: 'POST',
  url: '/v1/members/invitations',
  headers: { ...headers, 'idempotency-key': key },
  payload: body as Record<string, unknown>,
});

const confirm = (id = INVITATION_ID, key = 'confirm-1'): InjectOptions => ({
  method: 'POST',
  url: `/v1/members/invitations/${id}/confirm`,
  headers: { ...headers, 'idempotency-key': key },
});

const ADMIN_WRITING: InvitingAdmin = { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId };

describe('POST /v1/members/invitations keeps an admin’s invitation as a draft, for them to sign in again', () => {
  it('answers 202 with the invitation and the step-up to sign in again for', async () => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 202, invitation: DRAFT });

    const response = await app.inject(ask());

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({
      invitation: { id: INVITATION_ID, role: 'developer', status: 'DRAFT', expiresAt: '2026-09-28T09:00:00.123Z' },
      stepUpChallengeId: CHALLENGE_ID,
    });
    expect(asked).toEqual([
      {
        kind: 'ask',
        admin: ADMIN_WRITING,
        idempotent: {
          orgId: ORG,
          client: { kind: 'user', id: LIVE.userId },
          operation: 'members.invite',
          key: 'ask-1',
          payload: '{"body":{"email":"Sara@Example.test","role":"developer"},"params":{},"query":{}}',
        },
        invited: { email: 'Sara@Example.test', role: 'developer' },
      },
    ]);
  });

  it('answers a replay of an invitation confirmed since without the step-up', async () => {
    const { app } = await withWrites({ outcome: 'written', status: 202, invitation: OPEN });

    const response = await app.inject(ask());

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({
      invitation: { id: INVITATION_ID, role: 'developer', status: 'OPEN', expiresAt: '2026-09-28T09:00:00.123Z' },
    });
  });

  it.each([
    ['no address', { role: 'viewer' }],
    ['no role', { email: 'sara@example.test' }],
    ['a role that isn’t one', { email: 'sara@example.test', role: 'owner' }],
    ['an address that isn’t one', { email: 'sara', role: 'viewer' }],
    ['an address of 255 characters', { email: `${ADDRESS_254}t`, role: 'viewer' }],
    ['a field it doesn’t take', { email: 'sara@example.test', role: 'viewer', orgId: ORG }],
  ])('refuses %s as BAD_REQUEST, asking nothing of the writes', async (_what, body) => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 202, invitation: DRAFT });

    const response = await app.inject(ask(body));

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(errorBody('BAD_REQUEST', FIRST_ID));
    expect(asked).toEqual([]);
  });

  it('takes an address of 254 characters', async () => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 202, invitation: DRAFT });

    const response = await app.inject(ask({ email: ADDRESS_254, role: 'viewer' }));

    expect(ADDRESS_254).toHaveLength(254);
    expect(response.statusCode).toBe(202);
    expect(asked).toHaveLength(1);
  });

  it('refuses a body over 1 KiB', async () => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 202, invitation: DRAFT });

    const response = await app.inject(ask({ email: 'sara@example.test', role: 'viewer', pad: 'x'.repeat(1024) }));

    expect(response.statusCode).toBe(413);
    expect(asked).toEqual([]);
  });

  it('refuses a request without its Idempotency-Key before reading it', async () => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 202, invitation: DRAFT });

    const response = await app.inject({ ...ask(), headers });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(errorBody('IDEMPOTENCY_KEY_INVALID', FIRST_ID));
    expect(asked).toEqual([]);
  });
});

describe('POST /v1/members/invitations/{id}/confirm opens the invitation, once the admin has signed in again', () => {
  it('answers 200 with the invitation and, this once, the link, its token in the fragment', async () => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 200, invitation: OPEN, token: TOKEN });

    const response = await app.inject(confirm(INVITATION_ID.toUpperCase()));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      invitation: { id: INVITATION_ID, role: 'developer', status: 'OPEN', expiresAt: '2026-09-28T09:00:00.123Z' },
      link: `${PUBLIC_ORIGIN}/invitations/accept#token=${TOKEN}`,
    });
    expect(asked).toEqual([
      {
        kind: 'confirm',
        admin: ADMIN_WRITING,
        idempotent: expect.objectContaining({ operation: 'members.invite.confirm', key: 'confirm-1' }) as unknown,
        id: INVITATION_ID.toUpperCase(),
      },
    ]);
  });

  it('answers a replay without the link', async () => {
    const { app } = await withWrites({ outcome: 'written', status: 200, invitation: OPEN });

    const response = await app.inject(confirm());

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      invitation: { id: INVITATION_ID, role: 'developer', status: 'OPEN', expiresAt: '2026-09-28T09:00:00.123Z' },
    });
  });

  it('takes an empty object as its body, as it takes none', async () => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 200, invitation: OPEN });

    const response = await app.inject({ ...confirm(), payload: {} });

    expect(response.statusCode).toBe(200);
    expect(asked).toHaveLength(1);
  });

  it('refuses a body with anything in it, and one over 64 bytes, asking nothing of the writes', async () => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 200, invitation: OPEN });

    const field = await app.inject({ ...confirm(), payload: { challengeId: CHALLENGE_ID } });
    const large = await app.inject({ ...confirm(), payload: { pad: 'x'.repeat(64) } });

    expect(field.statusCode).toBe(400);
    expect(large.statusCode).toBe(413);
    expect(asked).toEqual([]);
  });

  it('refuses an ID that isn’t one, asking nothing of the writes', async () => {
    const { app, asked } = await withWrites({ outcome: 'written', status: 200, invitation: OPEN });

    const response = await app.inject(confirm('not-an-id'));

    expect(response.statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('only an admin reaches either route', () => {
  it.each(['approver', 'developer', 'viewer'] as const)(
    'refuses a %s as FORBIDDEN, asking nothing of the writes',
    async (role) => {
      for (const request of [ask(), confirm()]) {
        const { app, asked } = await withWrites({ outcome: 'written', status: 202, invitation: DRAFT }, role);

        const response = await app.inject(request);

        expect(response.statusCode).toBe(403);
        expect(response.json()).toEqual(errorBody('FORBIDDEN', FIRST_ID));
        expect(asked).toEqual([]);
      }
    },
  );
});

describe('both routes answer the writes’ refusals', () => {
  it.each([
    [403, 'STEP_UP_FAILED'],
    [409, 'INVITATION_CLOSED'],
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
    [403, 'FORBIDDEN'],
    [401, 'UNAUTHENTICATED'],
  ] as const)('%i %s', async (status, code) => {
    for (const request of [ask(), confirm()]) {
      const { app } = await withWrites({ outcome: 'refused', status, code });

      const response = await app.inject(request);

      expect(response.statusCode).toBe(status);
      expect(response.json()).toEqual(errorBody(code, FIRST_ID));
    }
  });

  it('409 IDEMPOTENCY_KEY_REUSED for a key used for another request, and IDEMPOTENCY_KEY_BUSY with Retry-After', async () => {
    for (const request of [ask(), confirm()]) {
      const reused = await withWrites({ outcome: 'conflict' });
      const busy = await withWrites({ outcome: 'busy' });

      const conflict = await reused.app.inject(request);
      const waiting = await busy.app.inject(request);

      expect(conflict.statusCode).toBe(409);
      expect(conflict.json()).toEqual(errorBody('IDEMPOTENCY_KEY_REUSED', FIRST_ID));
      expect(waiting.statusCode).toBe(409);
      expect(waiting.headers['retry-after']).toBe('5');
      expect(waiting.json()).toEqual(errorBody('IDEMPOTENCY_KEY_BUSY', FIRST_ID));
    }
  });

  it('fails as INTERNAL_ERROR when the writes fail, or when none were given', async () => {
    for (const request of [ask(), confirm()]) {
      for (const { app } of [await withWrites(new Error('the database is away')), await withWrites(undefined)]) {
        const response = await app.inject(request);

        expect(response.statusCode).toBe(500);
        expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
      }
    }
  });
});

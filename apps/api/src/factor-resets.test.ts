// B6-3b: the resets' routes, answering an admin with each outcome of the
// writes and the list. Who reaches them is the access hook's
// (role-matrix.test.ts); what the writes do in the database is the identity
// module's reset-changes.db.test.ts.
import type {
  ContactConfirmation,
  ContactConfirmations,
  InvitingAdmin,
  LiveSession,
  MembershipCheck,
  ResetChanges,
  ResetChangeWrite,
  ResetsList,
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
const RESET = '0199a0f0-0000-7000-8000-0000000000f6';
const MEMBER = '0199a0f0-0000-7000-8000-0000000000d6';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c6';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-27T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-09-27T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-27T09:10:00.000Z'),
  endsAt: new Date('2099-09-27T21:00:05.000Z'),
  idleEndsAt: new Date('2099-09-27T09:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(undefined),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const ADMIN_MEMBERSHIP = '0199a0f0-0000-7000-8000-000000000033';
const ADMIN: MembershipCheck = { outcome: 'active', id: ADMIN_MEMBERSHIP, role: 'admin' };
const ADMIN_WRITING: InvitingAdmin = { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId };

type Reset = Extract<ResetChangeWrite, { outcome: 'written' }>['reset'];

const reset = (changes: Partial<Reset> = {}): Reset => ({
  id: RESET,
  status: 'AWAITING_CONTACT',
  person: MEMBER,
  requestedBy: ADMIN_MEMBERSHIP,
  stepUpChallengeId: CHALLENGE,
  expiresAt: new Date('2026-09-30T09:00:00.123Z'),
  confirmedBy: null,
  coolingOffUntil: null,
  ...changes,
});

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface Call {
  readonly kind: 'ask' | 'confirm' | 'cancel';
  readonly admin: InvitingAdmin;
  readonly keyed: IdempotentRequest;
  readonly subject: string;
}

/** A server whose writes answer `answer` and whose list answers `listed` (no writes given the server when undefined), the caller holding `role`. */
async function withResets(
  answer: ResetChangeWrite | undefined,
  {
    role = 'admin',
    listed = { outcome: 'listed', resets: [] },
    confirmed,
  }: { role?: Role; listed?: ResetsList; confirmed?: ContactConfirmation } = {},
) {
  const pressed: string[] = [];
  const confirmations: ContactConfirmations = {
    confirm: (token) => {
      pressed.push(token);
      return confirmed === undefined ? Promise.reject(new Error('no confirmations')) : Promise.resolve(confirmed);
    },
  };
  const asked: Call[] = [];
  const lists: string[] = [];
  const answered = () => (answer === undefined ? Promise.reject(new Error('no writes')) : Promise.resolve(answer));
  const changes: ResetChanges = {
    ask: (admin, keyed, id) => {
      asked.push({ kind: 'ask', admin, keyed, subject: id });
      return answered();
    },
    confirm: (admin, keyed, id) => {
      asked.push({ kind: 'confirm', admin, keyed, subject: id });
      return answered();
    },
    cancel: (admin, keyed, id) => {
      asked.push({ kind: 'cancel', admin, keyed, subject: id });
      return answered();
    },
    list: (orgId) => {
      lists.push(orgId);
      return Promise.resolve(listed);
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
      rateLimitPerAgentPerMinute: 1000,
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
      Promise.resolve(orgId.toLowerCase() === ORG ? { ...ADMIN, role } : ({ outcome: 'none' } as const)),
    ...(answer !== undefined && { resetChanges: changes }),
    ...(confirmed !== undefined && { contactConfirmations: confirmations }),
  });
  servers.push(app);
  await app.ready();
  return { app, asked, lists, pressed };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const post = (url: string, payload?: Record<string, unknown>, key = 'k-1'): InjectOptions => ({
  method: 'POST',
  url,
  headers: { ...headers, 'idempotency-key': key },
  ...(payload !== undefined && { payload }),
});

const LIST: InjectOptions = { method: 'GET', url: '/v1/factor-resets', headers };

/** The three writes, each well formed. */
const ALL = (): InjectOptions[] => [
  post(`/v1/members/${MEMBER}/factor-reset`),
  post(`/v1/factor-resets/${RESET}/confirm`),
  post(`/v1/factor-resets/${RESET}/cancel`),
];

/** A reset as the API answers it. */
const ANSWERED = {
  id: RESET,
  status: 'AWAITING_CONTACT',
  person: MEMBER,
  requestedBy: ADMIN_MEMBERSHIP,
  expiresAt: '2026-09-30T09:00:00.123Z',
  confirmedBy: null,
  coolingOffUntil: null,
};

describe('GET /v1/factor-resets lists the organisation’s resets (B6-3b)', () => {
  it('answers each, open or not, with its times as ISO strings', async () => {
    const cooling = reset({
      status: 'COOLING_OFF',
      confirmedBy: '0199a0f0-0000-7000-8000-0000000000e6',
      coolingOffUntil: new Date('2026-09-28T10:00:00Z'),
    });
    const { app, lists } = await withResets(
      { outcome: 'busy' },
      { listed: { outcome: 'listed', resets: [reset({ status: 'CANCELLED' }), cooling] } },
    );

    const response = await app.inject(LIST);

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      resets: [
        { ...ANSWERED, status: 'CANCELLED' },
        {
          ...ANSWERED,
          status: 'COOLING_OFF',
          confirmedBy: '0199a0f0-0000-7000-8000-0000000000e6',
          coolingOffUntil: '2026-09-28T10:00:00.000Z',
        },
      ],
    });
    expect(lists).toEqual([ORG]);
  });

  it.each([
    [503, 'INTEGRITY_FAILED'],
    [409, 'TOO_MANY_RESETS'],
  ] as const)('answers the list’s refusal %i %s', async (status, code) => {
    const { app } = await withResets({ outcome: 'busy' }, { listed: { outcome: 'refused', status, code } });

    const response = await app.inject(LIST);

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });
});

describe('POST /v1/members/{id}/factor-reset asks for a reset, sent once the admin has signed in again (B6-3b)', () => {
  it('asks: 202 with the draft and the step-up, for the admin’s own session', async () => {
    const { app, asked } = await withResets({
      outcome: 'written',
      status: 202,
      reset: reset({ status: 'DRAFT' }),
      stepUpChallengeId: CHALLENGE,
    });

    const response = await app.inject(post(`/v1/members/${MEMBER}/factor-reset`));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ reset: { ...ANSWERED, status: 'DRAFT' }, stepUpChallengeId: CHALLENGE });
    expect(asked).toEqual([
      {
        kind: 'ask',
        admin: ADMIN_WRITING,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'resets.ask', key: 'k-1' }) as unknown,
        subject: MEMBER,
      },
    ]);
  });

  it('answers a replay of a draft since sent without a step-up to sign in for', async () => {
    const { app } = await withResets({ outcome: 'written', status: 202, reset: reset() });

    const response = await app.inject(post(`/v1/members/${MEMBER}/factor-reset`));

    expect(response.statusCode).toBe(202);
    expect(response.json()).not.toHaveProperty('stepUpChallengeId');
  });

  it('sends it: 200 with the reset, AWAITING_CONTACT', async () => {
    const { app, asked } = await withResets({ outcome: 'written', status: 200, reset: reset() });

    const response = await app.inject(post(`/v1/factor-resets/${RESET}/confirm`));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ reset: ANSWERED });
    expect(asked).toMatchObject([
      { kind: 'confirm', admin: ADMIN_WRITING, keyed: { operation: 'resets.ask.confirm' }, subject: RESET },
    ]);
  });

  it('cancels it: 200 with the reset, CANCELLED', async () => {
    const { app, asked } = await withResets({ outcome: 'written', status: 200, reset: reset({ status: 'CANCELLED' }) });

    const response = await app.inject(post(`/v1/factor-resets/${RESET}/cancel`));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ reset: { ...ANSWERED, status: 'CANCELLED' } });
    expect(asked).toMatchObject([{ kind: 'cancel', keyed: { operation: 'resets.cancel' }, subject: RESET }]);
  });
});

describe('all three reset writes (B6-3b)', () => {
  it('refuse an ID that isn’t one, a body with anything in it, or one over the limit', async () => {
    const { app, asked } = await withResets({ outcome: 'written', status: 200, reset: reset() });

    for (const url of ['/v1/members/not-an-id/factor-reset', '/v1/factor-resets/not-an-id/confirm']) {
      expect((await app.inject(post(url))).statusCode).toBe(400);
    }
    for (const request of [
      post(`/v1/members/${MEMBER}/factor-reset`, { reason: 'lost' }),
      post(`/v1/factor-resets/${RESET}/cancel`, { note: 'x' }),
    ]) {
      expect((await app.inject(request)).statusCode).toBe(400);
    }
    expect((await app.inject(post(`/v1/factor-resets/${RESET}/confirm`, { pad: 'x'.repeat(64) }))).statusCode).toBe(
      413,
    );
    expect(asked).toEqual([]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuse a %s at all three, and at the list', async (role) => {
    const { app, asked, lists } = await withResets({ outcome: 'written', status: 200, reset: reset() }, { role });

    for (const request of [...ALL(), LIST]) {
      expect((await app.inject(request)).statusCode).toBe(403);
    }
    expect(asked).toEqual([]);
    expect(lists).toEqual([]);
  });

  it.each([
    [409, 'OWN_RESET'],
    [409, 'MEMBER_DEACTIVATED'],
    [409, 'MEMBER_ELSEWHERE'],
    [409, 'NO_COUNTING_CONTACTS'],
    [409, 'RESET_OPEN'],
    [409, 'RESET_CLOSED'],
    [409, 'RESET_ASKS_SPENT'],
    [409, 'TOO_MANY_RESETS'],
    [409, 'TOO_MANY_CONTACTS'],
    [403, 'STEP_UP_FAILED'],
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
    [403, 'FORBIDDEN'],
    [401, 'UNAUTHENTICATED'],
  ] as const)('answer the refusal %i %s at all three', async (status, code) => {
    const { app } = await withResets({ outcome: 'refused', status, code });

    for (const request of ALL()) {
      const response = await app.inject(request);

      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('answer a key used for another request, or still being done, at all three', async () => {
    for (const [outcome, code] of [
      ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
      ['busy', 'IDEMPOTENCY_KEY_BUSY'],
    ] as const) {
      const { app } = await withResets({ outcome });

      for (const request of ALL()) {
        expect((await app.inject(request)).json()).toMatchObject({ error: { code } });
      }
    }
  });

  it('are refused to a request without a key, and never reach the writes', async () => {
    const { app, asked } = await withResets({ outcome: 'written', status: 200, reset: reset() });

    const response = await app.inject({ method: 'POST', url: `/v1/factor-resets/${RESET}/cancel`, headers });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_INVALID' } });
    expect(asked).toEqual([]);
  });
});

describe('POST /v1/factor-resets/confirm: a registered contact confirms by its link (B6-3b-3)', () => {
  const TOKEN = `${ORG}.${RESET}.0199a0f0-0000-7000-8000-0000000000e6.${'s'.repeat(43)}`;
  /** A press on the console's page: no session, no organisation header, no idempotency key. */
  const press = (payload: Record<string, unknown>, origin: string | null = PUBLIC_ORIGIN): InjectOptions => ({
    method: 'POST',
    url: '/v1/factor-resets/confirm',
    headers: origin === null ? {} : { origin },
    payload,
  });

  it('answers when the factor is removed, and nothing else, to anyone holding the link', async () => {
    const { app, pressed } = await withResets(undefined, {
      confirmed: { outcome: 'confirmed', coolingOffUntil: new Date('2026-09-28T10:00:00Z') },
    });

    const response = await app.inject(press({ token: TOKEN }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ coolingOffUntil: '2026-09-28T10:00:00.000Z' });
    expect(pressed).toEqual([TOKEN]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [409, 'CONTACT_NOT_ACTIVE'],
    [409, 'RESET_CLOSED'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the refusal %i %s', async (status, code) => {
    const { app } = await withResets(undefined, { confirmed: { outcome: 'refused', status, code } });

    const response = await app.inject(press({ token: TOKEN }));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('refuses a press from another origin, a body without its token or with more, and one over the limit', async () => {
    const { app, pressed } = await withResets(undefined, {
      confirmed: { outcome: 'confirmed', coolingOffUntil: new Date('2026-09-28T10:00:00Z') },
    });

    expect((await app.inject(press({ token: TOKEN }, 'https://elsewhere.example'))).statusCode).toBe(403);
    expect((await app.inject(press({ token: TOKEN }, null))).statusCode).toBe(403);
    expect((await app.inject(press({}))).statusCode).toBe(400);
    expect((await app.inject(press({ token: TOKEN, contact: 'x' }))).statusCode).toBe(400);
    expect((await app.inject(press({ token: 'x'.repeat(600) }))).statusCode).toBe(413);
    expect(pressed).toEqual([]);
  });

  it('refuses a token outside its alphabet, and takes the longest one the document allows within the body limit (B8-3)', async () => {
    const { app, pressed } = await withResets(undefined, {
      confirmed: { outcome: 'confirmed', coolingOffUntil: new Date('2026-09-28T10:00:00Z') },
    });
    // The longest token the document allows: 256 characters of its alphabet, each one byte.
    const longest = 'aZ09._-'.repeat(37).slice(0, 256);

    expect((await app.inject(press({ token: 'é'.repeat(10) }))).statusCode).toBe(400);
    expect((await app.inject(press({ token: `${TOKEN} ` }))).statusCode).toBe(400);
    expect((await app.inject(press({ token: `${TOKEN}\n` }))).statusCode).toBe(400);
    expect(pressed).toEqual([]);
    expect((await app.inject(press({ token: longest }))).statusCode).toBe(200);
    expect(pressed).toEqual([longest]);
  });

  it('answers NOT_FOUND when the server was given no confirmations', async () => {
    const { app } = await withResets({ outcome: 'busy' });

    const response = await app.inject(press({ token: TOKEN }));

    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: 'NOT_FOUND' } });
  });
});

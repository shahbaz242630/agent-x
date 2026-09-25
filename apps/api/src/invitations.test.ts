// B4-3b: the invitation routes, answering an admin with each outcome of the
// writes. Who reaches them is the access hook's (role-matrix.test.ts); what
// the writes do in the database is the identity module's inviting.db.test.ts.
import type {
  Acceptance,
  AcceptanceConfirmations,
  ConfirmationWrite,
  AcceptingPerson,
  InvitationAcceptance,
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
  acceptedBy: null,
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

async function withWrites(
  answer: InvitationWrite | Error | undefined,
  role: Role = 'admin',
  acceptance?: InvitationAcceptance,
  confirmations?: AcceptanceConfirmations,
) {
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
    ...(acceptance !== undefined && { invitationAcceptance: acceptance }),
    ...(confirmations !== undefined && { acceptanceConfirmations: confirmations }),
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

describe('POST /v1/invitations/accept takes a signed-in person’s token (B4-4c)', () => {
  const TOKEN_SENT = 'A'.repeat(43);
  const ACCEPTED_BY = LIVE.userId;

  /** A server whose acceptance answers `answer`, recording what it was asked and the key's request for an organisation. */
  async function withAcceptance(answer: Acceptance | Error) {
    const asked: { person: AcceptingPerson; token: string; keyed: IdempotentRequest }[] = [];
    const acceptance: InvitationAcceptance = {
      accept: (person, token, idempotent) => {
        asked.push({ person, token, keyed: idempotent(ORG) });
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
    };
    // No membership anywhere: accepting needs none, only a signed-in person.
    const { app } = await withWrites(undefined, 'viewer', acceptance);
    return { app, asked };
  }

  const acceptRequest = (body: unknown = { token: TOKEN_SENT }, extra: Record<string, string> = {}): InjectOptions => ({
    method: 'POST',
    url: '/v1/invitations/accept',
    headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, origin: PUBLIC_ORIGIN, 'idempotency-key': 'accept-1', ...extra },
    payload: body as Record<string, unknown>,
  });

  it('answers 200 with the organisation and the invitation, keyed to the organisation the directory named', async () => {
    const { app, asked } = await withAcceptance({
      outcome: 'accepted',
      orgId: ORG,
      invitation: { ...OPEN, status: 'ACCEPTED', acceptedBy: ACCEPTED_BY },
    });

    const response = await app.inject(acceptRequest());

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      organizationId: ORG,
      invitation: { id: INVITATION_ID, role: 'developer', status: 'ACCEPTED', expiresAt: '2026-09-28T09:00:00.123Z' },
    });
    expect(asked).toEqual([
      {
        person: { userId: LIVE.userId, sessionId: LIVE.sessionId },
        token: TOKEN_SENT,
        keyed: {
          orgId: ORG,
          client: { kind: 'user', id: LIVE.userId },
          operation: 'invitations.accept',
          key: 'accept-1',
          payload: `{"body":{"token":"${TOKEN_SENT}"},"params":{},"query":{}}`,
        },
      },
    ]);
  });

  it('takes no organisation header: the directory names it', async () => {
    const { app, asked } = await withAcceptance({ outcome: 'accepted', orgId: ORG, invitation: OPEN });

    const response = await app.inject(acceptRequest(undefined, { [ORGANIZATION_HEADER]: 'not-an-id' }));

    expect(response.statusCode).toBe(200);
    expect(asked).toHaveLength(1);
  });

  it.each([
    [403, 'INVITATION_INVALID'],
    [409, 'INVITATION_CLOSED'],
    [409, 'ALREADY_A_MEMBER'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the refusal %i %s', async (status, code) => {
    const { app } = await withAcceptance({ outcome: 'refused', status, code });

    const response = await app.inject(acceptRequest());

    expect(response.statusCode).toBe(status);
    expect(response.json()).toEqual(errorBody(code, FIRST_ID));
  });

  it('answers a key used for another request, or one still being done', async () => {
    for (const [outcome, code] of [
      ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
      ['busy', 'IDEMPOTENCY_KEY_BUSY'],
    ] as const) {
      const { app } = await withAcceptance({ outcome });

      const response = await app.inject(acceptRequest());

      expect(response.statusCode).toBe(409);
      expect(response.json()).toEqual(errorBody(code, FIRST_ID));
    }
  });

  it.each([
    ['no token', {}],
    ['a token too short', { token: 'A'.repeat(42) }],
    ['a token too long', { token: 'A'.repeat(44) }],
    ['a token with a character base64url has not', { token: `${'A'.repeat(42)}+` }],
    ['a field it doesn’t take', { token: TOKEN_SENT, orgId: ORG }],
  ])('refuses %s as BAD_REQUEST, asking nothing of the acceptance', async (_what, body) => {
    const { app, asked } = await withAcceptance({ outcome: 'accepted', orgId: ORG, invitation: OPEN });

    const response = await app.inject(acceptRequest(body));

    expect(response.statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('refuses a body over 256 bytes', async () => {
    const { app, asked } = await withAcceptance({ outcome: 'accepted', orgId: ORG, invitation: OPEN });

    const response = await app.inject(acceptRequest({ token: TOKEN_SENT, pad: 'x'.repeat(256) }));

    expect(response.statusCode).toBe(413);
    expect(asked).toEqual([]);
  });

  it('refuses anyone not signed in as UNAUTHENTICATED', async () => {
    const { app, asked } = await withAcceptance({ outcome: 'accepted', orgId: ORG, invitation: OPEN });

    const response = await app.inject({
      ...acceptRequest(),
      headers: { origin: PUBLIC_ORIGIN, 'idempotency-key': 'k' },
    });

    expect(response.statusCode).toBe(401);
    expect(asked).toEqual([]);
  });

  it('fails as INTERNAL_ERROR when the acceptance fails, or when none was given', async () => {
    const failing = await withAcceptance(new Error('the database is away'));
    const none = (await withWrites(undefined, 'viewer')).app;

    for (const app of [failing.app, none]) {
      const response = await app.inject(acceptRequest());

      expect(response.statusCode).toBe(500);
      expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    }
  });
});

describe('an admin confirms or declines who accepted an admin’s or approver’s invitation (B4-4d)', () => {
  const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c9';
  interface Call {
    kind: string;
    admin: InvitingAdmin;
    keyed: IdempotentRequest;
    id: string;
    challengeId?: string;
  }

  async function withConfirmations(answer: ConfirmationWrite | Error, role: Role = 'admin') {
    const asked: Call[] = [];
    const answered = () => (answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer));
    const confirmations: AcceptanceConfirmations = {
      ask: (admin, keyed, id) => {
        asked.push({ kind: 'ask', admin, keyed, id });
        return answered();
      },
      confirm: (admin, keyed, id, challengeId) => {
        asked.push({ kind: 'confirm', admin, keyed, id, challengeId });
        return answered();
      },
      decline: (admin, keyed, id) => {
        asked.push({ kind: 'decline', admin, keyed, id });
        return answered();
      },
    };
    const { app } = await withWrites(undefined, role, undefined, confirmations);
    return { app, asked };
  }

  const post = (path: string, payload?: Record<string, unknown>, key = 'k-1'): InjectOptions => ({
    method: 'POST',
    url: `/v1/members/invitations/${INVITATION_ID}${path}`,
    headers: { ...headers, 'idempotency-key': key },
    ...(payload !== undefined && { payload }),
  });

  const DECIDED: ConfirmationWrite = {
    outcome: 'written',
    invitation: { ...OPEN, status: 'ACCEPTED', acceptedBy: LIVE.userId },
  };

  it('asks: 202 with the step-up, for the admin’s own session', async () => {
    const { app, asked } = await withConfirmations({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    const response = await app.inject(post('/approve'));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(asked).toEqual([
      {
        kind: 'ask',
        admin: ADMIN_WRITING,
        keyed: expect.objectContaining({ operation: 'members.approve', key: 'k-1' }) as unknown,
        id: INVITATION_ID,
      },
    ]);
  });

  it('confirms with the step-up it names: 200 with the invitation', async () => {
    const { app, asked } = await withConfirmations(DECIDED);

    const response = await app.inject(post('/approve/confirm', { stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      invitation: { id: INVITATION_ID, role: 'developer', status: 'ACCEPTED', expiresAt: '2026-09-28T09:00:00.123Z' },
    });
    expect(asked).toEqual([
      {
        kind: 'confirm',
        admin: ADMIN_WRITING,
        keyed: expect.objectContaining({ operation: 'members.approve.confirm' }) as unknown,
        id: INVITATION_ID,
        challengeId: CHALLENGE,
      },
    ]);
  });

  it('declines: 200 with the invitation', async () => {
    const { app, asked } = await withConfirmations({ ...DECIDED, invitation: { ...OPEN, status: 'DECLINED' } });

    const response = await app.inject(post('/decline'));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ invitation: { status: 'DECLINED' } });
    expect(asked).toMatchObject([{ kind: 'decline', keyed: { operation: 'members.decline' } }]);
  });

  it.each([
    ['no step-up', {}],
    ['a step-up that isn’t an ID', { stepUpChallengeId: 'not-an-id' }],
    ['a field it doesn’t take', { stepUpChallengeId: CHALLENGE, role: 'admin' }],
  ])('refuses a confirmation with %s as BAD_REQUEST', async (_what, body) => {
    const { app, asked } = await withConfirmations(DECIDED);

    const response = await app.inject(post('/approve/confirm', body));

    expect(response.statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('refuses a confirmation’s body over 128 bytes, and an ask’s or decline’s with anything in it', async () => {
    const { app, asked } = await withConfirmations(DECIDED);

    expect(
      (await app.inject(post('/approve/confirm', { stepUpChallengeId: CHALLENGE, pad: 'x'.repeat(128) }))).statusCode,
    ).toBe(413);
    expect((await app.inject(post('/approve', { role: 'admin' }))).statusCode).toBe(400);
    expect((await app.inject(post('/decline', { role: 'admin' }))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s at all three', async (role) => {
    const { app, asked } = await withConfirmations(DECIDED, role);

    for (const request of [
      post('/approve'),
      post('/approve/confirm', { stepUpChallengeId: CHALLENGE }),
      post('/decline'),
    ]) {
      expect((await app.inject(request)).statusCode).toBe(403);
    }
    expect(asked).toEqual([]);
  });

  it.each([
    [403, 'STEP_UP_FAILED'],
    [409, 'INVITATION_CLOSED'],
    [409, 'ALREADY_A_MEMBER'],
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
    [403, 'FORBIDDEN'],
    [401, 'UNAUTHENTICATED'],
  ] as const)('answers the refusal %i %s at all three', async (status, code) => {
    const { app } = await withConfirmations({ outcome: 'refused', status, code });

    for (const request of [
      post('/approve'),
      post('/approve/confirm', { stepUpChallengeId: CHALLENGE }),
      post('/decline'),
    ]) {
      const response = await app.inject(request);

      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('answers a key used for another request, or still being done, at all three', async () => {
    for (const [outcome, code] of [
      ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
      ['busy', 'IDEMPOTENCY_KEY_BUSY'],
    ] as const) {
      const { app } = await withConfirmations({ outcome });

      for (const request of [
        post('/approve'),
        post('/approve/confirm', { stepUpChallengeId: CHALLENGE }),
        post('/decline'),
      ]) {
        const response = await app.inject(request);

        expect(response.statusCode).toBe(409);
        expect(response.json()).toMatchObject({ error: { code } });
      }
    }
  });

  it('fails as INTERNAL_ERROR when the writes fail, when none were given, or when one answers out of turn', async () => {
    const failing = await withConfirmations(new Error('the database is away'));
    const none = (await withWrites(undefined, 'admin')).app;
    const outOfTurn = await withConfirmations({ outcome: 'asked', stepUpChallengeId: CHALLENGE });
    const decidedAsked = await withConfirmations(DECIDED);

    for (const [app, request] of [
      [failing.app, post('/approve')],
      [none, post('/approve')],
      [none, post('/approve/confirm', { stepUpChallengeId: CHALLENGE })],
      [none, post('/decline')],
      [outOfTurn.app, post('/decline')],
      [decidedAsked.app, post('/approve')],
    ] as const) {
      const response = await app.inject(request);

      expect(response.statusCode).toBe(500);
    }
  });
});

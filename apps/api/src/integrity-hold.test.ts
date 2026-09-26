// B3+-2b-2 and B3+-2c-2: the integrity hold's routes, answering an admin with each outcome
// of the use case. Who reaches them is the access hook's
// (role-matrix.test.ts); what the use case does in the database is the
// identity module's hold-investigations.db.test.ts and hold-clearing.db.test.ts.
import type {
  ClearingAdmin,
  ClearingWrite,
  HoldAdmin,
  HoldClearings,
  HoldInvestigations,
  HoldShown,
  InvestigationWrite,
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
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const INVESTIGATION = '0199a0f0-0000-7000-8000-0000000000e7';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-26T09:00:00.000Z'),
  amr: ['pwd', 'otp', 'mfa'],
  createdAt: new Date('2026-09-26T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-26T09:10:00.000Z'),
  endsAt: new Date('2026-09-26T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-26T09:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const ADMIN: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role: 'admin' };
const THE_ADMIN: HoldAdmin = { orgId: ORG, userId: LIVE.userId };
const CLEARING_ADMIN: ClearingAdmin = { ...THE_ADMIN, sessionId: LIVE.sessionId };
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c5';

const HELD: HoldShown = {
  outcome: 'shown',
  hold: {
    outcome: 'held',
    version: 2,
    eventId: '0199a0f0-0000-7000-8000-0000000000e2',
    since: new Date('2026-09-26T08:00:00.123Z'),
    reason: 'seal',
    foundOn: 'membership',
  },
};

const RECORDED: InvestigationWrite = {
  outcome: 'written',
  status: 201,
  investigation: {
    id: INVESTIGATION,
    holdVersion: 2,
    holdEventId: '0199a0f0-0000-7000-8000-0000000000e2',
    conclusion: 'NO_TAMPERING',
    reference: 'INC-7',
    recordedBy: LIVE.userId,
    recordedAt: new Date('2026-09-26T09:30:00.456Z'),
  },
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

type Call =
  | { readonly kind: 'show'; readonly admin: HoldAdmin }
  | {
      readonly kind: 'record';
      readonly admin: HoldAdmin;
      readonly keyed: IdempotentRequest;
      readonly investigation: unknown;
    }
  | {
      readonly kind: 'ask' | 'confirm';
      readonly admin: ClearingAdmin;
      readonly keyed: IdempotentRequest;
      readonly investigationId: string;
      readonly challengeId?: string;
    };

/**
 * A server whose use cases answer `shown`, `written` and `clearing` (none
 * given the server for either use case whose answers are all undefined), the
 * caller holding `role`.
 */
async function withHold(
  {
    shown,
    written,
    clearing,
  }: { shown?: HoldShown | Error; written?: InvestigationWrite | Error; clearing?: ClearingWrite | Error },
  role: Role = 'admin',
) {
  const asked: Call[] = [];
  const answer = <T>(value: T | Error | undefined): Promise<T> =>
    value instanceof Error
      ? Promise.reject(value)
      : value === undefined
        ? Promise.reject(new Error('unasked'))
        : Promise.resolve(value);
  const investigations: HoldInvestigations = {
    show: (admin) => {
      asked.push({ kind: 'show', admin });
      return answer(shown);
    },
    record: (admin, keyed, investigation) => {
      asked.push({ kind: 'record', admin, keyed, investigation });
      return answer(written);
    },
  };
  const clearings: HoldClearings = {
    ask: (admin, keyed, investigationId) => {
      asked.push({ kind: 'ask', admin, keyed, investigationId });
      return answer(clearing);
    },
    confirm: (admin, keyed, investigationId, challengeId) => {
      asked.push({ kind: 'confirm', admin, keyed, investigationId, challengeId });
      return answer(clearing);
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
    ...((shown !== undefined || written !== undefined) && { holdInvestigations: investigations }),
    ...(clearing !== undefined && { holdClearings: clearings }),
  });
  servers.push(app);
  await app.ready();
  return { app, asked };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const show = (): InjectOptions => ({ method: 'GET', url: '/v1/integrity-hold', headers });

const record = (payload: Record<string, unknown> = { conclusion: 'NO_TAMPERING', reference: 'INC-7' }, key = 'k-1') =>
  ({
    method: 'POST',
    url: '/v1/integrity-hold/investigations',
    headers: { ...headers, 'idempotency-key': key },
    payload,
  }) satisfies InjectOptions;

describe('GET /v1/integrity-hold shows the hold to its admin (B3+-2b-2)', () => {
  it('shows a HELD hold: since when, the sign, and the kind of record it was found on', async () => {
    const { app, asked } = await withHold({ shown: HELD });

    const response = await app.inject(show());

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      hold: { status: 'HELD', version: 2, since: '2026-09-26T08:00:00.123Z', reason: 'seal', foundOn: 'membership' },
    });
    expect(asked).toEqual([{ kind: 'show', admin: THE_ADMIN }]);
  });

  it('shows a CLEAR hold, naming no sign', async () => {
    const { app } = await withHold({
      shown: { outcome: 'shown', hold: { outcome: 'clear', version: 3, since: new Date('2026-09-26T10:00:00.000Z') } },
    });

    expect((await app.inject(show())).json()).toEqual({
      hold: { status: 'CLEAR', version: 3, since: '2026-09-26T10:00:00.000Z', reason: null, foundOn: null },
    });
  });

  it.each([
    [503, 'INTEGRITY_FAILED'],
    [403, 'FORBIDDEN'],
  ] as const)('answers the refusal %i %s', async (status, code) => {
    const { app } = await withHold({ shown: { outcome: 'refused', status, code } });

    const response = await app.inject(show());

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });
});

describe('POST /v1/integrity-hold/investigations records the investigation (B3+-2b-2)', () => {
  it('records the conclusion and the reference for the admin, keyed: 201 with the investigation', async () => {
    const { app, asked } = await withHold({ written: RECORDED });

    const response = await app.inject(record());

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      investigation: {
        id: INVESTIGATION,
        holdVersion: 2,
        conclusion: 'NO_TAMPERING',
        reference: 'INC-7',
        recordedBy: LIVE.userId,
        recordedAt: '2026-09-26T09:30:00.456Z',
      },
    });
    expect(asked).toEqual([
      {
        kind: 'record',
        admin: THE_ADMIN,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'integrity-hold.investigate', key: 'k-1' }) as unknown,
        investigation: { conclusion: 'NO_TAMPERING', reference: 'INC-7' },
      },
    ]);
  });

  it('takes a reference of exactly 64 characters', async () => {
    const { app } = await withHold({ written: RECORDED });

    expect(
      (await app.inject(record({ conclusion: 'CAUSE_REMOVED', reference: `A${'-'.repeat(63)}` }))).statusCode,
    ).toBe(201);
  });

  it.each([
    ['no conclusion', { reference: 'INC-7' }],
    ['a conclusion that isn’t one', { conclusion: 'FIXED', reference: 'INC-7' }],
    ['no reference', { conclusion: 'NO_TAMPERING' }],
    ['prose for a reference', { conclusion: 'NO_TAMPERING', reference: 'the DBA did it' }],
    ['a reference starting with a dash', { conclusion: 'NO_TAMPERING', reference: '-7' }],
    ['a reference past 64 characters', { conclusion: 'NO_TAMPERING', reference: 'A'.repeat(65) }],
    ['a field it doesn’t take', { conclusion: 'NO_TAMPERING', reference: 'INC-7', notes: 'x' }],
  ])('refuses %s as BAD_REQUEST', async (_what, body) => {
    const { app, asked } = await withHold({ written: RECORDED });

    const response = await app.inject(record(body));

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'BAD_REQUEST' } });
    expect(asked).toEqual([]);
  });

  it('refuses a body over 256 bytes', async () => {
    const { app, asked } = await withHold({ written: RECORDED });

    expect(
      (await app.inject(record({ conclusion: 'NO_TAMPERING', reference: 'INC-7', pad: 'x'.repeat(256) }))).statusCode,
    ).toBe(413);
    // Just under: read, and refused only for the field it doesn't take.
    expect(
      (await app.inject(record({ conclusion: 'NO_TAMPERING', reference: 'INC-7', pad: 'x'.repeat(180) }))).statusCode,
    ).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [409, 'NOT_ON_HOLD'],
    [503, 'INTEGRITY_FAILED'],
    [403, 'FORBIDDEN'],
  ] as const)('answers the refusal %i %s', async (status, code) => {
    const { app } = await withHold({ written: { outcome: 'refused', status, code } });

    const response = await app.inject(record());

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('answers a key used for another request, or still being done', async () => {
    for (const [outcome, code] of [
      ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
      ['busy', 'IDEMPOTENCY_KEY_BUSY'],
    ] as const) {
      const { app } = await withHold({ written: { outcome } });

      const response = await app.inject(record());

      expect(response.statusCode).toBe(409);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });
});

describe('both integrity hold routes (B3+-2b-2)', () => {
  it.each(['approver', 'developer', 'viewer'] as const)('refuse a %s', async (role) => {
    const { app, asked } = await withHold({ shown: HELD, written: RECORDED }, role);

    expect((await app.inject(show())).statusCode).toBe(403);
    expect((await app.inject(record())).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });

  it('fail as INTERNAL_ERROR when the use case fails, or when none was given', async () => {
    for (const hold of [{ shown: new Error('down'), written: new Error('down') }, {}]) {
      const { app } = await withHold(hold);

      for (const request of [show(), record()]) {
        const response = await app.inject(request);

        expect(response.statusCode).toBe(500);
        expect(response.json()).toMatchObject({ error: { code: 'INTERNAL_ERROR' } });
      }
    }
  });
});

const clear = (path: '' | '/confirm', payload: Record<string, unknown>, key = 'k-1') =>
  ({
    method: 'POST',
    url: `/v1/integrity-hold/clear${path}`,
    headers: { ...headers, 'idempotency-key': key },
    payload,
  }) satisfies InjectOptions;

const ASK = clear('', { investigationId: INVESTIGATION });
const CONFIRM = clear('/confirm', { investigationId: INVESTIGATION, stepUpChallengeId: CHALLENGE });

describe('POST /v1/integrity-hold/clear clears the hold, once the admin has signed in again (B3+-2c-2)', () => {
  it('asks: 202 with the step-up, for the admin’s own session and exactly this investigation', async () => {
    const { app, asked } = await withHold({ clearing: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });

    const response = await app.inject(ASK);

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(asked).toEqual([
      {
        kind: 'ask',
        admin: CLEARING_ADMIN,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'integrity-hold.clear', key: 'k-1' }) as unknown,
        investigationId: INVESTIGATION,
      },
    ]);
  });

  it('confirms with the investigation and the step-up: 200 with the hold, CLEAR', async () => {
    const { app, asked } = await withHold({
      clearing: {
        outcome: 'cleared',
        hold: { outcome: 'clear', version: 3, since: new Date('2026-09-26T11:00:00.000Z') },
      },
    });

    const response = await app.inject(CONFIRM);

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      hold: { status: 'CLEAR', version: 3, since: '2026-09-26T11:00:00.000Z', reason: null, foundOn: null },
    });
    expect(asked).toEqual([
      {
        kind: 'confirm',
        admin: CLEARING_ADMIN,
        keyed: expect.objectContaining({ operation: 'integrity-hold.clear.confirm' }) as unknown,
        investigationId: INVESTIGATION,
        challengeId: CHALLENGE,
      },
    ]);
  });

  it.each([
    ['an ask with no investigation', clear('', {})],
    ['an ask with an investigation that isn’t an ID', clear('', { investigationId: 'INC-7' })],
    [
      'an ask with a field it doesn’t take',
      clear('', { investigationId: INVESTIGATION, stepUpChallengeId: CHALLENGE }),
    ],
    ['a confirmation with no step-up', clear('/confirm', { investigationId: INVESTIGATION })],
    ['a confirmation with no investigation', clear('/confirm', { stepUpChallengeId: CHALLENGE })],
    [
      'a confirmation with a step-up that isn’t an ID',
      clear('/confirm', { investigationId: INVESTIGATION, stepUpChallengeId: 'not-an-id' }),
    ],
    [
      'a confirmation with a field it doesn’t take',
      clear('/confirm', { investigationId: INVESTIGATION, stepUpChallengeId: CHALLENGE, note: 'x' }),
    ],
  ])('refuses %s as BAD_REQUEST', async (_what, request) => {
    const { app, asked } = await withHold({ clearing: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });

    const response = await app.inject(request);

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'BAD_REQUEST' } });
    expect(asked).toEqual([]);
  });

  it('refuses a body over 192 bytes', async () => {
    const { app, asked } = await withHold({ clearing: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });

    expect((await app.inject(clear('', { investigationId: INVESTIGATION, pad: 'x'.repeat(192) }))).statusCode).toBe(
      413,
    );
    // Just under: read, and refused only for the field it doesn't take.
    expect((await app.inject(clear('', { investigationId: INVESTIGATION, pad: 'x'.repeat(100) }))).statusCode).toBe(
      400,
    );
    expect(asked).toEqual([]);
  });

  it.each([
    [409, 'NOT_ON_HOLD'],
    [409, 'NO_INVESTIGATION'],
    [409, 'HOLD_CHANGED'],
    [403, 'STEP_UP_FAILED'],
    [503, 'INTEGRITY_FAILED'],
    [403, 'FORBIDDEN'],
    [401, 'UNAUTHENTICATED'],
  ] as const)('answers the refusal %i %s at both', async (status, code) => {
    const { app } = await withHold({ clearing: { outcome: 'refused', status, code } });

    for (const request of [ASK, CONFIRM]) {
      const response = await app.inject(request);

      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('answers a key used for another request, or still being done, at both', async () => {
    for (const [outcome, code] of [
      ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
      ['busy', 'IDEMPOTENCY_KEY_BUSY'],
    ] as const) {
      const { app } = await withHold({ clearing: { outcome } });

      for (const request of [ASK, CONFIRM]) {
        const response = await app.inject(request);

        expect(response.statusCode).toBe(409);
        expect(response.json()).toMatchObject({ error: { code } });
      }
    }
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s at both', async (role) => {
    const { app, asked } = await withHold({ clearing: { outcome: 'asked', stepUpChallengeId: CHALLENGE } }, role);

    expect((await app.inject(ASK)).statusCode).toBe(403);
    expect((await app.inject(CONFIRM)).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });

  it('fails as INTERNAL_ERROR when the use case fails, when none was given, or when one answers out of turn', async () => {
    for (const hold of [
      { clearing: new Error('down') },
      { shown: HELD },
      {
        clearing: {
          outcome: 'cleared',
          hold: { outcome: 'clear', version: 3, since: new Date('2026-09-26T11:00:00.000Z') },
        } as const,
      },
    ]) {
      const { app } = await withHold(hold);

      const response = await app.inject(ASK);

      expect(response.statusCode).toBe(500);
      expect(response.json()).toMatchObject({ error: { code: 'INTERNAL_ERROR' } });
    }
    const { app } = await withHold({ clearing: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });

    expect((await app.inject(CONFIRM)).statusCode).toBe(500);
  });
});

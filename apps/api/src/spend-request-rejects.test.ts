// Phase 3 B4a: the reject routes over HTTP, their use case a stub: what each
// hands it (the member, the idempotency request, the request's ID, the
// reason as kept and the step-up), the answers, who may call them before the
// use case runs, a reason that can't be one, and the use case's own
// refusals. What the use case does is spend-request-rejects.db.test.ts.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LiveSession } from '@agentx/core/modules/identity';
import type { SpendRequestRecord } from '@agentx/core/modules/spend-requests';
import { money } from '@agentx/core/shared-kernel';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type { RejectAsked, Rejected, SpendRequestRejects } from './spend-request-rejects.ts';
import type { SessionMember } from './use-case-work.ts';

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY_ID = '0199a0f0-0000-7000-8000-0000000000b1';
const REQUEST_ID = '0199a0f0-0000-7000-8000-0000000000c1';
const CHALLENGE_ID = '0199a0f0-0000-7000-8000-0000000000c9';
const MEMBERSHIP_ID = '0199a0f0-0000-7000-8000-000000000033';

const KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-13T08:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-13T08:00:05.000Z'),
  lastSeenAt: new Date('2026-10-13T08:10:00.000Z'),
  endsAt: new Date('2099-10-07T20:00:05.000Z'),
  idleEndsAt: new Date('2099-10-07T08:40:00.000Z'),
};

const REJECTED: SpendRequestRecord = {
  id: REQUEST_ID,
  agentId: AGENT_ID,
  mandateId: '0199a0f0-0000-7000-8000-0000000000d1',
  supplierId: '0199a0f0-0000-7000-8000-0000000000e1',
  fundingSourceId: '0199a0f0-0000-7000-8000-0000000000f1',
  amount: money(200_000n, 'AED'),
  purpose: 'Printer paper',
  orderReference: 'INV_22',
  decision: 'REQUIRE_APPROVAL',
  reasons: ['APPROVAL_THRESHOLD'],
  status: 'DENIED',
};

type Role = 'admin' | 'approver' | 'developer' | 'viewer';

interface Asked {
  readonly member: SessionMember;
  readonly idempotent: IdempotentRequest;
  readonly requestId: string;
  readonly reason: string;
  readonly stepUpChallengeId?: string;
}

afterEach(closeServers);

/** A server whose use case answers `ask` and `confirm`, recording what it was asked, the member signed in as `role`. */
async function withRejects(
  answers: { readonly ask?: RejectAsked; readonly confirm?: Rejected } = {},
  role: Role = 'approver',
) {
  const asked: Asked[] = [];
  const rejects: SpendRequestRejects = {
    ask: (member, idempotent, requestId, reason) => {
      asked.push({ member, idempotent, requestId, reason });
      return Promise.resolve(answers.ask ?? { outcome: 'asked', stepUpChallengeId: CHALLENGE_ID });
    },
    confirm: (member, idempotent, requestId, { reason, stepUpChallengeId }) => {
      asked.push({ member, idempotent, requestId, reason, stepUpChallengeId });
      return Promise.resolve(answers.confirm ?? { outcome: 'rejected', request: REJECTED });
    },
  };
  const app = await routeServer({
    live: LIVE,
    member: { outcome: 'active', id: MEMBERSHIP_ID, role },
    checkAgentKey: (text) =>
      Promise.resolve(
        text === KEY
          ? {
              outcome: 'accepted',
              key: {
                orgId: ORG,
                agentId: AGENT_ID,
                keyId: KEY_ID,
                scopes: ['requests:write'],
                expiresAt: new Date('2099-12-28T09:00:00.000Z'),
              } satisfies AcceptedKey,
            }
          : { outcome: 'refused' },
      ),
    spendRequestRejects: rejects,
  });
  return { app, asked };
}

/** A signed-in member's JSON post, from our own origin. */
const post = (url: string, idempotencyKey: string, payload: unknown): InjectOptions => ({
  method: 'POST',
  url,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': idempotencyKey,
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

const ask = (payload: unknown, id = REQUEST_ID) => post(`/v1/spend-requests/${id}/reject`, 'reject-1', payload);

const confirm = (payload: unknown) => post(`/v1/spend-requests/${REQUEST_ID}/reject/confirm`, 'reject-2', payload);

describe('POST /v1/spend-requests/{id}/reject and …/confirm: an admin or approver rejects (B4a)', () => {
  it.each(['admin', 'approver'] as const)(
    'hands the %s’s ask and confirm to the use case, the reason as kept (composed), and answers 202 then 200',
    async (role) => {
      const { app, asked } = await withRejects({}, role);
      // Decomposed é: kept composed, so the ask and the confirm bind the same text however it was typed.
      const reason = 'Café order not needed';

      const asking = await app.inject(ask({ reason }));
      expect(asking.statusCode).toBe(202);
      expect(asking.json()).toEqual({ stepUpChallengeId: CHALLENGE_ID });
      const confirming = await app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID, reason }));
      expect(confirming.statusCode).toBe(200);
      expect(confirming.json()).toMatchObject({
        id: REQUEST_ID,
        status: 'DENIED',
        reasons: [{ code: 'APPROVAL_THRESHOLD' }],
      });

      expect(asked).toEqual([
        expect.objectContaining({ requestId: REQUEST_ID, reason: 'Café order not needed' }),
        expect.objectContaining({ reason: 'Café order not needed', stepUpChallengeId: CHALLENGE_ID }),
      ]);
      expect(asked[0]?.member).toMatchObject({ orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId });
      expect(asked.map(({ idempotent }) => idempotent.operation)).toEqual([
        'spend-requests.reject',
        'spend-requests.reject.confirm',
      ]);
    },
  );

  it.each(['developer', 'viewer'] as const)('refuses a %s before the use case runs', async (role) => {
    const { app, asked } = await withRejects({}, role);

    expect((await app.inject(ask({ reason: 'No' }))).statusCode).toBe(403);
    expect((await app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID, reason: 'No' }))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });

  it('refuses an agent’s key on either, before the use case runs (an agent never decides)', async () => {
    const { app, asked } = await withRejects();
    const headers = { authorization: `Bearer ${KEY}`, 'idempotency-key': 'x' };

    expect([401, 403]).toContain((await app.inject({ ...ask({ reason: 'No' }), headers })).statusCode);
    const confirming = await app.inject({ ...confirm({ stepUpChallengeId: CHALLENGE_ID, reason: 'No' }), headers });
    expect([401, 403]).toContain(confirming.statusCode);
    expect(asked).toEqual([]);
  });

  it.each([
    ['none', {}],
    ['empty', { reason: '' }],
    ['a long number in it', { reason: 'Call 050 123 4567 first' }],
    ['over 200 characters', { reason: 'x'.repeat(201) }],
    ['on two lines', { reason: 'one\ntwo' }],
    ['with another field', { reason: 'No', amount: 1 }],
  ])('refuses a reason %s before the use case runs', async (_what, body) => {
    const { app, asked } = await withRejects();

    expect((await app.inject(ask(body))).statusCode).toBe(400);
    expect((await app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID, ...body }))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('takes a reason of 200 characters, and refuses a confirm without its step-up or an ID that isn’t one', async () => {
    const { app, asked } = await withRejects();

    expect((await app.inject(ask({ reason: 'x'.repeat(200) }))).statusCode).toBe(202);
    expect((await app.inject(confirm({ reason: 'No' }))).statusCode).toBe(400);
    expect((await app.inject(ask({ reason: 'No' }, 'not-an-id'))).statusCode).toBe(400);
    expect(asked).toHaveLength(1);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [409, 'REQUEST_NOT_WAITING'],
    [403, 'STEP_UP_FAILED'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal of either: %i %s', async (status, code) => {
    const { app } = await withRejects({
      ask: { outcome: 'refused', status, code },
      confirm: { outcome: 'refused', status, code },
    });

    for (const sent of [ask({ reason: 'No' }), confirm({ stepUpChallengeId: CHALLENGE_ID, reason: 'No' })]) {
      const response = await app.inject(sent);
      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('answers a key used for another request, and one still being done, as the idempotency store says', async () => {
    const reused = await withRejects({ ask: { outcome: 'conflict' }, confirm: { outcome: 'conflict' } });
    expect((await reused.app.inject(ask({ reason: 'No' }))).json()).toMatchObject({
      error: { code: 'IDEMPOTENCY_KEY_REUSED' },
    });
    const busy = await withRejects({ confirm: { outcome: 'busy' } });
    expect((await busy.app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID, reason: 'No' }))).json()).toMatchObject({
      error: { code: 'IDEMPOTENCY_KEY_BUSY' },
    });
  });
});

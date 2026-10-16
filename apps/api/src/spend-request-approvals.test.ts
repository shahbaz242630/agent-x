// Phase 3 B4b: the approve routes over HTTP, their use case a stub: what each
// hands it (the member, the idempotency request, the request's ID, the
// step-up and any re-check, E5a), the answers, who may call them before the use case runs (no
// agent key: SEC-AG-07), a body that can't be one, and the use case's own
// refusals. What the use case does is spend-request-approvals.db.test.ts.
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
import type { ApproveAsked, Approved, SpendRequestApprovals } from './spend-request-approvals.ts';
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

const APPROVED: SpendRequestRecord = {
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
  status: 'APPROVED',
};

type Role = 'admin' | 'approver' | 'developer' | 'viewer';

interface Asked {
  readonly member: SessionMember;
  readonly idempotent: IdempotentRequest;
  readonly requestId: string;
  readonly stepUpChallengeId?: string;
  readonly recheck: boolean;
}

const RECHECKED = {
  fromSupplierVersionId: '0199a0f0-0000-7000-8000-0000000000e2',
  supplierVersionId: '0199a0f0-0000-7000-8000-0000000000e3',
  decidedAs: 'REQUIRE_APPROVAL',
  decidedReasons: ['APPROVAL_THRESHOLD'],
  decision: 'REQUIRE_APPROVAL',
  reasons: ['APPROVAL_THRESHOLD'],
} as const;

afterEach(closeServers);

/** A server whose use case answers `ask` and `confirm`, recording what it was asked, the member signed in as `role`. */
async function withApprovals(
  answers: { readonly ask?: ApproveAsked; readonly confirm?: Approved } = {},
  role: Role = 'approver',
) {
  const asked: Asked[] = [];
  const approvals: SpendRequestApprovals = {
    ask: (member, idempotent, requestId, recheck) => {
      asked.push({ member, idempotent, requestId, recheck });
      return Promise.resolve(answers.ask ?? { outcome: 'asked', stepUpChallengeId: CHALLENGE_ID, recheck: null });
    },
    confirm: (member, idempotent, requestId, stepUpChallengeId, recheck) => {
      asked.push({ member, idempotent, requestId, stepUpChallengeId, recheck });
      return Promise.resolve(answers.confirm ?? { outcome: 'approved', request: APPROVED });
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
                scopes: ['requests:write', 'requests:read'],
                expiresAt: new Date('2099-12-28T09:00:00.000Z'),
              } satisfies AcceptedKey,
            }
          : { outcome: 'refused' },
      ),
    spendRequestApprovals: approvals,
  });
  return { app, asked };
}

/** A signed-in member's post, from our own origin: JSON when it has a body. */
const post = (url: string, idempotencyKey: string, payload?: unknown): InjectOptions => ({
  method: 'POST',
  url,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': idempotencyKey,
    ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
  },
  ...(payload === undefined ? {} : { payload: JSON.stringify(payload) }),
});

const ask = (payload?: unknown, id = REQUEST_ID) => post(`/v1/spend-requests/${id}/approve`, 'approve-1', payload);
const confirm = (payload: unknown) => post(`/v1/spend-requests/${REQUEST_ID}/approve/confirm`, 'approve-2', payload);

describe('POST /v1/spend-requests/{id}/approve and …/confirm: an admin or approver approves (B4b)', () => {
  it.each(['admin', 'approver'] as const)(
    'hands the %s’s ask and confirm to the use case, and answers 202 then 200',
    async (role) => {
      const { app, asked } = await withApprovals({}, role);

      const asking = await app.inject(ask());
      expect(asking.statusCode).toBe(202);
      expect(asking.json()).toEqual({ stepUpChallengeId: CHALLENGE_ID, recheck: null });
      const confirming = await app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID }));
      expect(confirming.statusCode).toBe(200);
      expect(confirming.json()).toMatchObject({
        id: REQUEST_ID,
        status: 'APPROVED',
        reasons: [{ code: 'APPROVAL_THRESHOLD' }],
      });

      expect(asked).toEqual([
        expect.objectContaining({ requestId: REQUEST_ID, recheck: false }),
        expect.objectContaining({ requestId: REQUEST_ID, stepUpChallengeId: CHALLENGE_ID, recheck: false }),
      ]);
      expect(asked[0]?.member).toMatchObject({ orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId });
      expect(asked.map(({ idempotent }) => idempotent.operation)).toEqual([
        'spend-requests.approve',
        'spend-requests.approve.confirm',
      ]);
    },
  );

  it('takes an ask with an empty JSON body as with none', async () => {
    const { app, asked } = await withApprovals();

    expect((await app.inject(ask({}))).statusCode).toBe(202);
    expect(asked).toHaveLength(1);
  });

  it('hands a re-check on to the use case in both, and answers what changed with each reason’s words (E5a)', async () => {
    const { app, asked } = await withApprovals({
      ask: { outcome: 'asked', stepUpChallengeId: CHALLENGE_ID, recheck: RECHECKED },
    });

    const asking = await app.inject(ask({ recheck: true }));
    expect(asking.statusCode).toBe(202);
    expect(asking.json()).toEqual({
      stepUpChallengeId: CHALLENGE_ID,
      recheck: {
        ...RECHECKED,
        decidedReasons: [{ code: 'APPROVAL_THRESHOLD', message: expect.any(String) as unknown }],
        reasons: [{ code: 'APPROVAL_THRESHOLD', message: expect.any(String) as unknown }],
      },
    });
    const confirming = await app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID, recheck: true }));
    expect(confirming.statusCode).toBe(200);
    expect(asked.map(({ recheck }) => recheck)).toEqual([true, true]);
  });

  it('refuses a re-check that isn’t `true` in either, before the use case runs', async () => {
    const { app, asked } = await withApprovals();

    expect((await app.inject(ask({ recheck: false }))).statusCode).toBe(400);
    expect((await app.inject(ask({ recheck: 'yes' }))).statusCode).toBe(400);
    expect((await app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID, recheck: 1 }))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each(['developer', 'viewer'] as const)('refuses a %s before the use case runs', async (role) => {
    const { app, asked } = await withApprovals({}, role);

    expect((await app.inject(ask())).statusCode).toBe(403);
    expect((await app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID }))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });

  it('refuses an agent’s key on either, before the use case runs, even for its own request (SEC-AG-07)', async () => {
    const { app, asked } = await withApprovals();
    const headers = { authorization: `Bearer ${KEY}`, 'idempotency-key': 'x' };

    expect([401, 403]).toContain((await app.inject({ ...ask(), headers })).statusCode);
    const confirming = await app.inject({ ...confirm({ stepUpChallengeId: CHALLENGE_ID }), headers });
    expect([401, 403]).toContain(confirming.statusCode);
    expect(asked).toEqual([]);
  });

  it('refuses an ask with a body, a confirm without its step-up or with more, and an ID that isn’t one', async () => {
    const { app, asked } = await withApprovals();

    expect((await app.inject(ask({ reason: 'Fine' }))).statusCode).toBe(400);
    expect((await app.inject(confirm({}))).statusCode).toBe(400);
    expect((await app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID, amount: 1 }))).statusCode).toBe(400);
    expect((await app.inject(ask(undefined, 'not-an-id'))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [409, 'REQUEST_NOT_WAITING'],
    [409, 'REQUEST_CHANGED'],
    [409, 'RECHECK_REQUIRED'],
    [400, 'RECHECK_NOT_OFFERED'],
    [409, 'REQUEST_EXPIRED'],
    [409, 'ORG_FROZEN'],
    [403, 'STEP_UP_FAILED'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal of either: %i %s', async (status, code) => {
    const { app } = await withApprovals({
      ask: { outcome: 'refused', status, code },
      confirm: { outcome: 'refused', status, code },
    });

    for (const sent of [ask(), confirm({ stepUpChallengeId: CHALLENGE_ID })]) {
      const response = await app.inject(sent);
      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('answers a key used for another request, and one still being done, as the idempotency store says', async () => {
    const reused = await withApprovals({ ask: { outcome: 'conflict' }, confirm: { outcome: 'conflict' } });
    expect((await reused.app.inject(ask())).json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_REUSED' } });
    const busy = await withApprovals({ confirm: { outcome: 'busy' } });
    expect((await busy.app.inject(confirm({ stepUpChallengeId: CHALLENGE_ID }))).json()).toMatchObject({
      error: { code: 'IDEMPOTENCY_KEY_BUSY' },
    });
  });
});

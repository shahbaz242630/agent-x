// Phase 4 gate H10 (partner decision 38): the mark-failed routes over HTTP,
// their use case a stub: what each hands it (the member, the idempotency
// request, the payment's ID, the bank's evidence reference and the step-up),
// the answers, who may call them before the use case runs, a body that can't
// be one (no consequence confirmed among them), and the use case's own
// refusals. What the use case does is mark-failed.db.test.ts.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LiveSession } from '@agentx/core/modules/identity';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { MarkAsked, Marked, PaymentMarks } from './payment-marks.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type { SessionMember } from './use-case-work.ts';

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY_ID = '0199a0f0-0000-7000-8000-0000000000b1';
const PAYMENT_ID = '0199a0f0-0000-7000-8000-0000000000c1';
const CHALLENGE_ID = '0199a0f0-0000-7000-8000-0000000000c9';
const MEMBERSHIP_ID = '0199a0f0-0000-7000-8000-000000000033';
const EVIDENCE = 'BANK-NACK-77311';
const CONFIRMED = 'invoice_can_be_paid_again';

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

type Role = 'admin' | 'approver' | 'developer' | 'viewer';

interface Asked {
  readonly member: SessionMember;
  readonly idempotent: IdempotentRequest;
  readonly paymentId: string;
  readonly evidenceRef: string;
  readonly stepUpChallengeId?: string;
}

afterEach(closeServers);

/** A server whose use case answers `ask` and `confirm`, recording what it was asked, the member signed in as `role`. */
async function withMarks(answers: { readonly ask?: MarkAsked; readonly confirm?: Marked } = {}, role: Role = 'admin') {
  const asked: Asked[] = [];
  const marks: PaymentMarks = {
    ask: (member, idempotent, paymentId, evidenceRef) => {
      asked.push({ member, idempotent, paymentId, evidenceRef });
      return Promise.resolve(answers.ask ?? { outcome: 'asked', stepUpChallengeId: CHALLENGE_ID });
    },
    confirm: (member, idempotent, paymentId, { evidenceRef, stepUpChallengeId }) => {
      asked.push({ member, idempotent, paymentId, evidenceRef, stepUpChallengeId });
      return Promise.resolve(answers.confirm ?? { outcome: 'marked', paymentId });
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
    paymentMarks: marks,
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

const BODY = { evidenceRef: EVIDENCE, confirmed: CONFIRMED };

const ask = (payload: unknown, id = PAYMENT_ID) => post(`/v1/payments/${id}/mark-failed`, 'mark-1', payload);

const confirm = (payload: unknown) => post(`/v1/payments/${PAYMENT_ID}/mark-failed/confirm`, 'mark-2', payload);

describe('POST /v1/payments/{id}/mark-failed and …/confirm: an admin marks a payment failed (H10; decision 38)', () => {
  it('hands the admin’s ask and confirm to the use case, and answers 202 then 200 with the payment FAILED', async () => {
    const { app, asked } = await withMarks();

    const asking = await app.inject(ask(BODY));
    expect(asking.statusCode).toBe(202);
    expect(asking.json()).toEqual({ stepUpChallengeId: CHALLENGE_ID });
    const confirming = await app.inject(confirm({ ...BODY, stepUpChallengeId: CHALLENGE_ID }));
    expect(confirming.statusCode).toBe(200);
    expect(confirming.json()).toEqual({ id: PAYMENT_ID, status: 'FAILED' });

    expect(asked).toEqual([
      expect.objectContaining({ paymentId: PAYMENT_ID, evidenceRef: EVIDENCE }),
      expect.objectContaining({ evidenceRef: EVIDENCE, stepUpChallengeId: CHALLENGE_ID }),
    ]);
    expect(asked[0]?.member).toMatchObject({ orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId });
    expect(asked.map(({ idempotent }) => idempotent.operation)).toEqual([
      'payments.mark-failed',
      'payments.mark-failed.confirm',
    ]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s before the use case runs', async (role) => {
    const { app, asked } = await withMarks({}, role);

    expect((await app.inject(ask(BODY))).statusCode).toBe(403);
    expect((await app.inject(confirm({ ...BODY, stepUpChallengeId: CHALLENGE_ID }))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });

  it('refuses an agent’s key on either, before the use case runs (an agent never marks a payment)', async () => {
    const { app, asked } = await withMarks();
    const headers = { authorization: `Bearer ${KEY}`, 'idempotency-key': 'x' };

    expect([401, 403]).toContain((await app.inject({ ...ask(BODY), headers })).statusCode);
    const confirming = await app.inject({ ...confirm({ ...BODY, stepUpChallengeId: CHALLENGE_ID }), headers });
    expect([401, 403]).toContain(confirming.statusCode);
    expect(asked).toEqual([]);
  });

  it.each([
    ['nothing', {}],
    ['no consequence confirmed', { evidenceRef: EVIDENCE }],
    ['another consequence', { evidenceRef: EVIDENCE, confirmed: 'yes' }],
    ['no evidence reference', { confirmed: CONFIRMED }],
    ['a reference too short', { ...BODY, evidenceRef: 'AB' }],
    ['a reference over 64', { ...BODY, evidenceRef: `A${'b'.repeat(64)}` }],
    ['a reference with a space', { ...BODY, evidenceRef: 'BANK NACK 1' }],
    ['a reference starting with a mark', { ...BODY, evidenceRef: '-BANK-1' }],
    ['another field', { ...BODY, amount: 1 }],
  ])('refuses %s before the use case runs', async (_what, body) => {
    const { app, asked } = await withMarks();

    expect((await app.inject(ask(body))).statusCode).toBe(400);
    expect((await app.inject(confirm({ ...body, stepUpChallengeId: CHALLENGE_ID }))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('takes a reference of 64, and refuses a confirm without its step-up or a payment ID that isn’t one', async () => {
    const { app, asked } = await withMarks();

    expect((await app.inject(ask({ ...BODY, evidenceRef: `A.b_c/d-${'e'.repeat(56)}` }))).statusCode).toBe(202);
    expect((await app.inject(confirm(BODY))).statusCode).toBe(400);
    expect((await app.inject(ask(BODY, 'not-an-id'))).statusCode).toBe(400);
    expect(asked).toHaveLength(1);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [409, 'PAYMENT_NOT_UNKNOWN'],
    [409, 'PAYMENT_TOO_RECENT'],
    [403, 'STEP_UP_FAILED'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal of either: %i %s', async (status, code) => {
    const { app } = await withMarks({
      ask: { outcome: 'refused', status, code },
      confirm: { outcome: 'refused', status, code },
    });

    for (const sent of [ask(BODY), confirm({ ...BODY, stepUpChallengeId: CHALLENGE_ID })]) {
      const response = await app.inject(sent);
      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('answers a key used for another request, and one still being done, as the idempotency store says', async () => {
    const reused = await withMarks({ ask: { outcome: 'conflict' }, confirm: { outcome: 'conflict' } });
    expect((await reused.app.inject(ask(BODY))).json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_REUSED' } });
    const busy = await withMarks({ confirm: { outcome: 'busy' } });
    expect((await busy.app.inject(confirm({ ...BODY, stepUpChallengeId: CHALLENGE_ID }))).json()).toMatchObject({
      error: { code: 'IDEMPOTENCY_KEY_BUSY' },
    });
  });
});

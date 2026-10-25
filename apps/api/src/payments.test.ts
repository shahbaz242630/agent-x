// Phase 4 gate H10 (partner decision 38 and its S145 heads-up): the
// two-admin mark-failed routes over HTTP, their use case a stub: what each
// hands it (the member, the idempotency request, the payment's ID, the bank's
// evidence reference and the step-up), the answers, who may call them before
// the use case runs, a body that can't be one (no consequence confirmed among
// them), and the use case's own refusals. What the use case does is
// mark-failed.db.test.ts.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LiveSession } from '@agentx/core/modules/identity';
import type { FailureProposalRecord } from '@agentx/core/modules/transactions';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { PaymentMarks } from './payment-marks.ts';
import type { Refused } from './refused.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type { SessionMember } from './use-case-work.ts';

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY_ID = '0199a0f0-0000-7000-8000-0000000000b1';
const PAYMENT_ID = '0199a0f0-0000-7000-8000-0000000000c1';
const PROPOSAL_ID = '0199a0f0-0000-7000-8000-0000000000c2';
const CHALLENGE_ID = '0199a0f0-0000-7000-8000-0000000000c9';
const MEMBERSHIP_ID = '0199a0f0-0000-7000-8000-000000000033';
const PROPOSER = '0199a0f0-0000-7000-8000-000000000044';
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

const PROPOSAL: FailureProposalRecord = {
  id: PROPOSAL_ID,
  transactionId: PAYMENT_ID,
  evidenceRef: EVIDENCE,
  proposedBy: PROPOSER,
  status: 'OPEN',
  createdAt: new Date('2026-10-14T09:00:00.000Z'),
};
const PROPOSAL_SHOWN = {
  id: PROPOSAL_ID,
  paymentId: PAYMENT_ID,
  evidenceRef: EVIDENCE,
  proposedBy: PROPOSER,
  status: 'OPEN',
  proposedAt: '2026-10-14T09:00:00.000Z',
};

type Role = 'admin' | 'approver' | 'developer' | 'viewer';

interface Asked {
  readonly step: string;
  readonly member: SessionMember;
  readonly idempotent: IdempotentRequest;
  readonly paymentId: string;
  readonly evidenceRef?: string;
  readonly stepUpChallengeId?: string;
}

afterEach(closeServers);

const ASKED = { outcome: 'asked', stepUpChallengeId: CHALLENGE_ID } as const;

/** A server whose use case answers each step as given (or as it would), recording what it was asked, the member `role`. */
async function withMarks(refusal?: Refused | { readonly outcome: 'conflict' | 'busy' }, role: Role = 'admin') {
  const asked: Asked[] = [];
  const marks: PaymentMarks = {
    propose: (member, idempotent, paymentId, evidenceRef) => {
      asked.push({ step: 'propose', member, idempotent, paymentId, evidenceRef });
      return Promise.resolve(refusal ?? ASKED);
    },
    confirmProposal: (member, idempotent, paymentId, { evidenceRef, stepUpChallengeId }) => {
      asked.push({ step: 'confirmProposal', member, idempotent, paymentId, evidenceRef, stepUpChallengeId });
      return Promise.resolve(refusal ?? { outcome: 'proposed', proposal: PROPOSAL });
    },
    approve: (member, idempotent, paymentId) => {
      asked.push({ step: 'approve', member, idempotent, paymentId });
      return Promise.resolve(refusal ?? { ...ASKED, proposal: PROPOSAL });
    },
    confirmApproval: (member, idempotent, paymentId, stepUpChallengeId) => {
      asked.push({ step: 'confirmApproval', member, idempotent, paymentId, stepUpChallengeId });
      return Promise.resolve(refusal ?? { outcome: 'marked', paymentId });
    },
    withdraw: (member, idempotent, paymentId) => {
      asked.push({ step: 'withdraw', member, idempotent, paymentId });
      return Promise.resolve(refusal ?? ASKED);
    },
    confirmWithdrawal: (member, idempotent, paymentId, stepUpChallengeId) => {
      asked.push({ step: 'confirmWithdrawal', member, idempotent, paymentId, stepUpChallengeId });
      return Promise.resolve(refusal ?? { outcome: 'withdrawn', proposal: { ...PROPOSAL, status: 'WITHDRAWN' } });
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
const post = (path: string, payload: unknown, id = PAYMENT_ID): InjectOptions => ({
  method: 'POST',
  url: `/v1/payments/${id}/failure-proposal${path}`,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': `mark${path.replaceAll('/', '-')}`,
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

const PROPOSE = { evidenceRef: EVIDENCE, confirmed: CONFIRMED };
const STEPPED = { stepUpChallengeId: CHALLENGE_ID };

/** Every step, with a body each takes. */
const STEPS = [
  ['propose', '', PROPOSE],
  ['confirm a proposal', '/confirm', { ...PROPOSE, ...STEPPED }],
  ['approve', '/approve', { confirmed: CONFIRMED }],
  ['confirm an approval', '/approve/confirm', { confirmed: CONFIRMED, ...STEPPED }],
  ['withdraw', '/withdraw', {}],
  ['confirm a withdrawal', '/withdraw/confirm', STEPPED],
] as const;

describe('POST /v1/payments/{id}/failure-proposal…: two admins mark a payment failed (H10; decision 38)', () => {
  it('hands each step to the use case, and answers 202, 201, 202 with the proposal, 200 FAILED, 202, 200', async () => {
    const { app, asked } = await withMarks();

    const answers = [];
    for (const [, path, body] of STEPS) answers.push(await app.inject(post(path, body)));

    expect(answers.map((answer) => answer.statusCode)).toEqual([202, 201, 202, 200, 202, 200]);
    expect(answers.map((answer) => answer.json<unknown>())).toEqual([
      STEPPED,
      PROPOSAL_SHOWN,
      { ...STEPPED, proposal: PROPOSAL_SHOWN },
      { id: PAYMENT_ID, status: 'FAILED' },
      STEPPED,
      { ...PROPOSAL_SHOWN, status: 'WITHDRAWN' },
    ]);
    expect(
      asked.map(({ step, paymentId, evidenceRef, stepUpChallengeId }) => ({
        step,
        paymentId,
        evidenceRef,
        stepUpChallengeId,
      })),
    ).toEqual([
      { step: 'propose', paymentId: PAYMENT_ID, evidenceRef: EVIDENCE, stepUpChallengeId: undefined },
      { step: 'confirmProposal', paymentId: PAYMENT_ID, evidenceRef: EVIDENCE, stepUpChallengeId: CHALLENGE_ID },
      { step: 'approve', paymentId: PAYMENT_ID, evidenceRef: undefined, stepUpChallengeId: undefined },
      { step: 'confirmApproval', paymentId: PAYMENT_ID, evidenceRef: undefined, stepUpChallengeId: CHALLENGE_ID },
      { step: 'withdraw', paymentId: PAYMENT_ID, evidenceRef: undefined, stepUpChallengeId: undefined },
      { step: 'confirmWithdrawal', paymentId: PAYMENT_ID, evidenceRef: undefined, stepUpChallengeId: CHALLENGE_ID },
    ]);
    expect(asked[0]?.member).toMatchObject({ orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId });
    expect(asked.map(({ idempotent }) => idempotent.operation)).toEqual([
      'payments.failure-proposal',
      'payments.failure-proposal.confirm',
      'payments.failure-proposal.approve',
      'payments.failure-proposal.approve.confirm',
      'payments.failure-proposal.withdraw',
      'payments.failure-proposal.withdraw.confirm',
    ]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)(
    'refuses a %s on every step before the use case runs',
    async (role) => {
      const { app, asked } = await withMarks(undefined, role);

      for (const [, path, body] of STEPS) expect((await app.inject(post(path, body))).statusCode).toBe(403);
      expect(asked).toEqual([]);
    },
  );

  it('refuses an agent’s key on every step before the use case runs (an agent never marks a payment)', async () => {
    const { app, asked } = await withMarks();
    const headers = { authorization: `Bearer ${KEY}`, 'idempotency-key': 'x' };

    for (const [, path, body] of STEPS) {
      expect([401, 403]).toContain((await app.inject({ ...post(path, body), headers })).statusCode);
    }
    expect(asked).toEqual([]);
  });

  it.each([
    ['nothing', '', {}],
    ['no consequence confirmed', '', { evidenceRef: EVIDENCE }],
    ['another consequence', '', { evidenceRef: EVIDENCE, confirmed: 'yes' }],
    ['no evidence reference', '', { confirmed: CONFIRMED }],
    ['a reference too short', '', { ...PROPOSE, evidenceRef: 'AB' }],
    ['a reference over 64', '', { ...PROPOSE, evidenceRef: `A${'b'.repeat(64)}` }],
    ['a reference with a space', '', { ...PROPOSE, evidenceRef: 'BANK NACK 1' }],
    ['a reference starting with a mark', '', { ...PROPOSE, evidenceRef: '-BANK-1' }],
    ['another field', '', { ...PROPOSE, amount: 1 }],
    ['a proposal’s confirm without its step-up', '/confirm', PROPOSE],
    ['an approval without the consequence', '/approve', {}],
    ['an approval with a reference of its own', '/approve', { confirmed: CONFIRMED, evidenceRef: EVIDENCE }],
    ['an approval’s confirm without its step-up', '/approve/confirm', { confirmed: CONFIRMED }],
    ['an approval’s confirm without the consequence', '/approve/confirm', STEPPED],
    ['a withdrawal with a field', '/withdraw', { evidenceRef: EVIDENCE }],
    ['a withdrawal’s confirm without its step-up', '/withdraw/confirm', {}],
  ])('refuses %s before the use case runs', async (_what, path, body) => {
    const { app, asked } = await withMarks();

    expect((await app.inject(post(path, body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('takes a reference of 64 of every mark allowed, and refuses a payment ID that isn’t one', async () => {
    const { app, asked } = await withMarks();

    expect((await app.inject(post('', { ...PROPOSE, evidenceRef: `A.b_c/d-${'e'.repeat(56)}` }))).statusCode).toBe(202);
    expect((await app.inject(post('', PROPOSE, 'not-an-id'))).statusCode).toBe(400);
    expect(asked).toHaveLength(1);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [409, 'PAYMENT_NOT_UNKNOWN'],
    [409, 'PAYMENT_TOO_RECENT'],
    [409, 'FAILURE_PROPOSAL_OPEN'],
    [409, 'NO_FAILURE_PROPOSAL'],
    [409, 'FAILURE_PROPOSAL_TOO_RECENT'],
    [403, 'FAILURE_PROPOSAL_YOURS'],
    [403, 'STEP_UP_FAILED'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal of every step: %i %s', async (status, code) => {
    const { app } = await withMarks({ outcome: 'refused', status, code });

    for (const [, path, body] of STEPS) {
      const response = await app.inject(post(path, body));
      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it.each([
    ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
    ['busy', 'IDEMPOTENCY_KEY_BUSY'],
  ] as const)('answers a key %s on every step as the idempotency store says', async (outcome, code) => {
    const { app } = await withMarks({ outcome });

    for (const [, path, body] of STEPS)
      expect((await app.inject(post(path, body))).json()).toMatchObject({ error: { code } });
  });
});

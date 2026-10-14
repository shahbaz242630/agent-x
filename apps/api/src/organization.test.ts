// Phase 3 D1: the organisation's freeze routes, answering an admin with each
// outcome of the use case, and refusing a body that doesn't choose, confirm
// or give a reason before it runs. Who reaches them is the access hook's
// (role-matrix.test.ts); what the use case does in the database is
// brake-voids.db.test.ts (its freezing describe) and
// spend-request-approvals.db.test.ts.
import type { LiveSession, MembershipCheck } from '@agentx/core/modules/identity';
import type { PendingChoice } from '@agentx/core/modules/spend-requests';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { OrganizationChanges, OrganizationChangeWrite } from './organization-changes.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-15T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-15T09:00:05.000Z'),
  lastSeenAt: new Date('2026-10-15T09:10:00.000Z'),
  endsAt: new Date('2026-10-15T21:00:05.000Z'),
  idleEndsAt: new Date('2026-10-15T09:40:00.000Z'),
};

const ADMIN = {
  outcome: 'active',
  id: '0199a0f0-0000-7000-8000-000000000033',
  role: 'admin',
} as const satisfies MembershipCheck;
const MEMBER = { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId };
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c5';

afterEach(closeServers);

type Call =
  | { readonly kind: 'freeze'; readonly keyed: IdempotentRequest; readonly pendingRequests: PendingChoice }
  | { readonly kind: 'unfreeze'; readonly keyed: IdempotentRequest; readonly reason: string }
  | {
      readonly kind: 'unfreezeConfirm';
      readonly keyed: IdempotentRequest;
      readonly reason: string;
      readonly stepUpChallengeId: string;
    };

/** A server whose use case answers `written`, the caller an admin. */
async function withChanges(written: OrganizationChangeWrite) {
  const asked: (Call & { readonly member: object })[] = [];
  const changes: OrganizationChanges = {
    freeze: (member, keyed, pendingRequests) => {
      asked.push({ kind: 'freeze', member, keyed, pendingRequests });
      return Promise.resolve(written);
    },
    unfreeze: (member, keyed, reason) => {
      asked.push({ kind: 'unfreeze', member, keyed, reason });
      return Promise.resolve(written);
    },
    unfreezeConfirm: (member, keyed, { stepUpChallengeId, reason }) => {
      asked.push({ kind: 'unfreezeConfirm', member, keyed, reason, stepUpChallengeId });
      return Promise.resolve(written);
    },
  };
  const app = await routeServer({ live: LIVE, member: ADMIN, organizationChanges: changes });
  return { app, asked };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const post = (path: string, payload: Record<string, unknown>): InjectOptions => ({
  method: 'POST',
  url: `/v1/organization${path}`,
  headers: { ...headers, 'idempotency-key': 'k-1' },
  payload,
});

const FROZEN: OrganizationChangeWrite = { outcome: 'changed', organization: { id: ORG, status: 'FROZEN' } };
const ACTIVE: OrganizationChangeWrite = { outcome: 'changed', organization: { id: ORG, status: 'ACTIVE' } };

describe('POST /v1/organization/freeze: the brake, chosen and confirmed (decisions 10 and 11)', () => {
  it.each(['cancel', 'pause'] as const)('freezes it with %s: 200 with the organisation, FROZEN', async (choice) => {
    const { app, asked } = await withChanges(FROZEN);

    const response = await app.inject(post('/freeze', { pendingRequests: choice, confirmed: true }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ organization: { id: ORG, status: 'FROZEN' } });
    expect(asked).toMatchObject([
      { kind: 'freeze', member: MEMBER, keyed: { operation: 'organization.freeze' }, pendingRequests: choice },
    ]);
  });

  it.each([
    [{}],
    [{ pendingRequests: 'cancel' }],
    [{ pendingRequests: 'cancel', confirmed: false }],
    [{ confirmed: true }],
    [{ pendingRequests: 'hold', confirmed: true }],
    [{ pendingRequests: 'cancel', confirmed: true, more: 1 }],
  ])('refuses %j (no choice, or not confirmed) before the use case runs', async (body) => {
    const { app, asked } = await withChanges(FROZEN);

    expect((await app.inject(post('/freeze', body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('answers a pause over a cancel as the use case refuses it', async () => {
    const { app } = await withChanges({ outcome: 'refused', status: 409, code: 'PENDING_REQUESTS_CANCELLED' });

    const response = await app.inject(post('/freeze', { pendingRequests: 'pause', confirmed: true }));

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'PENDING_REQUESTS_CANCELLED' } });
  });
});

describe('POST /v1/organization/unfreeze, then /confirm: a passkey and a reason', () => {
  it('asks with the reason as it is kept: 202 with the step-up', async () => {
    const { app, asked } = await withChanges({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    const response = await app.inject(post('/unfreeze', { reason: 'Café checked: all clear' }));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(asked).toMatchObject([
      {
        kind: 'unfreeze',
        member: MEMBER,
        keyed: { operation: 'organization.unfreeze' },
        reason: 'Café checked: all clear',
      },
    ]);
  });

  it('confirms with the step-up and the same reason: 200 with the organisation, ACTIVE', async () => {
    const { app, asked } = await withChanges(ACTIVE);

    const response = await app.inject(post('/unfreeze/confirm', { reason: 'All clear', stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ organization: { id: ORG, status: 'ACTIVE' } });
    expect(asked).toMatchObject([
      {
        kind: 'unfreezeConfirm',
        keyed: { operation: 'organization.unfreeze.confirm' },
        reason: 'All clear',
        stepUpChallengeId: CHALLENGE,
      },
    ]);
  });

  it.each([
    ['/unfreeze', {}],
    ['/unfreeze', { reason: '' }],
    ['/unfreeze', { reason: 'Call 0501234567 for details' }],
    ['/unfreeze', { reason: 'All clear', more: 1 }],
    ['/unfreeze/confirm', { reason: 'All clear' }],
    ['/unfreeze/confirm', { stepUpChallengeId: CHALLENGE }],
  ])(
    'refuses %s with %j (no reason, one that can’t be kept, no step-up) before the use case runs',
    async (path, body) => {
      const { app, asked } = await withChanges(ACTIVE);

      expect((await app.inject(post(path, body))).statusCode).toBe(400);
      expect(asked).toEqual([]);
    },
  );

  it.each([
    [409, 'ORG_NOT_FROZEN'],
    [409, 'PENDING_REQUESTS_TOO_MANY'],
    [403, 'STEP_UP_FAILED'],
  ] as const)('answers %i %s as the use case refuses', async (status, code) => {
    const { app } = await withChanges({ outcome: 'refused', status, code });

    const response = await app.inject(post('/unfreeze/confirm', { reason: 'All clear', stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });
});

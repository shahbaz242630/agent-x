// Phase 2 D8: the two cancel routes over HTTP, their use case a stub: what
// each hands it (the member or the agent, the idempotency request, the
// request's ID), the answer, who may call each before the use case runs, and
// the use case's own refusals. What the use case does is
// spend-request-cancels.db.test.ts.
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
import type { Cancelled, SpendRequestCancels } from './spend-request-cancels.ts';
import type { AgentActing } from './spend-request-decisions.ts';
import type { Member } from './use-case-work.ts';

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY_ID = '0199a0f0-0000-7000-8000-0000000000b1';
const REQUEST_ID = '0199a0f0-0000-7000-8000-0000000000c1';
const MEMBERSHIP_ID = '0199a0f0-0000-7000-8000-000000000033';

const KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const KEY_READING_ONLY = `axk_${'c'.repeat(32)}_${'b'.repeat(43)}`;
const accepted = (scopes: AcceptedKey['scopes']): AcceptedKey => ({
  orgId: ORG,
  agentId: AGENT_ID,
  keyId: KEY_ID,
  scopes,
  expiresAt: new Date('2099-12-28T09:00:00.000Z'),
});
const KEYS: ReadonlyMap<string, AcceptedKey> = new Map([
  [KEY, accepted(['requests:write'])],
  [KEY_READING_ONLY, accepted(['requests:read'])],
]);

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-12T08:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-12T08:00:05.000Z'),
  lastSeenAt: new Date('2026-10-12T08:10:00.000Z'),
  endsAt: new Date('2099-10-07T20:00:05.000Z'),
  idleEndsAt: new Date('2099-10-07T08:40:00.000Z'),
};

const CANCELLED: SpendRequestRecord = {
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
  status: 'CANCELLED',
};

type Role = 'admin' | 'approver' | 'developer' | 'viewer';

interface Asked {
  readonly by: Member | AgentActing;
  readonly idempotent: IdempotentRequest;
  readonly requestId: string;
}

afterEach(closeServers);

/** A server whose use case answers `answer`, recording what it was asked, the member signed in as `role`. */
async function withCancels(answer: Cancelled = { outcome: 'cancelled', request: CANCELLED }, role: Role = 'admin') {
  const asked: Asked[] = [];
  const cancels: SpendRequestCancels = {
    byMember: (member, idempotent, requestId) => {
      asked.push({ by: member, idempotent, requestId });
      return Promise.resolve(answer);
    },
    byAgent: (agent, idempotent, requestId) => {
      asked.push({ by: agent, idempotent, requestId });
      return Promise.resolve(answer);
    },
  };
  const app = await routeServer({
    live: LIVE,
    member: { outcome: 'active', id: MEMBERSHIP_ID, role },
    checkAgentKey: (text) => {
      const key = KEYS.get(text);
      return Promise.resolve(key === undefined ? { outcome: 'refused' } : { outcome: 'accepted', key });
    },
    spendRequestCancels: cancels,
  });
  return { app, asked };
}

/** A signed-in member's headers, from our own origin. */
const memberHeaders = (idempotencyKey: string) => ({
  cookie: `${SESSION_COOKIE}=${COOKIE}`,
  [ORGANIZATION_HEADER]: ORG,
  origin: PUBLIC_ORIGIN,
  'idempotency-key': idempotencyKey,
});

const asMember = (id = REQUEST_ID, idempotencyKey = 'cancel-1'): InjectOptions => ({
  method: 'POST',
  url: `/v1/spend-requests/${id}/cancel`,
  headers: memberHeaders(idempotencyKey),
});

const asAgent = (key = KEY, id = REQUEST_ID): InjectOptions => ({
  method: 'POST',
  url: `/v1/agent/spend-requests/${id}/cancel`,
  headers: { authorization: `Bearer ${key}`, 'idempotency-key': 'cancel-1' },
});

/** The request as both routes show it. */
const SHOWN = {
  id: REQUEST_ID,
  status: 'CANCELLED',
  decision: 'REQUIRE_APPROVAL',
  amountMinor: 200_000,
  currency: 'AED',
  orderReference: 'INV_22',
  bankReference: 'INV-22',
};

describe('POST /v1/spend-requests/{id}/cancel: an admin or approver cancels (D8)', () => {
  it.each(['admin', 'approver'] as const)(
    'hands the use case the %s and the request, and answers 200',
    async (role) => {
      const { app, asked } = await withCancels(undefined, role);
      const response = await app.inject(asMember());

      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject(SHOWN);
      expect(asked).toHaveLength(1);
      const [first] = asked;
      expect(first?.by).toMatchObject({ orgId: ORG, userId: LIVE.userId });
      expect(first?.requestId).toBe(REQUEST_ID);
      expect(first?.idempotent).toMatchObject({
        orgId: ORG,
        client: { kind: 'user', id: LIVE.userId },
        operation: 'spend-requests.cancel',
        key: 'cancel-1',
      });
    },
  );

  it.each(['developer', 'viewer'] as const)('refuses a %s before the use case runs', async (role) => {
    const { app, asked } = await withCancels(undefined, role);
    const response = await app.inject(asMember());

    expect(response.statusCode).toBe(403);
    expect(asked).toEqual([]);
  });

  it('refuses an ID that isn’t one, a missing idempotency key and an agent’s key, before the use case runs', async () => {
    const { app, asked } = await withCancels();
    expect((await app.inject(asMember('not-an-id'))).statusCode).toBe(400);
    const noKey = asMember();
    noKey.headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };
    expect((await app.inject(noKey)).json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_INVALID' } });
    const agent = await app.inject({
      ...asMember(),
      headers: { authorization: `Bearer ${KEY}`, 'idempotency-key': 'x' },
    });
    expect([401, 403]).toContain(agent.statusCode);
    expect(asked).toEqual([]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [409, 'REQUEST_NOT_CANCELLABLE'],
    [403, 'FORBIDDEN'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal: %i %s', async (status, code) => {
    const { app } = await withCancels({ outcome: 'refused', status, code });
    const response = await app.inject(asMember());

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('answers a key used for another request, and one still being done, as the idempotency store says', async () => {
    const reused = await withCancels({ outcome: 'conflict' });
    expect((await reused.app.inject(asMember())).json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_REUSED' } });
    const busy = await withCancels({ outcome: 'busy' });
    expect((await busy.app.inject(asMember())).json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_BUSY' } });
  });
});

describe('the reasons each route shows (decision 11c)', () => {
  const refused: SpendRequestRecord = {
    ...CANCELLED,
    decision: 'DENY',
    reasons: ['DUPLICATE_ORDER_REFERENCE', 'APPROVAL_THRESHOLD'],
    status: 'DENIED',
  };
  const codes = (response: { json: () => { reasons: { code: string }[] } }) =>
    response.json().reasons.map(({ code }) => code);

  it('shows a person every reason, and the agent only the refusal’s own', async () => {
    const { app } = await withCancels({ outcome: 'cancelled', request: refused });

    expect(codes(await app.inject(asMember()))).toEqual(['DUPLICATE_ORDER_REFERENCE', 'APPROVAL_THRESHOLD']);
    expect(codes(await app.inject(asAgent()))).toEqual(['DUPLICATE_ORDER_REFERENCE']);
  });
});

describe('POST /v1/agent/spend-requests/{id}/cancel: the agent cancels its own (D8)', () => {
  it('hands the use case the agent, its key and the request, and answers 200', async () => {
    const { app, asked } = await withCancels();
    const response = await app.inject(asAgent());

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject(SHOWN);
    const [first] = asked;
    expect(first?.by).toEqual({ orgId: ORG, agentId: AGENT_ID, keyId: KEY_ID });
    expect(first?.idempotent).toMatchObject({
      client: { kind: 'agent', id: AGENT_ID },
      operation: 'spend-requests.agent-cancel',
    });
  });

  it('refuses a key without requests:write and a member’s session, before the use case runs', async () => {
    const { app, asked } = await withCancels();
    expect((await app.inject(asAgent(KEY_READING_ONLY))).json()).toMatchObject({
      error: { code: 'INSUFFICIENT_SCOPE' },
    });
    const member = await app.inject({ ...asAgent(), headers: memberHeaders('cancel-1') });
    expect([401, 403]).toContain(member.statusCode);
    expect(asked).toEqual([]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [409, 'REQUEST_NOT_CANCELLABLE'],
  ] as const)('answers the use case’s refusal: %i %s', async (status, code) => {
    const { app } = await withCancels({ outcome: 'refused', status, code });
    const response = await app.inject(asAgent());

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });
});

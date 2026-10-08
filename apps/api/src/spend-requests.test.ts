// Phase 2 D4r: the agent's spend-request route over HTTP, its use case a
// stub: what it hands decideAndReserve (the agent, its key, the idempotency
// request, the checked body), the answer field by field with the bank
// reference shown only when it differs (decision 8), the edge's refusals
// before the use case runs, and the use case's own. What the use case does
// is spend-request-decisions.db.test.ts.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LiveSession } from '@agentx/core/modules/identity';
import type { SpendRequestRecord } from '@agentx/core/modules/spend-requests';
import { money, REASON_CODES } from '@agentx/core/shared-kernel';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { closeServers, COOKIE, ORG, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type {
  AgentActing,
  SpendAskedByAgent,
  SpendRequestDecided,
  SpendRequestDecisions,
} from './spend-request-decisions.ts';

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY_ID = '0199a0f0-0000-7000-8000-0000000000b1';
const REQUEST_ID = '0199a0f0-0000-7000-8000-0000000000c1';
const MANDATE_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const SUPPLIER_ID = '0199a0f0-0000-7000-8000-0000000000e1';
const SOURCE_ID = '0199a0f0-0000-7000-8000-0000000000f1';

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
  [KEY_READING_ONLY, accepted(['requests:read', 'sources:read'])],
]);

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-07T08:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-07T08:00:05.000Z'),
  lastSeenAt: new Date('2026-10-07T08:10:00.000Z'),
  endsAt: new Date('2099-10-07T20:00:05.000Z'),
  idleEndsAt: new Date('2099-10-07T08:40:00.000Z'),
};

const BODY = {
  amountMinor: 125_050,
  currency: 'AED',
  supplierId: SUPPLIER_ID,
  fundingSourceId: SOURCE_ID,
  orderReference: 'PO-1',
  purpose: 'Printer paper',
};

const ALLOWED: SpendRequestRecord = {
  id: REQUEST_ID,
  agentId: AGENT_ID,
  mandateId: MANDATE_ID,
  supplierId: SUPPLIER_ID,
  fundingSourceId: SOURCE_ID,
  amount: money(125_050n, 'AED'),
  orderReference: 'PO-1',
  decision: 'ALLOW',
  reasons: [],
  status: 'APPROVED',
};

interface Asked {
  readonly agent: AgentActing;
  readonly idempotent: IdempotentRequest;
  readonly asked: SpendAskedByAgent;
}

afterEach(closeServers);

/** A server whose use case answers `answer`, recording what it was asked. */
async function withDecisions(answer: SpendRequestDecided = { outcome: 'decided', request: ALLOWED }) {
  const asked: Asked[] = [];
  const decisions: SpendRequestDecisions = {
    decideAndReserve: (agent, idempotent, request) => {
      asked.push({ agent, idempotent, asked: request });
      return Promise.resolve(answer);
    },
  };
  const app = await routeServer({
    live: LIVE,
    findMembership: () => Promise.resolve({ outcome: 'active', id: LIVE.userId, role: 'admin' } as const),
    checkAgentKey: (text) => {
      const key = KEYS.get(text);
      return Promise.resolve(key === undefined ? { outcome: 'refused' } : { outcome: 'accepted', key });
    },
    spendRequestDecisions: decisions,
  });
  return { app, asked };
}

const asAgent = (body: Record<string, unknown>, { key = KEY, idempotencyKey = 'ask-1' } = {}): InjectOptions => ({
  method: 'POST',
  url: '/v1/spend-requests',
  headers: { authorization: `Bearer ${key}`, 'idempotency-key': idempotencyKey },
  payload: body,
});

describe('POST /v1/spend-requests: an agent asks to pay (D4r)', () => {
  it('hands the use case the agent and its key, its idempotency request and the body checked, and answers 201', async () => {
    const { app, asked } = await withDecisions();
    const response = await app.inject(asAgent({ ...BODY, purpose: 'Cafe\u0301 beans', orderReference: 'PO-e\u0301' }));

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      id: REQUEST_ID,
      status: 'APPROVED',
      decision: 'ALLOW',
      reasons: [],
      amountMinor: 125_050,
      currency: 'AED',
      supplierId: SUPPLIER_ID,
      fundingSourceId: SOURCE_ID,
      mandateId: MANDATE_ID,
      orderReference: 'PO-1',
      bankReference: null,
    });
    expect(asked).toHaveLength(1);
    const [first] = asked;
    expect(first?.agent).toEqual({ orgId: ORG, agentId: AGENT_ID, keyId: KEY_ID });
    expect(first?.idempotent).toMatchObject({
      orgId: ORG,
      client: { kind: 'agent', id: AGENT_ID },
      operation: 'spend-requests.create',
      key: 'ask-1',
    });
    expect(first?.asked).toEqual({
      amount: money(125_050n, 'AED'),
      supplierId: SUPPLIER_ID,
      fundingSourceId: SOURCE_ID,
      // Each composed, as the request keeps it.
      orderReference: 'PO-é',
      purpose: 'Café beans',
    });
  });

  it('shows the bank reference when it differs from the order reference (decision 8)', async () => {
    const { app } = await withDecisions({ outcome: 'decided', request: { ...ALLOWED, orderReference: 'INV_22#' } });
    const response = await app.inject(asAgent({ ...BODY, orderReference: 'INV_22#' }));

    expect(response.json()).toMatchObject({ orderReference: 'INV_22#', bankReference: 'INV-22' });
  });

  it('answers a request denied with each reason and what it means, as 201: it is recorded', async () => {
    const denied: SpendRequestRecord = {
      ...ALLOWED,
      mandateId: null,
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_NOT_IN_FORCE'],
      status: 'DENIED',
    };
    const { app } = await withDecisions({ outcome: 'decided', request: denied });
    const response = await app.inject(asAgent(BODY));

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({
      status: 'DENIED',
      decision: 'REQUIRE_NEW_MANDATE',
      mandateId: null,
      reasons: [{ code: 'MANDATE_NOT_IN_FORCE', message: REASON_CODES.MANDATE_NOT_IN_FORCE }],
    });
  });

  it.each([
    ['an amount of nothing', { amountMinor: 0 }],
    ['a fraction of a fils', { amountMinor: 1.5 }],
    ['an amount as text', { amountMinor: '100' }],
    ['an amount past 2^53 − 1', { amountMinor: 2 ** 53 }],
    ['a currency that is no ISO code', { currency: 'dirham' }],
    ['a supplier not named by its ID', { supplierId: 'acme' }],
    ['an order reference of 101 characters', { orderReference: 'r'.repeat(101) }],
    ['an order reference with no letter or digit', { orderReference: '#' }],
    ['an order reference with a control character', { orderReference: 'PO\u00071' }],
    ['a purpose of 201 characters', { purpose: 'p'.repeat(201) }],
    ['a purpose with spaces at its ends', { purpose: ' Paper ' }],
    ['a field it does not take', { approvalThresholdMinor: 1 }],
  ])('refuses %s as 400, before the use case runs', async (_what, change) => {
    const { app, asked } = await withDecisions();
    const response = await app.inject(asAgent({ ...BODY, ...change }));

    expect(response.statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('takes the longest body the schema allows within the body limit: every character escaped, each sent decomposed (B8-3)', async () => {
    const { app, asked } = await withDecisions();
    const escaped = (text: string) =>
      Array.from(
        text,
        (c) => `${String.fromCharCode(92)}u${(c.codePointAt(0) ?? 0).toString(16).padStart(4, '0')}`,
      ).join('');
    // U+1F82 sent as its four code points: one character kept, four sent.
    const decomposed = (count: number) => escaped('\u1F82'.normalize('NFD').repeat(count));
    const body = `{${[
      ['amountMinor', String(Number.MAX_SAFE_INTEGER)],
      ['currency', `"${escaped('AED')}"`],
      ['supplierId', `"${escaped(SUPPLIER_ID)}"`],
      ['fundingSourceId', `"${escaped(SOURCE_ID)}"`],
      ['orderReference', `"${decomposed(100)}"`],
      ['purpose', `"${decomposed(200)}"`],
    ]
      .map(([name, value]) => `"${escaped(name ?? '')}":${value ?? ''}`)
      .join(',')}}`;
    const response = await app.inject({
      ...asAgent(BODY),
      payload: body,
      headers: { ...asAgent(BODY).headers, 'content-type': 'application/json' },
    });

    expect(response.statusCode).toBe(201);
    expect(asked[0]?.asked.orderReference).toBe('\u1F82'.repeat(100));
  });

  it('refuses a request with no idempotency key, a key without requests:write and a member’s session, before the use case runs', async () => {
    const { app, asked } = await withDecisions();
    const noKey = asAgent(BODY);
    noKey.headers = { authorization: `Bearer ${KEY}` };

    expect((await app.inject(noKey)).json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_INVALID' } });
    expect((await app.inject(asAgent(BODY, { key: KEY_READING_ONLY }))).json()).toMatchObject({
      error: { code: 'INSUFFICIENT_SCOPE' },
    });
    const member = await app.inject({
      ...asAgent(BODY),
      headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, 'idempotency-key': 'ask-1' },
    });
    expect([401, 403]).toContain(member.statusCode);
    expect(asked).toEqual([]);
  });

  it.each([
    [422, 'CURRENCY_NOT_ALLOWED'],
    [409, 'ORG_FROZEN'],
    [401, 'UNAUTHENTICATED'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal: %i %s', async (status, code) => {
    const { app } = await withDecisions({ outcome: 'refused', status, code });
    const response = await app.inject(asAgent(BODY));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('answers a key used for another request, and one still being done, as the idempotency store says', async () => {
    const reused = await withDecisions({ outcome: 'conflict' });
    expect((await reused.app.inject(asAgent(BODY))).json()).toMatchObject({
      error: { code: 'IDEMPOTENCY_KEY_REUSED' },
    });
    const busy = await withDecisions({ outcome: 'busy' });
    const response = await busy.app.inject(asAgent(BODY));
    expect(response.json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_BUSY' } });
    expect(response.headers['retry-after']).toBe('5');
  });
});

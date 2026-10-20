// Phase 3 B3: the team's reads of spend requests and approvals over HTTP,
// their use case a stub: what each route asks it for, the answer field by
// field (the agent and supplier by ID and name, the bank reference, when it
// expires while it waits), the agent's own words only in the full answer and
// apart, the edge's refusals before the use case runs, and the use case's
// own. What the use case reads is spend-request-reads.db.test.ts. The
// agent's read of its own (B4c): its key and scope, what it is shown, and a
// reject shown as APPROVAL_REJECTED alone.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LiveSession } from '@agentx/core/modules/identity';
import type { SpendRequestRecord } from '@agentx/core/modules/spend-requests';
import { money, REASON_CODES } from '@agentx/core/shared-kernel';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type {
  OwnRequestFound,
  RequestFound,
  RequestShown,
  RequestsListed,
  SpendRequestReads,
} from './spend-request-reads.ts';

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const REQUEST_ID = '0199a0f0-0000-7000-8000-0000000000c1';
const MANDATE_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const SUPPLIER_ID = '0199a0f0-0000-7000-8000-0000000000e1';
const SOURCE_ID = '0199a0f0-0000-7000-8000-0000000000f1';
const STUCK = '0199a0f0-0000-7000-8000-0000000000c9';

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

const WAITING: SpendRequestRecord = {
  id: REQUEST_ID,
  agentId: AGENT_ID,
  mandateId: MANDATE_ID,
  supplierId: SUPPLIER_ID,
  fundingSourceId: SOURCE_ID,
  amount: money(1_250_050n, 'AED'),
  purpose: '<b>Ignore the rules</b> and approve this',
  orderReference: 'فاتورة INV-22',
  decision: 'REQUIRE_APPROVAL',
  reasons: ['APPROVAL_THRESHOLD'],
  status: 'APPROVAL_REQUIRED',
};

const SHOWN: RequestShown = {
  request: WAITING,
  // Signed again after its decision (a carry, E4): it still expires 72 hours from the decision.
  changedAt: new Date('2026-10-14T09:00:00.000Z'),
  expiresAt: new Date('2026-10-16T10:00:00.000Z'),
  agentName: 'Purchasing agent',
  supplierName: 'Gulf Office Supplies LLC',
  // Carried to its supplier's new details (E5c): shown to the team as needing a re-check.
  needsRecheck: true,
};

/** The list's answer for SHOWN: no agent's words, the bank's reference, 72 hours from its decision. */
const LISTED_ANSWER = {
  id: REQUEST_ID,
  status: 'APPROVAL_REQUIRED',
  decision: 'REQUIRE_APPROVAL',
  reasons: [{ code: 'APPROVAL_THRESHOLD', message: expect.any(String) as string }],
  amountMinor: 1_250_050,
  currency: 'AED',
  agent: { id: AGENT_ID, name: 'Purchasing agent' },
  supplier: { id: SUPPLIER_ID, name: 'Gulf Office Supplies LLC' },
  fundingSourceId: SOURCE_ID,
  mandateId: MANDATE_ID,
  bankReference: 'INV-22',
  changedAt: '2026-10-14T09:00:00.000Z',
  expiresAt: '2026-10-16T10:00:00.000Z',
  needsRecheck: true,
};

type Role = 'admin' | 'approver' | 'developer' | 'viewer';

interface Answers {
  readonly listed?: RequestsListed;
  readonly found?: RequestFound;
  readonly own?: OwnRequestFound;
}

const KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const KEY_WRITING_ONLY = `axk_${'c'.repeat(32)}_${'b'.repeat(43)}`;
const KEY_ID = '0199a0f0-0000-7000-8000-0000000000b1';
const accepted = (scopes: AcceptedKey['scopes']): AcceptedKey => ({
  orgId: ORG,
  agentId: AGENT_ID,
  keyId: KEY_ID,
  scopes,
  expiresAt: new Date('2099-12-28T09:00:00.000Z'),
});
const KEYS: ReadonlyMap<string, AcceptedKey> = new Map([
  [KEY, accepted(['requests:read'])],
  [KEY_WRITING_ONLY, accepted(['requests:write'])],
]);

afterEach(closeServers);

/** A server whose reads answer `answers`, recording what each was asked, the member signed in as `role`. */
async function withReads(answers: Answers, role: Role = 'admin') {
  const asked: unknown[][] = [];
  const reads: SpendRequestReads = {
    list: (...args) => {
      asked.push(args);
      return Promise.resolve(answers.listed ?? { outcome: 'listed', requests: [], next: null, unchecked: [] });
    },
    show: (...args) => {
      asked.push(args);
      return Promise.resolve(answers.found ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
    ofAgent: (...args) => {
      asked.push(args);
      return Promise.resolve(answers.own ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
  };
  const app = await routeServer({
    live: LIVE,
    member: { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role },
    checkAgentKey: (text) => {
      const key = KEYS.get(text);
      return Promise.resolve(key === undefined ? { outcome: 'refused' } : { outcome: 'accepted', key });
    },
    spendRequestReads: reads,
  });
  return { app, asked };
}

const get = (url: string): InjectOptions => ({
  method: 'GET',
  url,
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN },
});

describe('GET /v1/spend-requests: every request, newest first (Phase 3 B3)', () => {
  it('lists a page to any member, the agent and supplier by ID and name, never the agent’s own words', async () => {
    const { app, asked } = await withReads(
      { listed: { outcome: 'listed', requests: [SHOWN], next: REQUEST_ID, unchecked: [STUCK] } },
      'viewer',
    );
    const reply = await app.inject(get('/v1/spend-requests'));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({ spendRequests: [LISTED_ANSWER], next: REQUEST_ID, unchecked: [STUCK] });
    expect(reply.body).not.toContain('Ignore the rules');
    expect(asked).toEqual([[ORG, { after: null, limit: 50 }, 'all', expect.any(String)]]);
  });

  it('asks for the page named, and shows no expiry for one no longer waiting', async () => {
    const approved: RequestShown = {
      ...SHOWN,
      request: { ...WAITING, decision: 'ALLOW', reasons: [], status: 'APPROVED' },
      expiresAt: null,
    };
    const { app, asked } = await withReads({
      listed: { outcome: 'listed', requests: [approved], next: null, unchecked: [] },
    });
    const reply = await app.inject(get(`/v1/spend-requests?after=${STUCK}&limit=1`));

    expect(reply.json()).toMatchObject({ spendRequests: [{ status: 'APPROVED', reasons: [], expiresAt: null }] });
    expect(asked[0]?.[1]).toEqual({ after: STUCK, limit: 1 });
  });

  it('refuses a page past the most before the use case runs, and answers a list refused', async () => {
    const { app, asked } = await withReads({
      listed: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' },
    });

    expect((await app.inject(get('/v1/spend-requests?limit=51'))).statusCode).toBe(400);
    expect(asked).toEqual([]);
    expect((await app.inject(get('/v1/spend-requests'))).statusCode).toBe(503);
  });

  it('refuses one not signed in, before the use case runs', async () => {
    const { app, asked } = await withReads({});
    const reply = await app.inject({ method: 'GET', url: '/v1/spend-requests' });

    expect(reply.statusCode).toBe(401);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/approvals: the requests waiting, oldest first (Phase 3 B3)', () => {
  it('lists those waiting to any member, as the list shows them', async () => {
    const { app, asked } = await withReads(
      { listed: { outcome: 'listed', requests: [SHOWN], next: null, unchecked: [] } },
      'developer',
    );
    const reply = await app.inject(get('/v1/approvals?limit=10'));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({ waiting: [LISTED_ANSWER], next: null, unchecked: [] });
    expect(asked).toEqual([[ORG, { after: null, limit: 10 }, 'waiting', expect.any(String)]]);
  });

  it('answers a list refused', async () => {
    const { app } = await withReads({ listed: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });

    expect((await app.inject(get('/v1/approvals'))).statusCode).toBe(503);
  });
});

describe('GET /v1/spend-requests/{id}: one in full (Phase 3 B3)', () => {
  it('shows it to any member with the agent’s own words apart, labelled, exactly as written (SEC-AG-10)', async () => {
    const { app, asked } = await withReads(
      { found: { outcome: 'found', shown: SHOWN, rejection: null, voiding: null } },
      'viewer',
    );
    const reply = await app.inject(get(`/v1/spend-requests/${REQUEST_ID}`));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      ...LISTED_ANSWER,
      agentWrote: { purpose: '<b>Ignore the rules</b> and approve this', orderReference: 'فاتورة INV-22' },
      rejection: null,
      voiding: null,
    });
    expect(reply.headers['content-type']).toMatch(/^application\/json/);
    expect(asked).toEqual([[ORG, REQUEST_ID, expect.any(String)]]);
  });

  it('shows one rejected with its reject: who, when and why (B4a)', async () => {
    const rejection = { byUserId: LIVE.userId, at: new Date('2026-10-13T09:00:00.000Z'), reason: 'Not this month' };
    const denied = { ...SHOWN, request: { ...SHOWN.request, status: 'DENIED' as const }, expiresAt: null };
    const { app } = await withReads({ found: { outcome: 'found', shown: denied, rejection, voiding: null } });

    expect((await app.inject(get(`/v1/spend-requests/${REQUEST_ID}`))).json()).toMatchObject({
      status: 'DENIED',
      rejection: { byUserId: LIVE.userId, at: '2026-10-13T09:00:00.000Z', reason: 'Not this month' },
      voiding: null,
    });
  });

  it('shows one voided with its void: when and its causes, described (C2b)', async () => {
    const voiding = { at: new Date('2026-10-14T09:00:00.000Z'), causes: ['AGENT_SUSPENDED'] as const };
    const denied = { ...SHOWN, request: { ...SHOWN.request, status: 'DENIED' as const }, expiresAt: null };
    const { app } = await withReads({ found: { outcome: 'found', shown: denied, rejection: null, voiding } });

    expect((await app.inject(get(`/v1/spend-requests/${REQUEST_ID}`))).json()).toMatchObject({
      status: 'DENIED',
      rejection: null,
      voiding: {
        at: '2026-10-14T09:00:00.000Z',
        reasons: [{ code: 'AGENT_SUSPENDED', message: REASON_CODES.AGENT_SUSPENDED }],
      },
    });
  });

  it('answers one not found, or that can’t be believed, as the use case says', async () => {
    const missing = await withReads({});
    expect((await missing.app.inject(get(`/v1/spend-requests/${REQUEST_ID}`))).statusCode).toBe(404);

    const tampered = await withReads({ found: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });
    expect((await tampered.app.inject(get(`/v1/spend-requests/${REQUEST_ID}`))).statusCode).toBe(503);
  });

  it('refuses an ID that is not one before the use case runs', async () => {
    const { app, asked } = await withReads({});

    expect((await app.inject(get('/v1/spend-requests/not-an-id'))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/agent/spend-requests/{id}: the agent reads its own (Phase 3 B4c)', () => {
  const asAgent = (key = KEY, id = REQUEST_ID): InjectOptions => ({
    method: 'GET',
    url: `/v1/agent/spend-requests/${id}`,
    headers: { authorization: `Bearer ${key}` },
  });
  const codes = (response: { json: () => { reasons: { code: string }[] } }) =>
    response.json().reasons.map(({ code }) => code);

  it('asks for the agent’s own, by its key, and shows it as it stands, with no team-only field', async () => {
    const { app, asked } = await withReads({ own: { outcome: 'found', request: WAITING, endedBecause: null } });
    const reply = await app.inject(asAgent());

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toMatchObject({ id: REQUEST_ID, status: 'APPROVAL_REQUIRED', decision: 'REQUIRE_APPROVAL' });
    expect(codes(reply)).toEqual(['APPROVAL_THRESHOLD']);
    expect(reply.json()).not.toHaveProperty('agent');
    expect(reply.json()).not.toHaveProperty('rejection');
    expect(asked).toEqual([[ORG, AGENT_ID, REQUEST_ID, expect.any(String)]]);
  });

  it('shows one a person rejected as DENIED with APPROVAL_REJECTED alone (decision 6)', async () => {
    const denied = { ...WAITING, status: 'DENIED' as const };
    const { app } = await withReads({
      own: { outcome: 'found', request: denied, endedBecause: ['APPROVAL_REJECTED'] },
    });
    const reply = await app.inject(asAgent());

    expect(reply.json()).toMatchObject({ status: 'DENIED' });
    expect(codes(reply)).toEqual(['APPROVAL_REJECTED']);
  });

  it('shows one voided as DENIED with REQUEST_VOIDED, then its causes (C2b)', async () => {
    const denied = { ...WAITING, status: 'DENIED' as const };
    const endedBecause = ['REQUEST_VOIDED', 'MANDATE_NOT_IN_FORCE'] as const;
    const { app } = await withReads({ own: { outcome: 'found', request: denied, endedBecause } });

    expect(codes(await app.inject(asAgent()))).toEqual(['REQUEST_VOIDED', 'MANDATE_NOT_IN_FORCE']);
  });

  it('shows a refusal’s own reasons alone, as at its decision (decision 11c)', async () => {
    const refused = {
      ...WAITING,
      decision: 'DENY' as const,
      reasons: ['DUPLICATE_ORDER_REFERENCE', 'APPROVAL_THRESHOLD'] as const,
      status: 'DENIED' as const,
    };
    const { app } = await withReads({ own: { outcome: 'found', request: refused, endedBecause: null } });

    expect(codes(await app.inject(asAgent()))).toEqual(['DUPLICATE_ORDER_REFERENCE']);
  });

  it('refuses a key without requests:read, a member’s session and an ID that isn’t one, before the use case runs', async () => {
    const { app, asked } = await withReads({});

    expect((await app.inject(asAgent(KEY_WRITING_ONLY))).json()).toMatchObject({
      error: { code: 'INSUFFICIENT_SCOPE' },
    });
    const member = await app.inject(get(`/v1/agent/spend-requests/${REQUEST_ID}`));
    expect([401, 403]).toContain(member.statusCode);
    expect((await app.inject(asAgent(KEY, 'not-an-id'))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal: %i %s', async (status, code) => {
    const { app } = await withReads({ own: { outcome: 'refused', status, code } });
    const reply = await app.inject(asAgent());

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });
});

// Phase 6 C2a, 6C2c: a spend request's evidence routes, its read and its
// download, answering an admin with each outcome of the use case, admins
// alone, its ID checked at the edge. What each reads and the download records
// in the database is spend-request-evidence.db.test.ts; who reaches them,
// role-matrix.test.ts.
import type { MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { liveSession } from './live-session.helper.test.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type {
  Evidence,
  EvidenceRead,
  EvidenceView,
  EvidenceWrite,
  SpendRequestEvidence,
} from './spend-request-evidence.ts';

const LIVE = liveSession('2026-11-15T09:00:00.000Z');
const REQUEST_ID = '0199a0f0-0000-7000-8000-0000000c2a01';
const EVENT = {
  seq: '7',
  id: '0199a0f0-0000-7000-8000-0000000c2a02',
  recordedAt: '2026-11-15T08:00:00.000Z',
  actor: { type: 'agent' as const, id: '0199a0f0-0000-7000-8000-0000000c2a03', name: 'Buyer', email: null },
  action: 'spend_request.decided',
  subject: { type: 'spend_request', id: REQUEST_ID, version: 1 },
  details: [{ name: 'decision', value: 'DENY' }],
  hash: 'a'.repeat(64),
  prevHash: 'b'.repeat(64),
};

/** A denied request's evidence: no reservation, no payment. */
const EVIDENCE: Evidence = {
  id: '0199a0f0-0000-7000-8000-0000000c2a04',
  recordSeq: '8',
  upToSeq: '8',
  spendRequest: {
    id: REQUEST_ID,
    status: 'DENIED',
    decision: 'DENY',
    reasons: [],
    amountMinor: 12_500,
    currency: 'AED',
    orderReference: 'INV-1',
    bankReference: 'INV-1',
    purpose: 'Printer paper',
    idempotencyKey: 'k-agent-1',
    inputHash: 'c'.repeat(64),
    decidedAt: '2026-11-15T08:00:00.000Z',
    changedAt: '2026-11-15T08:00:00.000Z',
    expiresAt: null,
  },
  agent: { id: EVENT.actor.id, name: 'Buyer', keyId: '0199a0f0-0000-7000-8000-0000000c2a05' },
  mandate: null,
  policies: { organizationPolicyVersionId: null, mandatePolicyVersionId: null },
  supplier: {
    id: '0199a0f0-0000-7000-8000-0000000c2a06',
    name: 'Paper Co',
    version: {
      id: '0199a0f0-0000-7000-8000-0000000c2a08',
      number: 2,
      name: 'Paper Co',
      beneficiaryRef: 'fake-beneficiary-c2a08',
      verification: null,
    },
  },
  fundingSource: {
    id: '0199a0f0-0000-7000-8000-0000000c2a07',
    holderName: 'Acme LLC',
    hint: 'AE…6026',
    partner: 'fake',
    accountConsentId: 'fake-consent-c2a07',
  },
  approval: null,
  rejection: null,
  voiding: null,
  reservation: null,
  payment: null,
  events: [{ ...EVENT, actor: { ...EVENT.actor, shownFrom: 'agent' as const } }],
};

/** The same bundle as read on screen: no record of its own. */
const { id: _record, recordSeq: _recordSeq, ...EVIDENCE_READ } = EVIDENCE satisfies EvidenceRead;

afterEach(closeServers);

async function withEvidence(answer: EvidenceWrite, role: Role = 'admin', view?: EvidenceView) {
  const asked: string[] = [];
  const read: string[] = [];
  const evidence: SpendRequestEvidence = {
    read: (orgId, requestId) => {
      expect(orgId).toBe(ORG);
      read.push(requestId);
      return Promise.resolve(view ?? { outcome: 'read', evidence: EVIDENCE_READ });
    },
    export: (member, keyed, requestId) => {
      expect(member).toMatchObject({ orgId: ORG, userId: LIVE.userId });
      expect(keyed).toMatchObject({ operation: 'spend-requests.evidence-export', key: 'k-1' });
      asked.push(requestId);
      return Promise.resolve(answer);
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, spendRequestEvidence: evidence });
  return { app, asked, read };
}

const get = (id: string): InjectOptions => ({
  method: 'GET',
  url: `/v1/spend-requests/${id}/evidence`,
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG },
});

const post = (id: string, payload?: unknown): InjectOptions => ({
  method: 'POST',
  url: `/v1/spend-requests/${id}/evidence-exports`,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': 'k-1',
    ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
  },
  ...(payload === undefined ? {} : { payload: JSON.stringify(payload) }),
});

describe('POST /v1/spend-requests/{id}/evidence-exports (Phase 6 C2a, BR-16)', () => {
  it('answers 201 with the evidence whole, for the request named', async () => {
    const { app, asked } = await withEvidence({ outcome: 'exported', evidence: EVIDENCE });
    const reply = await app.inject(post(REQUEST_ID));

    expect(reply.statusCode).toBe(201);
    expect(reply.json()).toEqual({ evidence: EVIDENCE });
    expect(asked).toEqual([REQUEST_ID]);
  });

  it('takes an empty body too', async () => {
    const { app } = await withEvidence({ outcome: 'exported', evidence: EVIDENCE });

    expect((await app.inject(post(REQUEST_ID, {}))).statusCode).toBe(201);
  });

  it.each([
    ['an ID that isn’t a UUID', 'not-a-uuid', undefined],
    ['a body with a field', REQUEST_ID, { format: 'pdf' }],
  ])('refuses %s at the edge, the download never asked', async (_what, id, body) => {
    const { app, asked } = await withEvidence({ outcome: 'exported', evidence: EVIDENCE });

    expect((await app.inject(post(id, body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 404, code: 'NOT_FOUND' } as const, 404, 'NOT_FOUND'],
    [{ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } as const, 503, 'INTEGRITY_FAILED'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
    [{ outcome: 'busy' } as const, 409, 'IDEMPOTENCY_KEY_BUSY'],
  ])('answers the use case’s %o as %i %s', async (answer, status, code) => {
    const { app } = await withEvidence(answer);
    const reply = await app.inject(post(REQUEST_ID));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s (admins only)', async (role) => {
    const { app, asked } = await withEvidence({ outcome: 'exported', evidence: EVIDENCE }, role);

    expect((await app.inject(post(REQUEST_ID))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/spend-requests/{id}/evidence (6C2c, decision 24: a page read, not logged)', () => {
  it('answers 200 with the bundle as read, no record of its own, and never downloads', async () => {
    const { app, asked, read } = await withEvidence({ outcome: 'exported', evidence: EVIDENCE });
    const reply = await app.inject(get(REQUEST_ID));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({ evidence: EVIDENCE_READ });
    expect(reply.json()).not.toHaveProperty('evidence.recordSeq');
    expect(read).toEqual([REQUEST_ID]);
    expect(asked).toEqual([]);
  });

  it('refuses an ID that isn’t a UUID at the edge, the read never asked', async () => {
    const { app, read } = await withEvidence({ outcome: 'exported', evidence: EVIDENCE });

    expect((await app.inject(get('not-a-uuid'))).statusCode).toBe(400);
    expect(read).toEqual([]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
    [409, 'EVIDENCE_CHANGED_WHILE_READING'],
    [409, 'EVIDENCE_TOO_LARGE'],
  ] as const)('answers the read refused %i %s as it is', async (status, code) => {
    const { app } = await withEvidence({ outcome: 'exported', evidence: EVIDENCE }, 'admin', {
      outcome: 'refused',
      status,
      code,
    });
    const reply = await app.inject(get(REQUEST_ID));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s (admins only)', async (role) => {
    const { app, read } = await withEvidence({ outcome: 'exported', evidence: EVIDENCE }, role);

    expect((await app.inject(get(REQUEST_ID))).statusCode).toBe(403);
    expect(read).toEqual([]);
  });
});

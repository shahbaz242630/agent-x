// Phase 6 C2a: a spend request's evidence route, answering an admin with each
// outcome of the use case, admins alone, its ID checked at the edge. What the
// download reads and records in the database is spend-request-evidence.db.test.ts;
// who reaches it, role-matrix.test.ts.
import type { MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { liveSession } from './live-session.helper.test.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type { Evidence, EvidenceWrite, SpendRequestEvidence } from './spend-request-evidence.ts';

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
    version: { id: '0199a0f0-0000-7000-8000-0000000c2a08', number: 2, name: 'Paper Co', verification: null },
  },
  fundingSource: {
    id: '0199a0f0-0000-7000-8000-0000000c2a07',
    holderName: 'Acme LLC',
    hint: 'AE…6026',
    partner: 'fake',
  },
  approval: null,
  rejection: null,
  voiding: null,
  reservation: null,
  payment: null,
  events: [{ ...EVENT, actor: { ...EVENT.actor, shownFrom: 'agent' as const } }],
};

afterEach(closeServers);

async function withEvidence(answer: EvidenceWrite, role: Role = 'admin') {
  const asked: string[] = [];
  const evidence: SpendRequestEvidence = {
    export: (member, keyed, requestId) => {
      expect(member).toMatchObject({ orgId: ORG, userId: LIVE.userId });
      expect(keyed).toMatchObject({ operation: 'spend-requests.evidence-export', key: 'k-1' });
      asked.push(requestId);
      return Promise.resolve(answer);
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, spendRequestEvidence: evidence });
  return { app, asked };
}

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

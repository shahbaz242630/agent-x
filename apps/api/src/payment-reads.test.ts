// Phase 6 C1: the team's reads of payments over HTTP, their use case a stub:
// what each route asks it for (the page, the group, the exceptions), the
// answer field by field (the supplier by ID and name, the bank's and the
// partner's references, contradicted, where marking it failed stands, its
// history), never the payee's reference or the consent, the edge's refusals
// before the use case runs, and the use case's own. What the use case reads
// is payment-reads.db.test.ts.
import type { FailureProposalRecord } from '@agentx/core/modules/transactions';
import type { PaymentRecord } from '@agentx/core/modules/outcomes';
import { money } from '@agentx/core/shared-kernel';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { liveSession } from './live-session.helper.test.ts';
import type { PaymentFound, PaymentReads, PaymentShown, PaymentsListed } from './payment-reads.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PAYMENT_ID = '0199a0f0-0000-7000-8000-0000000000c1';
const INSTRUCTION_ID = '0199a0f0-0000-7000-8000-0000000000c3';
const REQUEST_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const VERSION_ID = '0199a0f0-0000-7000-8000-0000000000e2';
const SUPPLIER_ID = '0199a0f0-0000-7000-8000-0000000000e1';
const PROPOSAL_ID = '0199a0f0-0000-7000-8000-0000000000c2';
const PROPOSER = '0199a0f0-0000-7000-8000-000000000044';
const STUCK = '0199a0f0-0000-7000-8000-0000000000c9';

const LIVE = liveSession('2026-10-07T08:00:00.000Z', { endless: true });

const PAID: PaymentRecord = {
  transaction: {
    id: PAYMENT_ID,
    instructionId: INSTRUCTION_ID,
    status: 'SUCCEEDED',
    providerStatus: 'Rejected',
    paymentInstructionRef: 'fake-pi-0001',
    rejectCode: 'AANI.FF01',
    providerChangedAt: new Date('2026-10-14T09:30:00.000Z'),
    createdAt: new Date('2026-10-14T09:00:00.000Z'),
  },
  changedAt: new Date('2026-10-14T09:31:00.000Z'),
  spendRequestId: REQUEST_ID,
  supplierVersionId: VERSION_ID,
  amount: money(50_000n, 'AED'),
  paymentReference: 'INV-22',
  contradicted: true,
};

const SHOWN: PaymentShown = { payment: PAID, supplierId: SUPPLIER_ID, supplierName: 'Gulf Office Supplies LLC' };

/** The list's answer for SHOWN: its own fields alone, the supplier by ID and name. */
const LISTED_ANSWER = {
  id: PAYMENT_ID,
  spendRequestId: REQUEST_ID,
  status: 'SUCCEEDED',
  amountMinor: 50_000,
  currency: 'AED',
  supplier: { id: SUPPLIER_ID, name: 'Gulf Office Supplies LLC' },
  bankReference: 'INV-22',
  partnerReference: 'fake-pi-0001',
  bankStatus: 'Rejected',
  rejectCode: 'AANI.FF01',
  createdAt: '2026-10-14T09:00:00.000Z',
  changedAt: '2026-10-14T09:31:00.000Z',
  contradicted: true,
};

const PROPOSAL: FailureProposalRecord = {
  id: PROPOSAL_ID,
  transactionId: PAYMENT_ID,
  evidenceRef: 'BANK-NACK-77311',
  proposedBy: PROPOSER,
  status: 'OPEN',
  createdAt: new Date('2026-10-15T09:00:00.000Z'),
};

type Role = 'admin' | 'approver' | 'developer' | 'viewer';

interface Answers {
  readonly listed?: PaymentsListed;
  readonly found?: PaymentFound;
}

afterEach(closeServers);

/** A server whose reads answer `answers`, recording what each was asked, the member signed in as `role`. */
async function withReads(answers: Answers, role: Role = 'admin') {
  const asked: unknown[][] = [];
  const reads: PaymentReads = {
    list: (...args) => {
      asked.push(args);
      return Promise.resolve(answers.listed ?? { outcome: 'listed', payments: [], next: null, unchecked: [] });
    },
    show: (...args) => {
      asked.push(args);
      return Promise.resolve(answers.found ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
  };
  const app = await routeServer({
    live: LIVE,
    member: { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role },
    paymentReads: reads,
  });
  return { app, asked };
}

const get = (url: string, headers: Record<string, string> = {}): InjectOptions => ({
  method: 'GET',
  url,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    ...headers,
  },
});

describe('GET /v1/payments: every payment, newest first (Phase 6 C1)', () => {
  it.each(['admin', 'approver', 'developer', 'viewer'] as const)(
    'lists a page to a %s, the supplier by ID and name, never the payee or the consent',
    async (role) => {
      const { app, asked } = await withReads(
        { listed: { outcome: 'listed', payments: [SHOWN], next: PAYMENT_ID, unchecked: [STUCK] } },
        role,
      );
      const reply = await app.inject(get('/v1/payments'));

      expect(reply.statusCode).toBe(200);
      expect(reply.json()).toEqual({ payments: [LISTED_ANSWER], next: PAYMENT_ID, unchecked: [STUCK] });
      expect(reply.body).not.toMatch(/beneficiary|consent|licen[cs]e|legal/i);
      expect(asked).toEqual([[ORG, { after: null, limit: 50 }, 'all', expect.any(String)]]);
    },
  );

  it('asks for the page and the group named, and shows one the partner hasn’t spoken of with nulls', async () => {
    const pending: PaymentShown = {
      ...SHOWN,
      payment: {
        ...PAID,
        transaction: {
          ...PAID.transaction,
          status: 'SUBMITTED',
          providerStatus: null,
          paymentInstructionRef: null,
          rejectCode: null,
        },
        contradicted: false,
      },
    };
    const { app, asked } = await withReads({
      listed: { outcome: 'listed', payments: [pending], next: null, unchecked: [] },
    });
    const reply = await app.inject(get(`/v1/payments?after=${STUCK}&limit=1&status=pending`));

    expect(reply.json()).toMatchObject({
      payments: [{ status: 'SUBMITTED', partnerReference: null, bankStatus: null, rejectCode: null }],
    });
    expect(asked).toEqual([[ORG, { after: STUCK, limit: 1 }, 'pending', expect.any(String)]]);
  });

  it.each(['paid', 'failed', 'cancelled', 'unknown', 'reversed'])('asks for the %s group', async (status) => {
    const { app, asked } = await withReads({});

    expect((await app.inject(get(`/v1/payments?status=${status}`))).statusCode).toBe(200);
    expect(asked[0]?.[2]).toBe(status);
  });

  it.each([
    ['a page past the most', '/v1/payments?limit=51'],
    ['a group that isn’t one', '/v1/payments?status=exceptions'],
    ['a status rather than a group', '/v1/payments?status=SUCCEEDED'],
    ['a field it doesn’t take', '/v1/payments?supplier=x'],
    ['an after that isn’t an ID', '/v1/payments?after=nope'],
  ])('refuses %s before the use case runs', async (_what, url) => {
    const { app, asked } = await withReads({});

    expect((await app.inject(get(url))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('answers a list refused', async () => {
    const { app } = await withReads({ listed: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });
    const reply = await app.inject(get('/v1/payments'));

    expect(reply.statusCode).toBe(503);
    expect(reply.json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });

  it('refuses one not signed in, or naming no organisation, before the use case runs', async () => {
    const { app, asked } = await withReads({});

    expect((await app.inject({ method: 'GET', url: '/v1/payments' })).statusCode).toBe(401);
    const unnamed = await app.inject({
      method: 'GET',
      url: '/v1/payments',
      headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, origin: PUBLIC_ORIGIN },
    });
    expect(unnamed.statusCode).toBeGreaterThanOrEqual(400);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/payments/exceptions: what to follow up with the bank (Phase 6 C1; BR-17)', () => {
  it('lists the exceptions to any member, as the list shows them', async () => {
    const { app, asked } = await withReads(
      { listed: { outcome: 'listed', payments: [SHOWN], next: null, unchecked: [] } },
      'viewer',
    );
    const reply = await app.inject(get('/v1/payments/exceptions?limit=10'));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({ payments: [LISTED_ANSWER], next: null, unchecked: [] });
    expect(asked).toEqual([[ORG, { after: null, limit: 10 }, 'exceptions', expect.any(String)]]);
  });

  it('refuses a page past the most, or a group, before the use case runs; answers a list refused', async () => {
    const { app, asked } = await withReads({
      listed: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' },
    });

    expect((await app.inject(get('/v1/payments/exceptions?limit=51'))).statusCode).toBe(400);
    expect((await app.inject(get('/v1/payments/exceptions?status=paid'))).statusCode).toBe(400);
    expect(asked).toEqual([]);
    expect((await app.inject(get(`/v1/payments/exceptions?after=${STUCK}`))).statusCode).toBe(503);
    expect(asked[0]?.[1]).toEqual({ after: STUCK, limit: 50 });
  });
});

describe('GET /v1/payments/{id}: one in full (Phase 6 C1)', () => {
  const unknown: PaymentShown = {
    ...SHOWN,
    payment: { ...PAID, transaction: { ...PAID.transaction, status: 'UNKNOWN' }, contradicted: false },
  };

  it('shows it to any member with where marking it failed stands and its history, an allow-list of facts', async () => {
    const { app, asked } = await withReads(
      {
        found: {
          outcome: 'found',
          shown: unknown,
          markFailed: { markableFrom: new Date('2026-10-15T09:00:00.000Z'), openProposal: PROPOSAL },
          timeline: [
            {
              at: new Date('2026-10-14T09:00:00.000Z'),
              what: 'transaction.opened',
              status: 'SUBMISSION_PENDING',
              by: { type: 'system', id: 'api' },
              via: null,
              evidenceRef: null,
            },
            {
              at: new Date('2026-10-14T10:00:00.000Z'),
              what: 'transaction.lose_track',
              status: 'UNKNOWN',
              by: { type: 'system', id: 'api' },
              via: 'bank_check',
              evidenceRef: null,
            },
          ],
          earlier: true,
        },
      },
      'viewer',
    );
    const reply = await app.inject(get(`/v1/payments/${PAYMENT_ID}`));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      ...LISTED_ANSWER,
      status: 'UNKNOWN',
      contradicted: false,
      markFailed: {
        markableFrom: '2026-10-15T09:00:00.000Z',
        openProposal: {
          id: PROPOSAL_ID,
          paymentId: PAYMENT_ID,
          evidenceRef: 'BANK-NACK-77311',
          proposedBy: PROPOSER,
          status: 'OPEN',
          proposedAt: '2026-10-15T09:00:00.000Z',
        },
      },
      timeline: [
        {
          at: '2026-10-14T09:00:00.000Z',
          what: 'transaction.opened',
          status: 'SUBMISSION_PENDING',
          by: { type: 'system', id: 'api' },
          via: null,
          evidenceRef: null,
        },
        {
          at: '2026-10-14T10:00:00.000Z',
          what: 'transaction.lose_track',
          status: 'UNKNOWN',
          by: { type: 'system', id: 'api' },
          via: 'bank_check',
          evidenceRef: null,
        },
      ],
      earlier: true,
    });
    expect(asked).toEqual([[ORG, PAYMENT_ID, expect.any(String)]]);
  });

  it('shows one with no proposal open, and one not UNKNOWN with no mark at all', async () => {
    const open = await withReads({
      found: {
        outcome: 'found',
        shown: unknown,
        markFailed: { markableFrom: new Date('2026-10-15T09:00:00.000Z'), openProposal: null },
        timeline: [],
        earlier: false,
      },
    });
    expect((await open.app.inject(get(`/v1/payments/${PAYMENT_ID}`))).json()).toMatchObject({
      markFailed: { openProposal: null },
      timeline: [],
      earlier: false,
    });

    const paid = await withReads({
      found: { outcome: 'found', shown: SHOWN, markFailed: null, timeline: [], earlier: false },
    });
    expect((await paid.app.inject(get(`/v1/payments/${PAYMENT_ID}`))).json()).toMatchObject({
      status: 'SUCCEEDED',
      markFailed: null,
    });
  });

  it('answers the exception list’s path as the list, never as a payment’s ID', async () => {
    const { app, asked } = await withReads({});

    await app.inject(get('/v1/payments/exceptions'));
    expect(asked[0]?.[2]).toBe('exceptions');
  });

  it.each([
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal: %i %s', async (status, code) => {
    const { app } = await withReads({ found: { outcome: 'refused', status, code } });
    const reply = await app.inject(get(`/v1/payments/${PAYMENT_ID}`));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });

  it('refuses an ID that is not one before the use case runs', async () => {
    const { app, asked } = await withReads({});

    expect((await app.inject(get('/v1/payments/not-an-id'))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

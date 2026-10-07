// Phase 2 B2: the mandates' routes, answering a member with each outcome of
// the registry: a draft's body read into its terms (or refused at the edge
// with every problem), the mandate as it now stands, every refusal, and the
// reads; B3's accept and B4's suspend, resume and revoke, each asked then
// confirmed. Who reaches them is the access hook's (role-matrix.test.ts); what
// the use case does in the database is mandate-registry.db.test.ts.
import type { MembershipCheck, LiveSession, Role } from '@agentx/core/modules/identity';
import { money } from '@agentx/core/shared-kernel';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { AcceptAsked, MandateAcceptance, MandateAccepted } from './mandate-acceptance.ts';
import type { MandateMove, MandateMoved, MandateMoves, MoveAsked } from './mandate-moves.ts';
import type { MandateView } from './mandate-reads.ts';
import type { MandateDraft, MandateRegistry, MandateWrite } from './mandate-registry.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const MANDATE_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const VERSION_ID = '0199a0f0-0000-7000-8000-0000000000d2';
const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const SOURCE_ID = '0199a0f0-0000-7000-8000-0000000000f1';
const SUPPLIERS = ['0199a0f0-0000-7000-8000-0000000000e1', '0199a0f0-0000-7000-8000-0000000000e2'];
const ADMIN = '0199a0f0-0000-7000-8000-000000000033';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-07T09:00:00.000Z'),
  // A passkey's sign-in, as an admin needs (ADR-012 §7).
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-07T09:00:05.000Z'),
  lastSeenAt: new Date('2026-10-07T09:10:00.000Z'),
  endsAt: new Date('2099-10-07T21:00:05.000Z'),
  idleEndsAt: new Date('2099-10-07T09:40:00.000Z'),
};

const AED = (minor: bigint) => money(minor, 'AED');

const VIEW: MandateView = {
  mandate: {
    id: MANDATE_ID,
    agentId: AGENT_ID,
    timeZone: 'Asia/Dubai',
    splitWindowHours: 24,
    status: 'PENDING_ACCEPTANCE',
    currentVersionId: null,
    acceptedBy: null,
    acceptedAt: null,
    pendingVersionId: VERSION_ID,
  },
  current: null,
  pending: {
    version: {
      id: VERSION_ID,
      mandateId: MANDATE_ID,
      version: 1,
      purpose: 'Office supplies',
      perOrderLimit: AED(500_000n),
      monthlyLimit: AED(2_000_000n),
      approvalThreshold: AED(100_000n),
      supplierIds: SUPPLIERS,
      fundingSourceId: SOURCE_ID,
      splitCheck: true,
      consentLimits: 'flexible',
      endsAt: new Date('2027-01-01T00:00:00.000Z'),
      termsHash: 'a'.repeat(64),
      draftedBy: ADMIN,
      draftedAt: new Date('2026-10-07T09:15:00.000Z'),
    },
    consentWarnings: ['the per-order limit is above the bank consent’s per payment'],
  },
};

/** The mandate as the routes answer it. */
const VERSION_ANSWERED = {
  id: VERSION_ID,
  version: 1,
  purpose: 'Office supplies',
  currency: 'AED',
  perOrderLimitMinor: 500_000,
  monthlyLimitMinor: 2_000_000,
  approvalThresholdMinor: 100_000,
  supplierIds: SUPPLIERS,
  fundingSourceId: SOURCE_ID,
  splitCheck: true,
  consentLimits: 'flexible',
  endsAt: '2027-01-01T00:00:00.000Z',
  termsHash: 'a'.repeat(64),
  draftedBy: ADMIN,
  draftedAt: '2026-10-07T09:15:00.000Z',
  consentWarnings: ['the per-order limit is above the bank consent’s per payment'],
};

const DETAILS_ANSWERED = {
  id: MANDATE_ID,
  agentId: AGENT_ID,
  timeZone: 'Asia/Dubai',
  splitWindowHours: 24,
  status: 'PENDING_ACCEPTANCE',
  acceptedBy: null,
  acceptedAt: null,
  current: null,
  pending: VERSION_ANSWERED,
};

afterEach(closeServers);

interface Call {
  readonly kind: 'draft' | 'redraft' | 'list' | 'show' | 'accept' | 'acceptConfirm' | 'ask' | 'confirm';
  readonly member?: unknown;
  readonly keyed?: IdempotentRequest;
  readonly subject?: unknown;
}

interface Answers {
  readonly write?: MandateWrite;
  readonly listed?: Awaited<ReturnType<MandateRegistry['list']>>;
  readonly found?: Awaited<ReturnType<MandateRegistry['show']>>;
  readonly asked?: AcceptAsked;
  readonly accepted?: MandateAccepted;
  readonly moveAsked?: MoveAsked;
  readonly moved?: MandateMoved;
}

/** A server whose registry answers `answers`, the caller holding `role`. */
async function withMandates(answers: Answers, role: Role = 'admin') {
  const calls: Call[] = [];
  const written = () => Promise.resolve(answers.write ?? { outcome: 'busy' as const });
  const acceptance: MandateAcceptance = {
    accept: (member, keyed, mandateId, versionId) => {
      calls.push({ kind: 'accept', member, keyed, subject: { mandateId, versionId } });
      return Promise.resolve(answers.asked ?? { outcome: 'busy' as const });
    },
    acceptConfirm: (member, keyed, mandateId, stepUpChallengeId) => {
      calls.push({ kind: 'acceptConfirm', member, keyed, subject: { mandateId, stepUpChallengeId } });
      return Promise.resolve(answers.accepted ?? { outcome: 'busy' as const });
    },
  };
  const moves: MandateMoves = {
    ask: (member, keyed, mandateId, move) => {
      calls.push({ kind: 'ask', member, keyed, subject: { mandateId, move } });
      return Promise.resolve(answers.moveAsked ?? { outcome: 'busy' as const });
    },
    confirm: (member, keyed, mandateId, move, stepUpChallengeId) => {
      calls.push({ kind: 'confirm', member, keyed, subject: { mandateId, move, stepUpChallengeId } });
      return Promise.resolve(answers.moved ?? { outcome: 'busy' as const });
    },
  };
  const registry: MandateRegistry = {
    draft: (_member, keyed, draft) => {
      calls.push({ kind: 'draft', keyed, subject: draft });
      return written();
    },
    redraft: (_member, keyed, mandateId, terms) => {
      calls.push({ kind: 'redraft', keyed, subject: { mandateId, terms } });
      return written();
    },
    list: (orgId, page) => {
      calls.push({ kind: 'list', subject: { orgId, ...page } });
      return Promise.resolve(answers.listed ?? { outcome: 'listed', mandates: [], next: null });
    },
    show: (orgId, mandateId) => {
      calls.push({ kind: 'show', subject: { orgId, mandateId } });
      return Promise.resolve(answers.found ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: ADMIN, role };
  const app = await routeServer({
    live: LIVE,
    member,
    mandateRegistry: registry,
    mandateAcceptance: acceptance,
    mandateMoves: moves,
  });
  return { app, calls };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const post = (url: string, payload: unknown): InjectOptions => ({
  method: 'POST',
  url,
  headers: { ...headers, 'idempotency-key': 'k-1', 'content-type': 'application/json' },
  payload: JSON.stringify(payload),
});

const TERMS = {
  purpose: 'Office supplies',
  currency: 'AED',
  perOrderLimitMinor: 500_000,
  monthlyLimitMinor: 2_000_000,
  approvalThresholdMinor: 100_000,
  supplierIds: [SUPPLIERS[1], SUPPLIERS[0]],
  fundingSourceId: SOURCE_ID,
};

const DRAFTED: MandateWrite = { outcome: 'drafted', ...VIEW };

describe('POST /v1/mandates drafts a mandate (B2)', () => {
  it('answers 201 with the mandate, its terms read with the defaults: strict, split check on, no end, zone and window unset', async () => {
    const { app, calls } = await withMandates({ write: DRAFTED });
    const reply = await app.inject(post('/v1/mandates', { agentId: AGENT_ID, ...TERMS }));

    expect(reply.statusCode).toBe(201);
    expect(reply.json()).toEqual(DETAILS_ANSWERED);
    expect(calls).toHaveLength(1);
    const draft = calls[0]?.subject as MandateDraft;
    expect(draft).toMatchObject({ agentId: AGENT_ID, timeZone: null, splitWindowHours: null });
    expect(draft.terms).toMatchObject({
      purpose: 'Office supplies',
      perOrderLimit: AED(500_000n),
      supplierIds: [...SUPPLIERS].sort(),
      splitCheck: true,
      consentLimits: 'strict',
      endsAt: null,
    });
    expect(calls[0]?.keyed).toMatchObject({ orgId: ORG, operation: 'mandates.draft', key: 'k-1' });
  });

  it('passes the zone, window, end and settings given', async () => {
    const { app, calls } = await withMandates({ write: DRAFTED });
    const reply = await app.inject(
      post('/v1/mandates', {
        agentId: AGENT_ID,
        timeZone: 'Europe/London',
        splitWindowHours: 48,
        ...TERMS,
        splitCheck: false,
        consentLimits: 'flexible',
        endsAt: '2099-01-01T00:00:00.000Z',
      }),
    );

    expect(reply.statusCode).toBe(201);
    expect(calls[0]?.subject).toMatchObject({
      timeZone: 'Europe/London',
      splitWindowHours: 48,
      terms: { splitCheck: false, consentLimits: 'flexible', endsAt: new Date('2099-01-01T00:00:00.000Z') },
    });
  });

  it.each([
    ['a zone the IANA database doesn’t name', { timeZone: 'Mars/Olympus' }],
    ['an amount that is a fraction', { perOrderLimitMinor: 1.5 }],
    ['limits that don’t nest', { approvalThresholdMinor: 600_000 }],
    ['an end in the past', { endsAt: '2020-01-01T00:00:00.000Z' }],
  ])('refuses %s at the edge, the registry never asked', async (_what, change) => {
    const { app, calls } = await withMandates({ write: DRAFTED });
    const reply = await app.inject(post('/v1/mandates', { agentId: AGENT_ID, ...TERMS, ...change }));

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'MANDATE_OPEN' } as const, 409, 'MANDATE_OPEN'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
    [{ outcome: 'busy' } as const, 409, 'IDEMPOTENCY_KEY_BUSY'],
  ])('answers the registry’s %o as %i %s', async (write, status, code) => {
    const { app } = await withMandates({ write });
    const reply = await app.inject(post('/v1/mandates', { agentId: AGENT_ID, ...TERMS }));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });

  it('refuses a member who isn’t an admin', async () => {
    const { app, calls } = await withMandates({ write: DRAFTED }, 'approver');
    const reply = await app.inject(post('/v1/mandates', { agentId: AGENT_ID, ...TERMS }));

    expect(reply.statusCode).toBe(403);
    expect(calls).toEqual([]);
  });
});

describe('POST /v1/mandates/:id/supersede drafts a later version (B2)', () => {
  it('answers 200 with the mandate, passing its ID and the terms', async () => {
    const { app, calls } = await withMandates({ write: DRAFTED });
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/supersede`, TERMS));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual(DETAILS_ANSWERED);
    expect(calls[0]).toMatchObject({
      kind: 'redraft',
      keyed: { operation: 'mandates.redraft' },
      subject: { mandateId: MANDATE_ID, terms: { purpose: 'Office supplies' } },
    });
  });

  it('refuses an agent named in it: the agent, zone and window stay as they are', async () => {
    const { app, calls } = await withMandates({ write: DRAFTED });
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/supersede`, { ...TERMS, agentId: AGENT_ID }));

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it('answers the registry’s refusal', async () => {
    const { app } = await withMandates({ write: { outcome: 'refused', status: 409, code: 'MANDATE_ENDED' } });
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/supersede`, TERMS));

    expect(reply.statusCode).toBe(409);
    expect(reply.json()).toMatchObject({ error: { code: 'MANDATE_ENDED' } });
  });
});

const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c6';

describe('POST /v1/mandates/:id/accept asks a passkey step-up to accept the draft (B3)', () => {
  it('answers 202 with the step-up, passing the member in their session, the key and the draft named', async () => {
    const { app, calls } = await withMandates({ asked: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/accept`, { versionId: VERSION_ID }));

    expect(reply.statusCode).toBe(202);
    expect(reply.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(calls).toEqual([
      {
        kind: 'accept',
        member: { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId },
        keyed: expect.objectContaining({ operation: 'mandates.accept', key: 'k-1' }) as unknown,
        subject: { mandateId: MANDATE_ID, versionId: VERSION_ID },
      },
    ]);
  });

  it.each([
    ['no version', {}],
    ['a version not named by its ID', { versionId: 'v1' }],
    ['anything more', { versionId: VERSION_ID, terms: {} }],
  ])('refuses a body with %s at the edge', async (_what, body) => {
    const { app, calls } = await withMandates({});
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/accept`, body));

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'MANDATE_NOT_WAITING' } as const, 409, 'MANDATE_NOT_WAITING'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
    [{ outcome: 'busy' } as const, 409, 'IDEMPOTENCY_KEY_BUSY'],
  ])('answers the use case’s %o as %i %s', async (asked, status, code) => {
    const { app } = await withMandates({ asked });
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/accept`, { versionId: VERSION_ID }));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });

  it('refuses a member who isn’t an admin', async () => {
    const { app, calls } = await withMandates({}, 'approver');
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/accept`, { versionId: VERSION_ID }));

    expect(reply.statusCode).toBe(403);
    expect(calls).toEqual([]);
  });
});

describe('POST /v1/mandates/:id/accept/confirm accepts the draft (B3)', () => {
  const ACCEPTED: MandateView = {
    ...VIEW,
    mandate: {
      ...VIEW.mandate,
      status: 'ACTIVE',
      currentVersionId: VERSION_ID,
      pendingVersionId: null,
      acceptedBy: ADMIN,
      acceptedAt: new Date('2026-10-07T10:00:00.000Z'),
    },
    current: VIEW.pending,
    pending: null,
  };

  it('answers 200 with the mandate in force, passing the step-up', async () => {
    const { app, calls } = await withMandates({ accepted: { outcome: 'accepted', ...ACCEPTED } });
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/accept/confirm`, { stepUpChallengeId: CHALLENGE }));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      ...DETAILS_ANSWERED,
      status: 'ACTIVE',
      acceptedBy: ADMIN,
      acceptedAt: '2026-10-07T10:00:00.000Z',
      current: VERSION_ANSWERED,
      pending: null,
    });
    expect(calls[0]).toMatchObject({
      kind: 'acceptConfirm',
      keyed: { operation: 'mandates.accept.confirm' },
      subject: { mandateId: MANDATE_ID, stepUpChallengeId: CHALLENGE },
    });
  });

  it('refuses a confirm with no step-up named', async () => {
    const { app, calls } = await withMandates({});
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/accept/confirm`, {}));

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' } as const, 403, 'STEP_UP_FAILED'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
  ])('answers the use case’s %o as %i %s', async (accepted, status, code) => {
    const { app } = await withMandates({ accepted });
    const reply = await app.inject(post(`/v1/mandates/${MANDATE_ID}/accept/confirm`, { stepUpChallengeId: CHALLENGE }));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });
});

describe.each<{ move: MandateMove; status: string }>([
  { move: 'suspend', status: 'SUSPENDED' },
  { move: 'resume', status: 'ACTIVE' },
  { move: 'revoke', status: 'REVOKED' },
])('POST /v1/mandates/:id/$move, then …/confirm (B4)', ({ move, status }) => {
  const ask = `/v1/mandates/${MANDATE_ID}/${move}`;
  const MOVED: MandateMoved = {
    outcome: 'moved',
    ...VIEW,
    mandate: { ...VIEW.mandate, status } as MandateView['mandate'],
  };

  it('asks a passkey step-up: 202, passing the member in their session, the key and the move', async () => {
    const { app, calls } = await withMandates({ moveAsked: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });
    const reply = await app.inject(post(ask, {}));

    expect(reply.statusCode).toBe(202);
    expect(reply.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(calls).toEqual([
      {
        kind: 'ask',
        member: { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId },
        keyed: expect.objectContaining({ operation: `mandates.${move}`, key: 'k-1' }) as unknown,
        subject: { mandateId: MANDATE_ID, move },
      },
    ]);
  });

  it('confirms: 200 with the mandate moved, passing the step-up', async () => {
    const { app, calls } = await withMandates({ moved: MOVED });
    const reply = await app.inject(post(`${ask}/confirm`, { stepUpChallengeId: CHALLENGE }));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({ ...DETAILS_ANSWERED, status });
    expect(calls[0]).toMatchObject({
      kind: 'confirm',
      keyed: { operation: `mandates.${move}.confirm` },
      subject: { mandateId: MANDATE_ID, move, stepUpChallengeId: CHALLENGE },
    });
  });

  it('refuses a body on the ask, and a confirm with no step-up named, at the edge', async () => {
    const { app, calls } = await withMandates({});

    expect((await app.inject(post(ask, { reason: 'x' }))).statusCode).toBe(400);
    expect((await app.inject(post(`${ask}/confirm`, {}))).statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'MANDATE_ENDED' } as const, 409, 'MANDATE_ENDED'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
    [{ outcome: 'busy' } as const, 409, 'IDEMPOTENCY_KEY_BUSY'],
  ])('answers the use case’s %o as %i %s, on the ask and the confirm', async (answer, code, reason) => {
    const { app } = await withMandates({ moveAsked: answer, moved: answer });
    for (const reply of [
      await app.inject(post(ask, {})),
      await app.inject(post(`${ask}/confirm`, { stepUpChallengeId: CHALLENGE })),
    ]) {
      expect(reply.statusCode).toBe(code);
      expect(reply.json()).toMatchObject({ error: { code: reason } });
    }
  });

  it('refuses a member who isn’t an admin', async () => {
    const { app, calls } = await withMandates({}, 'approver');

    expect((await app.inject(post(ask, {}))).statusCode).toBe(403);
    expect((await app.inject(post(`${ask}/confirm`, { stepUpChallengeId: CHALLENGE }))).statusCode).toBe(403);
    expect(calls).toEqual([]);
  });
});

describe('reading mandates (B2)', () => {
  const get = (url: string): InjectOptions => ({ method: 'GET', url, headers });

  it('lists a page to any member, each with its purpose', async () => {
    const { app, calls } = await withMandates(
      { listed: { outcome: 'listed', mandates: [{ ...VIEW.mandate, purpose: 'Office supplies' }], next: MANDATE_ID } },
      'viewer',
    );
    const reply = await app.inject(get('/v1/mandates?limit=1'));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      mandates: [
        {
          id: MANDATE_ID,
          agentId: AGENT_ID,
          timeZone: 'Asia/Dubai',
          splitWindowHours: 24,
          status: 'PENDING_ACCEPTANCE',
          purpose: 'Office supplies',
        },
      ],
      next: MANDATE_ID,
    });
    expect(calls[0]?.subject).toEqual({ orgId: ORG, after: null, limit: 1 });
  });

  it('answers a list refused', async () => {
    const { app } = await withMandates({ listed: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });
    const reply = await app.inject(get('/v1/mandates'));

    expect(reply.statusCode).toBe(503);
  });

  it('shows one to any member, with its version in force and its draft', async () => {
    const accepted: MandateView = {
      ...VIEW,
      mandate: {
        ...VIEW.mandate,
        status: 'ACTIVE',
        currentVersionId: VERSION_ID,
        acceptedBy: ADMIN,
        acceptedAt: new Date('2026-10-07T10:00:00.000Z'),
      },
      current: VIEW.pending,
    };
    const { app } = await withMandates({ found: { outcome: 'found', ...accepted } }, 'viewer');
    const reply = await app.inject(get(`/v1/mandates/${MANDATE_ID}`));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      ...DETAILS_ANSWERED,
      status: 'ACTIVE',
      acceptedBy: ADMIN,
      acceptedAt: '2026-10-07T10:00:00.000Z',
      current: VERSION_ANSWERED,
    });
  });

  it('answers one not found', async () => {
    const { app } = await withMandates({});
    const reply = await app.inject(get(`/v1/mandates/${MANDATE_ID}`));

    expect(reply.statusCode).toBe(404);
  });
});

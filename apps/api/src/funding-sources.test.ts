// D2-3b: the funding sources' linking routes, answering an admin with each
// outcome of the use case. Who reaches them is the access hook's
// (role-matrix.test.ts); what the use case does with the partner and the
// database is funding-source-links.db.test.ts.
import type { LinkRecord, SourceRecord } from '@agentx/core/modules/funding-sources';
import type { LiveSession, MembershipCheck, SignIn } from '@agentx/core/modules/identity';
import type { IdempotentRequest } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { FundingSourceLinks, LinkConfirmWrite, LinkingMember, LinkStartWrite } from './funding-source-links.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const LINK_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const SOURCE_ID = '0199a0f0-0000-7000-8000-0000000000d2';
const AUTHORISE_URL = 'https://bank.fake-partner.invalid/authorise/fake-link-1';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-01T08:00:00.000Z'),
  // A passkey's sign-in, as an admin needs (ADR-012 §7).
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-01T08:00:05.000Z'),
  lastSeenAt: new Date('2026-10-01T08:10:00.000Z'),
  endsAt: new Date('2099-10-01T20:00:05.000Z'),
  idleEndsAt: new Date('2099-10-01T08:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const ADMIN: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role: 'admin' };
const LINKING: LinkingMember = { orgId: ORG, userId: LIVE.userId };

const OPEN_LINK: LinkRecord = {
  id: LINK_ID,
  startedBy: '0199a0f0-0000-7000-8000-000000000033',
  partner: 'fake',
  sessionRef: 'fake-link-1',
  expiresAt: new Date('2026-10-01T08:25:00.000Z'),
  createdAt: new Date('2026-10-01T08:10:00.000Z'),
  outcome: 'open',
  sourceId: null,
  settledAt: null,
};

const LINKED: LinkRecord = {
  ...OPEN_LINK,
  outcome: 'linked',
  sourceId: SOURCE_ID,
  settledAt: new Date('2026-10-01T08:12:00.000Z'),
};

const SOURCE: SourceRecord = {
  id: SOURCE_ID,
  linkId: LINK_ID,
  partner: 'fake',
  externalRef: 'fake-source-1',
  status: 'ACTIVE',
  availability: 'ACTIVE',
  consentStatus: 'Authorized',
  accountConsentId: 'fake-consent-1',
  replacesConsentId: null,
  consentExpiresAt: new Date('2027-10-01T08:12:00.000Z'),
  controls: {
    currency: 'AED',
    period: 'month',
    maxPaymentMinor: 5_000_000n,
    maxPeriodMinor: 20_000_000n,
    maxPeriodPayments: 100,
  },
  summary: { holderName: 'Jasmine AI FZ-LLC', accountType: 'sme', hint: 'AE…6026' },
  partnerChangedAt: new Date('2026-10-01T08:12:00.000Z'),
};

const LINK_ANSWERED = {
  id: LINK_ID,
  status: 'open',
  expiresAt: '2026-10-01T08:25:00.000Z',
  createdAt: '2026-10-01T08:10:00.000Z',
  settledAt: null,
  sourceId: null,
};

/** The source as the routes answer it: never the partner's references, and money as text. */
const SOURCE_ANSWERED = {
  id: SOURCE_ID,
  status: 'ACTIVE',
  availability: 'ACTIVE',
  consentStatus: 'Authorized',
  consentExpiresAt: '2027-10-01T08:12:00.000Z',
  holderName: 'Jasmine AI FZ-LLC',
  accountType: 'sme',
  hint: 'AE…6026',
  controls: {
    currency: 'AED',
    period: 'month',
    maxPaymentMinor: '5000000',
    maxPeriodMinor: '20000000',
    maxPeriodPayments: 100,
  },
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface Call {
  readonly kind: 'start' | 'confirm';
  readonly member: LinkingMember;
  readonly keyed: IdempotentRequest;
  readonly linkId?: string;
}

/** A server whose use case answers `start` and `confirm`. */
async function withLinks(answers: { start?: LinkStartWrite; confirm?: LinkConfirmWrite }) {
  const calls: Call[] = [];
  const links: FundingSourceLinks = {
    start: (member, keyed) => {
      calls.push({ kind: 'start', member, keyed });
      return Promise.resolve(answers.start ?? { outcome: 'busy' });
    },
    confirm: (member, keyed, linkId) => {
      calls.push({ kind: 'confirm', member, keyed, linkId });
      return Promise.resolve(answers.confirm ?? { outcome: 'busy' });
    },
  };
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: 1000,
      rateLimitPerUserPerMinute: 1000,
      rateLimitPerAgentPerMinute: 1000,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const app = await buildServer({
    config,
    logger: createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', ...config },
      destination: new LogCapture(),
    }),
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: { service: SIGN_IN, sessionSeconds: 43_200 },
    restrictedUntil: () => Promise.resolve(undefined),
    findMembership: (orgId) => Promise.resolve(orgId.toLowerCase() === ORG ? ADMIN : ({ outcome: 'none' } as const)),
    fundingSourceLinks: links,
  });
  servers.push(app);
  await app.ready();
  return { app, calls };
}

const post = (path: string, payload: unknown = {}, key = 'k-1'): InjectOptions => ({
  method: 'POST',
  url: `/v1/funding-sources/link-sessions${path}`,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': key,
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

describe('POST /v1/funding-sources/link-sessions starts a link at the partner (D2-3b)', () => {
  it('answers 201 with the link and the partner’s page, passing the admin and the key', async () => {
    const { app, calls } = await withLinks({
      start: { outcome: 'started', link: OPEN_LINK, authoriseUrl: AUTHORISE_URL },
    });

    const response = await app.inject(post(''));

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({ link: LINK_ANSWERED, authoriseUrl: AUTHORISE_URL });
    expect(calls).toEqual([
      {
        kind: 'start',
        member: LINKING,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'funding-sources.link.start', key: 'k-1' }) as unknown,
      },
    ]);
  });

  it.each([
    [503, 'PARTNER_UNAVAILABLE'],
    [409, 'LINK_STARTS_SPENT'],
    [403, 'FORBIDDEN'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers %i %s as the use case refuses', async (status, code) => {
    const { app } = await withLinks({ start: { outcome: 'refused', status, code } });

    const response = await app.inject(post(''));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it.each([
    ['conflict', 409, 'IDEMPOTENCY_KEY_REUSED'],
    ['busy', 409, 'IDEMPOTENCY_KEY_BUSY'],
  ] as const)('answers a key %s as the idempotency store says', async (outcome, status, code) => {
    const { app } = await withLinks({ start: { outcome } });

    const response = await app.inject(post(''));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('takes no body but an empty one, before the use case runs', async () => {
    const { app, calls } = await withLinks({});

    const response = await app.inject(post('', { sourceId: SOURCE_ID }));

    expect(response.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });
});

describe('POST /v1/funding-sources/link-sessions/:linkId/confirm asks the partner how it ended (D2-3b)', () => {
  it('answers 202 with the link while the business hasn’t finished at its bank', async () => {
    const { app, calls } = await withLinks({ confirm: { outcome: 'confirmed', link: OPEN_LINK, source: null } });

    const response = await app.inject(post(`/${LINK_ID}/confirm`));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ link: LINK_ANSWERED, source: null });
    expect(calls).toEqual([
      {
        kind: 'confirm',
        member: LINKING,
        keyed: expect.objectContaining({ operation: 'funding-sources.link.confirm' }) as unknown,
        linkId: LINK_ID,
      },
    ]);
  });

  it('answers 200 with the link, linked, and its source: never an account number or a partner reference', async () => {
    const { app } = await withLinks({ confirm: { outcome: 'confirmed', link: LINKED, source: SOURCE } });

    const response = await app.inject(post(`/${LINK_ID}/confirm`));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      link: { ...LINK_ANSWERED, status: 'linked', sourceId: SOURCE_ID, settledAt: '2026-10-01T08:12:00.000Z' },
      source: SOURCE_ANSWERED,
    });
    expect(response.body).not.toContain('fake-source-1');
    expect(response.body).not.toContain('fake-consent-1');
  });

  it.each(['rejected', 'expired', 'unknown'] as const)(
    'answers 200 with a link settled %s, and no source',
    async (outcome) => {
      const settled = { ...OPEN_LINK, outcome, settledAt: LINKED.settledAt };
      const { app } = await withLinks({ confirm: { outcome: 'confirmed', link: settled, source: null } });

      const response = await app.inject(post(`/${LINK_ID}/confirm`));

      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ link: { status: outcome, sourceId: null }, source: null });
    },
  );

  it.each([
    [404, 'NOT_FOUND'],
    [503, 'PARTNER_UNAVAILABLE'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers %i %s as the use case refuses', async (status, code) => {
    const { app } = await withLinks({ confirm: { outcome: 'refused', status, code } });

    const response = await app.inject(post(`/${LINK_ID}/confirm`));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('answers a key reused for another request as the idempotency store says', async () => {
    const { app } = await withLinks({ confirm: { outcome: 'conflict' } });

    expect((await app.inject(post(`/${LINK_ID}/confirm`))).statusCode).toBe(409);
  });

  it('refuses a link ID that isn’t one, and any body, before the use case runs', async () => {
    const { app, calls } = await withLinks({});

    expect((await app.inject(post('/not-a-link/confirm'))).statusCode).toBe(400);
    expect((await app.inject(post(`/${LINK_ID}/confirm`, { sourceId: SOURCE_ID }))).statusCode).toBe(400);
    expect(calls).toEqual([]);
  });
});

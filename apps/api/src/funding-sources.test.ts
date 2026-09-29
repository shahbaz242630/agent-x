// D2-3b, D2-4a: the funding sources' routes, answering a member or an agent
// with each outcome of the use cases. Who reaches them is the access hook's
// (role-matrix.test.ts); what the use cases do with the partner and the
// database is funding-source-links.db.test.ts and
// funding-source-changes.db.test.ts.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LinkRecord, SourceRecord } from '@agentx/core/modules/funding-sources';
import type { LiveSession, MembershipCheck, SignIn } from '@agentx/core/modules/identity';
import type { IdempotentRequest } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { FundingSourceChanges, SourceChangeWrite } from './funding-source-changes.ts';
import type { FundingSourceLinks, LinkConfirmWrite, LinkingMember, LinkStartWrite } from './funding-source-links.ts';
import type { FundingSourceReads, SourcePage, SourceShown, SourcesListed } from './funding-source-reads.ts';
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

/** A read or a change asked of the D2-4a use cases. */
type Asked =
  | { readonly kind: 'list' | 'usableByAgent'; readonly orgId: string; readonly page: SourcePage }
  | { readonly kind: 'show'; readonly orgId: string; readonly sourceId: string }
  | {
      readonly kind: 'refresh' | 'suspend' | 'reactivate' | 'reactivateConfirm';
      readonly member: LinkingMember;
      readonly keyed: IdempotentRequest;
      readonly sourceId: string;
      readonly stepUpChallengeId?: string;
    };

const AGENT_KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const AGENT_KEY_WITHOUT_SOURCES = `axk_${'c'.repeat(32)}_${'b'.repeat(43)}`;
const acceptedKey = (scopes: AcceptedKey['scopes']): AcceptedKey => ({
  orgId: ORG,
  agentId: '0199a0f0-0000-7000-8000-0000000000a1',
  keyId: '0199a0f0-0000-7000-8000-0000000000b1',
  scopes,
  expiresAt: new Date('2099-12-28T09:00:00.000Z'),
});
const AGENT_KEYS: ReadonlyMap<string, AcceptedKey> = new Map([
  [AGENT_KEY, acceptedKey(['sources:read'])],
  [AGENT_KEY_WITHOUT_SOURCES, acceptedKey(['requests:read'])],
]);

/** A server whose use cases answer `start`, `confirm`, the reads and `refresh`. */
async function withLinks(
  answers: {
    start?: LinkStartWrite;
    confirm?: LinkConfirmWrite;
    list?: SourcesListed;
    show?: SourceShown;
    refresh?: SourceChangeWrite;
    change?: SourceChangeWrite;
  },
  asked: Asked[] = [],
) {
  const calls: Call[] = [];
  const reads: FundingSourceReads = {
    list: (orgId, page) => {
      asked.push({ kind: 'list', orgId, page });
      return Promise.resolve(answers.list ?? { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    },
    show: (orgId, sourceId) => {
      asked.push({ kind: 'show', orgId, sourceId });
      return Promise.resolve(answers.show ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
    usableByAgent: (orgId, page) => {
      asked.push({ kind: 'usableByAgent', orgId, page });
      return Promise.resolve(answers.list ?? { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    },
  };
  const changes: FundingSourceChanges = {
    refresh: (member, keyed, sourceId) => {
      asked.push({ kind: 'refresh', member, keyed, sourceId });
      return Promise.resolve(answers.refresh ?? { outcome: 'busy' });
    },
    suspend: (member, keyed, sourceId) => {
      asked.push({ kind: 'suspend', member, keyed, sourceId });
      return Promise.resolve(answers.change ?? { outcome: 'busy' });
    },
    reactivate: (member, keyed, sourceId) => {
      asked.push({ kind: 'reactivate', member, keyed, sourceId });
      return Promise.resolve(answers.change ?? { outcome: 'busy' });
    },
    reactivateConfirm: (member, keyed, sourceId, stepUpChallengeId) => {
      asked.push({ kind: 'reactivateConfirm', member, keyed, sourceId, stepUpChallengeId });
      return Promise.resolve(answers.change ?? { outcome: 'busy' });
    },
  };
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
    checkAgentKey: (text) => {
      const key = AGENT_KEYS.get(text);
      return Promise.resolve(key === undefined ? { outcome: 'refused' } : { outcome: 'accepted', key });
    },
    fundingSourceLinks: links,
    fundingSourceReads: reads,
    fundingSourceChanges: changes,
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

const read = (url: string): InjectOptions => ({
  method: 'GET',
  url,
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG },
});

const refresh = (sourceId: string, payload: unknown = {}): InjectOptions => ({
  method: 'POST',
  url: `/v1/funding-sources/${sourceId}/refresh`,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': 'k-1',
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

const LAST_ID = '0199a0f0-0000-7000-8000-0000000000ff';

describe('GET /v1/funding-sources lists the organisation’s sources (D2-4a)', () => {
  it('answers a page of sources as Agent X holds them, and where the next starts', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({ list: { outcome: 'listed', sources: [SOURCE], next: LAST_ID } }, asked);

    const response = await app.inject(read('/v1/funding-sources'));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ sources: [SOURCE_ANSWERED], next: LAST_ID });
    expect(asked).toEqual([{ kind: 'list', orgId: ORG, page: { after: null, limit: 50 } }]);
  });

  it('passes the page asked for', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({ list: { outcome: 'listed', sources: [], next: null } }, asked);

    const response = await app.inject(read(`/v1/funding-sources?after=${LAST_ID}&limit=2`));

    expect(response.json()).toEqual({ sources: [], next: null });
    expect(asked).toEqual([{ kind: 'list', orgId: ORG, page: { after: LAST_ID, limit: 2 } }]);
  });

  it.each(['limit=0', 'limit=51', 'after=not-an-id', 'other=1'])(
    'refuses %s before the use case runs',
    async (query) => {
      const asked: Asked[] = [];
      const { app } = await withLinks({}, asked);

      expect((await app.inject(read(`/v1/funding-sources?${query}`))).statusCode).toBe(400);
      expect(asked).toEqual([]);
    },
  );

  it('answers 503 INTEGRITY_FAILED as the use case refuses', async () => {
    const { app } = await withLinks({ list: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });

    const response = await app.inject(read('/v1/funding-sources'));

    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });
});

describe('GET /v1/funding-sources/:id shows one (D2-4a)', () => {
  it('answers the source as Agent X holds it', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({ show: { outcome: 'found', source: SOURCE } }, asked);

    const response = await app.inject(read(`/v1/funding-sources/${SOURCE_ID}`));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(SOURCE_ANSWERED);
    expect(asked).toEqual([{ kind: 'show', orgId: ORG, sourceId: SOURCE_ID }]);
  });

  it('answers 404 as the use case refuses, and refuses an ID that isn’t one before it runs', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({}, asked);

    expect((await app.inject(read(`/v1/funding-sources/${SOURCE_ID}`))).statusCode).toBe(404);
    expect((await app.inject(read('/v1/funding-sources/not-an-id'))).statusCode).toBe(400);
    expect(asked).toHaveLength(1);
  });
});

describe('POST /v1/funding-sources/:id/refresh asks the partner how it stands (D2-4a)', () => {
  it('answers 200 with the source brought up to the partner’s answer, passing the admin and the key', async () => {
    const asked: Asked[] = [];
    const suspended: SourceRecord = { ...SOURCE, availability: 'SUSPENDED', consentStatus: 'Suspended' };
    const { app } = await withLinks({ refresh: { outcome: 'changed', source: suspended } }, asked);

    const response = await app.inject(refresh(SOURCE_ID));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ...SOURCE_ANSWERED, availability: 'SUSPENDED', consentStatus: 'Suspended' });
    expect(asked).toEqual([
      {
        kind: 'refresh',
        member: LINKING,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'funding-sources.refresh' }) as unknown,
        sourceId: SOURCE_ID,
      },
    ]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [503, 'PARTNER_UNAVAILABLE'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers %i %s as the use case refuses', async (status, code) => {
    const { app } = await withLinks({ refresh: { outcome: 'refused', status, code } });

    const response = await app.inject(refresh(SOURCE_ID));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('answers a key reused for another request as the idempotency store says', async () => {
    const { app } = await withLinks({ refresh: { outcome: 'conflict' } });

    expect((await app.inject(refresh(SOURCE_ID))).statusCode).toBe(409);
  });

  it('refuses any body, before the use case runs', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({}, asked);

    expect((await app.inject(refresh(SOURCE_ID, { availability: 'ACTIVE' }))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/agent/funding-sources: an agent sees the safe summary alone (D2-4a, SEC-AG-05)', () => {
  const asAgent = (key: string, query = ''): InjectOptions => ({
    method: 'GET',
    url: `/v1/agent/funding-sources${query}`,
    headers: { authorization: `Bearer ${key}` },
  });

  it('answers each usable source’s ID, currency, kind and hint, and nothing else of it', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({ list: { outcome: 'listed', sources: [SOURCE], next: LAST_ID } }, asked);

    const response = await app.inject(asAgent(AGENT_KEY, '?limit=10'));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      sources: [{ id: SOURCE_ID, currency: 'AED', accountType: 'sme', hint: 'AE…6026' }],
      next: LAST_ID,
    });
    for (const withheld of ['Jasmine', 'fake-source', 'fake-consent', 'Authorized', '5000000', LINK_ID]) {
      expect(response.body).not.toContain(withheld);
    }
    expect(asked).toEqual([{ kind: 'usableByAgent', orgId: ORG, page: { after: null, limit: 10 } }]);
  });

  it('refuses a key without sources:read, before the use case runs', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({}, asked);

    const response = await app.inject(asAgent(AGENT_KEY_WITHOUT_SOURCES));

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: { code: 'INSUFFICIENT_SCOPE' } });
    expect(asked).toEqual([]);
  });

  it('refuses a member’s session: agent routes are the agents’ alone', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({}, asked);

    const response = await app.inject(read('/v1/agent/funding-sources'));

    expect([401, 403]).toContain(response.statusCode);
    expect(asked).toEqual([]);
  });

  it('answers 503 INTEGRITY_FAILED as the use case refuses', async () => {
    const { app } = await withLinks({ list: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });

    expect((await app.inject(asAgent(AGENT_KEY))).statusCode).toBe(503);
  });
});

const change = (path: string, payload: unknown = {}): InjectOptions => ({
  method: 'POST',
  url: `/v1/funding-sources/${SOURCE_ID}/${path}`,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': 'k-1',
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

const CHALLENGE_ID = '0199a0f0-0000-7000-8000-0000000000c1';
/** The member as the step-up routes pass them: with their session. */
const IN_SESSION = { ...LINKING, sessionId: LIVE.sessionId };

describe('POST /v1/funding-sources/:id/suspend: the brake (D2-4b)', () => {
  it('answers 200 with the source, SUSPENDED, passing the member and the key', async () => {
    const asked: Asked[] = [];
    const suspended: SourceRecord = { ...SOURCE, status: 'SUSPENDED' };
    const { app } = await withLinks({ change: { outcome: 'changed', source: suspended } }, asked);

    const response = await app.inject(change('suspend'));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ...SOURCE_ANSWERED, status: 'SUSPENDED' });
    expect(asked).toEqual([
      {
        kind: 'suspend',
        member: LINKING,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'funding-sources.suspend' }) as unknown,
        sourceId: SOURCE_ID,
      },
    ]);
  });

  it('refuses any body, before the use case runs', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({}, asked);

    expect((await app.inject(change('suspend', { status: 'SUSPENDED' }))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('POST /v1/funding-sources/:id/reactivate, then /confirm, with a step-up (D2-4b)', () => {
  it('answers the ask 202 with the step-up to sign in again for', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({ change: { outcome: 'asked', stepUpChallengeId: CHALLENGE_ID } }, asked);

    const response = await app.inject(change('reactivate'));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE_ID });
    expect(asked).toMatchObject([{ kind: 'reactivate', member: IN_SESSION, sourceId: SOURCE_ID }]);
  });

  it('answers the confirm 200 with the source, ACTIVE, passing the step-up', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({ change: { outcome: 'changed', source: SOURCE } }, asked);

    const response = await app.inject(change('reactivate/confirm', { stepUpChallengeId: CHALLENGE_ID }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(SOURCE_ANSWERED);
    expect(asked).toMatchObject([
      { kind: 'reactivateConfirm', member: IN_SESSION, sourceId: SOURCE_ID, stepUpChallengeId: CHALLENGE_ID },
    ]);
  });

  it.each([
    [409, 'SOURCE_NOT_SUSPENDED'],
    [403, 'STEP_UP_FAILED'],
    [404, 'NOT_FOUND'],
  ] as const)('answers %i %s as the use case refuses', async (status, code) => {
    const { app } = await withLinks({ change: { outcome: 'refused', status, code } });

    const response = await app.inject(change('reactivate/confirm', { stepUpChallengeId: CHALLENGE_ID }));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('answers a key reused for another request as the idempotency store says', async () => {
    const { app } = await withLinks({ change: { outcome: 'conflict' } });

    expect((await app.inject(change('reactivate'))).statusCode).toBe(409);
  });

  it('refuses a confirm without a step-up’s ID, or with more, before the use case runs', async () => {
    const asked: Asked[] = [];
    const { app } = await withLinks({}, asked);

    for (const payload of [
      {},
      { stepUpChallengeId: 'not-an-id' },
      { stepUpChallengeId: CHALLENGE_ID, status: 'ACTIVE' },
    ]) {
      expect((await app.inject(change('reactivate/confirm', payload))).statusCode).toBe(400);
    }
    expect(asked).toEqual([]);
  });
});

// E1-2: the suppliers' routes, answering a member or an agent with each
// outcome of the use cases, and refusing a body that can't be a supplier's
// before they run. Who reaches them is the access hook's
// (role-matrix.test.ts); what the use cases do with the database is
// supplier-registry.db.test.ts and supplier-changes.db.test.ts.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LiveSession, MembershipCheck, SignIn } from '@agentx/core/modules/identity';
import type { SupplierDetails, SupplierRecord, SupplierShown, VersionRecord } from '@agentx/core/modules/suppliers';
import type { IdempotentRequest } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type { SupplierChanges, SupplierChangeWrite } from './supplier-changes.ts';
import type { SupplierAddWrite, SupplierPage, SupplierRegistry, SuppliersListed } from './supplier-registry.ts';
import type { SupplierView } from './supplier-work.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const SUPPLIER_ID = '0199a0f0-0000-7000-8000-0000000000e1';
const VERSION_ID = '0199a0f0-0000-7000-8000-0000000000e2';
const MEMBERSHIP = '0199a0f0-0000-7000-8000-000000000033';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000e3';

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

const ADMIN: MembershipCheck = { outcome: 'active', id: MEMBERSHIP, role: 'admin' };
const MEMBER = { orgId: ORG, userId: LIVE.userId };

const SUPPLIER: SupplierRecord = {
  id: SUPPLIER_ID,
  status: 'UNVERIFIED',
  currentVersionId: VERSION_ID,
  pendingVersionId: null,
  coolingOffUntil: null,
  verifiedBy: null,
  verifiedVersionId: null,
  payeeKey: 'a-payee-key',
  payeeKeyVersion: 1,
};

const VERSION: VersionRecord = {
  id: VERSION_ID,
  supplierId: SUPPLIER_ID,
  version: 1,
  displayName: 'Gulf Office Supplies LLC',
  contacts: 'phone email',
  phoneSince: new Date('2026-10-01T08:00:00.000Z'),
  source: { kind: 'registry', ref: 'DED-123456' },
  enteredBy: MEMBERSHIP,
  enteredAt: new Date('2026-10-01T08:00:00.000Z'),
  registrationId: null,
  beneficiaryRef: 'a-beneficiary-ref',
  payeeHint: 'AE…1234',
};

const VIEW: SupplierView = {
  supplier: SUPPLIER,
  version: VERSION,
  contacts: { phone: '+971501234567', email: 'accounts@gulfoffice.example', tradeLicence: null },
};

const SUPPLIER_ANSWERED = {
  id: SUPPLIER_ID,
  status: 'UNVERIFIED',
  displayName: 'Gulf Office Supplies LLC',
  changeWaiting: false,
  coolingOffUntil: null,
  verifiedBy: null,
};

/** The supplier as the routes answer it: never its payee key, reference or hint. */
const DETAILS_ANSWERED = {
  ...SUPPLIER_ANSWERED,
  version: 1,
  phone: '+971501234567',
  phoneSince: '2026-10-01T08:00:00.000Z',
  email: 'accounts@gulfoffice.example',
  tradeLicence: null,
  source: { kind: 'registry', ref: 'DED-123456' },
  enteredBy: MEMBERSHIP,
  enteredAt: '2026-10-01T08:00:00.000Z',
};

const BODY = {
  displayName: 'Gulf Office Supplies LLC',
  phone: '+971501234567',
  email: 'Accounts@GulfOffice.example',
  source: { kind: 'registry', ref: 'DED-123456' },
};

const AGENT_KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const AGENT_KEY_WITHOUT_SUPPLIERS = `axk_${'c'.repeat(32)}_${'b'.repeat(43)}`;
const acceptedKey = (scopes: AcceptedKey['scopes']): AcceptedKey => ({
  orgId: ORG,
  agentId: '0199a0f0-0000-7000-8000-0000000000a1',
  keyId: '0199a0f0-0000-7000-8000-0000000000b1',
  scopes,
  expiresAt: new Date('2099-12-28T09:00:00.000Z'),
});
const AGENT_KEYS: ReadonlyMap<string, AcceptedKey> = new Map([
  [AGENT_KEY, acceptedKey(['suppliers:read'])],
  [AGENT_KEY_WITHOUT_SUPPLIERS, acceptedKey(['sources:read'])],
]);

/** What the routes asked of the use cases. */
type Asked =
  | { readonly kind: 'add'; readonly keyed: IdempotentRequest; readonly details: SupplierDetails }
  | { readonly kind: 'list' | 'usableByAgent'; readonly orgId: string; readonly page: SupplierPage }
  | { readonly kind: 'show'; readonly orgId: string; readonly supplierId: string }
  | {
      readonly kind: 'suspend' | 'reactivate' | 'reactivateConfirm';
      readonly member: object;
      readonly keyed: IdempotentRequest;
      readonly supplierId: string;
      readonly stepUpChallengeId?: string;
    };

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** A server whose use cases answer as given, noting what they were asked. */
async function withSuppliers(
  answers: { add?: SupplierAddWrite; list?: SuppliersListed; change?: SupplierChangeWrite; found?: boolean },
  asked: Asked[] = [],
) {
  const registry: SupplierRegistry = {
    add: (_member, keyed, details) => {
      asked.push({ kind: 'add', keyed, details });
      return Promise.resolve(answers.add ?? { outcome: 'busy' });
    },
    list: (orgId, page) => {
      asked.push({ kind: 'list', orgId, page });
      return Promise.resolve(answers.list ?? { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    },
    show: (orgId, supplierId) => {
      asked.push({ kind: 'show', orgId, supplierId });
      return Promise.resolve(
        answers.found === true ? { outcome: 'found', ...VIEW } : { outcome: 'refused', status: 404, code: 'NOT_FOUND' },
      );
    },
    usableByAgent: (orgId, page) => {
      asked.push({ kind: 'usableByAgent', orgId, page });
      return Promise.resolve(answers.list ?? { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    },
  };
  const change =
    (kind: 'suspend' | 'reactivate') =>
    (member: object, keyed: IdempotentRequest, supplierId: string): Promise<SupplierChangeWrite> => {
      asked.push({ kind, member, keyed, supplierId });
      return Promise.resolve(answers.change ?? { outcome: 'busy' });
    };
  const changes: SupplierChanges = {
    suspend: change('suspend'),
    reactivate: change('reactivate'),
    reactivateConfirm: (member, keyed, supplierId, stepUpChallengeId) => {
      asked.push({ kind: 'reactivateConfirm', member, keyed, supplierId, stepUpChallengeId });
      return Promise.resolve(answers.change ?? { outcome: 'busy' });
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
    supplierRegistry: registry,
    supplierChanges: changes,
  });
  servers.push(app);
  await app.ready();
  return app;
}

const post = (path: string, payload: unknown = {}, key = 'k-1'): InjectOptions => ({
  method: 'POST',
  url: `/v1/suppliers${path}`,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': key,
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

const get = (path: string): InjectOptions => ({
  method: 'GET',
  url: `/v1/suppliers${path}`,
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG },
});

const SHOWN: SupplierShown = { ...SUPPLIER, displayName: 'Gulf Office Supplies LLC' };

describe('POST /v1/suppliers adds a supplier, unverified (E1-2)', () => {
  it('answers 201 with the supplier, passing the admin, the key and the details as kept', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ add: { outcome: 'added', ...VIEW } }, asked);

    const response = await app.inject(post('', BODY));

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual(DETAILS_ANSWERED);
    expect(asked).toEqual([
      {
        kind: 'add',
        keyed: expect.objectContaining({ orgId: ORG, operation: 'suppliers.add', key: 'k-1' }) as unknown,
        details: {
          displayName: 'Gulf Office Supplies LLC',
          contacts: { phone: '+971501234567', email: 'accounts@gulfoffice.example', tradeLicence: null },
          source: { kind: 'registry', ref: 'DED-123456' },
        },
      },
    ]);
  });

  it.each([
    ['no name', { ...BODY, displayName: '' }],
    ['a name of 101 characters', { ...BODY, displayName: 'a'.repeat(101) }],
    ['a phone not in international form', { ...BODY, phone: '0501234567' }],
    ['an email that isn’t one', { ...BODY, email: 'not an email' }],
    ['a trade licence with a space', { ...BODY, tradeLicence: 'DED 123' }],
    ['a source of another kind', { ...BODY, source: { kind: 'a friend', ref: 'x' } }],
    ['a source reference of 201 characters', { ...BODY, source: { kind: 'registry', ref: 'r'.repeat(201) } }],
    ['a field it doesn’t know', { ...BODY, iban: 'AE070331234567890123456' }],
    ['no phone', { displayName: 'A', source: BODY.source }],
  ])('refuses %s with 400, before the use case runs', async (_what, body) => {
    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);

    const response = await app.inject(post('', body));

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'BAD_REQUEST' } });
    expect(asked).toEqual([]);
  });

  // Every character as a \uXXXX escape (6 bytes), as the longest JSON can write it.
  const unit = (code: number) => `\\u${code.toString(16).padStart(4, '0')}`;
  // Matched code point by code point: an astral one is two units, each escaped.
  const escaped = (text: string) =>
    text.replace(/[^]/gu, (c) => unit(c.charCodeAt(0)) + (c.length === 2 ? unit(c.charCodeAt(1)) : ''));
  const longest = (name: string) =>
    `{"displayName":"${escaped(name)}","phone":"${escaped('+971501234567890')}","email":"${escaped(`${'a'.repeat(64)}@${'b'.repeat(189)}`)}","tradeLicence":"${escaped('L'.repeat(50))}","source":{"kind":"registry","ref":"${escaped('r'.repeat(200))}"}}`;

  it.each([
    ['100 astral characters', String.fromCodePoint(0x1d400).repeat(100)],
    // U+1F82 sent decomposed: alpha and 3 marks, Unicode's longest canonical decomposition, kept as 1 (#221's review).
    [
      '100 characters sent decomposed, 4 code points each',
      String.fromCodePoint(0x3b1, 0x313, 0x300, 0x345).repeat(100),
    ],
  ])(
    'takes a name of %s, every field at its longest and escaped, without a 413 (the B8-3 lesson)',
    async (_what, name) => {
      const asked: Asked[] = [];
      const app = await withSuppliers({ add: { outcome: 'added', ...VIEW } }, asked);

      const response = await app.inject({ ...post(''), payload: longest(name) });

      expect(response.statusCode).toBe(201);
      expect(asked).toHaveLength(1);
    },
  );

  it('refuses a name sent as more than 1,000 UTF-16 units with 400, unread', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);

    const response = await app.inject(post('', { ...BODY, displayName: 'x'.repeat(1001) }));

    expect(response.statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [409, 'SUPPLIER_ADDS_SPENT'],
    [403, 'FORBIDDEN'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers %i %s as the use case refuses', async (status, code) => {
    const app = await withSuppliers({ add: { outcome: 'refused', status, code } });

    const response = await app.inject(post('', BODY));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it.each([
    ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
    ['busy', 'IDEMPOTENCY_KEY_BUSY'],
  ] as const)('answers a key %s as the idempotency store says', async (outcome, code) => {
    const app = await withSuppliers({ add: { outcome } });

    const response = await app.inject(post('', BODY));

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code } });
  });
});

describe('GET /v1/suppliers and /v1/suppliers/:id (E1-2)', () => {
  it('answers a page of suppliers, and where the next starts, passing the page asked for', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ list: { outcome: 'listed', suppliers: [SHOWN], next: SUPPLIER_ID } }, asked);

    const response = await app.inject(get(`?after=${SUPPLIER_ID}&limit=10`));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ suppliers: [SUPPLIER_ANSWERED], next: SUPPLIER_ID });
    expect(asked).toEqual([{ kind: 'list', orgId: ORG, page: { after: SUPPLIER_ID, limit: 10 } }]);
  });

  it.each(['limit=0', 'limit=51', 'after=not-an-id', 'other=1'])(
    'refuses %s before the use case runs',
    async (query) => {
      const asked: Asked[] = [];
      const app = await withSuppliers({}, asked);

      expect((await app.inject(get(`?${query}`))).statusCode).toBe(400);
      expect(asked).toEqual([]);
    },
  );

  it('answers 503 INTEGRITY_FAILED as the use case refuses a list', async () => {
    const app = await withSuppliers({});

    expect((await app.inject(get(''))).json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });

  it('answers one with its details, a change waiting and a cooling-off shown', async () => {
    const waiting = {
      ...VIEW,
      supplier: { ...SUPPLIER, pendingVersionId: VERSION_ID, coolingOffUntil: new Date('2026-10-02T08:00:00.000Z') },
    };
    const app = await withSuppliers({ change: { outcome: 'changed', ...waiting } });

    const response = await app.inject(post(`/${SUPPLIER_ID}/suspend`));

    expect(response.json()).toMatchObject({ changeWaiting: true, coolingOffUntil: '2026-10-02T08:00:00.000Z' });
  });

  it('answers the supplier shown, 404 as the use case refuses, and refuses an ID that isn’t one before it runs', async () => {
    const shown = await withSuppliers({ found: true });
    expect((await shown.inject(get(`/${SUPPLIER_ID}`))).json()).toEqual(DETAILS_ANSWERED);

    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);
    expect((await app.inject(get(`/${SUPPLIER_ID}`))).statusCode).toBe(404);
    expect((await app.inject(get('/not-an-id'))).statusCode).toBe(400);
    expect(asked).toEqual([{ kind: 'show', orgId: ORG, supplierId: SUPPLIER_ID }]);
  });
});

describe('POST /v1/suppliers/:id/suspend: the brake (E1-2)', () => {
  it('answers 200 with the supplier, SUSPENDED, passing the member and the key', async () => {
    const asked: Asked[] = [];
    const suspended = { ...VIEW, supplier: { ...SUPPLIER, status: 'SUSPENDED' as const } };
    const app = await withSuppliers({ change: { outcome: 'changed', ...suspended } }, asked);

    const response = await app.inject(post(`/${SUPPLIER_ID}/suspend`));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ...DETAILS_ANSWERED, status: 'SUSPENDED' });
    expect(asked).toEqual([
      {
        kind: 'suspend',
        member: MEMBER,
        keyed: expect.objectContaining({ operation: 'suppliers.suspend' }) as unknown,
        supplierId: SUPPLIER_ID,
      },
    ]);
  });

  it('refuses any body, before the use case runs', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);

    expect((await app.inject(post(`/${SUPPLIER_ID}/suspend`, { reason: 'x' }))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('POST /v1/suppliers/:id/reactivate, then /confirm, with a step-up (E1-2)', () => {
  it('answers the ask 202 with the step-up to sign in again for', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ change: { outcome: 'asked', stepUpChallengeId: CHALLENGE } }, asked);

    const response = await app.inject(post(`/${SUPPLIER_ID}/reactivate`));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(asked).toMatchObject([{ kind: 'reactivate', member: { ...MEMBER, sessionId: LIVE.sessionId } }]);
  });

  it('answers the confirm 200 with the supplier, passing the step-up', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ change: { outcome: 'changed', ...VIEW } }, asked);

    const response = await app.inject(post(`/${SUPPLIER_ID}/reactivate/confirm`, { stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(DETAILS_ANSWERED);
    expect(asked).toMatchObject([
      {
        kind: 'reactivateConfirm',
        member: { ...MEMBER, sessionId: LIVE.sessionId },
        keyed: { operation: 'suppliers.reactivate.confirm' },
        supplierId: SUPPLIER_ID,
        stepUpChallengeId: CHALLENGE,
      },
    ]);
  });

  it.each([
    [409, 'SUPPLIER_NOT_SUSPENDED'],
    [403, 'STEP_UP_FAILED'],
    [404, 'NOT_FOUND'],
  ] as const)('answers %i %s as the use case refuses', async (status, code) => {
    const app = await withSuppliers({ change: { outcome: 'refused', status, code } });

    const response = await app.inject(post(`/${SUPPLIER_ID}/reactivate/confirm`, { stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('answers a key reused for another request as the idempotency store says', async () => {
    const app = await withSuppliers({ change: { outcome: 'conflict' } });

    expect((await app.inject(post(`/${SUPPLIER_ID}/reactivate`))).json()).toMatchObject({
      error: { code: 'IDEMPOTENCY_KEY_REUSED' },
    });
  });

  it('refuses a confirm without a step-up’s ID, or with more, before the use case runs', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);

    expect((await app.inject(post(`/${SUPPLIER_ID}/reactivate/confirm`, {}))).statusCode).toBe(400);
    expect(
      (await app.inject(post(`/${SUPPLIER_ID}/reactivate/confirm`, { stepUpChallengeId: CHALLENGE, more: 1 })))
        .statusCode,
    ).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/agent/suppliers: an agent sees the ID and name alone (E1-2, SEC-AG-05)', () => {
  const asAgent = (key: string): InjectOptions => ({
    method: 'GET',
    url: '/v1/agent/suppliers',
    headers: { authorization: `Bearer ${key}` },
  });

  it('answers each verified supplier’s ID and name, and nothing else of it', async () => {
    const asked: Asked[] = [];
    const verified = { ...SHOWN, status: 'VERIFIED' as const };
    const app = await withSuppliers({ list: { outcome: 'listed', suppliers: [verified], next: null } }, asked);

    const response = await app.inject(asAgent(AGENT_KEY));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      suppliers: [{ id: SUPPLIER_ID, displayName: 'Gulf Office Supplies LLC' }],
      next: null,
    });
    expect(response.body).not.toMatch(/payee|beneficiary|AE…1234|\+971|registry/);
    expect(asked).toEqual([{ kind: 'usableByAgent', orgId: ORG, page: { after: null, limit: 50 } }]);
  });

  it('refuses a key without suppliers:read, before the use case runs', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);

    const response = await app.inject(asAgent(AGENT_KEY_WITHOUT_SUPPLIERS));

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: { code: 'INSUFFICIENT_SCOPE' } });
    expect(asked).toEqual([]);
  });

  it('refuses a member’s session: agent routes are the agents’ alone', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);

    const response = await app.inject({
      method: 'GET',
      url: '/v1/agent/suppliers',
      headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG },
    });

    expect(response.statusCode).toBe(403);
    expect(asked).toEqual([]);
  });

  it('answers 503 INTEGRITY_FAILED as the use case refuses', async () => {
    const app = await withSuppliers({});

    expect((await app.inject(asAgent(AGENT_KEY))).json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });
});

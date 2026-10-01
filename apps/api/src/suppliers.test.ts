// E1-2: the suppliers' routes, answering a member or an agent with each
// outcome of the use cases, and refusing a body that can't be a supplier's
// before they run; E2-2a: registering a supplier's bank details with the
// partner; E2-2b: confirming or withdrawing the change it left waiting, and a
// supplier's payee shown. Who reaches them is the access hook's
// (role-matrix.test.ts); what the use cases do with the database is
// supplier-registry.db.test.ts, supplier-changes.db.test.ts,
// supplier-payees.db.test.ts and supplier-payee-changes.db.test.ts.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LiveSession, MembershipCheck, SignIn } from '@agentx/core/modules/identity';
import type {
  RegistrationRecord,
  SupplierDetails,
  SupplierRecord,
  SupplierShown,
  VersionRecord,
} from '@agentx/core/modules/suppliers';
import type { IdempotentRequest } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type { SupplierChanges } from './supplier-changes.ts';
import type { SupplierPayeeChanges } from './supplier-payee-changes.ts';
import type { PayeeWrite, SupplierPayees } from './supplier-payees.ts';
import type { SupplierAddWrite, SupplierPage, SupplierRegistry, SuppliersListed } from './supplier-registry.ts';
import type { SupplierChangeWrite, SupplierView } from './supplier-work.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const SUPPLIER_ID = '0199a0f0-0000-7000-8000-0000000000e1';
const VERSION_ID = '0199a0f0-0000-7000-8000-0000000000e2';
const MEMBERSHIP = '0199a0f0-0000-7000-8000-000000000033';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000e3';
const REGISTRATION_ID = '0199a0f0-0000-7000-8000-0000000000e4';

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
  payee: null,
  pending: null,
};

/** A payee as the partner described it (E2-2b). */
const PAYEE = {
  registrationId: REGISTRATION_ID,
  payeeHint: 'AE…1234',
  nameCheck: 'match' as const,
  maskedName: 'G*** O***** S*******',
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
  payee: null,
  pendingChange: null,
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

const REGISTRATION: RegistrationRecord = {
  id: REGISTRATION_ID,
  supplierId: SUPPLIER_ID,
  versionId: '0199a0f0-0000-7000-8000-0000000000e5',
  partner: 'fake',
  route: 'hosted',
  startedBy: MEMBERSHIP,
  status: 'STARTED',
  beneficiaryRef: null,
  payeeKey: null,
  payeeKeyVersion: null,
  nameCheck: null,
  maskedName: null,
  payeeHint: null,
  registeredAt: null,
  failure: null,
};

const FORM = {
  url: 'https://payees.fake-partner.invalid/form/fake-form-1',
  expiresAt: new Date('2026-10-01T08:30:00.000Z'),
};

/** A registration as the routes answer it: never its reference or payee key. */
const REGISTRATION_ANSWERED = {
  id: REGISTRATION_ID,
  supplierId: SUPPLIER_ID,
  route: 'hosted',
  status: 'STARTED',
  nameCheck: null,
  maskedName: null,
  payeeHint: null,
  failure: null,
  form: { url: FORM.url, expiresAt: '2026-10-01T08:30:00.000Z' },
};

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
    }
  | {
      readonly kind: 'payeeApprove' | 'payeeApproveConfirm' | 'payeeWithdraw';
      readonly member: object;
      readonly keyed: IdempotentRequest;
      readonly supplierId: string;
      readonly stepUpChallengeId?: string;
    }
  | {
      readonly kind: 'payeeStart' | 'payeeCheck';
      readonly member: object;
      readonly keyed: IdempotentRequest;
      readonly supplierId: string;
      readonly registrationId?: string;
    }
  | {
      readonly kind: 'payeePassThrough';
      readonly member: object;
      readonly keyed: IdempotentRequest;
      readonly supplierId: string;
      readonly payee: object;
    };

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** A server whose use cases answer as given, noting what they were asked. */
async function withSuppliers(
  answers: {
    add?: SupplierAddWrite;
    list?: SuppliersListed;
    change?: SupplierChangeWrite;
    found?: boolean;
    payee?: PayeeWrite;
  },
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
    (kind: 'suspend' | 'reactivate' | 'payeeApprove' | 'payeeWithdraw') =>
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
  const payees: SupplierPayees = {
    start: (member, keyed, supplierId) => {
      asked.push({ kind: 'payeeStart', member, keyed, supplierId });
      return Promise.resolve(answers.payee ?? { outcome: 'busy' });
    },
    check: (member, keyed, supplierId, registrationId) => {
      asked.push({ kind: 'payeeCheck', member, keyed, supplierId, registrationId });
      return Promise.resolve(answers.payee ?? { outcome: 'busy' });
    },
    passThrough: (member, keyed, supplierId, payee) => {
      asked.push({ kind: 'payeePassThrough', member, keyed, supplierId, payee });
      return Promise.resolve(answers.payee ?? { outcome: 'busy' });
    },
  };
  const payeeChanges: SupplierPayeeChanges = {
    approve: change('payeeApprove'),
    withdraw: change('payeeWithdraw'),
    approveConfirm: (member, keyed, supplierId, stepUpChallengeId) => {
      asked.push({ kind: 'payeeApproveConfirm', member, keyed, supplierId, stepUpChallengeId });
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
    supplierPayees: payees,
    supplierPayeeChanges: payeeChanges,
  });
  servers.push(app);
  await app.ready();
  return app;
}

// The first server built in a run pays for loading the server's every route and schema: paid here, with time to
// spare, not by the first test against its 5 s limit (it failed so under load twice in a week, S72 and S73).
beforeAll(async () => {
  await withSuppliers({});
}, 30_000);

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

// Every character as a \uXXXX escape (6 bytes), as the longest JSON can write it.
const unit = (code: number) => `\\u${code.toString(16).padStart(4, '0')}`;
// Matched code point by code point: an astral one is two units, each escaped.
const escaped = (text: string) =>
  text.replace(/[^]/gu, (c) => unit(c.charCodeAt(0)) + (c.length === 2 ? unit(c.charCodeAt(1)) : ''));

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

  const longestEmail = `${'a'.repeat(64)}@${'b'.repeat(189)}`;
  const longest = (name: string) =>
    `{"displayName":"${escaped(name)}","phone":"${escaped('+971501234567890')}","email":"${escaped(longestEmail)}","tradeLicence":"${escaped('L'.repeat(50))}","source":{"kind":"registry","ref":"${escaped('r'.repeat(200))}"}}`;

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

describe('POST /v1/suppliers/:id/payee-registrations, then …/check: a payee through the partner’s form (E2-2a)', () => {
  it('answers the start 201 with the registration and the form, passing the member and the key', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ payee: { outcome: 'started', registration: REGISTRATION, form: FORM } }, asked);

    const response = await app.inject(post(`/${SUPPLIER_ID}/payee-registrations`));

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual(REGISTRATION_ANSWERED);
    expect(asked).toEqual([
      {
        kind: 'payeeStart',
        member: MEMBER,
        keyed: expect.objectContaining({ operation: 'suppliers.payee.start' }) as unknown,
        supplierId: SUPPLIER_ID,
      },
    ]);
  });

  it('answers a check 202 while the form waits, and 200 once the partner has the payee: its hint, never its reference', async () => {
    const asked: Asked[] = [];
    const waiting = await withSuppliers(
      { payee: { outcome: 'waiting', registration: REGISTRATION, form: FORM } },
      asked,
    );
    const path = `/${SUPPLIER_ID}/payee-registrations/${REGISTRATION_ID}/check`;

    const still = await waiting.inject(post(path));
    expect(still.statusCode).toBe(202);
    expect(still.json()).toEqual(REGISTRATION_ANSWERED);
    expect(asked).toEqual([
      {
        kind: 'payeeCheck',
        member: MEMBER,
        keyed: expect.objectContaining({ operation: 'suppliers.payee.check' }) as unknown,
        supplierId: SUPPLIER_ID,
        registrationId: REGISTRATION_ID,
      },
    ]);

    const registered: RegistrationRecord = {
      ...REGISTRATION,
      status: 'REGISTERED',
      beneficiaryRef: 'fake-beneficiary-1',
      payeeKey: 'fake-payee-1',
      nameCheck: 'partial',
      maskedName: 'G*** O***',
      payeeHint: 'AE…6026',
      registeredAt: new Date('2026-10-01T08:20:00.000Z'),
    };
    const done = await withSuppliers({ payee: { outcome: 'checked', registration: registered, form: null } });
    const answered = await done.inject(post(path));
    expect(answered.statusCode).toBe(200);
    expect(answered.json()).toEqual({
      ...REGISTRATION_ANSWERED,
      status: 'REGISTERED',
      nameCheck: 'partial',
      maskedName: 'G*** O***',
      payeeHint: 'AE…6026',
      form: null,
    });
    expect(answered.body).not.toContain('fake-beneficiary-1');
    expect(answered.body).not.toContain('fake-payee-1');
  });

  it('answers each refusal as the use case gives it, and a key reused as the idempotency store says', async () => {
    const taken = await withSuppliers({ payee: { outcome: 'refused', status: 409, code: 'SUPPLIER_PAYEE_TAKEN' } });
    const refusal = await taken.inject(post(`/${SUPPLIER_ID}/payee-registrations/${REGISTRATION_ID}/check`));
    expect(refusal.statusCode).toBe(409);
    expect(refusal.json()).toMatchObject({ error: { code: 'SUPPLIER_PAYEE_TAKEN' } });

    const reused = await withSuppliers({ payee: { outcome: 'conflict' } });
    expect((await reused.inject(post(`/${SUPPLIER_ID}/payee-registrations`))).json()).toMatchObject({
      error: { code: 'IDEMPOTENCY_KEY_REUSED' },
    });
  });

  it('refuses any body, or a registration that isn’t an ID, before the use case runs', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);

    expect((await app.inject(post(`/${SUPPLIER_ID}/payee-registrations`, { iban: 'AE07' }))).statusCode).toBe(400);
    expect((await app.inject(post(`/${SUPPLIER_ID}/payee-registrations/not-an-id/check`))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('POST /v1/suppliers/:id/payee-registrations/pass-through: the details passed through (E2-2d)', () => {
  /** A UAE IBAN with valid check digits, built here so no scanner takes it for a real one. */
  const iban = ['AE07', '0331234567890123456'].join('');
  const registered = {
    outcome: 'started' as const,
    registration: { ...REGISTRATION, status: 'REGISTERED' as const, payeeHint: 'AE…3456', nameCheck: 'match' as const },
    form: null,
  };

  it('answers 201 with the registration, passing the name composed and the IBAN compacted, never answering it', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ payee: registered }, asked);

    const response = await app.inject(
      post(`/${SUPPLIER_ID}/payee-registrations/pass-through`, {
        name: 'Jasmine AI FZ-LLC',
        iban: iban.toLowerCase().replace(/(.{4})/g, '$1 '),
      }),
    );

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({ status: 'REGISTERED', payeeHint: 'AE…3456', form: null });
    expect(response.body).not.toContain(iban.slice(4));
    expect(asked).toEqual([
      {
        kind: 'payeePassThrough',
        member: MEMBER,
        keyed: expect.objectContaining({ operation: 'suppliers.payee.pass-through' }) as unknown,
        supplierId: SUPPLIER_ID,
        payee: { name: 'Jasmine AI FZ-LLC', iban },
      },
    ]);
  });

  it.each([
    ['100 astral characters', String.fromCodePoint(0x1d400).repeat(100)],
    [
      '100 characters sent decomposed, 4 code points each',
      String.fromCodePoint(0x3b1, 0x313, 0x300, 0x345).repeat(100),
    ],
  ])(
    'takes a name of %s and an IBAN of 64 with spaces, each escaped, without a 413 (the B8-3 lesson)',
    async (_what, name) => {
      const asked: Asked[] = [];
      const app = await withSuppliers({ payee: registered }, asked);
      const spaced = iban.replace(/(.{4})/g, '$1 ').padEnd(64, ' ');

      const response = await app.inject({
        ...post(`/${SUPPLIER_ID}/payee-registrations/pass-through`),
        payload: `{"name":"${escaped(name)}","iban":"${escaped(spaced)}"}`,
      });

      expect(response.statusCode).toBe(201);
      expect(asked).toHaveLength(1);
    },
  );

  it('refuses an IBAN that isn’t a UAE one with valid check digits, or a name no one could read, never echoing it', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ payee: registered }, asked);
    const wrongDigits = `AE08${iban.slice(4)}`;

    for (const body of [
      { name: 'Jasmine AI FZ-LLC', iban: wrongDigits },
      { name: 'Jasmine AI FZ-LLC', iban: `GB82WEST12345698765432` },
      { name: '   ', iban },
      { name: 'Jasmine AI FZ-LLC', iban, also: 'x' },
      { name: 'Jasmine AI FZ-LLC' },
      // A valid IBAN, spaced past the 64 its body limit is reckoned on.
      { name: 'Jasmine AI FZ-LLC', iban: iban.padEnd(65, ' ') },
    ]) {
      const response = await app.inject(post(`/${SUPPLIER_ID}/payee-registrations/pass-through`, body));
      expect(response.statusCode).toBe(400);
      expect(response.body).not.toMatch(/0331234567890123456|12345698765432/);
    }
    expect(asked).toEqual([]);
  });
});

describe('POST /v1/suppliers/:id/payee-change/approve, then /confirm, and /withdraw (E2-2b)', () => {
  const PENDING_VERSION = { ...VERSION, id: '0199a0f0-0000-7000-8000-0000000000e5', version: 2 };

  it('shows a supplier’s payee and the change waiting as the partner described them, never a reference or key', async () => {
    const waiting: SupplierView = {
      ...VIEW,
      supplier: { ...SUPPLIER, pendingVersionId: PENDING_VERSION.id },
      payee: { ...PAYEE, nameCheck: 'partial' },
      pending: { version: PENDING_VERSION, payee: PAYEE },
    };
    const app = await withSuppliers({ change: { outcome: 'changed', ...waiting } });

    const response = await app.inject(post(`/${SUPPLIER_ID}/payee-change/withdraw`));

    expect(response.json()).toEqual({
      ...DETAILS_ANSWERED,
      changeWaiting: true,
      payee: { ...PAYEE, nameCheck: 'partial' },
      pendingChange: { version: 2, enteredAt: '2026-10-01T08:00:00.000Z', payee: PAYEE },
    });
    expect(response.body).not.toMatch(/a-beneficiary-ref|a-payee-key/);
  });

  it('answers the ask 202 with the step-up to sign in again for, passing the member in their session', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ change: { outcome: 'asked', stepUpChallengeId: CHALLENGE } }, asked);

    const response = await app.inject(post(`/${SUPPLIER_ID}/payee-change/approve`));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(asked).toMatchObject([
      {
        kind: 'payeeApprove',
        member: { ...MEMBER, sessionId: LIVE.sessionId },
        keyed: { operation: 'suppliers.payee.approve' },
        supplierId: SUPPLIER_ID,
      },
    ]);
  });

  it('answers the confirm 200 with the supplier, passing the step-up', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ change: { outcome: 'changed', ...VIEW } }, asked);

    const response = await app.inject(
      post(`/${SUPPLIER_ID}/payee-change/approve/confirm`, { stepUpChallengeId: CHALLENGE }),
    );

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(DETAILS_ANSWERED);
    expect(asked).toMatchObject([
      {
        kind: 'payeeApproveConfirm',
        member: { ...MEMBER, sessionId: LIVE.sessionId },
        keyed: { operation: 'suppliers.payee.approve.confirm' },
        supplierId: SUPPLIER_ID,
        stepUpChallengeId: CHALLENGE,
      },
    ]);
  });

  it('answers a withdrawal 200 with the supplier, passing the member and the key', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({ change: { outcome: 'changed', ...VIEW } }, asked);

    const response = await app.inject(post(`/${SUPPLIER_ID}/payee-change/withdraw`));

    expect(response.statusCode).toBe(200);
    expect(asked).toEqual([
      {
        kind: 'payeeWithdraw',
        member: MEMBER,
        keyed: expect.objectContaining({ operation: 'suppliers.payee.withdraw', key: 'k-1' }) as unknown,
        supplierId: SUPPLIER_ID,
      },
    ]);
  });

  it('answers each refusal as the use case gives it', async () => {
    for (const [status, code] of [
      [403, 'PAYEE_CHANGE_NOT_YOURS'],
      [409, 'SUPPLIER_NO_CHANGE_WAITING'],
      [409, 'SUPPLIER_PAYEE_TAKEN'],
    ] as const) {
      const app = await withSuppliers({ change: { outcome: 'refused', status, code } });
      const response = await app.inject(
        post(`/${SUPPLIER_ID}/payee-change/approve/confirm`, { stepUpChallengeId: CHALLENGE }),
      );
      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('refuses a body where none belongs, or a confirm without a step-up’s ID, before the use case runs', async () => {
    const asked: Asked[] = [];
    const app = await withSuppliers({}, asked);

    expect((await app.inject(post(`/${SUPPLIER_ID}/payee-change/approve`, { versionId: 'x' }))).statusCode).toBe(400);
    expect((await app.inject(post(`/${SUPPLIER_ID}/payee-change/withdraw`, { versionId: 'x' }))).statusCode).toBe(400);
    expect((await app.inject(post(`/${SUPPLIER_ID}/payee-change/approve/confirm`))).statusCode).toBe(400);
    expect(
      (
        await app.inject(
          post(`/${SUPPLIER_ID}/payee-change/approve/confirm`, { stepUpChallengeId: CHALLENGE, also: 'x' }),
        )
      ).statusCode,
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

// B6-1c: the registered contacts' routes, answering an admin with each
// outcome of the writes and the list. Who reaches them is the access hook's
// (role-matrix.test.ts); what the writes do in the database is the identity
// module's contact-changes.db.test.ts.
import type {
  ContactChanges,
  ContactChangeWrite,
  ContactWithAddress,
  InvitingAdmin,
  LiveSession,
  MembershipCheck,
  Role,
  SignIn,
} from '@agentx/core/modules/identity';
import { TooManyContacts } from '@agentx/core/modules/identity';
import type { IdempotentRequest } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { ListContacts } from './registered-contacts.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const CONTACT = '0199a0f0-0000-7000-8000-0000000000e6';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c6';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-27T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-09-27T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-27T09:10:00.000Z'),
  endsAt: new Date('2099-09-27T21:00:05.000Z'),
  idleEndsAt: new Date('2099-09-27T09:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const ADMIN: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role: 'admin' };
const ADMIN_WRITING: InvitingAdmin = { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId };

const contact = (changes: Partial<ContactWithAddress> = {}): ContactWithAddress => ({
  id: CONTACT,
  email: 'finance.office@example.test',
  status: 'ACTIVE',
  addedBy: '0199a0f0-0000-7000-8000-000000000033',
  countsFrom: new Date('2026-09-20T08:00:00.123Z'),
  stepUpChallengeId: CHALLENGE,
  ...changes,
});

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface Call {
  readonly kind: 'add' | 'confirm' | 'remove' | 'removeConfirm';
  readonly admin: InvitingAdmin;
  readonly keyed: IdempotentRequest;
  readonly subject: string;
  readonly challengeId?: string;
}

/** A server whose writes answer `answer` and whose list answers `listed` (none given the server when undefined), the caller holding `role`. */
async function withContacts(
  answer: ContactChangeWrite | Error | undefined,
  { role = 'admin', listed }: { role?: Role; listed?: Awaited<ReturnType<ListContacts>> | Error } = {},
) {
  const asked: Call[] = [];
  const answered = () =>
    (answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer)) as Promise<ContactChangeWrite>;
  const changes: ContactChanges = {
    add: (admin, keyed, email) => {
      asked.push({ kind: 'add', admin, keyed, subject: email });
      return answered();
    },
    confirm: (admin, keyed, id) => {
      asked.push({ kind: 'confirm', admin, keyed, subject: id });
      return answered();
    },
    remove: (admin, keyed, id) => {
      asked.push({ kind: 'remove', admin, keyed, subject: id });
      return answered();
    },
    removeConfirm: (admin, keyed, id, challengeId) => {
      asked.push({ kind: 'removeConfirm', admin, keyed, subject: id, challengeId });
      return answered();
    },
  };
  const lists: string[] = [];
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: 1000,
      rateLimitPerUserPerMinute: 1000,
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
    findMembership: (orgId) =>
      Promise.resolve(orgId.toLowerCase() === ORG ? { ...ADMIN, role } : ({ outcome: 'none' } as const)),
    ...(answer !== undefined && { contactChanges: changes }),
    ...(listed !== undefined && {
      listContacts: (orgId: string) => {
        lists.push(orgId);
        return listed instanceof Error ? Promise.reject(listed) : Promise.resolve(listed);
      },
    }),
  });
  servers.push(app);
  await app.ready();
  return { app, asked, lists };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const post = (path: string, payload?: Record<string, unknown>, key = 'k-1'): InjectOptions => ({
  method: 'POST',
  url: `/v1/registered-contacts${path}`,
  headers: { ...headers, 'idempotency-key': key },
  ...(payload !== undefined && { payload }),
});

/** The four writes, each well formed. */
const ALL = (): InjectOptions[] => [
  post('', { email: 'finance.office@example.test' }),
  post(`/${CONTACT}/confirm`),
  post(`/${CONTACT}/remove`),
  post(`/${CONTACT}/remove/confirm`, { stepUpChallengeId: CHALLENGE }),
];

describe('GET /v1/registered-contacts lists the organisation’s ACTIVE contacts (B6-1c)', () => {
  it('answers each with its address, its start, and whether it counts now', async () => {
    const counting = contact();
    const waiting = contact({
      id: '0199a0f0-0000-7000-8000-0000000000e7',
      countsFrom: new Date('2099-01-01T00:00:00Z'),
    });
    const { app, lists } = await withContacts(undefined, {
      listed: { outcome: 'listed', contacts: [counting, waiting] },
    });

    const response = await app.inject({ method: 'GET', url: '/v1/registered-contacts', headers });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      contacts: [
        {
          id: CONTACT,
          email: 'finance.office@example.test',
          status: 'ACTIVE',
          countsFrom: '2026-09-20T08:00:00.123Z',
          counts: true,
        },
        {
          id: waiting.id,
          email: 'finance.office@example.test',
          status: 'ACTIVE',
          countsFrom: '2099-01-01T00:00:00.000Z',
          counts: false,
        },
      ],
    });
    expect(lists).toEqual([ORG]);
  });

  it('answers 409 TOO_MANY_CONTACTS past the records the list reads (B8-2), and 500 for any other failure', async () => {
    const tooMany = await withContacts(undefined, { listed: new TooManyContacts() });
    const failed = await withContacts(undefined, { listed: new Error('the database went away') });

    const response = await tooMany.app.inject({ method: 'GET', url: '/v1/registered-contacts', headers });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'TOO_MANY_CONTACTS' } });
    expect((await failed.app.inject({ method: 'GET', url: '/v1/registered-contacts', headers })).statusCode).toBe(500);
  });

  it('withholds the list when a contact can’t be believed: 503 INTEGRITY_FAILED', async () => {
    const { app } = await withContacts(undefined, { listed: { outcome: 'tampered' } });

    const response = await app.inject({ method: 'GET', url: '/v1/registered-contacts', headers });

    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });
});

describe('POST /v1/registered-contacts adds a contact, once the admin has signed in again (B6-1c)', () => {
  it('asks: 202 with the draft and the step-up, for the admin’s own session', async () => {
    const draft = contact({ status: 'DRAFT', countsFrom: null });
    const { app, asked } = await withContacts({
      outcome: 'written',
      status: 202,
      contact: draft,
      stepUpChallengeId: CHALLENGE,
    });

    const response = await app.inject(post('', { email: 'Finance.Office@Example.test' }));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({
      contact: { id: CONTACT, email: 'finance.office@example.test', status: 'DRAFT', countsFrom: null, counts: false },
      stepUpChallengeId: CHALLENGE,
    });
    expect(asked).toEqual([
      {
        kind: 'add',
        admin: ADMIN_WRITING,
        keyed: expect.objectContaining({ orgId: ORG, operation: 'contacts.add', key: 'k-1' }) as unknown,
        subject: 'Finance.Office@Example.test',
      },
    ]);
  });

  it('answers a replay of a draft since confirmed without a step-up to sign in for', async () => {
    const { app } = await withContacts({ outcome: 'written', status: 202, contact: contact() });

    const response = await app.inject(post('', { email: 'finance.office@example.test' }));

    expect(response.statusCode).toBe(202);
    expect(response.json()).not.toHaveProperty('stepUpChallengeId');
  });

  it('confirms: 200 with the contact, ACTIVE', async () => {
    const { app, asked } = await withContacts({ outcome: 'written', status: 200, contact: contact() });

    const response = await app.inject(post(`/${CONTACT}/confirm`));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ contact: { id: CONTACT, status: 'ACTIVE', counts: true } });
    expect(asked).toMatchObject([
      { kind: 'confirm', admin: ADMIN_WRITING, keyed: { operation: 'contacts.add.confirm' }, subject: CONTACT },
    ]);
  });

  it.each([
    ['no address', {}],
    ['an address that isn’t one', { email: 'no-at-sign' }],
    ['a field it doesn’t take', { email: 'a@example.test', role: 'admin' }],
  ])('refuses an add with %s as BAD_REQUEST', async (_what, body) => {
    const { app, asked } = await withContacts({ outcome: 'written', status: 202, contact: contact() });

    expect((await app.inject(post('', body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('POST /v1/registered-contacts/{id}/remove removes a contact, once the admin has signed in again (B6-1c)', () => {
  it('asks: 202 with the step-up', async () => {
    const { app, asked } = await withContacts({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    const response = await app.inject(post(`/${CONTACT}/remove`));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(asked).toMatchObject([{ kind: 'remove', keyed: { operation: 'contacts.remove' }, subject: CONTACT }]);
  });

  it('confirms with the step-up it names: 200 with the contact, REMOVED', async () => {
    const { app, asked } = await withContacts({
      outcome: 'written',
      status: 200,
      contact: contact({ status: 'REMOVED' }),
    });

    const response = await app.inject(post(`/${CONTACT}/remove/confirm`, { stepUpChallengeId: CHALLENGE }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ contact: { id: CONTACT, status: 'REMOVED', counts: false } });
    expect(asked).toEqual([
      {
        kind: 'removeConfirm',
        admin: ADMIN_WRITING,
        keyed: expect.objectContaining({ operation: 'contacts.remove.confirm' }) as unknown,
        subject: CONTACT,
        challengeId: CHALLENGE,
      },
    ]);
  });

  it('refuses a confirmation without a step-up, or with more', async () => {
    const { app, asked } = await withContacts({ outcome: 'written', status: 200, contact: contact() });

    expect((await app.inject(post(`/${CONTACT}/remove/confirm`, {}))).statusCode).toBe(400);
    expect(
      (await app.inject(post(`/${CONTACT}/remove/confirm`, { stepUpChallengeId: CHALLENGE, note: 'x' }))).statusCode,
    ).toBe(400);
    expect((await app.inject(post(`/${CONTACT}/remove`, { note: 'x' }))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });
});

describe('all four registered contact writes (B6-1c)', () => {
  it('refuse a contact that isn’t an ID as BAD_REQUEST', async () => {
    const { app, asked } = await withContacts({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    for (const path of ['/not-an-id/confirm', '/not-an-id/remove']) {
      expect((await app.inject(post(path))).statusCode).toBe(400);
    }
    expect(asked).toEqual([]);
  });

  it('refuse a body over their limit', async () => {
    const { app, asked } = await withContacts({ outcome: 'written', status: 200, contact: contact() });

    expect((await app.inject(post('', { email: `${'a'.repeat(600)}@example.test` }))).statusCode).toBe(413);
    expect((await app.inject(post(`/${CONTACT}/confirm`, { pad: 'x'.repeat(64) }))).statusCode).toBe(413);
    expect(
      (await app.inject(post(`/${CONTACT}/remove/confirm`, { stepUpChallengeId: CHALLENGE, pad: 'x'.repeat(128) })))
        .statusCode,
    ).toBe(413);
    expect(asked).toEqual([]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuse a %s at all four, and at the list', async (role) => {
    const { app, asked, lists } = await withContacts(
      { outcome: 'written', status: 200, contact: contact() },
      { role, listed: { outcome: 'listed', contacts: [] } },
    );

    for (const request of [...ALL(), { method: 'GET' as const, url: '/v1/registered-contacts', headers }]) {
      expect((await app.inject(request)).statusCode).toBe(403);
    }
    expect(asked).toEqual([]);
    expect(lists).toEqual([]);
  });

  it.each([
    [409, 'CONTACT_EXISTS'],
    [409, 'CONTACTS_FULL'],
    [409, 'CONTACT_ADDS_SPENT'],
    [409, 'TOO_MANY_CONTACTS'],
    [409, 'CONTACT_CLOSED'],
    [409, 'CONTACT_NOT_ACTIVE'],
    [403, 'STEP_UP_FAILED'],
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
    [403, 'FORBIDDEN'],
    [401, 'UNAUTHENTICATED'],
  ] as const)('answer the refusal %i %s at all four', async (status, code) => {
    const { app } = await withContacts({ outcome: 'refused', status, code });

    for (const request of ALL()) {
      const response = await app.inject(request);

      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code } });
    }
  });

  it('answer a key used for another request, or still being done, at all four', async () => {
    for (const [outcome, code] of [
      ['conflict', 'IDEMPOTENCY_KEY_REUSED'],
      ['busy', 'IDEMPOTENCY_KEY_BUSY'],
    ] as const) {
      const { app } = await withContacts({ outcome });

      for (const request of ALL()) {
        expect((await app.inject(request)).json()).toMatchObject({ error: { code } });
      }
    }
  });

  it('fail as an internal error when a write answers out of turn, never with a half answer', async () => {
    const { app } = await withContacts({ outcome: 'asked', stepUpChallengeId: CHALLENGE });

    for (const request of [post('', { email: 'a@example.test' }), post(`/${CONTACT}/confirm`)]) {
      expect((await app.inject(request)).statusCode).toBe(500);
    }
    const { app: other } = await withContacts({ outcome: 'written', status: 200, contact: contact() });
    expect((await other.inject(post(`/${CONTACT}/remove`))).statusCode).toBe(500);
  });
});

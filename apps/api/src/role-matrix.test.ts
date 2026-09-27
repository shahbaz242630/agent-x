// FX-ROLEMATRIX, SEC-HA-09 and SEC-OPS-01 (B4-2a): every operation the API's
// document holds, by every kind of caller, allowed exactly when its x-access
// names them and refused otherwise. The operations come from the document the
// server builds, never from a list here, so each new route is in the matrix
// the moment it is added.
//
// A caller is allowed when the answer is not the access hook's refusal
// (UNAUTHENTICATED, FORBIDDEN, or the organisation's header refused): the
// route may still refuse what it was sent, which is its own business. An agent's key and an operator's credentials
// aren't read by the API yet (C2; operators have no API routes), so each is
// anyone else to it: refused everywhere but the public routes.
//
// SEC-HA-12 (B3+-1): an admin and an approver signed in with an authenticator
// app, not a passkey, are allowed only where a developer or a viewer is too,
// and refused everywhere else their role is named as PASSKEY_REQUIRED.
// SEC-OPS-04 (B6-3d): so are an admin and an approver in the 7 days after a
// second factor of theirs was removed, as SECOND_FACTOR_REMOVED.
import type { LiveSession, MembershipCheck, Role, SignIn } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER, type Principal } from './access.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const ROLES: readonly Role[] = ['admin', 'approver', 'developer', 'viewer'];

/**
 * Each signed-in caller: a cookie of their own, a person, their role in the
 * organisation, if any, how they signed in, and whether a second factor of
 * theirs was removed in the last 7 days.
 */
const PEOPLE: readonly {
  readonly name: string;
  readonly role: Role | null;
  readonly passkey: boolean;
  readonly restricted?: true;
}[] = [
  { name: 'person', role: null, passkey: false },
  ...ROLES.map((role) => ({ name: role, role, passkey: true })),
  { name: 'admin with an app code', role: 'admin', passkey: false },
  { name: 'approver with an app code', role: 'approver', passkey: false },
  { name: 'admin whose second factor was removed', role: 'admin', passkey: true, restricted: true },
  { name: 'approver whose second factor was removed', role: 'approver', passkey: true, restricted: true },
];

/** The roles a privileged person signed in without a passkey still acts in (access.ts). */
const WITHOUT_PASSKEY: readonly Principal[] = ['developer', 'viewer'];

const cookieOf = (index: number): string => String.fromCharCode(0x41 + index).repeat(43);
const userOf = (index: number): string => `0199a0f0-0000-7000-8000-${(0x100 + index).toString(16).padStart(12, '0')}`;

const session = (index: number): LiveSession => ({
  sessionId: `0199a0f0-0000-7000-8000-${(0x200 + index).toString(16).padStart(12, '0')}`,
  userId: userOf(index),
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-24T09:00:00.000Z'),
  amr: PEOPLE[index]?.passkey === true ? ['pwd', 'user', 'mfa'] : ['pwd', 'otp', 'mfa'],
  createdAt: new Date('2026-09-24T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-24T09:10:00.000Z'),
  endsAt: new Date('2026-09-24T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-24T09:40:00.000Z'),
});

/** A sign-in that knows each person's session and does nothing else a route asks of it. */
const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in the matrix')),
  beginStepUp: () => Promise.reject(new Error('not in the matrix')),
  complete: () => Promise.reject(new Error('not in the matrix')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => {
    const index = PEOPLE.findIndex((_, at) => cookieOf(at) === cookie);
    return Promise.resolve(index === -1 ? undefined : session(index));
  },
};

const membership = (orgId: string, userId: string): Promise<MembershipCheck> => {
  const index = PEOPLE.findIndex((_, at) => userOf(at) === userId);
  const role = PEOPLE[index]?.role ?? null;
  return Promise.resolve(
    orgId.toLowerCase() === ORG && role !== null
      ? { outcome: 'active', id: `0199a0f0-0000-7000-8000-${(0x300 + index).toString(16).padStart(12, '0')}`, role }
      : { outcome: 'none' },
  );
};

/** Until when a person is restricted: those PEOPLE says are. */
const restrictedUntil = (userId: string): Promise<Date | undefined> =>
  Promise.resolve(
    PEOPLE.find((_, at) => userOf(at) === userId)?.restricted === true
      ? new Date('2026-10-05T10:00:00.000Z')
      : undefined,
  );

/** Every kind of caller, and what they send besides the request itself. */
interface Caller {
  readonly name: string;
  /** Who they are to a route's access list. */
  readonly is: readonly Principal[];
  readonly headers: Readonly<Record<string, string>>;
  /**
   * In a role whose powers they lack (signed in without a passkey, or a second
   * factor removed): allowed only where a developer or a viewer is too, and
   * refused elsewhere for this reason.
   */
  readonly withoutPowers?: { readonly role: Role; readonly code: 'PASSKEY_REQUIRED' | 'SECOND_FACTOR_REMOVED' };
}

const CALLERS: readonly Caller[] = [
  { name: 'anyone', is: [], headers: {} },
  // No agent key or operator credential is read yet: each is anyone else to the API.
  { name: 'an agent', is: [], headers: { authorization: `Bearer axk_${'k'.repeat(40)}` } },
  { name: 'an operator', is: [], headers: {} },
  ...PEOPLE.map(({ name, role, passkey, restricted }, index) => ({
    name,
    is: role === null ? (['person'] as const) : (['person', role] as const),
    headers: { cookie: `${SESSION_COOKIE}=${cookieOf(index)}`, [ORGANIZATION_HEADER]: ORG },
    ...(role !== null && !passkey && { withoutPowers: { role, code: 'PASSKEY_REQUIRED' as const } }),
    ...(role !== null && restricted === true && { withoutPowers: { role, code: 'SECOND_FACTOR_REMOVED' as const } }),
  })),
];

interface Operation {
  readonly method: string;
  readonly path: string;
  readonly access: readonly Principal[];
}

let app: FastifyInstance;
let operations: Operation[];
/** The paths whose GET the document shows a HEAD for too. */
let heads: Set<string>;

beforeAll(async () => {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: 100_000,
      rateLimitPerUserPerMinute: 100_000,
    },
    log: { level: 'info' as const, eventCapPerMinute: 100_000 },
  };
  app = await buildServer({
    config,
    logger: createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', ...config },
      destination: new LogCapture(),
    }),
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: { service: SIGN_IN, sessionSeconds: 43_200 },
    restrictedUntil,
    findMembership: (orgId, userId) => membership(orgId, userId),
  });
  await app.ready();
  const paths = app.swagger().paths ?? {};
  heads = new Set(
    Object.entries(paths)
      .filter(([, item]) => item !== undefined && 'head' in item)
      .map(([path]) => path),
  );
  operations = Object.entries(paths).flatMap(([path, item]) =>
    Object.entries((item ?? {}) as Record<string, unknown>)
      .filter(([method]) => ['get', 'post', 'put', 'patch', 'delete'].includes(method))
      .map(([method, operation]) => ({
        method: method.toUpperCase(),
        path,
        access: (operation as { 'x-access': Principal[] })['x-access'],
      })),
  );
});

afterAll(async () => {
  await app.close();
});

/** The request a caller sends to an operation: any path parameter an ID, a write from our own origin with a key. */
const requestFor = (operation: Operation, caller: Caller): InjectOptions => ({
  method: operation.method as NonNullable<InjectOptions['method']>,
  url: operation.path.replace(/\{[^}]+\}/g, '0199a0f0-0000-7000-8000-00000000eeee'),
  headers: {
    origin: PUBLIC_ORIGIN,
    'idempotency-key': 'matrix-1',
    ...caller.headers,
  },
});

/**
 * Whether the answer is the access hook's refusal: by its reason code, since a
 * route may answer 401 or 403 of its own for what it was sent (the sign-in's
 * callback answers a failed sign-in so).
 */
const accessRefusal = (status: number, body: string): boolean => {
  if (status !== 400 && status !== 401 && status !== 403) return false;
  const { error } = JSON.parse(body) as { error?: { code?: string } };
  return ['UNAUTHENTICATED', 'FORBIDDEN', 'ORGANIZATION_INVALID', 'PASSKEY_REQUIRED', 'SECOND_FACTOR_REMOVED'].includes(
    error?.code ?? '',
  );
};

/** The refusal's reason code. */
const codeOf = (body: string): string | undefined => (JSON.parse(body) as { error?: { code?: string } }).error?.code;

/** Whether the caller's role is named, yet on a route for the powers they lack. */
const lacksPowers = (operation: Operation, caller: Caller): boolean =>
  caller.withoutPowers !== undefined &&
  operation.access.includes(caller.withoutPowers.role) &&
  !operation.access.some((principal) => WITHOUT_PASSKEY.includes(principal));

const allowed = (operation: Operation, caller: Caller): boolean =>
  operation.access.includes('public') ||
  (caller.is.some((principal) => operation.access.includes(principal)) && !lacksPowers(operation, caller));

describe('FX-ROLEMATRIX every operation × every caller', () => {
  it('reads the operations from the document, the sign-in and the session among them', () => {
    expect(operations.map(({ method, path }) => `${method} ${path}`)).toEqual(
      expect.arrayContaining([
        'GET /v1/auth/session',
        'GET /v1/auth/step-up',
        'GET /v1/auth/sign-in',
        'GET /v1/members',
      ]),
    );
  });

  it('SEC-HA-09 answers each caller its access names, and refuses every other with 401 or 403', async () => {
    const wrong: string[] = [];
    for (const operation of operations) {
      for (const caller of CALLERS) {
        const response = await app.inject(requestFor(operation, caller));
        const refused = accessRefusal(response.statusCode, response.body);
        if (refused === allowed(operation, caller)) {
          wrong.push(`${operation.method} ${operation.path} by ${caller.name}: ${String(response.statusCode)}`);
        } else if (
          refused &&
          (codeOf(response.body) === caller.withoutPowers?.code) !== lacksPowers(operation, caller)
        ) {
          wrong.push(`${operation.method} ${operation.path} by ${caller.name}: ${response.body}`);
        }
      }
    }
    expect(wrong).toEqual([]);
  });

  it("refuses a GET's HEAD exactly when it refuses the GET (a HEAD's answer has no body to read its reason from)", async () => {
    const wrong: string[] = [];
    for (const operation of operations.filter(({ method, path }) => method === 'GET' && heads.has(path))) {
      for (const caller of CALLERS) {
        const get = await app.inject(requestFor(operation, caller));
        const head = await app.inject({ ...requestFor(operation, caller), method: 'HEAD' });
        const headRefused = head.statusCode === 401 || head.statusCode === 403;
        if (headRefused !== accessRefusal(get.statusCode, get.body)) {
          wrong.push(
            `HEAD ${operation.path} by ${caller.name}: ${String(head.statusCode)}, GET ${String(get.statusCode)}`,
          );
        }
      }
    }
    expect(wrong).toEqual([]);
  });

  it('SEC-OPS-01 no operation outside /operator/ names operators, so no operator reaches a tenant route', () => {
    const named = operations.filter(
      ({ path, access }) => access.includes('operator') && !path.startsWith('/operator/'),
    );
    expect(named).toEqual([]);
  });

  it.each(['admin with an app code', 'admin whose second factor was removed'])(
    'SEC-HA-12, SEC-OPS-04 refuses an %s on the admin routes, never vacuously, and still lets them read the members',
    async (name) => {
      const admin = CALLERS.find((caller) => caller.name === name);
      if (admin === undefined) throw new Error(`no ${name}`);
      const refused = operations.filter((operation) => lacksPowers(operation, admin));
      expect(refused.map(({ method, path }) => `${method} ${path}`)).toContain('POST /v1/members/invitations');
      const members = operations.find(({ method, path }) => method === 'GET' && path === '/v1/members');
      if (members === undefined) throw new Error('no members list');
      const listed = await app.inject(requestFor(members, admin));
      expect(accessRefusal(listed.statusCode, listed.body), listed.body).toBe(false);
    },
  );

  it('refuses a person in a role everywhere their role is not named, in an organisation they do belong to', async () => {
    const roleRoutes = operations.filter(({ access }) => ROLES.some((role) => access.includes(role)));
    // Never vacuous: the members list is the first route naming roles (B4-2b).
    expect(roleRoutes.map(({ method, path }) => `${method} ${path}`)).toContain('GET /v1/members');
    for (const operation of roleRoutes) {
      for (const caller of CALLERS.filter((one) => one.is.length === 2 && !allowed(operation, one))) {
        const response = await app.inject(requestFor(operation, caller));
        expect(response.statusCode, `${operation.method} ${operation.path} by ${caller.name}`).toBe(403);
      }
    }
  });
});

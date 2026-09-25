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

/** Each signed-in caller: a cookie of their own, a person, and their role in the organisation, if any. */
const PEOPLE: readonly { readonly name: string; readonly role: Role | null }[] = [
  { name: 'person', role: null },
  ...ROLES.map((role) => ({ name: role, role })),
];

const cookieOf = (index: number): string => String.fromCharCode(0x41 + index).repeat(43);
const userOf = (index: number): string => `0199a0f0-0000-7000-8000-${(0x100 + index).toString(16).padStart(12, '0')}`;

const session = (index: number): LiveSession => ({
  sessionId: `0199a0f0-0000-7000-8000-${(0x200 + index).toString(16).padStart(12, '0')}`,
  userId: userOf(index),
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-24T09:00:00.000Z'),
  amr: ['pwd', 'otp', 'mfa'],
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

/** Every kind of caller, and what they send besides the request itself. */
interface Caller {
  readonly name: string;
  /** Who they are to a route's access list. */
  readonly is: readonly Principal[];
  readonly headers: Readonly<Record<string, string>>;
}

const CALLERS: readonly Caller[] = [
  { name: 'anyone', is: [], headers: {} },
  // No agent key or operator credential is read yet: each is anyone else to the API.
  { name: 'an agent', is: [], headers: { authorization: `Bearer axk_${'k'.repeat(40)}` } },
  { name: 'an operator', is: [], headers: {} },
  ...PEOPLE.map(({ name, role }, index) => ({
    name,
    is: role === null ? (['person'] as const) : (['person', role] as const),
    headers: { cookie: `${SESSION_COOKIE}=${cookieOf(index)}`, [ORGANIZATION_HEADER]: ORG },
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
  return ['UNAUTHENTICATED', 'FORBIDDEN', 'ORGANIZATION_INVALID'].includes(error?.code ?? '');
};

const allowed = (operation: Operation, caller: Caller): boolean =>
  operation.access.includes('public') || caller.is.some((principal) => operation.access.includes(principal));

describe('FX-ROLEMATRIX every operation × every caller', () => {
  it('reads the operations from the document, the sign-in and the session among them', () => {
    expect(operations.map(({ method, path }) => `${method} ${path}`)).toEqual(
      expect.arrayContaining(['GET /v1/auth/session', 'GET /v1/auth/step-up', 'GET /v1/auth/sign-in']),
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

  it('refuses a person in a role everywhere their role is not named, in an organisation they do belong to', async () => {
    const roleRoutes = operations.filter(({ access }) => ROLES.some((role) => access.includes(role)));
    for (const operation of roleRoutes) {
      for (const caller of CALLERS.filter((one) => one.is.length === 2 && !allowed(operation, one))) {
        const response = await app.inject(requestFor(operation, caller));
        expect(response.statusCode, `${operation.method} ${operation.path} by ${caller.name}`).toBe(403);
      }
    }
  });
});

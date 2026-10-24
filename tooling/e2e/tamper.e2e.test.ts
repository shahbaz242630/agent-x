// F1: SEC-HA-09, SEC-AG-04 and SEC-TEN-01, outside in.
// Every documented operation is exercised against local compose; x-access
// decides which credential substitutions must fail. Real signed tenant rows
// and sessions ensure these are attacks on the running product, not mocks.
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import { chromium, type Browser } from 'playwright';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it } from 'vitest';
import { z } from 'zod';

import { SCOPES } from '../../packages/core/src/modules/agents/index.ts';
import { createSessions, type Role } from '../../packages/core/src/modules/identity/index.ts';
import { uuidV7Ids } from '../../packages/core/src/shared-kernel/index.ts';
import { createDatabase, withTenant } from '../../packages/platform/src/db/index.ts';
import { loadKeys } from '../../packages/platform/src/keys/index.ts';
import { FixedClock, testLogger } from '../../packages/testing/src/index.ts';

import { createMandateRegistry } from '../../apps/api/src/mandate-registry.ts';
import {
  AED,
  mandateWorld,
  type MandateWorldTables,
  type World,
} from '../../apps/api/src/mandate-world.helper.test.ts';
import { APP_KEYS } from '../../deploy/compose/prepare.ts';
import { apiAnswers } from './api-sign-in.ts';
import { API_ORIGIN, localLogin, restartInPlace, SECRETS_DIR } from './compose.ts';
import { loginDriver, where } from './login-pages.ts';

interface Schema extends z.core.JSONSchema.JSONSchema {
  readonly anyOf?: Schema[];
  readonly properties?: Record<string, Schema>;
  readonly items?: Schema;
}

interface Operation {
  readonly method: string;
  readonly route: string;
  readonly access: readonly string[];
  readonly schema?: Schema;
}

const document = JSON.parse(readFileSync(new URL('../../apps/api/openapi.json', import.meta.url), 'utf8')) as {
  paths: Record<
    string,
    Record<
      string,
      {
        'x-access': string[];
        requestBody?: { content?: { 'application/json'?: { schema: Schema } } };
      }
    >
  >;
};
const operations: Operation[] = Object.entries(document.paths).flatMap(([route, item]) =>
  Object.entries(item).map(([method, operation]) => ({
    method: method.toUpperCase(),
    route,
    access: operation['x-access'],
    ...(operation.requestBody?.content?.['application/json']?.schema === undefined
      ? {}
      : { schema: operation.requestBody.content['application/json'].schema }),
  })),
);
const roles: readonly Role[] = ['admin', 'approver', 'developer', 'viewer'];
const roleRoute = (op: Operation) => roles.some((role) => op.access.includes(role));
const cookieHeader = (cookie: string) => ({ cookie: `__Host-agentx-session=${cookie}` });
const { password, users } = inject('e2e');
const database = createDatabase<MandateWorldTables>(
  {
    host: '127.0.0.1',
    port: 56541,
    database: 'agentx',
    user: 'agentx_app',
    password: localLogin('AGENTX_LOCAL_DB_APP_PASSWORD'),
    tls: 'disable',
    applicationName: 'agentx-tamper-e2e',
  },
  testLogger(),
);
const clock = new FixedClock(new Date());
const keys = loadKeys({ directory: path.join(SECRETS_DIR, APP_KEYS), current: {} });
const shared = mandateWorld({ app: () => database, clock: () => clock, ids: uuidV7Ids, name: 'tamper', keyring: keys });
const registry = createMandateRegistry({ database, keys, ids: uuidV7Ids, clock, logger: testLogger() });

interface Tenant {
  readonly world: World;
  readonly mandate: string;
  readonly key: { readonly text: string; readonly keyId: string };
  readonly draftAgent: string;
  readonly supplierName: string;
  request?: string;
  link?: { readonly id: string; readonly sessionRef: string };
}
let own: Tenant;
let foreign: Tenant;
let browser: Browser | undefined;
let realCookie: string;
let endedCookie: string;
let foreignCookie: string;
let people: Record<Role, string>;
let bankAccountId: string;
let foreignBefore: Awaited<ReturnType<typeof foreignChain>> | undefined;
let canaries: readonly string[] = [];
// One file at a time in this suite: <=240/minute per client and <=100/minute
// per credential, below the unchanged 300/client and 120/person or agent.
let lastSent = 0;
const credentialLastSent = new Map<string, number>();

/** Pick a caller from this operation's contract, so a lower role cannot mask a tenant/body refusal. */
function allowedHeaders(op: Operation): Record<string, string> {
  if (op.access.includes('public')) return {};
  if (op.access.includes('agent')) return { authorization: `Bearer ${own.key.text}` };
  if (op.access.includes('person')) return cookieHeader(realCookie);
  const role = roles.find((role) => op.access.includes(role));
  if (role === undefined) throw new Error(`${op.method} ${op.route} has no callable fixture`);
  return cookieHeader(people[role]);
}

/** The response text is checked even for redirects/errors, without following a foreign Location. */
async function send(op: Operation, headers: Record<string, string>, body?: unknown, url = routeOf(op, own)) {
  const credential = headers.authorization ?? headers.cookie ?? '';
  await sleep(Math.max(0, lastSent + 250 - Date.now(), (credentialLastSent.get(credential) ?? 0) + 600 - Date.now()));
  lastSent = Date.now();
  credentialLastSent.set(credential, lastSent);
  const response = await fetch(`${API_ORIGIN}${url}`, {
    method: op.method,
    redirect: 'manual',
    signal: AbortSignal.timeout(20_000),
    headers: {
      origin: API_ORIGIN,
      'idempotency-key': randomUUID(),
      'agentx-organization': own.world.org,
      ...headers,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  const answer = [text, ...response.headers.values()].join('\n');
  for (const value of canaries) {
    // A denied spend request can echo the IDs the attacker submitted. Those
    // are known inputs; other foreign identifiers and the private purpose aren't.
    if (body !== undefined && JSON.stringify(body).includes(value)) continue;
    expect(answer.includes(value), `${op.method} ${op.route} leaked tenant data`).toBe(false);
  }
  expect(response.status, `${op.method} ${op.route}: rate limiting must never count as refusal`).not.toBe(429);
  return { status: response.status, text };
}

/** Each rejection has an exact reason; malformed bodies and server failures cannot pass an access test. */
async function refused(op: Operation, headers: Record<string, string>, code: string, body?: unknown) {
  const answer = await send(op, headers, body);
  const label = `${op.method} ${op.route}: ${code}`;
  expect(answer.status, label).toBe(code === 'UNAUTHENTICATED' ? 401 : 403);
  if (op.method !== 'HEAD') expect(JSON.parse(answer.text), label).toMatchObject({ error: { code } });
}

/** Resource IDs are real in the foreign tenant whenever that resource is seeded. */
function routeOf(op: Operation, tenant: Tenant): string {
  const w = tenant.world;
  const resources: Readonly<Record<string, string | undefined>> = {
    members: w.admin.membershipId,
    mandates: tenant.mandate,
    agents: w.agent,
    'funding-sources': w.source,
    suppliers: w.suppliers[0],
    'spend-requests': tenant.request,
  };
  const resource = op.route.includes('/spend-requests/') ? tenant.request : resources[op.route.split('/')[2] ?? ''];
  return op.route.replace(/\{([^}]+)\}/g, (_, name: string) => {
    if (name === 'month') return new Date().toISOString().slice(0, 7);
    if (name === 'index') return '0';
    if (name === 'keyId') return tenant.key.keyId;
    if (name === 'linkId') return tenant.link?.id ?? w.org;
    if (name === 'sessionRef') return tenant.link?.sessionRef ?? w.org;
    return resource ?? w.org;
  });
}

/** Make a schema-valid request before adding forbidden fields, so missing fields cannot mask acceptance. */
function sample(schema: Schema, tenant: Tenant, field = ''): unknown {
  const alternative = schema.anyOf?.[0];
  if (alternative !== undefined) return sample(alternative, tenant, field);
  if (schema.enum !== undefined) return schema.enum[0];
  if (schema.type === 'object')
    return Object.fromEntries(
      [
        ...(schema.required ?? []),
        ...(schema.properties?.monthlyCapChoice === undefined ? [] : ['monthlyCapMinor']),
      ].map((name) => [name, sample(schema.properties?.[name] ?? {}, tenant, name)]),
    );
  if (schema.type === 'array')
    return Array.from({ length: schema.minItems ?? 1 }, () => sample(schema.items ?? {}, tenant, field));
  if (schema.type === 'boolean') return true;
  if (schema.type === 'number') return 100;
  if (Array.isArray(schema.type) && schema.type.includes('null')) return field === 'monthlyCapMinor' ? 100 : null;
  return textSample(schema, tenant, field);
}

/** Domain strings supplement the document's shape and satisfy server refinements. */
function textSample(schema: Schema, tenant: Tenant, field: string): unknown {
  const values: Record<string, unknown> = {
    currency: 'AED',
    timeZone: 'Asia/Dubai',
    splitWindowHours: 24,
    phone: '+971501234567',
    email: 'tamper@example.test',
    iban: 'AE070331234567890123456',
    token: 't'.repeat(43),
    oldKey: tenant.key.text,
    accountId: bankAccountId,
    url: 'https://example.test/form',
    agentId: tenant.draftAgent,
    fundingSourceId: tenant.world.source,
    supplierId: tenant.world.suppliers[0],
    supplierIds: tenant.world.suppliers[0],
    owner: tenant.world.admin.membershipId,
    from: new Date(Date.now() - 3_600_000).toISOString(),
    to: new Date().toISOString(),
  };
  if (values[field] !== undefined) return values[field];
  if (schema.format === 'uuid') return tenant.mandate;
  if (schema.format === 'date-time') return new Date(Date.now() + 86_400_000).toISOString();
  if (schema.format === 'email') return 'tamper@example.test';
  return 'tamper';
}

/** Snapshot the whole chain, not merely its length: a changed old event must fail too. */
const foreignChain = () =>
  withTenant(database, foreign.world.org, async (tx) => {
    const events = await tx.selectFrom('audit.events').selectAll().orderBy('seq').execute();
    const head = await tx.selectFrom('audit.heads').selectAll().execute();
    const bytes = JSON.stringify({ events, head }, (_key, value: unknown) =>
      typeof value === 'bigint' ? String(value) : value,
    );
    return { events: events.length, digest: createHash('sha256').update(bytes).digest('hex') };
  });

/** Positive controls prove the credentials and tenant records work before any attacks run. */
async function controls(): Promise<void> {
  const members = operations.find((op) => op.method === 'GET' && op.route === '/v1/members');
  const asks = operations.find((op) => op.method === 'POST' && op.route === '/v1/spend-requests');
  if (members === undefined || asks === undefined) throw new Error('positive-control operations missing');
  expect((await send(members, cookieHeader(realCookie))).status).toBe(200);
  const foreignPurpose = `private-tenant-${randomUUID()}`;
  for (const tenant of [own, foreign]) {
    const answer = await send(
      asks,
      { authorization: `Bearer ${tenant.key.text}` },
      {
        ...(sample(asks.schema ?? {}, tenant) as Record<string, unknown>),
        purpose: tenant === foreign ? foreignPurpose : 'Own order',
        orderReference: randomUUID(),
      },
    );
    expect(answer.status).toBe(201);
    const request = JSON.parse(answer.text) as { id: string; status: string };
    expect(request.status).toBe('APPROVAL_REQUIRED');
    tenant.request = request.id;
  }
  const detail = operations.find((op) => op.method === 'GET' && op.route === '/v1/spend-requests/{id}');
  if (detail === undefined) throw new Error('positive-control detail operation missing');
  const full = await send(
    detail,
    { ...cookieHeader(foreignCookie), 'agentx-organization': foreign.world.org },
    undefined,
    routeOf(detail, foreign),
  );
  expect(full.status).toBe(200);
  expect(full.text.includes(foreignPurpose), 'private purpose is present for its own tenant').toBe(true);
  expect(full.text.includes(foreign.supplierName), 'private supplier is present for its own tenant').toBe(true);
  await bankControls();
  canaries = [
    foreignPurpose,
    foreign.supplierName,
    foreignCookie,
    foreign.world.org,
    foreign.world.agent,
    foreign.world.source,
    ...foreign.world.suppliers,
    foreign.mandate,
    foreign.world.admin.membershipId,
    foreign.world.admin.userId,
    foreign.world.admin.sessionId,
    foreign.key.text,
    foreign.request ?? '',
    foreign.link?.id ?? '',
    foreign.link?.sessionRef ?? '',
  ];
}

/** A real, waiting foreign bank session and a real account ID isolate the bank's tenant check. */
async function bankControls(): Promise<void> {
  const accounts = operations.find((op) => op.method === 'GET' && op.route === '/v1/fake-bank/accounts');
  const start = operations.find((op) => op.method === 'POST' && op.route === '/v1/funding-sources/link-sessions');
  if (accounts === undefined || start === undefined) throw new Error('bank control operations missing');
  const listed = await send(accounts, allowedHeaders(accounts));
  expect(listed.status).toBe(200);
  bankAccountId = z
    .string()
    .min(1)
    .parse((JSON.parse(listed.text) as { accounts: { accountId: string }[] }).accounts[0]?.accountId);
  const linked = await send(start, { ...cookieHeader(foreignCookie), 'agentx-organization': foreign.world.org }, {});
  expect(linked.status).toBe(201);
  const body = JSON.parse(linked.text) as { link: { id: string }; authoriseUrl: string };
  foreign.link = {
    id: z.uuid().parse(body.link.id),
    sessionRef: z.string().min(1).parse(new URL(body.authoriseUrl).pathname.split('/').at(-1)),
  };
}

/** Both tenants have signed authority and a real agent key that the stack can authenticate. */
async function seed(): Promise<Tenant> {
  const supplierName = `Private supplier ${randomUUID()}`;
  const world = await shared.world({ scopes: SCOPES, supplierName });
  for (const id of world.suppliers) await shared.verified(world, id);
  const mandate = await shared.inForce(registry, world, { approvalThreshold: AED(1n) });
  return {
    world,
    mandate,
    draftAgent: (await shared.anotherAgent(world)).agent,
    supplierName,
    key: await shared.agentKey(world, world.agent, SCOPES),
  };
}

/** Foreign references in bodies must be refused too, including a recorded DENY for an agent's ask. */
async function foreignReferences(op: Operation, body: unknown): Promise<void> {
  if (op.schema === undefined) return;
  const replacements: Record<string, unknown> = {
    agentId: foreign.draftAgent,
    fundingSourceId: foreign.world.source,
    supplierId: foreign.world.suppliers[0],
    supplierIds: foreign.world.suppliers,
    owner: foreign.world.admin.membershipId,
  };
  for (const [field, value] of Object.entries(replacements)) {
    if (op.schema.properties?.[field] === undefined) continue;
    const headers = {
      ...allowedHeaders(op),
      ...(op.access.includes('agent') ? { 'agentx-organization': foreign.world.org } : {}),
    };
    const answer = await send(op, headers, { ...(body as Record<string, unknown>), [field]: value });
    const parsed = JSON.parse(answer.text) as { status?: string; decision?: string; error?: { code?: string } };
    const label = `${op.method} ${op.route}: foreign ${field}`;
    if (answer.status === 200 || answer.status === 201) {
      expect(parsed.decision, label).toBe('DENY');
      if (answer.status === 201) expect(parsed.status, label).toBe('DENIED');
    } else {
      expect([403, 404, 409], label).toContain(answer.status);
      expect(
        [
          'NOT_FOUND',
          'SOURCE_NOT_USABLE',
          'SUPPLIER_UNKNOWN',
          'POLICY_SUPPLIER_UNKNOWN',
          'POLICY_WIDER_THAN_MANDATE',
          'AGENT_OWNER_NOT_ELIGIBLE',
          'STEP_UP_FAILED',
        ],
        label,
      ).toContain(parsed.error?.code);
    }
  }
}

beforeAll(async () => {
  expect(API_ORIGIN).toBe('http://localhost:8080');
  // The copier deliberately ends sessions for password/factor setup events.
  // Drain the fixture's creation events (its one-minute settle window) before
  // this long pass signs in, as first-admin's copier test drains its event.
  await sleep(Math.max(0, users.tamper.provisionedAt + 61_000 - Date.now()));
  await restartInPlace('api');
  await apiAnswers();
  own = await seed();
  foreign = await seed();
  people = {} as Record<Role, string>;
  for (const role of roles.filter((role) => role !== 'developer')) {
    people[role] = (await shared.signedInMember(own.world.org, role)).cookie;
  }
  foreignCookie = (await shared.signedInMember(foreign.world.org, 'admin')).cookie;
  endedCookie = (await shared.signedInMember(own.world.org, 'admin')).cookie;
  await createSessions({ ids: uuidV7Ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } }).end(
    database,
    endedCookie,
  );

  browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=/tamper-signed-in`);
  const { drive } = loginDriver({ password, callback: /^http:\/\/localhost:8080\/tamper-signed-in$/ });
  expect((await drive(page, users.tamper, [])).stoppedAt, where(page)).toBe('callback');
  const cookie = (await context.cookies(API_ORIGIN)).find((one) => one.name === '__Host-agentx-session');
  if (cookie === undefined) throw new Error('tamper person did not sign in');
  realCookie = cookie.value;
  const session = await context.request.get(`${API_ORIGIN}/v1/auth/session`);
  expect(session.status()).toBe(200);
  const { userId } = (await session.json()) as { userId: string };
  await shared.joined(own.world.org, userId, 'developer');
  people.developer = realCookie;
  // Foreign IDs in URLs are attacker inputs, so check disclosure using the
  // foreign authority's other identifiers and sealed payloads, not their echo.
  await controls();
  foreignBefore = await foreignChain();
  expect(foreignBefore.events).toBeGreaterThan(0);
});

afterEach(async () => {
  if (foreignBefore !== undefined) expect(await foreignChain(), 'foreign audit chain changed').toEqual(foreignBefore);
});

afterAll(async () => {
  await browser?.close();
  await database.destroy();
});

/** Substituted sessions and credentials must fail before input validation. */
async function credentials(op: Operation, body: unknown, forged: string): Promise<void> {
  await refused(op, cookieHeader(endedCookie), 'UNAUTHENTICATED', body);
  await refused(
    op,
    { authorization: `Bearer ${forged}` },
    op.access.includes('agent') ? 'UNAUTHENTICATED' : 'FORBIDDEN',
    body,
  );
  if (!op.access.includes('agent')) {
    await refused(op, { authorization: `Bearer ${own.key.text}` }, 'FORBIDDEN', body);
    await refused(op, { authorization: `Bearer ${own.key.text}`, ...cookieHeader(people.admin) }, 'FORBIDDEN', body);
  } else {
    await refused(op, cookieHeader(realCookie), 'FORBIDDEN', body);
    // An agent's key fixes its tenant; a stray organisation header grants
    // nothing. Reads still return its own data, checked for leaks by send().
    if (op.method === 'GET' || op.method === 'HEAD') {
      const answer = await send(op, { ...allowedHeaders(op), 'agentx-organization': foreign.world.org }, body);
      expect(answer.status, `${op.route}: an agent's tenant cannot be selected by a header`).toBe(200);
    }
  }
  if (roleRoute(op)) {
    await refused(op, cookieHeader(foreignCookie), 'FORBIDDEN', body);
    await refused(op, { ...allowedHeaders(op), 'agentx-organization': foreign.world.org }, 'FORBIDDEN', body);
    for (const role of roles.filter((role) => !op.access.includes(role))) {
      await refused(op, cookieHeader(people[role]), 'FORBIDDEN', body);
    }
  }
}

/** Forbidden server-owned fields are tested using a caller the route allows. */
async function injectedFields(op: Operation, body: unknown): Promise<void> {
  // An allowed caller must still be refused for extra server-owned fields.
  // `role` is legitimate on invitations/role changes, so inject org_id there.
  if (op.schema !== undefined) {
    const headers = allowedHeaders(op);
    for (const field of ['org_id', 'role'].filter((field) => op.schema?.properties?.[field] === undefined)) {
      const answer = await send(op, headers, {
        ...(body as Record<string, unknown>),
        [field]: field === 'role' ? 'admin' : foreign.world.org,
      });
      // A small body's cap can reject the injected UUID before JSON validation.
      expect([400, 413], `${op.route}: extra ${field}`).toContain(answer.status);
      expect(JSON.parse(answer.text)).toMatchObject({
        error: { code: answer.status === 413 ? 'PAYLOAD_TOO_LARGE' : 'BAD_REQUEST' },
      });
    }
    await foreignReferences(op, body);
  }
}

/** An allowed caller still cannot address the other organisation's resources. */
async function foreignResources(op: Operation, body: unknown): Promise<void> {
  if (!(roleRoute(op) || op.access.includes('agent')) || !op.route.includes('{')) return;
  const headers = {
    ...allowedHeaders(op),
    ...(op.access.includes('agent') ? { 'agentx-organization': foreign.world.org } : {}),
  };
  const answer = await send(op, headers, body, routeOf(op, foreign));
  const bankSession = op.route.includes('{sessionRef}');
  expect(answer.status, `${op.route}: foreign resource`).toBe(bankSession ? 409 : 404);
  if (op.method !== 'HEAD')
    expect(JSON.parse(answer.text)).toMatchObject({
      error: { code: bankSession ? 'BANK_LINK_NOT_WAITING' : 'NOT_FOUND' },
    });
}

describe('F1 SEC-HA-09, SEC-AG-04, SEC-TEN-01: every documented operation', () => {
  it('covers the document without an unclassified operation', () => {
    expect(operations.length).toBeGreaterThan(100);
    for (const op of operations) {
      expect(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']).toContain(op.method);
      expect(op.access.length, `${op.method} ${op.route} needs x-access`).toBeGreaterThan(0);
      for (const caller of op.access) expect([...roles, 'person', 'agent', 'public', 'operator']).toContain(caller);
    }
  });

  it.each(operations)('$method $route ($access)', async (op) => {
    const body = op.schema === undefined ? undefined : sample(op.schema, own);
    if (op.schema !== undefined) {
      expect(z.fromJSONSchema(op.schema).safeParse(body).success, `${op.method} ${op.route}: invalid baseline`).toBe(
        true,
      );
    }
    const forged = [
      'eyJhbGciOiJIUzI1NiJ9',
      Buffer.from(JSON.stringify({ sub: own.world.admin.userId, role: 'admin', org_id: foreign.world.org })).toString(
        'base64url',
      ),
      'forged',
    ].join('.');
    if (op.access.includes('public')) {
      // Public means public even with substituted credentials. Still send
      // the attack, without a live cookie that would deliberately sign out.
      const answer = await send(op, { authorization: `Bearer ${forged}`, ...cookieHeader(endedCookie) }, body);
      expect(answer.status).toBeLessThan(500);
      await injectedFields(op, body);
      return;
    }
    await credentials(op, body, forged);
    await injectedFields(op, body);
    await foreignResources(op, body);
  });
});

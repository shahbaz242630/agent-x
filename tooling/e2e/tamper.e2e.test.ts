// F1: the outside-in "Burp pass" the partner asked for in S137, before
// Phase 5 and on every PR after. It replays every documented operation
// against local compose with changed credentials, tenant IDs and body fields,
// using real sign-ins and signed records. Refusals must reveal no foreign
// data or change the foreign audit chain. This does not replace the paid pentest.
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import { chromium, type Browser } from 'playwright';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';
import { z } from 'zod';

import { SCOPES } from '../../packages/core/src/modules/agents/index.ts';
import {
  addBackgroundExport,
  claimFile,
  fileReady,
  type ActivityExportTables,
  type ActivityTables,
} from '../../packages/core/src/modules/activity/index.ts';
import { createAuditTrail } from '../../packages/core/src/modules/audit/index.ts';
import { createSessions, type Role } from '../../packages/core/src/modules/identity/index.ts';
import { tamperIdentityFixtures } from '../../packages/core/src/modules/identity/tamper-fixtures.helper.test.ts';
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
// Reuse the driver's code history when recovery signs the same person in again.
const personLogin = loginDriver({ password, callback: /^http:\/\/localhost:8080\/tamper-signed-in$/ });
const database = createDatabase<MandateWorldTables & ActivityExportTables & ActivityTables>(
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
  identity?: { readonly invitation: string; readonly contact: string; readonly reset: string };
  exportId?: string;
  downloadId?: string;
  registrationId?: string;
  exportMonth?: string;
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
let startedAt = 0;
let needsReseed = false;
let ownReseeds = 0;
const requestCounts = { attack: 0, control: 0 };
const covered = new Set<string>();
interface Finding {
  kind: string;
  method: string;
  route: string;
  credential: string;
  attack: string;
  answer: { status: number; code?: string; decision?: string; state?: string };
}
const findings: Finding[] = [];
let currentAttack = '';
let lastAnswer: { op: Operation; headers: Record<string, string>; answer: Finding['answer'] } | undefined;
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
async function send(
  op: Operation,
  headers: Record<string, string>,
  body?: unknown,
  url = routeOf(op, own),
  purpose: 'attack' | 'control' = 'attack',
) {
  const credential = headers.authorization ?? headers.cookie ?? '';
  await sleep(Math.max(0, lastSent + 250 - Date.now(), (credentialLastSent.get(credential) ?? 0) + 600 - Date.now()));
  lastSent = Date.now();
  credentialLastSent.set(credential, lastSent);
  requestCounts[purpose] += 1;
  covered.add(`${op.method} ${op.route}`);
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
  const answerSummary = summaryOf(response.status, text);
  lastAnswer = { op, headers, answer: answerSummary };
  const problems: string[] = [];
  // Record only credential labels and safe answer fields; a successful key-creation bug must not print its secret.
  if (purpose === 'attack' && response.status >= 200 && response.status < 300) {
    needsReseed = true;
    problems.push('2xx to attack');
  }
  const answer = [text, ...response.headers.values()].join('\n');
  for (const value of canaries) {
    // A denied spend request can echo the IDs the attacker submitted. Those
    // are known inputs; other foreign identifiers and the private purpose aren't.
    if (body !== undefined && JSON.stringify(body).includes(value)) continue;
    if (answer.includes(value)) {
      needsReseed = true;
      problems.push('foreign data leaked');
    }
  }
  if (problems.length > 0) finding(op, headers, [...new Set(problems)].join('; '), answerSummary);
  expect(response.status, `${op.method} ${op.route}: rate limiting must never count as refusal`).not.toBe(429);
  return { status: response.status, text };
}

/** Positive controls may succeed; their responses still undergo the leak checks. */
const controlSend = (op: Operation, headers: Record<string, string>, body?: unknown, url = routeOf(op, own)) =>
  send(op, headers, body, url, 'control');

/** Keep the finding useful without copying cookies, keys or arbitrary response content to logs. */
function summaryOf(status: number, text: string): Finding['answer'] {
  if (text === '' || !text.startsWith('{')) return { status };
  const body = JSON.parse(text) as { error?: { code?: string }; decision?: string; status?: string };
  return {
    status,
    ...(body.error?.code === undefined ? {} : { code: body.error.code }),
    ...(body.decision === undefined ? {} : { decision: body.decision }),
    ...(body.status === undefined ? {} : { state: body.status }),
  };
}

/** One failure is reported at its source, then afterEach restores the attacking tenant. */
function finding(op: Operation, headers: Record<string, string>, kind: string, answer: Finding['answer']): never {
  const credential =
    headers.authorization === undefined
      ? (Object.entries(people).find(([, cookie]) => headers.cookie === cookieHeader(cookie).cookie)?.[0] ??
          'foreign or ended session') + ' cookie'
      : headers.authorization === `Bearer ${own.key.text}`
        ? 'agent key'
        : 'forged bearer token';
  const found = { kind, method: op.method, route: op.route, credential, attack: currentAttack, answer };
  findings.push(found);
  throw new Error(`FINDING ${JSON.stringify(found)}`);
}

/** Each rejection has an exact reason; malformed bodies and server failures cannot pass an access test. */
async function refused(op: Operation, headers: Record<string, string>, code: string, body?: unknown) {
  const answer = await send(op, headers, body);
  const label = `${op.method} ${op.route}: ${code}`;
  expect(answer.status, label).toBe(code === 'UNAUTHENTICATED' ? 401 : 403);
  if (op.method !== 'HEAD') expect(JSON.parse(answer.text), label).toMatchObject({ error: { code } });
}

/** Resource IDs are real in the foreign tenant whenever that resource is seeded. */
function routeOf(op: Operation, tenant: Tenant, missing = false): string {
  const w = tenant.world;
  const resources: Readonly<Record<string, string | undefined>> = {
    members: w.admin.membershipId,
    mandates: tenant.mandate,
    agents: w.agent,
    'funding-sources': w.source,
    suppliers: w.suppliers[0],
    'spend-requests': tenant.request,
    'registered-contacts': tenant.identity?.contact,
    'factor-resets': tenant.identity?.reset,
    'access-log': tenant.exportId,
  };
  const resource = op.route.includes('/members/invitations/')
    ? tenant.identity?.invitation
    : op.route.includes('/spend-requests/')
      ? tenant.request
      : op.route.includes('{registrationId}')
        ? w.suppliers.at(-1)
        : resources[op.route.split('/')[2] ?? ''];
  const values: Readonly<Record<string, string | undefined>> = {
    id: resource,
    keyId: tenant.key.keyId,
    linkId: tenant.link?.id,
    sessionRef: tenant.link?.sessionRef,
    registrationId: tenant.registrationId,
    downloadId: tenant.downloadId,
    month: tenant.exportMonth,
    index: '0',
    orgId: w.org,
    organizationId: w.org,
  };
  // Both own and foreign probes must use the right record kind; an organisation ID cannot stand in for one.
  return op.route.replace(/\{([^}]+)\}/g, (_, name: string) => {
    const value = values[name];
    if (value === undefined) throw new Error(`${op.route}: no seeded ${name} for this tenant`);
    if (missing && name !== 'month' && name !== 'index') return randomUUID();
    return value;
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
  if (schema.type === 'number' || schema.type === 'integer') return 100;
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
  // Patterns used for decimal minor amounts can require text rather than a JSON number.
  if (schema.pattern !== undefined && new RegExp(schema.pattern).test('100')) return '100';
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
  if (members === undefined) throw new Error('positive-control operation missing');
  expect((await controlSend(members, cookieHeader(realCookie))).status).toBe(200);
  const foreignPurpose = `private-tenant-${randomUUID()}`;
  await seedRequest(foreign, foreignPurpose);
  const detail = operations.find((op) => op.method === 'GET' && op.route === '/v1/spend-requests/{id}');
  if (detail === undefined) throw new Error('positive-control detail operation missing');
  const full = await controlSend(
    detail,
    { ...cookieHeader(foreignCookie), 'agentx-organization': foreign.world.org },
    undefined,
    routeOf(detail, foreign),
  );
  expect(full.status).toBe(200);
  expect(full.text.includes(foreignPurpose), 'private purpose is present for its own tenant').toBe(true);
  expect(full.text.includes(foreign.supplierName), 'private supplier is present for its own tenant').toBe(true);
  await bankControls(foreign, foreignCookie);
  const bankDetails = await payeeControls(foreign, foreignCookie);
  canaries = [
    foreignPurpose,
    foreign.supplierName,
    ...bankDetails,
    foreignCookie,
    foreign.world.org,
    foreign.world.agent,
    foreign.draftAgent,
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
async function bankControls(tenant: Tenant, adminCookie: string): Promise<void> {
  const accounts = operations.find((op) => op.method === 'GET' && op.route === '/v1/fake-bank/accounts');
  const start = operations.find((op) => op.method === 'POST' && op.route === '/v1/funding-sources/link-sessions');
  if (accounts === undefined || start === undefined) throw new Error('bank control operations missing');
  const listed = await controlSend(accounts, allowedHeaders(accounts));
  expect(listed.status).toBe(200);
  bankAccountId = z
    .string()
    .min(1)
    .parse((JSON.parse(listed.text) as { accounts: { accountId: string }[] }).accounts[0]?.accountId);
  const linked = await controlSend(
    start,
    { ...cookieHeader(adminCookie), 'agentx-organization': tenant.world.org },
    {},
  );
  expect(linked.status).toBe(201);
  const body = JSON.parse(linked.text) as { link: { id: string }; authoriseUrl: string };
  tenant.link = {
    id: z.uuid().parse(body.link.id),
    sessionRef: z.string().min(1).parse(new URL(body.authoriseUrl).pathname.split('/').at(-1)),
  };
}

/** A new request proves each replacement tenant is usable before another attack starts. */
async function seedRequest(tenant: Tenant, purpose: string): Promise<void> {
  const op = operation('POST', '/v1/spend-requests');
  const answer = await controlSend(
    op,
    { authorization: `Bearer ${tenant.key.text}` },
    {
      ...(sample(op.schema ?? {}, tenant) as Record<string, unknown>),
      purpose,
      orderReference: randomUUID(),
    },
  );
  expect(answer.status).toBe(201);
  const request = JSON.parse(answer.text) as { id: string; status: string };
  expect(request.status).toBe('APPROVAL_REQUIRED');
  tenant.request = z.uuid().parse(request.id);
}

/** Control routes are looked up in the document too, so removed routes fail clearly. */
function operation(method: string, route: string): Operation {
  const op = operations.find((one) => one.method === method && one.route === route);
  if (op === undefined) throw new Error(`control operation missing: ${method} ${route}`);
  return op;
}

/** Fresh authority prevents one accepted attack from invalidating the following cases. */
async function resetOwn(): Promise<void> {
  clock.advanceBy(Math.max(0, Date.now() - clock.now().getTime()));
  own = await seed();
  const admin = await shared.signedInMember(own.world.org, 'admin');
  people = { admin: admin.cookie } as Record<Role, string>;
  for (const role of roles.filter((role) => role !== 'developer' && role !== 'admin')) {
    people[role] = (await shared.signedInMember(own.world.org, role)).cookie;
  }
  endedCookie = (await shared.signedInMember(own.world.org, 'admin')).cookie;
  await createSessions({ ids: uuidV7Ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } }).end(
    database,
    endedCookie,
  );
  await signInPerson();
  await seedRequest(own, 'Own order');
  // Own-ID controls need the same ancillary record kinds as the foreign-ID probes.
  own.identity = await tamperIdentityFixtures(database, keys, uuidV7Ids, clock, admin, own.world.admin.membershipId);
  await bankControls(own, admin.cookie);
  await payeeControls(own, admin.cookie);
  await exportFixtures(own, admin.userId);
  needsReseed = false;
}

/** Sign in again after recovery too: an attack may have ended the old real session. */
async function signInPerson(): Promise<void> {
  if (browser === undefined) throw new Error('the tamper browser is not open');
  const context = await browser.newContext();
  context.on('request', (request) => {
    if (new URL(request.url()).origin === API_ORIGIN) requestCounts.control += 1;
  });
  try {
    const page = await context.newPage();
    await page.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=/tamper-signed-in`);
    expect((await personLogin.drive(page, users.tamper, [])).stoppedAt, where(page)).toBe('callback');
    const cookie = (await context.cookies(API_ORIGIN)).find((one) => one.name === '__Host-agentx-session');
    if (cookie === undefined) throw new Error('tamper person did not sign in');
    realCookie = cookie.value;
    requestCounts.control += 1;
    const session = await context.request.get(`${API_ORIGIN}/v1/auth/session`);
    expect(session.status()).toBe(200);
    const { userId } = (await session.json()) as { userId: string };
    await shared.joined(own.world.org, userId, 'developer');
    people.developer = realCookie;
  } finally {
    await context.close();
  }
}

/** Both tenants have signed authority and a real agent key that the stack can authenticate. */
async function seed(): Promise<Tenant> {
  const supplierName = `Private supplier ${randomUUID()}`;
  const world = await shared.world({ scopes: SCOPES, supplierName, suppliers: 3 });
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

/** Give the foreign suppliers distinct real bank details, kept by the local fake partner only. */
async function payeeControls(tenant: Tenant, adminCookie: string): Promise<string[]> {
  const op = operation('POST', '/v1/suppliers/{id}/payee-registrations/pass-through');
  const details: string[] = [];
  for (const supplier of tenant.world.suppliers.slice(1)) {
    const digits = BigInt(`0x${randomUUID().replaceAll('-', '')}`)
      .toString()
      .slice(-16)
      .padStart(16, '0');
    const bban = `033${digits}`;
    const check = (98n - (BigInt(`${bban}101400`) % 97n)).toString().padStart(2, '0');
    const iban = `AE${check}${bban}`;
    const name = `Foreign payee ${randomUUID()}`;
    const registered = await controlSend(
      op,
      { ...cookieHeader(adminCookie), 'agentx-organization': tenant.world.org },
      { name, iban, pendingRequests: 'pause' },
      op.route.replace('{id}', supplier),
    );
    expect(registered.status).toBe(201);
    tenant.registrationId = z.uuid().parse((JSON.parse(registered.text) as { id: string }).id);
    details.push(name, iban);
  }
  return details;
}

/** Real export/file/download IDs cover ancillary routes too; ready records cannot be changed by a builder later. */
async function exportFixtures(tenant: Tenant, requestedBy: string): Promise<void> {
  const org = tenant.world.org;
  const now = new Date();
  const from = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const id = uuidV7Ids.next();
  await withTenant(database, org, async (tx) => {
    await addBackgroundExport(tx, org, {
      id,
      requestedBy,
      from,
      to: new Date(from.getTime() + 1000),
      format: 'ndjson',
      writtenUpTo: null,
    });
    const claim = await claimFile(tx, org, { leaseMs: 60_000, mostTries: 3 });
    if (claim.outcome !== 'claimed') throw new Error('foreign export file was not claimed');
    const file = claim.file;
    const facts = { requests: 0, bytes: 1, sha256: 'ab'.repeat(32) };
    expect(await fileReady(tx, { orgId: org, exportId: id, month: file.month, lease: file.lease }, facts)).toBe(
      'ready',
    );
    const trail = createAuditTrail({ keys, ids: uuidV7Ids, correlationId: uuidV7Ids.next() });
    const subject = { type: 'access_log', id: org, version: 1 };
    const actor = { type: 'user' as const, id: requestedBy };
    await trail.record(tx, org, {
      actor,
      action: 'access_log.export_file_made',
      subject,
      details: { exportId: id, month: file.month.slice(0, 7), attempt: file.attempt, ...facts },
    });
    const downloaded = await trail.record(tx, org, {
      actor,
      action: 'access_log.export_downloaded',
      subject,
      details: {
        exportId: id,
        month: file.month.slice(0, 7),
        attempt: file.attempt,
        fileName: 'foreign.ndjson.gz',
        bytes: 1,
        sha256: facts.sha256,
        parts: 1,
        partBytes: 1,
      },
    });
    tenant.exportId = id;
    tenant.downloadId = downloaded.id;
    tenant.exportMonth = file.month.slice(0, 7);
  });
  if (tenant === foreign)
    canaries = [...canaries, id, tenant.downloadId ?? '', ...Object.values(tenant.identity ?? {})];
}

/** Foreign references in bodies must be refused too, including a recorded DENY for an agent's ask. */
const referenceFields = ['agentId', 'fundingSourceId', 'supplierId', 'supplierIds', 'owner'] as const;

/** Each foreign reference is a separate case, so a finding cannot hide the next field's attack. */
async function foreignReference(op: Operation, body: unknown, field: (typeof referenceFields)[number]): Promise<void> {
  const replacements: Record<(typeof referenceFields)[number], unknown> = {
    agentId: foreign.draftAgent,
    fundingSourceId: foreign.world.source,
    supplierId: foreign.world.suppliers[0],
    supplierIds: foreign.world.suppliers,
    owner: foreign.world.admin.membershipId,
  };
  currentAttack = `foreign ${field} in body`;
  const headers = {
    ...allowedHeaders(op),
    ...(op.access.includes('agent') ? { 'agentx-organization': foreign.world.org } : {}),
  };
  const answer = await send(op, headers, { ...(body as Record<string, unknown>), [field]: replacements[field] });
  const parsed = summaryOf(answer.status, answer.text);
  const label = `${op.method} ${op.route}: foreign ${field}`;
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
  ).toContain(parsed.code);
}

beforeAll(async () => {
  startedAt = Date.now();
  expect(API_ORIGIN).toBe('http://localhost:8080');
  // Account-setup events end sessions; drain their settle window before signing in.
  await sleep(Math.max(0, users.tamper.provisionedAt + 61_000 - Date.now()));
  await restartInPlace('api');
  await apiAnswers();
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  foreign = await seed();
  const admin = await shared.signedInMember(foreign.world.org, 'admin');
  foreignCookie = admin.cookie;
  foreign.identity = await tamperIdentityFixtures(
    database,
    keys,
    uuidV7Ids,
    clock,
    admin,
    foreign.world.admin.membershipId,
  );
  await resetOwn();
  await controls();
  await exportFixtures(foreign, admin.userId);
  foreignBefore = await foreignChain();
  expect(foreignBefore.events).toBeGreaterThan(0);
});

beforeEach(async () => {
  // Recovery must finish before any later request can use credentials damaged by an attack.
  if (needsReseed) await resetOwn();
  currentAttack = '';
  lastAnswer = undefined;
});

afterEach(async () => {
  try {
    if (foreignBefore !== undefined) {
      const current = await foreignChain();
      if (current.digest !== foreignBefore.digest) {
        foreignBefore = current;
        if (lastAnswer === undefined) throw new Error('foreign audit changed without an HTTP request');
        finding(lastAnswer.op, lastAnswer.headers, 'foreign audit chain changed', lastAnswer.answer);
      }
    }
  } finally {
    if (needsReseed) {
      ownReseeds += 1;
      await resetOwn();
    }
  }
});

afterAll(async () => {
  // A failed run still leaves exact counts and safe findings for the reviewer.
  mkdirSync('.tools', { recursive: true });
  writeFileSync(
    '.tools/tamper-report.json',
    JSON.stringify(
      {
        operations: covered.size,
        requests: requestCounts,
        requestsSent: requestCounts.attack + requestCounts.control,
        durationMs: Date.now() - startedAt,
        ownReseeds,
        findings,
      },
      null,
      2,
    ),
  );
  try {
    await browser?.close();
  } finally {
    await database.destroy();
  }
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
      const answer = await controlSend(op, { ...allowedHeaders(op), 'agentx-organization': foreign.world.org }, body);
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
async function injectedField(op: Operation, body: unknown, field: 'org_id' | 'role'): Promise<void> {
  currentAttack = `injected ${field}`;
  const answer = await send(op, allowedHeaders(op), {
    ...(body as Record<string, unknown>),
    [field]: field === 'role' ? 'admin' : foreign.world.org,
  });
  // The body's cap can reject an injected UUID before strict JSON validation.
  expect([400, 413], `${op.route}: extra ${field}`).toContain(answer.status);
  expect(summaryOf(answer.status, answer.text).code).toBe(answer.status === 413 ? 'PAYLOAD_TOO_LARGE' : 'BAD_REQUEST');
}

/** An allowed caller still cannot address the other organisation's resources. */
async function foreignResources(op: Operation, body: unknown): Promise<void> {
  currentAttack = 'foreign path IDs compared with absent IDs';
  const headers = roleRoute(op) ? cookieHeader(people.admin) : allowedHeaders(op);
  if (op.method === 'GET' || op.method === 'HEAD') {
    // A hidden foreign record proves nothing when the route cannot read the caller's own record either.
    const local = await controlSend(op, headers, body, routeOf(op, own));
    if (local.status === 404)
      finding(
        op,
        headers,
        'own-ID control is 404; isolation was not demonstrated',
        summaryOf(local.status, local.text),
      );
    expect(local.status, `${op.route}: own-ID control should work`).toBe(200);
  }
  // Writes use only foreign and absent IDs: an own-ID write could revoke live test authority.
  const real = await send(op, headers, body, routeOf(op, foreign));
  const absent = await send(op, headers, body, routeOf(op, foreign, true));
  // Equal refusals hide whether the referenced record exists in another tenant.
  const realAnswer = summaryOf(real.status, real.text);
  const absentAnswer = summaryOf(absent.status, absent.text);
  expect(realAnswer.status, `${op.route}: foreign versus absent status`).toBe(absentAnswer.status);
  expect(realAnswer.code, `${op.route}: foreign versus absent reason`).toBe(absentAnswer.code);
  expect(real.status, `${op.route}: a server failure is not a refusal`).toBeLessThan(500);
  expect(realAnswer.code === undefined && op.method !== 'HEAD', `${op.route}: refusal has a reason`).toBe(false);
}

/** Every body used by any phase must start valid before the attack changes it. */
function baseline(op: Operation): unknown {
  const body = op.schema === undefined ? undefined : sample(op.schema, own);
  if (op.schema !== undefined)
    expect(z.fromJSONSchema(op.schema).safeParse(body).success, `${op.method} ${op.route}: invalid baseline`).toBe(
      true,
    );
  return body;
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
    const body = baseline(op);
    const forged = [
      'eyJhbGciOiJIUzI1NiJ9',
      Buffer.from(JSON.stringify({ sub: own.world.admin.userId, role: 'admin', org_id: foreign.world.org })).toString(
        'base64url',
      ),
      'forged',
    ].join('.');
    if (op.access.includes('public')) {
      // Public operations remain public; this is a leak control rather than an expected rejection.
      const answer = await controlSend(op, { authorization: `Bearer ${forged}`, ...cookieHeader(endedCookie) }, body);
      expect(answer.status).toBeLessThan(500);
    } else {
      await credentials(op, body, forged);
    }
  });
});

describe('F1 SEC-TEN-01: foreign IDs are indistinguishable from absent IDs', () => {
  it.each(operations.filter((op) => (roleRoute(op) || op.access.includes('agent')) && op.route.includes('{')))(
    '$method $route',
    async (op) => {
      await foreignResources(op, baseline(op));
    },
  );
});

describe('F1 SEC-TEN-01: foreign references in request bodies', () => {
  const cases = operations.flatMap((op) =>
    referenceFields
      .filter((field) => op.schema?.properties?.[field] !== undefined)
      .map((field) => ({ op, field, method: op.method, route: op.route })),
  );
  it.each(cases)('$method $route: $field', async ({ op, field }) => {
    await foreignReference(op, baseline(op), field);
  });
});

describe('F1 SEC-AG-04: injected authority fields after every refusal case', () => {
  const cases = operations
    .filter((op) => op.schema !== undefined)
    .flatMap((op) =>
      (['org_id', 'role'] as const)
        .filter((field) => op.schema?.properties?.[field] === undefined)
        .map((field) => ({ op, field, method: op.method, route: op.route })),
    );
  it.each(cases)('$method $route: $field', async ({ op, field }) => {
    await injectedField(op, baseline(op), field);
  });
});

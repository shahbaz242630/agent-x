// S206 V8, SEC-TEN-01 (FX-ROLEMATRIX's pattern): another organisation's
// resource IDs reach nothing. Through the whole API as it starts on staging
// (runApi, the `web` role), on the real migrated schema as the app role, an
// admin of organisation B sends every operation the API's document holds
// that takes a resource ID in its path, each with organisation A's real IDs
// (its member, mandate, agent and key, funding source and link, supplier and
// payee registration, spend request, payment, invitation, registered
// contact, factor reset, background export, bank session), and each again
// with IDs that never existed. Both answers must be the same refusal (status
// and reason code), the not-found one wherever the route reads the ID before
// anything else, and organisation A's rows must not change. An agent's own
// routes are sent by B's agent. The operations come from the document the
// server builds, so a new route with a path ID fails this test until it is
// given an ID of A's here or exempted with its reason.
//
// The body references (an agent, a funding source, suppliers, an owner) are
// swept too, each in a body otherwise B's own, against an ID that never
// existed: the same refusal for both, and nothing of A's changed.
//
// The compose stack's tamper pass (tooling/e2e/tamper.e2e.test.ts) does the
// same with real sign-ins; this runs in every PR's database tests.
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { type ActivityTables, addBackgroundExport } from '@agentx/core/modules/activity';
import { SCOPES } from '@agentx/core/modules/agents';
import { createOutbox } from '@agentx/core/modules/notifications';
// The tamper pass's own drafts (tooling/e2e/tamper.e2e.test.ts), shared: core keeps the draft makers to itself.
import { tamperIdentityFixtures } from '../../../packages/core/src/modules/identity/tamper-fixtures.helper.test.ts';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { API_PURPOSES, PURPOSES } from '@agentx/platform/keys';
import type { Output } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { createHandoff, handoffDatabaseGate } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables } from './handoff-world.helper.test.ts';
import { type ApiProcess, runApi } from './main.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, type World } from './mandate-world.helper.test.ts';
import { createRailHealth } from './rail-health.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';
import { worded } from './statement-words.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
/** With the access log's own tables, which a background export's rows sit beside. */
let app: Database<HandoffWorldTables & ActivityTables>;
let operator: Database<HandoffWorldTables>;
let api: FastifyInstance | undefined;
let keyFolder: string;

const ORIGIN = 'https://app.agentx.example';
const ids = new SequentialIds(0x5206_0800_0000);
let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
const spend = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'cross-org-sweep',
  registry: () => registry,
  decisions: () => decisions,
});
const paying = handoffWorld({ app: () => app, clock: () => clock, ids, registry: () => registry, shared: spend });

class FakeProcess extends EventEmitter implements ApiProcess {
  readonly stdout: Output = { write: () => true };
  readonly stderr: Output = { write: () => true };
  exitCode: number | string | null | undefined = undefined;
  exit(): void {
    // The test closes the server itself.
  }
}

interface Operation {
  readonly method: string;
  readonly route: string;
  readonly access: readonly string[];
  readonly body?: Schema;
}

interface Schema {
  readonly type?: string | readonly string[];
  readonly enum?: readonly unknown[];
  readonly anyOf?: readonly Schema[];
  readonly properties?: Readonly<Record<string, Schema>>;
  readonly required?: readonly string[];
  readonly items?: Schema;
  readonly minItems?: number;
  readonly format?: string;
  readonly pattern?: string;
}

/** Organisation A's real records, by the path parameter or route they stand for. */
interface Theirs {
  readonly world: World;
  readonly member: string;
  readonly mandate: string;
  readonly keyId: string;
  readonly request: string;
  readonly payment: string;
  readonly registration: string;
  readonly link: string;
  readonly sessionRef: string;
  readonly exportId: string;
  readonly month: string;
  readonly identity: { readonly invitation: string; readonly contact: string; readonly reset: string };
  /** A's own admin's headers: the own-ID control, which proves each ID real. */
  readonly admin: Readonly<Record<string, string>>;
}

/** Organisation B's own: its admin and agent, as each sends, and records its bodies name. */
interface Ours {
  readonly world: World;
  readonly admin: Readonly<Record<string, string>>;
  readonly agent: Readonly<Record<string, string>>;
  readonly keyText: string;
  readonly mandate: string;
  readonly draftAgent: string;
  /** An account at the fake bank, as its list gives it: a bank session is approved with one. */
  readonly bankAccount: string;
}

let theirs: Theirs;
let ours: Ours;
let operations: Operation[];

/**
 * The routes taking a path ID that this sweep leaves out, each with its reason. A new one goes here only with one;
 * any other is swept, or the coverage test fails.
 */
const EXEMPT: Readonly<Record<string, string>> = {
  '/v1/oauth/requests/{id}':
    'An OAuth flow belongs to no organisation until it is decided, and is read only by the browser that opened it (its flow cookie): SEC-OAUTH-10, oauth-connections.db.test.ts.',
  '/v1/oauth/requests/{id}/consent':
    'As /v1/oauth/requests/{id}: a flow is its own browser’s, never an organisation’s.',
  '/v1/oauth/requests/{id}/consent/confirm':
    'As /v1/oauth/requests/{id}: a flow is its own browser’s, never an organisation’s.',
  '/v1/oauth/requests/{id}/deny': 'As /v1/oauth/requests/{id}: a flow is its own browser’s, never an organisation’s.',
};

/**
 * The routes whose not-found answer is a refusal of their own, with its reason; every other route's is NOT_FOUND. Each
 * is still the same for A's ID as for one that never existed.
 */
const NOT_FOUND_AS: Readonly<Record<string, { readonly status: number; readonly code: string; readonly why: string }>> =
  {
    '/v1/fake-bank/sessions/{sessionRef}/approve': {
      status: 409,
      code: 'BANK_LINK_NOT_WAITING',
      why: 'The fake bank finds another organisation’s session as none is (SEC-PTR-08), and answers as its bank would: no link of yours is waiting.',
    },
    '/v1/fake-bank/sessions/{sessionRef}/reject': {
      status: 409,
      code: 'BANK_LINK_NOT_WAITING',
      why: 'As the approve: another organisation’s session is found as none is, answered as no link of yours waiting.',
    },
  };

/** Organisation A's ID for each path parameter of a route, by the first prefix the route starts with. */
function theirIds(route: string): Readonly<Record<string, string>> | undefined {
  const t = theirs;
  const byPrefix: readonly (readonly [string, Readonly<Record<string, string>>])[] = [
    ['/v1/members/invitations/', { id: t.identity.invitation }],
    ['/v1/members/', { id: t.member }],
    ['/v1/agent/spend-requests/', { id: t.request }],
    ['/v1/spend-requests/', { id: t.request }],
    ['/v1/payments/', { id: t.payment }],
    ['/v1/agents/', { id: t.world.agent, keyId: t.keyId }],
    ['/v1/funding-sources/link-sessions/', { linkId: t.link }],
    ['/v1/funding-sources/', { id: t.world.source }],
    ['/v1/suppliers/', { id: t.world.suppliers[0] ?? '', registrationId: t.registration }],
    ['/v1/mandates/', { id: t.mandate }],
    ['/v1/registered-contacts/', { id: t.identity.contact }],
    ['/v1/factor-resets/', { id: t.identity.reset }],
    // A download of A's export can't be started by B, so a download's ID is never one of A's: its export's is.
    ['/v1/access-log/background-exports/', { id: t.exportId, month: t.month, downloadId: randomUUID(), index: '0' }],
    ['/v1/fake-bank/sessions/', { sessionRef: t.sessionRef }],
  ];
  return byPrefix.find(([prefix]) => route.startsWith(prefix))?.[1];
}

/** The route with these values for its parameters; one missing throws, so no route is sent half-filled. */
const filled = (route: string, values: Readonly<Record<string, string>>): string =>
  route.replace(/\{(\w+)\}/g, (_, name: string) => {
    const value = values[name];
    if (value === undefined) throw new Error(`${route}: no value for {${name}}`);
    return value;
  });

/** IDs that never existed, for each of the route's parameters; a month and a part's index as they are. */
const absentIds = (values: Readonly<Record<string, string>>): Record<string, string> =>
  Object.fromEntries(
    Object.entries(values).map(([name, value]) => [
      name,
      name === 'month' || name === 'index' ? value : name === 'sessionRef' ? `absent-${randomUUID()}` : randomUUID(),
    ]),
  );

/** A schema-valid body of B's own, so a refusal is never the body's: each reference B's, each choice the first. */
function sample(schema: Schema, field = ''): unknown {
  const [first] = schema.anyOf ?? [];
  if (first !== undefined) return sample(first, field);
  if (schema.enum !== undefined) return schema.enum[0];
  if (schema.type === 'object') {
    // A set of words' version is the one served now (`worded`), never a sample's.
    const named = [
      ...(schema.required ?? []),
      ...(schema.properties?.monthlyCapChoice === undefined ? [] : ['monthlyCapMinor']),
    ];
    return Object.fromEntries(
      named
        .filter((name) => !/statementVersion$/i.test(name))
        .map((name) => [name, sample(schema.properties?.[name] ?? {}, name)]),
    );
  }
  if (schema.type === 'array')
    return Array.from({ length: schema.minItems ?? 1 }, () => sample(schema.items ?? {}, field));
  if (schema.type === 'boolean') return true;
  if (schema.type === 'number' || schema.type === 'integer') return 100;
  if (Array.isArray(schema.type) && schema.type.includes('null')) return field === 'monthlyCapMinor' ? 100 : null;
  return textSample(schema, field);
}

function textSample(schema: Schema, field: string): unknown {
  const values: Readonly<Record<string, unknown>> = {
    currency: 'AED',
    timeZone: 'Asia/Dubai',
    phone: '+971501234567',
    email: 'sweep@example.test',
    iban: 'AE070331234567890123456',
    token: 't'.repeat(43),
    oldKey: ours.keyText,
    accountId: ours.bankAccount,
    url: 'https://example.test/form',
    page: '/approvals',
    agentId: ours.draftAgent,
    fundingSourceId: ours.world.source,
    supplierId: ours.world.suppliers[0],
    supplierIds: ours.world.suppliers[0],
    owner: ours.world.admin.membershipId,
    from: new Date(Date.now() - 3_600_000).toISOString(),
    to: new Date().toISOString(),
  };
  if (values[field] !== undefined) return values[field];
  if (schema.format === 'uuid') return randomUUID();
  if (schema.format === 'date-time') return new Date(Date.now() + 86_400_000).toISOString();
  if (schema.format === 'email') return 'sweep@example.test';
  // A minor amount may be text of digits rather than a JSON number.
  if (schema.pattern !== undefined && new RegExp(schema.pattern).test('100')) return '100';
  return 'sweep';
}

/** The body fields naming another record that the sweep fills with A's: each a separate case. */
const REFERENCES = ['agentId', 'fundingSourceId', 'supplierId', 'supplierIds', 'owner'] as const;
type Reference = (typeof REFERENCES)[number];

/** The body fields naming a record that the sweep leaves out, each with its reason. */
const BODY_EXEMPT: Readonly<Record<string, string>> = {
  stepUpChallengeId:
    'A step-up challenge is found only as the caller’s own session’s: another’s is refused as none is (step-up-challenges, the role matrix).',
  investigationId:
    'An investigation exists only while its own organisation is held, and is read in the caller’s organisation alone (integrity-hold.ts); A is not held here.',
  versionId:
    'A mandate’s draft is accepted only as its own mandate’s pending version, read with the path’s mandate (mandate-acceptance), which the path sweep covers.',
  accountId: 'An account at the fake bank, not a record of an organisation’s: its sessions are swept by path.',
};

/** B's own ID for each path parameter of a route whose body is swept. */
function ourIds(route: string): Readonly<Record<string, string>> {
  if (route.startsWith('/v1/agents/')) return { id: ours.world.agent };
  if (route.startsWith('/v1/mandates/')) return { id: ours.mandate };
  if (route.includes('{')) throw new Error(`${route}: no ID of B's for its path`);
  return {};
}

const theirReference = (field: Reference): unknown =>
  ({
    agentId: theirs.world.agent,
    fundingSourceId: theirs.world.source,
    supplierId: theirs.world.suppliers[0],
    supplierIds: [theirs.world.suppliers[0]],
    owner: theirs.member,
  })[field];

const absentReference = (field: Reference): unknown => (field === 'supplierIds' ? [randomUUID()] : randomUUID());

/** Every operation and body field naming another record, with B's own path IDs: the OAuth flows' aside (EXEMPT). */
const referenceCases = () =>
  operations
    .filter(({ route }) => EXEMPT[route] === undefined)
    .flatMap((op) =>
      REFERENCES.filter((field) => op.body?.properties?.[field] !== undefined).map((field) => ({ op, field })),
    );

/** An answer as two are compared in a body's sweep: its status, reason code, and a decision's outcome and reasons. */
function summaryOf(response: LightMyRequestResponse) {
  const { status, code } = answerOf(response);
  interface Decided {
    readonly decision?: string;
    readonly reasons?: readonly { readonly code: string }[];
  }
  const decidedOf = (): Decided => {
    try {
      const body = JSON.parse(response.body) as Decided & { readonly request?: Decided; readonly simulation?: Decided };
      return body.request ?? body.simulation ?? body;
    } catch {
      return {};
    }
  };
  const decided = decidedOf();
  return { status, code, decision: decided.decision, reasons: decided.reasons?.map((reason) => reason.code) };
}

let keysUsed = 0;
/** One request as the caller sends it: a write from our own origin with a fresh idempotency key and its body. */
function send(
  caller: Readonly<Record<string, string>>,
  method: string,
  url: string,
  body?: unknown,
): Promise<LightMyRequestResponse> {
  keysUsed += 1;
  const writes = method !== 'GET';
  if (api === undefined) throw new Error('the API is not running');
  return api.inject({
    method: method as NonNullable<InjectOptions['method']>,
    url,
    headers: {
      ...caller,
      ...(writes && {
        origin: ORIGIN,
        'idempotency-key': `sweep-${String(keysUsed)}`,
        'content-type': 'application/json',
      }),
    },
    ...(writes && { payload: JSON.stringify(worded(url, body ?? {})) }),
  });
}

/** An answer as compared: its status and reason code. */
const answerOf = (response: LightMyRequestResponse) => {
  let code: string | undefined;
  try {
    code = (JSON.parse(response.body) as { error?: { code?: string } }).error?.code;
  } catch {
    code = undefined;
  }
  return { status: response.statusCode, code };
};

/** Who sends an operation: B's agent on an agent's own route, else B's admin. */
const callerOf = (op: Operation) =>
  op.access.includes('agent') && !op.access.includes('admin') ? ours.agent : ours.admin;

/** Every row of organisation A's, in every table that names an organisation, read as the admin: a digest a table. */
async function theirRows(): Promise<Record<string, string | null>> {
  // Each table's statement built in Postgres from its own name (%I) and A's ID (%L), run there, its digest read back.
  const rows = await database.as('admin').query<{ name: string; digest: string | null }>(
    `select c.table_schema || '.' || c.table_name as name,
            (pg_catalog.regexp_match(pg_catalog.query_to_xml(pg_catalog.format(
              'select pg_catalog.md5(pg_catalog.string_agg(pg_catalog.to_jsonb(t)::text, %L order by pg_catalog.to_jsonb(t)::text)) as digest from %I.%I t where t.org_id::text = %L',
              '|', c.table_schema, c.table_name, $1::text), true, false, '')::text, '<digest>([0-9a-f]{32})</digest>'))[1] as digest
       from information_schema.columns c
       join information_schema.tables t using (table_schema, table_name)
      where c.column_name = 'org_id' and t.table_type = 'BASE TABLE'
        and c.table_schema not in ('pg_catalog', 'information_schema')
      order by 1`,
    [theirs.world.org],
  );
  return Object.fromEntries(rows.map(({ name, digest }) => [name, digest]));
}

/** The operations taking an ID in their path, from the document the server builds. */
const withPathIds = () => operations.filter(({ route }) => route.includes('{'));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables & ActivityTables>(
    { ...database.connection('app'), maxConnections: 6 },
    testLogger(),
  );
  operator = createDatabase<HandoffWorldTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
  // The API's keys, each the same as the worlds' own (mandate-world's `keys`), so it believes what they sign.
  keyFolder = mkdtempSync(path.join(tmpdir(), 'agentx-sweep-keys-'));
  for (const purpose of API_PURPOSES) {
    const material = Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1).toString('base64url');
    writeFileSync(path.join(keyFolder, `key-${purpose}-v1`), `${material}\n`);
  }
  const connection = database.connection('app');
  const startLog = new LogCapture();
  const started = await runApi(new FakeProcess(), {
    env: {
      AGENTX_ENV: 'test',
      AGENTX_ROLE: 'web',
      AGENTX_HTTP_PORT: '0',
      AGENTX_PUBLIC_ORIGIN: ORIGIN,
      AGENTX_DB_HOST: connection.host,
      AGENTX_DB_PORT: String(connection.port),
      AGENTX_DB_NAME: connection.database,
      AGENTX_DB_USER: connection.user,
      AGENTX_DB_PASSWORD: connection.password,
      AGENTX_DB_TLS: 'disable',
      AGENTX_KEYS_DIR: keyFolder,
      // Sign-in on, so a session's cookie is read; the login service is never called by this test.
      AGENTX_OIDC_ISSUER: 'http://127.0.0.1:9',
      AGENTX_OIDC_CLIENT_ID: 'sweep-client',
      AGENTX_OIDC_CLIENT_SECRET: 's'.repeat(32),
      AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'http://127.0.0.1:9',
      AGENTX_MCP_OAUTH: 'on',
      AGENTX_RATE_LIMIT_PER_MINUTE: '50000',
      AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE: '50000',
      AGENTX_RATE_LIMIT_PER_AGENT_PER_MINUTE: '50000',
      AGENTX_RATE_LIMIT_PER_ORGANISATION_PER_MINUTE: '50000',
      AGENTX_LOG_EVENT_CAP_PER_MINUTE: '100000',
    },
    destination: startLog,
  });
  if (started === undefined) throw new Error(`the API did not start: ${JSON.stringify(startLog.lines().at(-1))}`);
  api = started;
  const paths = started.swagger().paths ?? {};
  operations = Object.entries(paths).flatMap(([route, item]) =>
    Object.entries((item ?? {}) as Record<string, Record<string, unknown>>)
      .filter(([method]) => ['get', 'post', 'put', 'patch', 'delete'].includes(method))
      .map(([method, operation]) => {
        const body = (operation.requestBody as { content?: Record<string, { schema?: Schema }> } | undefined)
          ?.content?.['application/json']?.schema;
        return {
          method: method.toUpperCase(),
          route,
          access: operation['x-access'] as string[],
          ...(body !== undefined && { body }),
        };
      }),
  );

  // The audit chain seals each event's time by the database's clock, so the worlds start from now.
  clock = new FixedClock(new Date());
  const logger = testLogger();
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });

  // Organisation A: a payee, a mandate in force, a request waiting for approval and one paid.
  const { w: a, acting } = await paying.ready();
  // Paid first: asked after the one waiting, the split check would weigh them together and hold it for approval too.
  const paid = await spend.ask(acting, a, { amount: ALLOWED(1n) });
  // Born paused (ADR-014 §4): resumed for the payment, as the operator would.
  await operator.transaction().execute((tx) =>
    changeHandoffPause(
      tx,
      { chain: createPlatformChain({ keys, ids }), keys, logger },
      {
        paused: false,
        reason: 'TEST-S206-V8',
        actor: { type: 'system', id: 'operator' },
        release: 'r-test',
        run: null,
      },
    ),
  );
  await createHandoff({
    list: () => Promise.resolve([a.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail: a.rail,
    keys,
    ids,
    clock,
    logger,
    health: createRailHealth({ clock, logger }),
    databaseGate: handoffDatabaseGate(6),
  }).run();
  const made = await paying.paymentOf(a, paid.id);
  if (typeof made.transaction !== 'object') throw new Error(`no payment was made: ${JSON.stringify(made)}`);
  const waiting = await spend.ask(acting, a);
  const aAdmin = await spend.signedInMember(a.org, 'admin');
  const aHeaders = { cookie: `${SESSION_COOKIE}=${aAdmin.cookie}`, [ORGANIZATION_HEADER]: a.org };
  const other = await spend.member(a.org, 'developer');
  // Each a signed draft, as an admin's ask leaves it before the step-up (a reset needs a contact that counts first).
  const identity = await tamperIdentityFixtures(app, keys, ids, clock, aAdmin, other.membershipId);
  const linked = await send(aHeaders, 'POST', '/v1/funding-sources/link-sessions', {});
  expect(linked.statusCode, linked.body).toBe(201);
  const link = JSON.parse(linked.body) as { link: { id: string }; authoriseUrl: string };
  const { registration, exportId, month } = await withTenant(app, a.org, async (tx) => {
    const row = await tx.selectFrom('suppliers.beneficiary_registrations').select('id').executeTakeFirstOrThrow();
    const now = clock.now();
    const from = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    const id = ids.next();
    await addBackgroundExport(tx, a.org, {
      id,
      requestedBy: aAdmin.userId,
      from,
      to: now,
      format: 'ndjson',
      writtenUpTo: ids.next(),
    });
    return { registration: row.id, exportId: id, month: from.toISOString().slice(0, 7) };
  });
  theirs = {
    world: a,
    member: other.membershipId,
    mandate: await spend.mandateIdOf(a),
    keyId: acting.keyId,
    request: waiting.id,
    payment: made.transaction.id,
    registration,
    link: link.link.id,
    sessionRef: new URL(link.authoriseUrl).pathname.split('/').at(-1) ?? '',
    exportId,
    month,
    identity,
    admin: aHeaders,
  };

  // Organisation B: its own admin and agent, a mandate in force, and an agent with none, for its bodies to name.
  const b = await spend.world({ scopes: SCOPES });
  const bMandate = await spend.inForce(registry, b);
  // Every scope, so an agent's route is refused for the ID alone, never for a scope.
  const bKey = await spend.agentKey(b, b.agent, SCOPES);
  const bAdmin = await spend.signedInMember(b.org, 'admin');
  const bHeaders = { cookie: `${SESSION_COOKIE}=${bAdmin.cookie}`, [ORGANIZATION_HEADER]: b.org };
  const accounts = await send(bHeaders, 'GET', '/v1/fake-bank/accounts');
  expect(accounts.statusCode, accounts.body).toBe(200);
  ours = {
    world: b,
    admin: bHeaders,
    agent: { authorization: `Bearer ${bKey.text}` },
    keyText: bKey.text,
    mandate: bMandate,
    draftAgent: (await spend.anotherAgent(b)).agent,
    bankAccount: (JSON.parse(accounts.body) as { accounts: { accountId: string }[] }).accounts[0]?.accountId ?? '',
  };
}, 120_000);

afterAll(async () => {
  await api?.close();
  await app.destroy();
  await operator.destroy();
  await database.drop();
  rmSync(keyFolder, { recursive: true, force: true });
});

describe('S206 V8 SEC-TEN-01 another organisation’s IDs reach nothing, on every route taking one', () => {
  it('sweeps every operation with a path ID the document holds, or names why not', () => {
    const unswept = withPathIds()
      .filter(({ route }) => EXEMPT[route] === undefined && theirIds(route) === undefined)
      .map(({ method, route }) => `${method} ${route}`);
    expect(unswept).toEqual([]);
    // Never vacuous: the sweep holds the routes the gap map named.
    expect(withPathIds().length).toBeGreaterThan(80);
    for (const reason of Object.values(EXEMPT)) expect(reason.length).toBeGreaterThan(20);
    // An exemption for a route no longer in the document is dropped, not kept.
    expect(Object.keys(EXEMPT).filter((route) => !operations.some((op) => op.route === route))).toEqual([]);
  });

  it('proves each ID of A’s real: A’s own admin reads every one B is refused', async () => {
    const wrong: string[] = [];
    const read: string[] = [];
    for (const op of withPathIds().filter(({ method, route }) => method === 'GET' && EXEMPT[route] === undefined)) {
      const values = theirIds(op.route) ?? {};
      // A download's ID is never A's (theirIds): nothing to read with it.
      if ('downloadId' in values || op.access.includes('agent')) continue;
      const answer = await send(theirs.admin, op.method, filled(op.route, values));
      read.push(op.route);
      if (answer.statusCode !== 200)
        wrong.push(`${op.method} ${op.route}: ${String(answer.statusCode)} ${answer.body}`);
    }
    expect(wrong).toEqual([]);
    expect(read.length).toBeGreaterThanOrEqual(8);
  });

  it('answers B’s admin, and B’s agent, A’s IDs exactly as IDs that never existed, and changes nothing of A’s', async () => {
    const before = await theirRows();
    // Never vacuous: A's rows are there to change, in many tables.
    expect(Object.values(before).filter((digest) => digest !== null).length).toBeGreaterThan(20);
    const wrong: string[] = [];
    const swept = withPathIds().filter(({ route }) => EXEMPT[route] === undefined);
    for (const op of swept) {
      const values = theirIds(op.route) ?? {};
      const body = op.body === undefined ? undefined : sample(op.body);
      const caller = callerOf(op);
      const real = answerOf(await send(caller, op.method, filled(op.route, values), body));
      const absent = answerOf(await send(caller, op.method, filled(op.route, absentIds(values)), body));
      const name = `${op.method} ${op.route}`;
      if (real.status !== absent.status || real.code !== absent.code) {
        wrong.push(`${name}: A's ${JSON.stringify(real)}, absent ${JSON.stringify(absent)}`);
      } else if (
        real.status !== (NOT_FOUND_AS[op.route]?.status ?? 404) ||
        real.code !== (NOT_FOUND_AS[op.route]?.code ?? 'NOT_FOUND')
      ) {
        wrong.push(`${name}: ${JSON.stringify(real)}, not the not-found answer`);
      }
    }
    expect(wrong).toEqual([]);
    expect(await theirRows()).toEqual(before);
  }, 120_000);

  it('answers a body naming A’s agent, funding source, suppliers or member exactly as one naming none, and changes nothing of A’s', async () => {
    const before = await theirRows();
    const cases = referenceCases();
    // Never vacuous: a mandate's draft, an agent's ask, a simulation, the policies, an agent's owner.
    expect(cases.length).toBeGreaterThan(15);
    const wrong: string[] = [];
    for (const { op, field } of cases) {
      const url = filled(op.route, ourIds(op.route));
      const base = sample(op.body ?? {}) as Record<string, unknown>;
      const caller = callerOf(op);
      const real = summaryOf(await send(caller, op.method, url, { ...base, [field]: theirReference(field) }));
      const absent = summaryOf(await send(caller, op.method, url, { ...base, [field]: absentReference(field) }));
      const name = `${op.method} ${op.route} (${field})`;
      if (JSON.stringify(real) !== JSON.stringify(absent)) {
        wrong.push(`${name}: A's ${JSON.stringify(real)}, absent ${JSON.stringify(absent)}`);
      } else if (real.status >= 500 || (real.status < 400 && real.decision !== 'DENY')) {
        wrong.push(`${name}: ${JSON.stringify(real)}, taken`);
      }
    }
    expect(wrong).toEqual([]);
    expect(await theirRows()).toEqual(before);
  }, 120_000);

  it('sweeps every body field naming a record, or names why not', () => {
    const named = operations.flatMap((op) =>
      Object.keys(op.body?.properties ?? {})
        .filter((field) => /Ids?$/.test(field) || field === 'owner')
        .filter((field) => !(REFERENCES as readonly string[]).includes(field) && BODY_EXEMPT[field] === undefined)
        .map((field) => `${op.method} ${op.route}: ${field}`),
    );
    expect(named).toEqual([]);
  });
});

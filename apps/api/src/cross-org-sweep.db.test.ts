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
import { holdOrganisation, withSignedStates } from '@agentx/core/modules/audit';
import { createPasskeyAdditions, createStepUpChallenges, draftReset } from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
import { challengeOf, type OauthTables } from '@agentx/core/modules/oauth';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { PURPOSES, WEB_PURPOSES } from '@agentx/platform/keys';
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
import { afterAll, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { CORRELATION_HEADER } from './correlation.ts';
import { createHandoff, handoffDatabaseGate } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables } from './handoff-world.helper.test.ts';
import { type ApiProcess, runApi } from './main.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, type Member, type World } from './mandate-world.helper.test.ts';
import { CONSENT_CONFIRM_OPERATION, CONSENT_OPERATION, createConnectionConsents } from './connection-consents.ts';
import { createOauthAuthorizing } from './oauth-authorizing.ts';
import { createOauthClients } from './oauth-clients.ts';
import { capabilitiesOf } from './oauth-wire.ts';
import { createRailHealth } from './rail-health.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';
import { worded } from './statement-words.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
/** With the access log's own tables, which a background export's rows sit beside. */
let app: Database<HandoffWorldTables & ActivityTables & OauthTables>;
let operator: Database<HandoffWorldTables>;
let api: FastifyInstance | undefined;
let keyFolder: string;
/** What the API writes: a server failure's own line is shown with the answer that failed. */
const apiLog = new LogCapture();

const ORIGIN = 'https://app.agentx.example';
const CORRELATION = '0199a0f0-0000-7000-8000-000000005208';
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
  /** Its query's parameters, by name, with their schemas. */
  readonly query: Readonly<Record<string, Schema>>;
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
  /** An MCP connection A's admin made for A's agent: its key's ID, as the connection routes name it. */
  readonly connection: string;
  readonly request: string;
  readonly payment: string;
  readonly registration: string;
  readonly link: string;
  readonly sessionRef: string;
  readonly exportId: string;
  readonly month: string;
  readonly identity: { readonly invitation: string; readonly contact: string; readonly reset: string };
  /** A passkey A's admin is adding (SA6), stepped up for in their own session: a person's own, no organisation's. */
  readonly passkeyAddition: string;
  /** A's own admin's headers: the own-ID control, which proves each ID real. */
  readonly admin: Readonly<Record<string, string>>;
  /** A's own admin as a person: an actor in A's audit and access logs. */
  readonly adminUser: string;
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
    'As /v1/oauth/requests/{id}: a flow is its own browser’s, never an organisation’s. Another organisation’s agentId in its body: SEC-OAUTH-10 in oauth-connections.db.test.ts.',
  '/v1/oauth/requests/{id}/consent/confirm':
    'As /v1/oauth/requests/{id}: a flow is its own browser’s, never an organisation’s. Another organisation’s agentId in its body: SEC-OAUTH-10 in oauth-connections.db.test.ts.',
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
    '/v1/auth/passkeys/additions/{id}/confirm': {
      status: 403,
      code: 'STEP_UP_FAILED',
      why: 'The confirm of a passkey step-up (SA6): another person’s addition is found as none is, answered as every step-up confirm answers a step-up not signed in again for in this session.',
    },
  };

/** The writes that answer even A's own admin not-found with A's IDs, each with its reason: none of theirs proven so. */
const NOT_FOUND_FOR_A: Readonly<Record<string, string>> = {
  '/v1/access-log/background-exports/{id}/files/{month}/downloads':
    'No file of the export is built in this test, so none is ready to download; the export itself is proven by A’s own GET of /v1/access-log/background-exports/{id}.',
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
    // A connection's key before any agent key: the connection routes name their own kind.
    ['/v1/agents/{id}/connections/', { id: t.world.agent, keyId: t.connection }],
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
    // A person's own, found only by its own session: B's admin is another person in another organisation.
    ['/v1/auth/passkeys/additions/', { id: t.passkeyAddition }],
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
  versionId:
    'A mandate’s draft is accepted only as its own mandate’s pending version, read with the path’s mandate (mandate-acceptance), which the path sweep covers.',
  accountId: 'An account at the fake bank, not a record of an organisation’s: its sessions are swept by path.',
};

/** Body fields swept by a test of their own: an investigation exists only while its organisation is held. */
const SWEPT_APART: readonly string[] = ['investigationId'];

/**
 * The query parameters naming a record (by name or as a UUID): each a filter over the caller's own organisation's
 * records, or a page's cursor among them. Swept with A's IDs below, unless named here with its reason.
 */
const QUERY_EXEMPT: Readonly<Record<string, string>> = {
  challenge:
    'A step-up challenge is found only as the caller’s own session’s: another’s is refused as none is (step-up-challenges, sign-in-flow.db.test.ts).',
  client_id:
    'A registered MCP client is no organisation’s (OAuth dynamic registration is public); its flows are the browser’s own (EXEMPT).',
};

/** Whether a query parameter names a record: an ID by its name, or a UUID by its schema. */
const namesRecord = (name: string, schema: Schema): boolean => /(Id|_id)$/.test(name) || schema.format === 'uuid';

/** A's ID for a query parameter: the filter's person or subject, or a cursor's record of the list's own kind. */
function theirQueryValue(route: string, name: string): Readonly<Record<string, string>> | undefined {
  const t = theirs;
  if (name === 'actorId') return { actorType: 'user', actorId: t.adminUser };
  if (name === 'subjectId') return { subjectType: 'mandate', subjectId: t.mandate };
  const cursors: readonly (readonly [string, string])[] = [
    ['/v1/spend-requests', t.request],
    ['/v1/approvals', t.request],
    ['/v1/payments', t.payment],
    ['/v1/agents', t.world.agent],
    ['/v1/agent/funding-sources', t.world.source],
    ['/v1/funding-sources', t.world.source],
    ['/v1/agent/suppliers', t.world.suppliers[0] ?? ''],
    ['/v1/suppliers', t.world.suppliers[0] ?? ''],
    ['/v1/mandates', t.mandate],
    ['/v1/access-log/background-exports', t.exportId],
  ];
  const cursor = cursors.find(([prefix]) => route === prefix || route.startsWith(`${prefix}/`))?.[1];
  return cursor === undefined ? undefined : { [name]: cursor };
}

/** Every ID of A's this file holds: none may appear in an answer to B. */
const everyIdOfTheirs = (): string[] => [
  theirs.world.org,
  theirs.world.agent,
  theirs.world.source,
  ...theirs.world.suppliers,
  theirs.member,
  theirs.adminUser,
  theirs.mandate,
  theirs.keyId,
  theirs.request,
  theirs.payment,
  theirs.registration,
  theirs.link,
  theirs.exportId,
  ...Object.values(theirs.identity),
];

/** Every operation and query parameter naming a record, but those exempted with their reason. */
const queryCases = () =>
  operations.flatMap((op) =>
    Object.entries(op.query)
      .filter(([name, schema]) => namesRecord(name, schema) && QUERY_EXEMPT[name] === undefined)
      .map(([name]) => ({ op, name })),
  );

/** An answer's body without its correlation ID, which every answer has its own of. */
const withoutCorrelation = (body: string): string => body.replaceAll(/"correlationId":"[^"]*"/g, '');

/**
 * One query parameter sent by B with A's ID and with a made-up one: what was wrong (A's shown, a server failure, the
 * two answered apart), and for a filter the address A's own admin then reads it at, as the control.
 */
async function queryChecked(op: Operation, name: string) {
  const asked = theirQueryValue(op.route, name) ?? {};
  // A log's window, where it takes one: the last day, holding every row of this file's.
  const window =
    op.query.from === undefined
      ? {}
      : { from: new Date(Date.now() - 86_400_000).toISOString(), to: new Date().toISOString() };
  const url = (values: Readonly<Record<string, string>>) =>
    `${op.route}?${new URLSearchParams({ ...window, ...values }).toString()}`;
  const caller = callerOf(op);
  const real = await send(caller, op.method, url(asked));
  const absent = await send(caller, op.method, url({ ...asked, [name]: randomUUID() }));
  const label = `${op.method} ${op.route}?${name}`;
  const wrong: string[] = [];
  const shown = everyIdOfTheirs().filter((id) => real.body.includes(id));
  if (shown.length > 0) wrong.push(`${label}: shows A's ${shown.join(', ')}`);
  if (real.statusCode >= 500 || real.statusCode !== absent.statusCode) {
    const failed = apiLog
      .lines()
      .filter((line) => line.level === 'error')
      .map((line) => [line.event, line.err]);
    wrong.push(
      `${label}: A's ${String(real.statusCode)}, absent ${String(absent.statusCode)} ${JSON.stringify(failed)}`,
    );
  }
  // A filter, unlike a cursor (whose page starts where its ID sorts), answers exactly as a made-up one.
  const filter = name.endsWith('Id');
  if (filter && withoutCorrelation(real.body) !== withoutCorrelation(absent.body)) {
    wrong.push(`${label}: A's filter answered otherwise than a made-up one`);
  }
  return { wrong, control: filter ? url(asked) : undefined };
}

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

/**
 * An MCP connection `owner` makes for the agent, as the consent's use cases make one (oauth-connections.db.test.ts): a
 * client registered, its flow opened, the consent asked, stepped up and confirmed. Its key's ID.
 */
async function connectionOf(owner: Member, agentId: string): Promise<string> {
  const logger = testLogger();
  const capabilities = capabilitiesOf(ORIGIN);
  const clients = createOauthClients({ database: app, keys, clock, logger, metadata: undefined });
  const authorizing = createOauthAuthorizing({ database: app, keys, clock, ids, logger, capabilities, clients });
  const consents = createConnectionConsents({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock, keys, logger }),
    logger,
    issuer: capabilities.issuer,
    clients,
  });
  const redirect = 'https://chatgpt.com/connector/oauth/cb';
  const registered = await authorizing.register({ redirect_uris: [redirect], client_name: 'ChatGPT' }, '192.0.2.81');
  if (registered.outcome !== 'registered') throw new Error(`not registered: ${registered.outcome}`);
  const flow = await authorizing.authorize(
    {
      response_type: 'code',
      client_id: registered.client.clientId,
      redirect_uri: redirect,
      state: 'sweep',
      code_challenge: challengeOf('v'.repeat(43)),
      code_challenge_method: 'S256',
      resource: capabilities.resource,
      scope: 'requests:write',
    },
    undefined,
    '192.0.2.82',
  );
  if (flow.outcome !== 'opened') throw new Error(`not opened: ${flow.outcome}`);
  const opened = { flowId: flow.flowId, cookie: flow.cookie };
  const asked = { agentId, scopes: ['requests:write' as const] };
  const consent = await consents.consent(owner, spend.keyed(owner, CONSENT_OPERATION), opened, asked, CORRELATION);
  if (consent.outcome !== 'asked') throw new Error(`not asked: ${consent.outcome}`);
  await spend.stepUp(owner, consent.stepUpChallengeId);
  const confirmed = await consents.confirm(
    owner,
    spend.keyed(owner, CONSENT_CONFIRM_OPERATION),
    opened,
    asked,
    consent.stepUpChallengeId,
    CORRELATION,
  );
  if (confirmed.outcome !== 'connected') throw new Error(`not connected: ${confirmed.outcome}`);
  return confirmed.connection.keyId;
}

let keysUsed = 0;
/** Each answered request's correlation ID, by the organisation its caller named: the access-log row it still owes. */
const owedRows = new Map<string, string>();
/** One request as the caller sends it: a write from our own origin with a fresh idempotency key and its body. */
async function send(
  caller: Readonly<Record<string, string>>,
  method: string,
  url: string,
  body?: unknown,
): Promise<LightMyRequestResponse> {
  keysUsed += 1;
  const writes = method !== 'GET';
  if (api === undefined) throw new Error('the API is not running');
  const response = await api.inject({
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
  const correlationId = response.headers[CORRELATION_HEADER];
  const org = caller[ORGANIZATION_HEADER];
  // A person's own routes (SA6's passkey additions, under /v1/auth/) verify no organisation: their rows are the person
  // log's (access.person_requests), never the organisation's, whatever header the caller sends.
  if (typeof correlationId === 'string' && org !== undefined && !url.startsWith('/v1/auth/')) {
    owedRows.set(correlationId, org);
  }
  return response;
}

/**
 * Waits until every request A's members sent has its access-log row. The recorder writes a row in onResponse, after
 * inject's answer has resolved, so a row of the step before could land between this step's before and after reads.
 * That is the probable cause of TR-15 (the access.requests digest differed once on pg16, then passed on re-run): not
 * proven, as the failure was not caught in the act.
 */
async function accessRowsWritten(): Promise<void> {
  const owed = [...owedRows].filter(([, org]) => org === theirs.world.org).map(([id]) => id);
  await vi.waitFor(
    async () => {
      const rows = await database
        .as('admin')
        .query<{ written: string }>(
          'select count(*)::text as written from access.requests where org_id = $1 and correlation_id = any($2::uuid[])',
          [theirs.world.org, owed],
        );
      expect(Number(rows[0]?.written)).toBe(owed.length);
    },
    { timeout: 10_000, interval: 50 },
  );
  for (const id of owed) owedRows.delete(id);
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
  await accessRowsWritten();
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
  app = createDatabase<HandoffWorldTables & ActivityTables & OauthTables>(
    { ...database.connection('app'), maxConnections: 6 },
    testLogger(),
  );
  operator = createDatabase<HandoffWorldTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
  // The API's keys, each the same as the worlds' own (mandate-world's `keys`), so it believes what they sign; a `web`
  // copy's, without the jobs' own (TR-20).
  keyFolder = mkdtempSync(path.join(tmpdir(), 'agentx-sweep-keys-'));
  for (const purpose of WEB_PURPOSES) {
    const material = Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1).toString('base64url');
    writeFileSync(path.join(keyFolder, `key-${purpose}-v1`), `${material}\n`);
  }
  const connection = database.connection('app');
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
      // A login service nothing here reaches (a closed port), on a name a host below it can hold the passkey page under.
      AGENTX_OIDC_ISSUER: 'http://localhost:9',
      AGENTX_OIDC_CLIENT_ID: 'sweep-client',
      AGENTX_OIDC_CLIENT_SECRET: 's'.repeat(32),
      // SA6 on, so a person's own passkey additions are swept too.
      AGENTX_ADD_PASSKEY_ORIGIN: 'http://addkey.localhost:9',
      AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'http://localhost:9',
      AGENTX_MCP_OAUTH: 'on',
      AGENTX_RATE_LIMIT_PER_MINUTE: '50000',
      AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE: '50000',
      AGENTX_RATE_LIMIT_PER_AGENT_PER_MINUTE: '50000',
      AGENTX_RATE_LIMIT_PER_ORGANISATION_PER_MINUTE: '50000',
      AGENTX_LOG_EVENT_CAP_PER_MINUTE: '100000',
    },
    destination: apiLog,
  });
  if (started === undefined) throw new Error(`the API did not start: ${JSON.stringify(apiLog.lines().at(-1))}`);
  api = started;
  const paths = started.swagger().paths ?? {};
  operations = Object.entries(paths).flatMap(([route, item]) =>
    Object.entries((item ?? {}) as Record<string, Record<string, unknown>>)
      .filter(([method]) => ['get', 'post', 'put', 'patch', 'delete'].includes(method))
      .map(([method, operation]) => {
        const body = (operation.requestBody as { content?: Record<string, { schema?: Schema }> } | undefined)
          ?.content?.['application/json']?.schema;
        const parameters = (operation.parameters ?? []) as { in: string; name: string; schema?: Schema }[];
        return {
          method: method.toUpperCase(),
          route,
          access: operation['x-access'] as string[],
          ...(body !== undefined && { body }),
          query: Object.fromEntries(
            parameters.filter((one) => one.in === 'query').map((one) => [one.name, one.schema ?? {}]),
          ),
        };
      }),
  );

  // The audit chain seals each event's time by the database's clock, so the worlds start from now.
  clock = new FixedClock(new Date());
  const logger = testLogger();
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock, keys }),
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
    outbox: createOutbox({ ids, clock, keys }),
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
  // A's admin asks for an invitation and a contact as the console does, each kept as a draft for the step-up; a
  // reset's draft is made past its use case, which asks first for a contact that has counted for 7 days.
  const drafted = async (url: string, body: unknown, kind: string): Promise<string> => {
    const asked = await send(aHeaders, 'POST', url, body);
    expect(asked.statusCode, asked.body).toBe(202);
    return (JSON.parse(asked.body) as Record<string, { id: string }>)[kind]?.id ?? '';
  };
  const reset = ids.next();
  await withSignedStates(app, a.org, { keys, ids, logger }, (tx, states) =>
    draftReset(
      tx,
      states,
      {
        orgId: a.org,
        id: reset,
        person: other.membershipId,
        requestedBy: aAdmin.membershipId,
        expiresAt: new Date(clock.now().getTime() + 86_400_000),
      },
      { stepUpChallengeId: ids.next(), createdAt: clock.now(), actor: { type: 'user', id: aAdmin.userId } },
    ),
  );
  const identity = {
    invitation: await drafted(
      '/v1/members/invitations',
      { email: 'invited@example.test', role: 'developer' },
      'invitation',
    ),
    contact: await drafted('/v1/registered-contacts', { email: 'contact@example.test' }, 'contact'),
    reset,
  };
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
  // A's admin starts adding a passkey and comes back from the step-up with it, as the step-up's return keeps it.
  const begun = await send(aHeaders, 'POST', '/v1/auth/passkeys/additions');
  expect(begun.statusCode, begun.body).toBe(202);
  const passkeyAddition = (JSON.parse(begun.body) as { stepUpChallengeId: string }).stepUpChallengeId;
  await app.transaction().execute((tx) =>
    createPasskeyAdditions({
      database: app,
      challenges: createStepUpChallenges({ ids, clock, keys, logger }),
      passkeys: {
        register: () => Promise.reject(new Error('unused')),
        confirm: () => Promise.reject(new Error('unused')),
      },
      revoke: () => Promise.resolve(true),
      keys,
      ids,
      clock,
      logger,
    }).steppedUp(tx, {
      challengeId: passkeyAddition,
      sessionId: aAdmin.sessionId,
      userId: aAdmin.userId,
      accessToken: ['sweep', 'person', 'stand', 'in'].join('-'),
    }),
  );
  theirs = {
    world: a,
    member: other.membershipId,
    mandate: await spend.mandateIdOf(a),
    keyId: acting.keyId,
    connection: await connectionOf(aAdmin, a.agent),
    request: waiting.id,
    payment: made.transaction.id,
    registration,
    link: link.link.id,
    sessionRef: new URL(link.authoriseUrl).pathname.split('/').at(-1) ?? '',
    exportId,
    month,
    identity,
    passkeyAddition,
    admin: aHeaders,
    adminUser: aAdmin.userId,
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

  it('sweeps every body field naming a record, or names why not', () => {
    const named = operations.flatMap((op) =>
      Object.keys(op.body?.properties ?? {})
        .filter((field) => /Ids?$/.test(field) || field === 'owner')
        .filter(
          (field) =>
            !(REFERENCES as readonly string[]).includes(field) &&
            !SWEPT_APART.includes(field) &&
            BODY_EXEMPT[field] === undefined,
        )
        .map((field) => `${op.method} ${op.route}: ${field}`),
    );
    expect(named).toEqual([]);
  });

  it('sweeps every query parameter naming a record, or names why not', () => {
    const unswept = queryCases()
      .filter(({ op, name }) => theirQueryValue(op.route, name) === undefined)
      .map(({ op, name }) => `${op.method} ${op.route}?${name}`);
    expect(unswept).toEqual([]);
    // Never vacuous: the logs' filters and the lists' cursors.
    expect(queryCases().length).toBeGreaterThan(10);
  });

  it('answers a query naming A’s person, subject or record as one naming none, showing B nothing of A’s', async () => {
    const before = await theirRows();
    const wrong: string[] = [];
    const controls: { readonly method: string; readonly url: string }[] = [];
    for (const { op, name } of queryCases()) {
      const checked = await queryChecked(op, name);
      wrong.push(...checked.wrong);
      if (checked.control !== undefined) controls.push({ method: op.method, url: checked.control });
    }
    expect(wrong).toEqual([]);
    expect(await theirRows()).toEqual(before);
    // The control, after the check (A's own reads are logged in A's access log): A's own admin, filtering on the same,
    // finds A's own rows. Never vacuous: the audit log's person and subject, and the access log's person.
    let foundByA = 0;
    for (const { method, url } of controls) {
      const own = await send(theirs.admin, method, url);
      if (own.statusCode === 200 && everyIdOfTheirs().some((id) => own.body.includes(id))) foundByA += 1;
    }
    expect(foundByA).toBeGreaterThanOrEqual(3);
  }, 120_000);

  // After the sweep, as it changes A's records (a cancel, a decline, a suspension): a write's ID read by no GET (an
  // invitation, a contact, a reset, a key, a registration, a link, a bank session) is proven real by A's own admin
  // being answered anything but not-found with it, so B's not-found above is for the organisation alone.
  it('proves each write’s IDs of A’s real: A’s own admin is never answered not-found', async () => {
    const wrong: string[] = [];
    const sent: string[] = [];
    const writes = withPathIds().filter(
      ({ method, route, access }) => method !== 'GET' && EXEMPT[route] === undefined && access.includes('admin'),
    );
    for (const op of writes) {
      const answer = answerOf(
        await send(theirs.admin, op.method, filled(op.route, theirIds(op.route) ?? {}), sample(op.body ?? {})),
      );
      sent.push(op.route);
      if (answer.status === 404 && NOT_FOUND_FOR_A[op.route] === undefined) {
        wrong.push(`${op.method} ${op.route}: ${JSON.stringify(answer)}`);
      }
    }
    expect(wrong).toEqual([]);
    expect(sent.length).toBeGreaterThan(60);
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

  // A bug the sweep found (S206 V8): an agent's ask naming a supplier its organisation doesn't have (none, or another
  // organisation's) is DENIED and sealed naming no version of the supplier's details (0039), and every reader of the
  // organisation's requests then failed: the list with a 500 (suppliersNamed threw), the request, its evidence and
  // its evidence's download as INTEGRITY_FAILED. Each now shows it, its supplier unnamed, never another's name.
  // The same for a funding source (S206 V8): an ask naming one its organisation doesn't have is DENIED, and its
  // evidence and the evidence's download failed as INTEGRITY_FAILED. Each reader now shows it, the source by the ID
  // the agent sent alone, never another organisation's holder, account or partner.
  it.each([
    ['one that never existed', () => randomUUID()],
    ['another organisation’s', () => theirs.world.source],
  ])(
    'shows a request denied for naming a funding source its organisation doesn’t have, %s, in every reader',
    async (_what, sourceOf) => {
      const fundingSourceId = sourceOf();
      const base = sample(
        operations.find(({ method, route }) => method === 'POST' && route === '/v1/spend-requests')?.body ?? {},
      ) as object;
      const asked = await send(ours.agent, 'POST', '/v1/spend-requests', { ...base, fundingSourceId });
      expect(asked.statusCode, asked.body).toBe(201);
      const { id, status } = JSON.parse(asked.body) as { id: string; status: string };
      expect(status).toBe('DENIED');
      const read = async (who: Readonly<Record<string, string>>, method: 'GET' | 'POST', url: string, code = 200) => {
        const answer = await send(who, method, url);
        expect(answer.statusCode, `${method} ${url}: ${answer.body}`).toBe(code);
        // Never another organisation's record, beyond the ID the agent itself sent.
        expect(everyIdOfTheirs().filter((one) => one !== fundingSourceId && answer.body.includes(one))).toEqual([]);
        return JSON.parse(answer.body) as Record<string, unknown>;
      };

      expect(await read(ours.admin, 'GET', '/v1/approvals')).toMatchObject({ unchecked: [] });
      expect(await read(ours.admin, 'GET', `/v1/spend-requests/${id}`)).toMatchObject({ fundingSourceId });
      expect(await read(ours.admin, 'GET', `/v1/spend-requests/${id}/evidence`)).toMatchObject({
        evidence: { fundingSource: { id: fundingSourceId, holderName: null, hint: null, partner: null } },
      });
      expect(await read(ours.admin, 'POST', `/v1/spend-requests/${id}/evidence-exports`, 201)).toBeDefined();
      expect(await read(ours.agent, 'GET', `/v1/agent/spend-requests/${id}`)).toMatchObject({ id, status: 'DENIED' });
    },
  );

  it.each([
    ['one that never existed', () => randomUUID()],
    ['another organisation’s', () => theirs.world.suppliers[0] ?? ''],
  ])(
    'shows a request denied for naming a supplier its organisation doesn’t have, %s, in every reader',
    async (_what, supplierOf) => {
      const supplierId = supplierOf();
      const base = sample(
        operations.find(({ method, route }) => method === 'POST' && route === '/v1/spend-requests')?.body ?? {},
      ) as object;
      const asked = await send(ours.agent, 'POST', '/v1/spend-requests', { ...base, supplierId });
      expect(asked.statusCode, asked.body).toBe(201);
      const { id, status } = JSON.parse(asked.body) as { id: string; status: string };
      expect(status).toBe('DENIED');
      const unnamed = { id: supplierId, name: null };
      const read = async (who: Readonly<Record<string, string>>, method: 'GET' | 'POST', url: string, code = 200) => {
        const answer = await send(who, method, url);
        expect(answer.statusCode, `${method} ${url}: ${answer.body}`).toBe(code);
        // Never another organisation's record, beyond the ID the agent itself sent. The list holds the sweep's own
        // denied asks too, each naming A's IDs as its agent sent them: checked below by name instead.
        if (!url.endsWith('/spend-requests')) {
          expect(everyIdOfTheirs().filter((one) => one !== supplierId && answer.body.includes(one))).toEqual([]);
        }
        return JSON.parse(answer.body) as Record<string, unknown>;
      };

      const listed = (await read(ours.admin, 'GET', '/v1/spend-requests')) as { spendRequests: { id: string }[] };
      expect(listed.spendRequests.find((one) => one.id === id)).toMatchObject({ supplier: unnamed });
      // Every request naming a supplier of A's, this one or the sweep's, names none: never A's supplier's name.
      const theirSuppliers = new Set(theirs.world.suppliers);
      const naming = (listed.spendRequests as unknown as { supplier: { id: string; name: string | null } }[]).filter(
        ({ supplier }) => theirSuppliers.has(supplier.id),
      );
      expect(naming.map(({ supplier }) => supplier.name)).toEqual(naming.map(() => null));
      // Denied, so never waiting: the approvals list is untouched by it.
      expect(await read(ours.admin, 'GET', '/v1/approvals')).toMatchObject({ unchecked: [] });
      expect(await read(ours.admin, 'GET', `/v1/spend-requests/${id}`)).toMatchObject({ supplier: unnamed });
      expect(await read(ours.admin, 'GET', `/v1/spend-requests/${id}/evidence`)).toMatchObject({
        evidence: { supplier: { ...unnamed, version: null } },
      });
      expect(await read(ours.admin, 'POST', `/v1/spend-requests/${id}/evidence-exports`, 201)).toBeDefined();
      // The agent's own read, and its MCP tool get_spend_request (its twin: the same use case).
      expect(await read(ours.agent, 'GET', `/v1/agent/spend-requests/${id}`)).toMatchObject({ id, status: 'DENIED' });
    },
  );

  // Near the end: it puts both organisations on hold, which stops their hand-offs.
  it('refuses B to clear its hold by an investigation of A’s, as by one never recorded, showing nothing of A’s', async () => {
    const quiet = { keys, ids, logger: testLogger() };
    await holdOrganisation(app, theirs.world.org, quiet, 'test');
    await holdOrganisation(app, ours.world.org, quiet, 'test');
    const investigated = async (headers: Readonly<Record<string, string>>) => {
      const recorded = await send(headers, 'POST', '/v1/integrity-hold/investigations', {
        conclusion: 'NO_TAMPERING',
        reference: 'INC-S206-V8',
      });
      expect(recorded.statusCode, recorded.body).toBe(201);
      return (JSON.parse(recorded.body) as { investigation: { id: string } }).investigation.id;
    };
    const theirInvestigation = await investigated(theirs.admin);
    const ourInvestigation = await investigated(ours.admin);
    const before = await theirRows();

    // The control: B's own investigation is taken, so each refusal below is for the ID alone.
    const own = await send(ours.admin, 'POST', '/v1/integrity-hold/clear', { investigationId: ourInvestigation });
    expect(own.statusCode, own.body).toBe(202);
    const wrong: string[] = [];
    for (const route of ['/v1/integrity-hold/clear', '/v1/integrity-hold/clear/confirm']) {
      const asked = async (investigationId: string) =>
        answerOf(
          await send(ours.admin, 'POST', route, {
            investigationId,
            ...(route.endsWith('/confirm') && { stepUpChallengeId: randomUUID() }),
          }),
        );
      const real = await asked(theirInvestigation);
      const absent = await asked(randomUUID());
      if (JSON.stringify(real) !== JSON.stringify(absent) || real.status < 400 || real.status >= 500) {
        wrong.push(`${route}: A's ${JSON.stringify(real)}, absent ${JSON.stringify(absent)}`);
      }
    }
    const shown = await send(ours.admin, 'GET', '/v1/integrity-hold');
    expect(shown.statusCode).toBe(200);
    expect([theirInvestigation, ...everyIdOfTheirs()].filter((id) => shown.body.includes(id))).toEqual([]);
    expect(wrong).toEqual([]);
    expect(await theirRows()).toEqual(before);
  });

  // The other side of the fix (S206 V8): only a request sealed naming no version of its supplier's details is shown
  // unnamed. One sealed naming a version, its supplier then deleted past the app (its foreign keys' triggers off,
  // which takes the test server's superuser), is still not believed: left out of the list and named there as unchecked, and its
  // own read INTEGRITY_FAILED. Last: it takes one of B's suppliers away.
  it('still refuses to believe a request sealed naming its supplier’s details once that supplier is gone', async () => {
    const supplierId = ours.world.suppliers[1] ?? '';
    const base = sample(
      operations.find(({ method, route }) => method === 'POST' && route === '/v1/spend-requests')?.body ?? {},
    ) as object;
    const asked = await send(ours.agent, 'POST', '/v1/spend-requests', { ...base, supplierId });
    expect(asked.statusCode, asked.body).toBe(201);
    const { id } = JSON.parse(asked.body) as { id: string };
    expect((await send(ours.admin, 'GET', `/v1/spend-requests/${id}`)).statusCode).toBe(200);

    const admin = await database.connect('admin');
    try {
      await admin.query('begin');
      await admin.query("select pg_catalog.set_config('session_replication_role', 'replica', true)");
      await admin.query('delete from suppliers.suppliers where org_id = $1 and id = $2', [ours.world.org, supplierId]);
      await admin.query(
        "delete from audit.events where org_id = $1 and subject_type = 'supplier' and subject_id = $2",
        [ours.world.org, supplierId],
      );
      await admin.query('commit');
    } finally {
      await admin.end();
    }

    const listed = await send(ours.admin, 'GET', '/v1/spend-requests');
    expect(listed.statusCode, listed.body).toBe(200);
    const page = JSON.parse(listed.body) as { spendRequests: { id: string }[]; unchecked: string[] };
    expect(page.spendRequests.map((one) => one.id)).not.toContain(id);
    expect(page.unchecked).toContain(id);
    expect(answerOf(await send(ours.admin, 'GET', `/v1/spend-requests/${id}`))).toEqual({
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });

  // And the funding source's (S206 V8): only a DENIED request is shown with a source none of the organisation's. A
  // request still waiting whose source is then deleted past the app, its events too, keeps its evidence refused.
  it('still refuses the evidence of a request not denied once its funding source is gone', async () => {
    const evidenceOf = async () =>
      answerOf(await send(theirs.admin, 'GET', `/v1/spend-requests/${theirs.request}/evidence`));
    // The control: A's waiting request's evidence reads before.
    expect((await evidenceOf()).status).toBe(200);
    const admin = await database.connect('admin');
    try {
      await admin.query('begin');
      await admin.query("select pg_catalog.set_config('session_replication_role', 'replica', true)");
      await admin.query('delete from funding_sources.sources where org_id = $1 and id = $2', [
        theirs.world.org,
        theirs.world.source,
      ]);
      await admin.query(
        "delete from audit.events where org_id = $1 and subject_type = 'funding_source' and subject_id = $2",
        [theirs.world.org, theirs.world.source],
      );
      await admin.query('commit');
    } finally {
      await admin.end();
    }
    expect(await evidenceOf()).toEqual({ status: 503, code: 'INTEGRITY_FAILED' });
  });

  // A DENIED request naming the organisation's own source is shown with it, never as none: that source's row deleted
  // past the app while its events stay reads as tampered, and the evidence stays refused.
  it('still refuses the evidence of a denied request whose own funding source’s row is gone', async () => {
    const base = sample(
      operations.find(({ method, route }) => method === 'POST' && route === '/v1/spend-requests')?.body ?? {},
    ) as object;
    const asked = await send(ours.agent, 'POST', '/v1/spend-requests', base);
    const { id, status } = JSON.parse(asked.body) as { id: string; status: string };
    expect(status).toBe('DENIED');
    const evidenceOf = async (of = id) => answerOf(await send(ours.admin, 'GET', `/v1/spend-requests/${of}/evidence`));
    expect((await evidenceOf()).status).toBe(200);
    // And one denied as an unusable source, its own: the source suspended by B's admin first.
    const suspend = operations.find(
      ({ method, route }) => method === 'POST' && route === '/v1/funding-sources/{id}/suspend',
    );
    const suspended = await send(
      ours.admin,
      'POST',
      `/v1/funding-sources/${ours.world.source}/suspend`,
      sample(suspend?.body ?? {}),
    );
    expect(suspended.statusCode, suspended.body).toBeLessThan(300);
    const unusable = JSON.parse((await send(ours.agent, 'POST', '/v1/spend-requests', base)).body) as {
      id: string;
      reasons: { code: string }[];
    };
    expect(unusable.reasons.map(({ code }) => code)).toContain('SOURCE_NOT_USABLE');
    expect((await evidenceOf(unusable.id)).status).toBe(200);
    const admin = await database.connect('admin');
    try {
      await admin.query('begin');
      await admin.query("select pg_catalog.set_config('session_replication_role', 'replica', true)");
      await admin.query('delete from funding_sources.sources where org_id = $1 and id = $2', [
        ours.world.org,
        ours.world.source,
      ]);
      await admin.query('commit');
    } finally {
      await admin.end();
    }
    expect(await evidenceOf()).toEqual({ status: 503, code: 'INTEGRITY_FAILED' });
    // Its source's row gone while its events stay is tampered with, never one none of B's, whatever it was denied for.
    expect(await evidenceOf(unusable.id)).toEqual({ status: 503, code: 'INTEGRITY_FAILED' });
    // Its events gone too, the source reads as missing; still refused: the request was denied for another reason
    // (its supplier), never as an unusable source, so its source was the organisation's.
    const events = await database.connect('admin');
    try {
      await events.query('begin');
      await events.query("select pg_catalog.set_config('session_replication_role', 'replica', true)");
      await events.query(
        "delete from audit.events where org_id = $1 and subject_type = 'funding_source' and subject_id = $2",
        [ours.world.org, ours.world.source],
      );
      await events.query('commit');
    } finally {
      await events.end();
    }
    expect(await evidenceOf()).toEqual({ status: 503, code: 'INTEGRITY_FAILED' });
  });
});

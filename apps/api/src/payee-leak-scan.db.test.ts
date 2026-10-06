// SEC-PAY-05 (ADR-014 §3; Phase 1 E2-2c): a supplier's bank details, entered
// through the partner's form or passed through, are found nowhere Agent X
// keeps anything. Through the whole server, on the real migrated schema, as
// the app role, with the fake partner over its records in the app's database
// as on staging: planted IBANs (UAE ones registered by both routes, after a
// lost answer too, and other countries' ones refused at the door), each
// spelled every way a person might send it, are then looked for in every row
// of every table (idempotency keys, audit events, the fake partner's records
// and the outbox included), every log line and every answer: as written,
// compacted, in lower case, as their bytes in hex, and as their plain SHA-256.
// The idempotency row's hash of the request is keyed, so it gives none of them.
import { createHash } from 'node:crypto';

import { withSignedStates } from '@agentx/core/modules/audit';
import {
  addMembership,
  type LiveSession,
  membershipFor,
  type SignIn,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  createDatabaseRecords,
  createFakeRail,
  type FakePartnerTables,
  type FakeRail,
  RailUnavailable,
} from '@agentx/core/modules/providers';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { createSupplierPayees } from './supplier-payees.ts';
import { createSupplierRegistry } from './supplier-registry.ts';
import type { SupplierTables } from './supplier-work.ts';

const server = inject('postgres');
let database: TestDatabase;
// The tables the use cases work on; the scan reads every table as the admin.
let app: Database<SupplierTables & OrganizationsTables & FakePartnerTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe22c_0000_0000);
const START = new Date('2026-10-02T08:00:00Z');
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const clock = new FixedClock(START);
const capture = new LogCapture();
const logger = createLogger({
  service: 'test',
  config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 10_000 } },
  destination: capture,
});

/** An IBAN with valid check digits (ISO 13616) around a country and an account number, built here so no scanner takes one for real. */
function ibanOf(country: string, account: string): string {
  // Each letter as its number (A is 10), digits as they are.
  const digits = (text: string) => text.replaceAll(/[A-Z]/g, (letter) => String(Number.parseInt(letter, 36)));
  const check = 98n - (BigInt(digits(`${account}${country}00`)) % 97n);
  return `${country}${String(check).padStart(2, '0')}${account}`;
}

/** UAE accounts the partner registers (one by its form, one passed through, one after a lost answer), and others' it can't pay. */
const BY_FORM = ibanOf('AE', ['033', '1000', '2222', '3333', '4444'].join(''));
const PASSED = ibanOf('AE', ['035', '5000', '6666', '7777', '8888'].join(''));
const AFTER_LOSS = ibanOf('AE', ['026', '9000', '1212', '3434', '5656'].join(''));
const AT_FAILURE = ibanOf('AE', ['033', '4000', '9191', '8282', '7373'].join(''));
const ELSEWHERE = [
  ibanOf('GB', ['WEST', '1234', '5698', '7654', '32'].join('')),
  ibanOf('DE', ['3705', '0198', '0020', '0001', '23'].join('')),
];
const PLANTED = [BY_FORM, PASSED, AFTER_LOSS, AT_FAILURE, ...ELSEWHERE];

const grouped = (iban: string) => iban.replace(/(.{4})/g, '$1 ').trim();
const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

/** Every form a planted IBAN could be kept in: as sent, compacted, lower case, its bytes in hex, its plain SHA-256s, its account number. */
const needlesOf = (iban: string): string[] => [
  iban,
  iban.toLowerCase(),
  grouped(iban),
  grouped(iban).toLowerCase(),
  Buffer.from(iban).toString('hex'),
  sha256(iban),
  sha256(grouped(iban)),
  sha256(iban.toLowerCase()),
  iban.slice(4),
];

/** Every row of every table, as JSON text, read as the admin: the statement for each table is built in Postgres. */
async function everyRow(): Promise<string> {
  const rows = await database.as('admin').query<{ rows: string }>(
    `select pg_catalog.query_to_xml(
        pg_catalog.format('select pg_catalog.to_jsonb(t)::text as row from %I.%I t', table_schema, table_name),
        true, false, '')::text as rows
       from information_schema.tables
      where table_type = 'BASE TABLE'
        and table_schema not in ('pg_catalog', 'information_schema')`,
  );
  return rows.map((row) => row.rows).join('\n');
}

const answers: string[] = [];

/** Everything kept: every row, every log line, every answer, in lower case. */
const keptAnywhere = (rows: string) => [rows, capture.text, ...answers].join('\n').toLowerCase();

/** The live session the fake sign-in gives for the cookie; its user is made in beforeAll. */
let live: LiveSession;
const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? live : undefined),
};

/** The whole server over `rail`, the partner the config would name, with the real supplier use cases. */
async function serverWith(rail: FakeRail): Promise<FastifyInstance> {
  const services = { database: app, keys, ids, clock, logger };
  const http = {
    host: '127.0.0.1',
    port: 0,
    publicOrigin: ORIGIN,
    trustedProxies: [],
    rateLimitPerMinute: 1000,
    rateLimitPerUserPerMinute: 1000,
    rateLimitPerAgentPerMinute: 1000,
  };
  const api = await buildServer({
    config: { http, log: { level: 'info', eventCapPerMinute: 10_000 } },
    logger,
    ids,
    healthChecks: [],
    signIn: { service: SIGN_IN, sessionSeconds: 43_200 },
    restrictedUntil: () => Promise.resolve(undefined),
    findMembership: (orgId, userId) => membershipFor(app, { keys, ids, logger }, orgId, userId),
    supplierRegistry: createSupplierRegistry(services),
    supplierPayees: createSupplierPayees({ ...services, rail, partner: 'fake' }),
    fakeBank: rail.bank,
  });
  await api.ready();
  return api;
}

let keysUsed = 0;
/** A write as the admin's browser sends it, its answer kept for the scan. */
async function sent(api: FastifyInstance, orgId: string, url: string, body: unknown, key?: string) {
  keysUsed += 1;
  const request: InjectOptions = {
    method: 'POST',
    url,
    headers: {
      cookie: `${SESSION_COOKIE}=${COOKIE}`,
      [ORGANIZATION_HEADER]: orgId,
      origin: ORIGIN,
      'idempotency-key': key ?? `scan-${String(keysUsed)}`,
      'content-type': 'application/json',
    },
    payload: JSON.stringify(body),
  };
  const response: LightMyRequestResponse = await api.inject(request);
  answers.push(response.body);
  return response;
}

let org: string;
const SUPPLIER = {
  displayName: 'Jasmine AI FZ-LLC',
  phone: '+971501234567',
  source: { kind: 'registry', ref: 'DED-123456' },
};
const supplierOf = async (api: FastifyInstance) => {
  const added = await sent(api, org, '/v1/suppliers', SUPPLIER);
  expect(added.statusCode).toBe(201);
  return added.json<{ id: string }>().id;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase({ ...database.connection('app'), maxConnections: 4 }, logger);
  org = ids.next();
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: 'payee-scan' },
    { ids, clock },
  );
  live = {
    sessionId: ids.next(),
    userId,
    idpSessionId: 'V1_1',
    authTime: START,
    amr: ['pwd', 'user', 'mfa'],
    createdAt: START,
    lastSeenAt: START,
    endsAt: new Date('2099-01-01T00:00:00Z'),
    idleEndsAt: new Date('2099-01-01T00:00:00Z'),
  };
  await withSignedStates(app, org, { keys, ids, logger }, async (tx, states) => {
    await createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR });
    await addMembership(tx, states, {
      orgId: org,
      id: ids.next(),
      userId,
      role: 'admin',
      joinedAt: START,
      actor: OPERATOR,
    });
  });
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`SEC-PAY-05 a supplier's bank details, kept nowhere (E2-2c, Postgres ${server.version})`, () => {
  it('registers payees by the form and passed through, refuses others, and keeps no planted IBAN anywhere', async () => {
    const rail = createFakeRail({ clock, ids, records: createDatabaseRecords(app) });
    const api = await serverWith(rail);
    try {
      // The partner's form, filled in with the IBAN in groups and lower case, then checked.
      const byForm = await supplierOf(api);
      const started = await sent(api, org, `/v1/suppliers/${byForm}/payee-registrations`, {});
      expect(started.statusCode).toBe(201);
      const { id, form } = started.json<{ id: string; form: { url: string } }>();
      const filled = await sent(api, org, '/v1/fake-bank/payee-forms', {
        url: form.url,
        name: 'Jasmine AI FZ-LLC',
        iban: grouped(BY_FORM).toLowerCase(),
      });
      expect(filled.statusCode).toBe(200);
      const checked = await sent(api, org, `/v1/suppliers/${byForm}/payee-registrations/${id}/check`, {});
      expect(checked.json()).toMatchObject({ status: 'REGISTERED' });

      // Passed through, in groups.
      const passed = await sent(api, org, `/v1/suppliers/${await supplierOf(api)}/payee-registrations/pass-through`, {
        name: 'Jasmine AI FZ-LLC',
        iban: grouped(PASSED),
      });
      expect(passed.json()).toMatchObject({ status: 'REGISTERED' });

      // Other countries' accounts, at both doors of a supplier with nothing under way: refused for the account, never echoed.
      for (const iban of ELSEWHERE) {
        const fresh = await supplierOf(api);
        const at = await sent(api, org, `/v1/suppliers/${fresh}/payee-registrations/pass-through`, {
          name: 'Gulf',
          iban,
        });
        expect(at.json()).toMatchObject({ error: { code: 'BAD_REQUEST' } });
        const open = await sent(api, org, `/v1/suppliers/${fresh}/payee-registrations`, {});
        const url = open.json<{ form: { url: string } }>().form.url;
        const bank = await sent(api, org, '/v1/fake-bank/payee-forms', { url, name: 'Gulf', iban });
        expect(bank.json()).toMatchObject({ error: { code: 'BANK_FORM_REFUSED' } });
      }
    } finally {
      await api.close();
    }

    // Passed through after a lost answer, then sent again with its key.
    const partner = createFakeRail({ clock, ids, records: createDatabaseRecords(app) });
    let lost = false;
    const losing = await serverWith({
      ...partner,
      registerBeneficiary: async (input) => {
        const outcome = await partner.registerBeneficiary(input);
        if (lost) return outcome;
        lost = true;
        throw new RailUnavailable();
      },
    });
    try {
      const afterLoss = await supplierOf(losing);
      const body = { name: 'Jasmine AI FZ-LLC', iban: AFTER_LOSS };
      const url = `/v1/suppliers/${afterLoss}/payee-registrations/pass-through`;
      expect((await sent(losing, org, url, body, 'after-loss')).statusCode).toBe(503);
      expect((await sent(losing, org, url, body, 'after-loss')).json()).toMatchObject({ status: 'REGISTERED' });
    } finally {
      await losing.close();
    }

    // A partner failing in a way no one planned for: a 500, its error logged, the details in neither.
    const failing = await serverWith({
      ...partner,
      registerBeneficiary: async (input) => {
        await partner.registerBeneficiary(input);
        throw new Error('the partner broke');
      },
    });
    try {
      const url = `/v1/suppliers/${await supplierOf(failing)}/payee-registrations/pass-through`;
      expect((await sent(failing, org, url, { name: 'Jasmine AI FZ-LLC', iban: AT_FAILURE })).statusCode).toBe(500);
    } finally {
      await failing.close();
    }
    expect(capture.lines().filter(({ level }) => level === 'error')).not.toEqual([]);

    const rows = await everyRow();
    // The scan reads what was written: the registrations, their idempotency keys and the partner's records.
    expect(rows).toContain('beneficiary_registration.registered');
    expect(rows).toContain('suppliers.payee.pass-through');
    expect(rows).toContain('fake-payee-');
    // And the suppliers' own tables, past their walls: a supplier's name is kept in the clear.
    expect(rows).toContain(SUPPLIER.displayName);
    const found = PLANTED.flatMap(needlesOf).filter((needle) => keptAnywhere(rows).includes(needle.toLowerCase()));
    expect(found).toEqual([]);
  });

  it('finds an IBAN where one is kept, so the scan is no empty check', async () => {
    const canary = ibanOf('AE', ['044', '7000', '1313', '2424', '3535'].join(''));
    const api = await serverWith(createFakeRail({ clock, ids, records: createDatabaseRecords(app) }));
    try {
      // An email's local part is any printable ASCII: an IBAN typed there is kept (the free-text fields refuse one).
      const added = await sent(api, org, '/v1/suppliers', { ...SUPPLIER, email: `${canary}@canary.example` });
      expect(added.statusCode).toBe(201);
    } finally {
      await api.close();
    }

    // A log line holding one of the forms looked for (an IBAN itself the logger blanks).
    logger.info('scan.canary', { note: sha256(canary) });

    // Each place on its own: the row keeps it, the answer gives it back, the log line holds its hash.
    const hits = (text: string) =>
      needlesOf(canary).filter((needle) => text.toLowerCase().includes(needle.toLowerCase()));
    expect(hits(await everyRow())).toContain(canary);
    expect(hits(answers.join('\n'))).toContain(canary);
    expect(hits(capture.text)).toEqual([sha256(canary)]);
  });
});

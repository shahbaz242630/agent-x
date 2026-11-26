// GA4 (PRD §9.3): the money-path snapshot on the real migrated schema, read as
// the app role, each organisation under its own wall. The rows are laid down
// by the database's admin with the triggers and foreign keys off (only the
// counted columns matter here; the ways in are each proven in their own
// tests), so every status and age can be set exactly. Each organisation's
// counts are its own: one organisation's rows never reach another's line, nor
// a pass that wasn't asked to read it.
import { v7Floor } from '@agentx/core/modules/activity';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMoneyPathSnapshot, type MoneyPathTables } from './money-path-snapshot.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MoneyPathTables>;
let capture: LogCapture;
const NOW = new Date('2027-03-10T12:00:00.000Z');
const clock = new FixedClock(NOW);
const HOUR_MS = 60 * 60_000;
const orgIds = new SequentialIds(0x6a40_0000_0000);
let ours: string;
let theirs: string;
let quiet: string;

let made = 0;
/** An ID made `hoursAgo` before the pass, as the app makes them (UUIDv7, by time). */
const idAt = (hoursAgo: number): string => {
  made += 1;
  return `${v7Floor(NOW.getTime() - hoursAgo * HOUR_MS).slice(0, 14)}7000-8000-${made.toString(16).padStart(12, '0')}`;
};
const ago = (hours: number) => new Date(NOW.getTime() - hours * HOUR_MS);
const HASH = 'a'.repeat(64);

interface Asked {
  readonly status: string;
  readonly hoursAgo: number;
  /** When its wait ends, for a request that waited for approval. */
  readonly waitsUntil?: Date;
  /** Its reservation, if any: its state, currency and amount. */
  readonly held?: readonly [state: string, currency: string, amountMinor: bigint];
  /** Its payment, for one handed off: the transaction's status and how long ago it was made. */
  readonly paid?: readonly [status: string, hoursAgo: number];
}

/** The organisation's requests, their reservations and payments, as the admin lays them down. */
async function laid(orgId: string, requests: readonly Asked[]): Promise<void> {
  const admin = await database.connect('admin');
  try {
    await admin.query('begin');
    await admin.query("select pg_catalog.set_config('session_replication_role', 'replica', true)");
    for (const { status, hoursAgo, waitsUntil, held, paid } of requests) {
      const id = idAt(hoursAgo);
      const waited = waitsUntil !== undefined || status === 'APPROVAL_REQUIRED';
      await admin.query(
        `insert into spend_requests.requests (org_id, id, agent_id, agent_key_id, mandate_id, mandate_version_id,
           supplier_id, supplier_version_id, funding_source_id, amount_minor, currency, purpose, order_reference,
           idempotency_key, input_hash, input_hash_key_version, decision, reason_codes, status, created_at, waits_until)
         values ($1, $2::uuid, $3, $3, $3, $3, $3, $3, $3, 100, 'AED', 'Paper', $2::text, $2::text, $4, 1, $5, $6, $7,
           $8, $9)`,
        [
          orgId,
          id,
          idAt(hoursAgo),
          HASH,
          waited ? 'REQUIRE_APPROVAL' : 'ALLOW',
          waited ? 'OVER_APPROVAL_THRESHOLD' : null,
          status,
          ago(hoursAgo),
          waitsUntil ?? (waited ? new Date(ago(hoursAgo).getTime() + 24 * HOUR_MS) : null),
        ],
      );
      if (held !== undefined) {
        const [state, currency, amount] = held;
        const ended = state === 'FINALISED' || state === 'RELEASED';
        await admin.query(
          `insert into limit_reservations.reservations (org_id, id, request_id, agent_id, mandate_id, month,
             supplier_id, amount_minor, currency, state, reserved_at, settled_at)
           values ($1, $2, $3, $2, $2, '2027-03', $2, $4, $5, $6, $7, $8)`,
          [orgId, idAt(hoursAgo), id, amount.toString(), currency, state, ago(hoursAgo), ended ? NOW : null],
        );
      }
      if (paid !== undefined) {
        const [transactionStatus, madeHoursAgo] = paid;
        const instruction = idAt(madeHoursAgo);
        await admin.query(
          `insert into instructions.instructions (org_id, id, spend_request_id, route, route_reason, funding_source_id,
             partner, partner_legal_entity_id, partner_licence_ref, account_consent_id, beneficiary_ref,
             supplier_version_id, amount_minor, currency, payment_reference, intent_hash, created_at)
           values ($1, $2, $3, 'push', 'only_route', $2, 'fake', 'LE-1', 'LIC-1', 'consent-1', 'payee-1', $2, 100,
             'AED', 'REF 1', $4, $5)`,
          [orgId, instruction, id, HASH, ago(madeHoursAgo)],
        );
        await admin.query(
          `insert into transactions.transactions (org_id, id, instruction_id, status, created_at)
           values ($1, $2, $3, $4, $5)`,
          [orgId, idAt(madeHoursAgo), instruction, transactionStatus, ago(madeHoursAgo)],
        );
      }
    }
    await admin.query('commit');
  } finally {
    await admin.end();
  }
}

const snapshot = (list: readonly string[], page = 2) =>
  createMoneyPathSnapshot({
    list: () => Promise.resolve(list),
    database: app,
    clock,
    logger: testLogger(capture),
    page,
  });

/** The lines of one event, without the logger's own fields. */
const linesOf = (event: string) =>
  capture
    .lines()
    .filter((line) => line.event === event)
    .map(
      ({
        time: _time,
        level: _level,
        event: _event,
        msg: _msg,
        pid: _pid,
        hostname: _host,
        env: _env,
        release: _release,
        service: _service,
        ...fields
      }) => fields,
    );

/** Our organisation's counts alone. */
const OURS = {
  approvalsWaiting: 2,
  approvalsExpiredLastDay: 1,
  unknownPayments: 2,
  oldestUnknownSeconds: 3 * 3600,
  stuckPayments: 1,
  stuckAfterMinutes: 60,
  held: [
    { currency: 'AED', reservations: 7, amountMinor: '41606' },
    { currency: 'USD', reservations: 1, amountMinor: '50' },
  ],
};

/** Theirs alone. */
const THEIRS = {
  approvalsWaiting: 1,
  approvalsExpiredLastDay: 0,
  unknownPayments: 1,
  oldestUnknownSeconds: 50 * 3600,
  stuckPayments: 0,
  stuckAfterMinutes: 60,
  held: [{ currency: 'AED', reservations: 2, amountMinor: '7003' }],
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MoneyPathTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
  ours = orgIds.next();
  theirs = orgIds.next();
  quiet = orgIds.next();
  await laid(ours, [
    // Two waiting, each holding its amount.
    { status: 'APPROVAL_REQUIRED', hoursAgo: 2, held: ['HELD', 'AED', 100n] },
    { status: 'APPROVAL_REQUIRED', hoursAgo: 5, held: ['HELD', 'AED', 200n] },
    // Approved, not yet handed off, in another currency.
    { status: 'APPROVED', hoursAgo: 1, held: ['HELD', 'USD', 50n] },
    // Expired: its wait ended two hours ago (counted), and one 30 hours ago (outside the day).
    { status: 'EXPIRED', hoursAgo: 26, waitsUntil: ago(2), held: ['RELEASED', 'AED', 9_000n] },
    { status: 'EXPIRED', hoursAgo: 54, waitsUntil: ago(30), held: ['RELEASED', 'AED', 9_000n] },
    // Denied, its reservation released: no money held.
    { status: 'DENIED', hoursAgo: 3, held: ['RELEASED', 'AED', 70_000n] },
    // Cancelled, its signed ending keeping the capacity (capacityKept, AT13d): its reservation stays HELD, still
    // counted against the agent's month, so money held, though the request has ended.
    { status: 'CANCELLED', hoursAgo: 200, held: ['HELD', 'AED', 40_000n] },
    // Handed off: UNKNOWN 3 hours (the oldest) and an hour, PROCESSING 2 hours (stuck), SUBMITTED 10 minutes (not
    // yet), and one paid (its money spent, not held).
    { status: 'HANDED_OFF', hoursAgo: 4, held: ['BLOCKED_UNKNOWN', 'AED', 1_000n], paid: ['UNKNOWN', 3] },
    { status: 'HANDED_OFF', hoursAgo: 2, held: ['BLOCKED_UNKNOWN', 'AED', 1n], paid: ['UNKNOWN', 1] },
    { status: 'HANDED_OFF', hoursAgo: 3, held: ['HELD', 'AED', 300n], paid: ['PROCESSING', 2] },
    { status: 'HANDED_OFF', hoursAgo: 1, held: ['HELD', 'AED', 5n], paid: ['SUBMITTED', 1 / 6] },
    { status: 'HANDED_OFF', hoursAgo: 6, held: ['FINALISED', 'AED', 80_000n], paid: ['SUCCEEDED', 5] },
  ]);
  await laid(theirs, [
    { status: 'APPROVAL_REQUIRED', hoursAgo: 1, held: ['HELD', 'AED', 7_000n] },
    { status: 'HANDED_OFF', hoursAgo: 51, held: ['BLOCKED_UNKNOWN', 'AED', 3n], paid: ['UNKNOWN', 50] },
  ]);
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe('GA4 the money-path snapshot', () => {
  it('adds every organisation up into one line, and names those with a payment unknown or stuck', async () => {
    await snapshot([ours, theirs, quiet, 'not-an-organisation', ours.toUpperCase()]).run();
    expect(linesOf('money_path.snapshot')).toEqual([
      {
        organisations: 3,
        missed: 0,
        complete: true,
        approvalsWaiting: 3,
        approvalsExpiredLastDay: 1,
        unknownPayments: 3,
        oldestUnknownSeconds: 50 * 3600,
        stuckPayments: 1,
        stuckAfterMinutes: 60,
        held: [
          { currency: 'AED', reservations: 9, amountMinor: '48609' },
          { currency: 'USD', reservations: 1, amountMinor: '50' },
        ],
      },
    ]);
    // Each organisation's line holds its own counts alone; the quiet one has none.
    expect(linesOf('money_path.organisation')).toEqual([
      { orgId: ours, ...OURS },
      { orgId: theirs, ...THEIRS },
    ]);
  });

  it("never counts one organisation's rows in another's pass: each read alone is its own", async () => {
    for (const [orgId, counts] of [
      [ours, OURS],
      [theirs, THEIRS],
    ] as const) {
      capture = new LogCapture();
      await snapshot([orgId]).run();
      expect(linesOf('money_path.snapshot')).toEqual([{ organisations: 1, missed: 0, complete: true, ...counts }]);
    }
    capture = new LogCapture();
    await snapshot([quiet]).run();
    expect(linesOf('money_path.snapshot')).toEqual([
      {
        organisations: 1,
        missed: 0,
        complete: true,
        approvalsWaiting: 0,
        approvalsExpiredLastDay: 0,
        unknownPayments: 0,
        oldestUnknownSeconds: null,
        stuckPayments: 0,
        stuckAfterMinutes: 60,
        held: [],
      },
    ]);
    expect(linesOf('money_path.organisation')).toEqual([]);
  });

  it('an organisation the database refuses says so and is left out; a stopped pass says it is incomplete', async () => {
    await database.as('owner').query('revoke select on limit_reservations.reservations from agentx_app');
    try {
      await snapshot([ours, theirs]).run();
    } finally {
      await database.as('owner').query('grant select on limit_reservations.reservations to agentx_app');
    }
    expect(capture.lines().filter(({ event }) => event === 'money_path.missed')).toEqual([
      expect.objectContaining({ level: 'warn', orgId: ours }),
      expect.objectContaining({ level: 'warn', orgId: theirs }),
    ]);
    expect(linesOf('money_path.snapshot')).toEqual([
      expect.objectContaining({ organisations: 0, missed: 2, complete: true, approvalsWaiting: 0 }),
    ]);

    capture = new LogCapture();
    const stopped = new AbortController();
    stopped.abort();
    await snapshot([ours, theirs]).run(stopped.signal);
    expect(linesOf('money_path.snapshot')).toEqual([
      expect.objectContaining({ organisations: 0, missed: 0, complete: false }),
    ]);
  });

  it('reads money held from 0120’s index of the reservations still holding, by organisation and currency', async () => {
    const rows = await database
      .as('admin')
      .query<{ indexdef: string }>(
        "select indexdef from pg_catalog.pg_indexes where schemaname = 'limit_reservations' and indexname = 'reservations_holding'",
      );
    expect(rows.map(({ indexdef }) => indexdef)).toEqual([
      "CREATE INDEX reservations_holding ON limit_reservations.reservations USING btree (org_id, currency) INCLUDE (amount_minor) WHERE (state = ANY (ARRAY['HELD'::text, 'BLOCKED_UNKNOWN'::text]))",
    ]);
  });

  it('a list that fails is the run’s own error, and nothing is logged as counted', async () => {
    await createMoneyPathSnapshot({
      list: () => Promise.reject(new Error('the directory is away')),
      database: app,
      clock,
      logger: testLogger(capture),
    }).run();
    expect(capture.lines()).toEqual([expect.objectContaining({ level: 'error', event: 'money_path.run_failed' })]);
  });
});

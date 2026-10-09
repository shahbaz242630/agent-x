// D2: the tables' own rules (0040), on the real migrated schema, as the app
// role. Reserving through them, and its forced lock tests, come with D4.
import { createDatabase, type Database, type DatabaseTransaction, withTenant } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger, waitUntilBlocked } from '@agentx/testing';
import type { Insertable, Updateable } from 'kysely';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { seedRows } from '../../../seed-rows.helper.test.ts';
import { RESERVATION } from '../domain/reservation.ts';
import { splitHeld } from './reservations.ts';
import type { LimitReservationsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<LimitReservationsTables>;

const AT = new Date('2026-10-08T08:00:00Z');
const LATER = new Date('2026-10-09T08:00:00Z');
const MONTH = '2026-10';

type Tx = DatabaseTransaction<LimitReservationsTables>;
type ReservationRow = Insertable<LimitReservationsTables['limit_reservations.reservations']>;

interface Org {
  readonly id: string;
  readonly agent: string;
  readonly key: string;
  readonly mandate: string;
  readonly version: string;
  readonly source: string;
  readonly supplier: string;
  readonly supplierVersion: string;
}

/**
 * An organisation with an agent and its key, a supplier and the agent's
 * mandate on a funding source, made past the app, as the steps that add them
 * are tested elsewhere: only the rows a reservation and its request point at.
 */
const organisation = async (payeeKey: string | null = null): Promise<Org> => {
  const seed = seedRows(database.as('admin'), AT);
  const id = randomUUID();
  await seed.org(id);
  const agent = await seed.agent(id);
  const key = await seed.agentKey(id, agent);
  const source = await seed.source(id);
  const supplier = await seed.supplier(id, payeeKey);
  const mandate = await seed.mandate(id, { agent, source, supplier: supplier.id });
  return {
    id,
    agent,
    key,
    mandate: mandate.id,
    version: mandate.version,
    source,
    supplier: supplier.id,
    supplierVersion: supplier.version,
  };
};

const inOrg = <Result>(org: Org, work: (tx: Tx) => Promise<Result>) => withTenant(app, org.id, work);

/** The agent's zone, then its period for the month, each added if it isn't there, as D4 adds them. */
const period = (org: Org, month = MONTH, zone = 'Asia/Dubai') =>
  inOrg(org, async (tx) => {
    await tx
      .insertInto('limit_reservations.agent_zones')
      .values({ org_id: org.id, agent_id: org.agent, time_zone: zone, created_at: AT })
      .onConflict((conflict) => conflict.doNothing())
      .execute();
    await tx
      .insertInto('limit_reservations.agent_periods')
      .values({ org_id: org.id, agent_id: org.agent, month, created_at: AT })
      .onConflict((conflict) => conflict.doNothing())
      .execute();
  });

/** The agent's spend request for AED 250, VALIDATING with its decision as D4 adds it, made past the app: its ID. */
const requestOf = async (org: Org, decision = 'ALLOW'): Promise<string> => {
  const id = randomUUID();
  await database.as('admin').query(
    `insert into spend_requests.requests (org_id, id, agent_id, agent_key_id, mandate_id, mandate_version_id,
       supplier_id, supplier_version_id, funding_source_id, amount_minor, currency, purpose, order_reference,
       idempotency_key, input_hash, input_hash_key_version, decision, reason_codes, status, created_at)
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 25000, 'AED', 'Printer paper', 'PO-1', $10, $11, 1, $12, $13,
       'VALIDATING', $14)`,
    [
      org.id,
      id,
      org.agent,
      org.key,
      org.mandate,
      org.version,
      org.supplier,
      org.supplierVersion,
      org.source,
      randomUUID(),
      'd'.repeat(64),
      decision,
      decision === 'ALLOW' ? null : 'APPROVAL_THRESHOLD',
      AT,
    ],
  );
  return id;
};

/** Moves a request through the statuses given, each in its own statement, past the app. */
const moveRequest = async (org: Org, id: string, ...statuses: string[]) => {
  for (const status of statuses) {
    await database
      .as('admin')
      .query('update spend_requests.requests set status = $3 where org_id = $1 and id = $2', [org.id, id, status]);
  }
};

/** A HELD reservation for the request, in the agent's month, with any column given otherwise. */
const reservationRow = (org: Org, request: string, overrides: Partial<ReservationRow> = {}): ReservationRow => ({
  org_id: org.id,
  id: randomUUID(),
  request_id: request,
  agent_id: org.agent,
  mandate_id: org.mandate,
  month: MONTH,
  supplier_id: org.supplier,
  payee_key: null,
  amount_minor: 25_000n,
  currency: 'AED',
  state: 'HELD',
  reserved_at: AT,
  settled_at: null,
  ...overrides,
});

const add = async (org: Org, row: ReservationRow): Promise<string> => {
  await inOrg(org, (tx) => tx.insertInto('limit_reservations.reservations').values(row).execute());
  return row.id;
};

/** A reservation for a new ALLOW request, with any column given otherwise. */
const reserve = async (org: Org, overrides: Partial<ReservationRow> = {}): Promise<string> =>
  add(org, reservationRow(org, await requestOf(org), overrides));

const change = (org: Org, id: string, values: Updateable<LimitReservationsTables['limit_reservations.reservations']>) =>
  inOrg(org, (tx) => tx.updateTable('limit_reservations.reservations').set(values).where('id', '=', id).execute());

/** The values that move a reservation to `state`: settled as it reaches an end. */
const moveTo = (state: string) => ({ state, settled_at: state === 'FINALISED' || state === 'RELEASED' ? LATER : null });

/** A reservation whose request is handed off, so it may follow its payment, moved through the states given. */
const moved = async (org: Org, ...states: string[]): Promise<string> => {
  const request = await requestOf(org);
  const id = await add(org, reservationRow(org, request));
  await moveRequest(org, request, 'APPROVED', 'INSTRUCTION_READY', 'HANDED_OFF');
  for (const state of states) await change(org, id, moveTo(state));
  return id;
};

const stateOf = (org: Org, id: string) =>
  inOrg(org, (tx) =>
    tx
      .selectFrom('limit_reservations.reservations')
      .select(['state', 'settled_at'])
      .where('id', '=', id)
      .executeTakeFirstOrThrow(),
  );

const refusedBy = (constraint: string): unknown => expect.objectContaining({ constraint });
const DENIED: unknown = expect.objectContaining({ code: '42501' });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<LimitReservationsTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe("an agent's zone", () => {
  it('is kept as first added: a later mandate in another zone never moves the agent’s month edges', async () => {
    const org = await organisation();
    await period(org, MONTH, 'Asia/Dubai');
    await period(org, '2026-11', 'Pacific/Kiritimati');
    const zones = await inOrg(org, (tx) =>
      tx.selectFrom('limit_reservations.agent_zones').select('time_zone').execute(),
    );
    expect(zones).toEqual([{ time_zone: 'Asia/Dubai' }]);
    await expect(
      inOrg(org, (tx) =>
        tx.updateTable('limit_reservations.agent_zones').set({ time_zone: 'Pacific/Kiritimati' }).execute(),
      ),
    ).rejects.toEqual(DENIED);
    await expect(inOrg(org, (tx) => tx.deleteFrom('limit_reservations.agent_zones').execute())).rejects.toEqual(DENIED);
  });

  it('comes before any period of the agent', async () => {
    const org = await organisation();
    await expect(
      inOrg(org, (tx) =>
        tx
          .insertInto('limit_reservations.agent_periods')
          .values({ org_id: org.id, agent_id: org.agent, month: MONTH, created_at: AT })
          .execute(),
      ),
    ).rejects.toEqual(refusedBy('of_an_agents_zone'));
  });
});

describe("an agent's period", () => {
  it('is one row an agent a month, added once however many requests add it', async () => {
    const org = await organisation();
    await period(org);
    await period(org);
    await period(org, '2026-11');
    const rows = await inOrg(org, (tx) =>
      tx.selectFrom('limit_reservations.agent_periods').select('month').orderBy('month').execute(),
    );
    expect(rows).toEqual([{ month: '2026-10' }, { month: '2026-11' }]);
  });

  it.each(['2026-13', '2026-1', '26-10', '2026-10-01', ''])('refuses the month %j', async (month) => {
    const org = await organisation();
    await expect(period(org, month)).rejects.toThrow(/check constraint/);
  });

  it('is locked by the app FOR NO KEY UPDATE, and never changed (`period_lock_only`)', async () => {
    const org = await organisation();
    await period(org);
    const locked = await inOrg(org, (tx) =>
      tx
        .selectFrom('limit_reservations.agent_periods')
        .select('month')
        .where('agent_id', '=', org.agent)
        .forNoKeyUpdate()
        .execute(),
    );
    expect(locked).toEqual([{ month: MONTH }]);
    await expect(
      inOrg(org, (tx) => tx.updateTable('limit_reservations.agent_periods').set({ created_at: AT }).execute()),
    ).rejects.toEqual(refusedBy('period_lock_only'));
    await expect(
      inOrg(org, (tx) => tx.updateTable('limit_reservations.agent_periods').set({ month: '2026-11' }).execute()),
    ).rejects.toEqual(DENIED);
    await expect(inOrg(org, (tx) => tx.deleteFrom('limit_reservations.agent_periods').execute())).rejects.toEqual(
      DENIED,
    );
  });

  it('makes a second request for the same month wait until the first commits', async () => {
    const org = await organisation();
    await period(org);
    const first = await database.connect('app');
    const second = await database.connect('app');
    const lockPeriod = async (session: typeof first) => {
      await session.query('begin');
      await session.query("select pg_catalog.set_config('app.org_id', $1, true)", [org.id]);
      return session.query('select month from limit_reservations.agent_periods where agent_id = $1 for no key update', [
        org.agent,
      ]);
    };
    try {
      await lockPeriod(first);
      const waiting = lockPeriod(second);
      expect(await waitUntilBlocked(database.as('admin'), second.pid)).toEqual([first.pid]);
      await first.query('commit');
      expect(await waiting).toEqual([{ month: MONTH }]);
      await second.query('commit');
    } finally {
      await first.end();
      await second.end();
    }
  });
});

describe('a reservation', () => {
  it('is born HELD, unsettled', async () => {
    const org = await organisation();
    await period(org);
    const id = await reserve(org);
    expect(await stateOf(org, id)).toEqual({ state: 'HELD', settled_at: null });
    for (const state of ['FINALISED', 'RELEASED', 'BLOCKED_UNKNOWN']) {
      await expect(reserve(org, moveTo(state))).rejects.toEqual(refusedBy('reservation_moves'));
    }
  });

  it('moves along its machine, and no other way', async () => {
    const org = await organisation();
    await period(org);
    for (const from of RESERVATION.states) {
      for (const to of RESERVATION.states.filter((state) => state !== from)) {
        // Every state is one move from HELD.
        const id = await moved(org, ...(from === 'HELD' ? [] : [from]));
        const allowed = RESERVATION.moves.some((move) => move.from === from && move.to === to);
        const moving = change(org, id, moveTo(to));
        if (allowed) {
          await moving;
          expect((await stateOf(org, id)).state).toBe(to);
        } else {
          await expect(moving).rejects.toEqual(refusedBy('reservation_moves'));
        }
      }
    }
  });

  it('is settled exactly as it reaches FINALISED or RELEASED, and only then', async () => {
    const org = await organisation();
    await period(org);
    const held = await moved(org);
    await expect(change(org, held, { state: 'FINALISED' })).rejects.toEqual(refusedBy('settled_at_its_end'));
    await expect(change(org, held, { state: 'BLOCKED_UNKNOWN', settled_at: LATER })).rejects.toEqual(
      refusedBy('settled_at_its_end'),
    );
    await expect(change(org, held, { settled_at: LATER })).rejects.toEqual(refusedBy('reservation_moves'));
    await expect(
      change(org, held, { state: 'RELEASED', settled_at: new Date('2026-10-01T00:00:00Z') }),
    ).rejects.toEqual(refusedBy('settled_after_reserved'));
    const released = await moved(org, 'RELEASED');
    await expect(change(org, released, { settled_at: new Date('2026-10-10T08:00:00Z') })).rejects.toEqual(
      refusedBy('reservation_moves'),
    );
    expect(await stateOf(org, released)).toEqual({ state: 'RELEASED', settled_at: LATER });
  });

  it('is changed in nothing but its state and when it settled, and never deleted', async () => {
    const org = await organisation();
    await period(org);
    const id = await moved(org);
    for (const values of [
      { amount_minor: 1n },
      { agent_id: randomUUID() },
      { month: '2026-11' },
      { mandate_id: randomUUID() },
      { request_id: randomUUID() },
      { reserved_at: LATER },
      { payee_key: 'PK-1' },
    ]) {
      await expect(change(org, id, values)).rejects.toEqual(DENIED);
    }
    await expect(
      inOrg(org, (tx) => tx.deleteFrom('limit_reservations.reservations').where('id', '=', id).execute()),
    ).rejects.toEqual(DENIED);
  });

  it('is one a request', async () => {
    const org = await organisation();
    await period(org);
    const request = await requestOf(org);
    await add(org, reservationRow(org, request));
    await expect(add(org, reservationRow(org, request))).rejects.toEqual(refusedBy('one_reservation_a_request'));
  });

  it("counts in the agent's month it was made in, by the agent's zone, in a period that exists", async () => {
    const org = await organisation();
    await period(org);
    // 8 Oct is October in Dubai, not November.
    await expect(reserve(org, { month: '2026-11' })).rejects.toEqual(refusedBy('reservation_moves'));
    // 31 Oct 21:00 UTC is 1 Nov in Dubai: its month, but no period row yet, so no lock taken.
    const late = new Date('2026-10-31T21:00:00Z');
    await expect(reserve(org, { reserved_at: late, month: '2026-10' })).rejects.toEqual(refusedBy('reservation_moves'));
    await expect(reserve(org, { reserved_at: late, month: '2026-11' })).rejects.toEqual(
      refusedBy('in_its_agents_period'),
    );
    await period(org, '2026-11');
    await reserve(org, { reserved_at: late, month: '2026-11' });
  });

  it("is named by the agent's own zone, whatever zone it was first given", async () => {
    const org = await organisation();
    // Kiritimati is UTC+14: 31 Oct 12:00 UTC is already 1 Nov there.
    await period(org, '2026-11', 'Pacific/Kiritimati');
    const there = new Date('2026-10-31T12:00:00Z');
    await expect(reserve(org, { reserved_at: there, month: '2026-10' })).rejects.toEqual(
      refusedBy('reservation_moves'),
    );
    await reserve(org, { reserved_at: there, month: '2026-11' });
  });
});

describe("a reservation's request (`held_for_its_request`, D2's review)", () => {
  it('is one just decided to hold capacity: VALIDATING, with ALLOW or REQUIRE_APPROVAL', async () => {
    const org = await organisation();
    await period(org);
    await add(org, reservationRow(org, await requestOf(org, 'REQUIRE_APPROVAL')));
    for (const decision of ['DENY', 'REQUIRE_NEW_MANDATE']) {
      await expect(add(org, reservationRow(org, await requestOf(org, decision)))).rejects.toEqual(
        refusedBy('held_for_its_request'),
      );
    }
    // Decided and moved on already, or no request at all.
    const approved = await requestOf(org);
    await moveRequest(org, approved, 'APPROVED');
    await expect(add(org, reservationRow(org, approved))).rejects.toEqual(refusedBy('held_for_its_request'));
    await expect(add(org, reservationRow(org, randomUUID()))).rejects.toEqual(refusedBy('held_for_its_request'));
  });

  it("is held to exactly what it asked: its agent, mandate, supplier and amount, and the supplier's payee key", async () => {
    const org = await organisation('PK-1');
    await period(org);
    for (const values of [
      { agent_id: randomUUID() },
      { mandate_id: randomUUID() },
      { supplier_id: randomUUID() },
      { amount_minor: 24_999n },
      { payee_key: null },
      { payee_key: 'PK-2' },
    ]) {
      await expect(reserve(org, { payee_key: 'PK-1', ...values })).rejects.toEqual(refusedBy('held_for_its_request'));
    }
    await reserve(org, { payee_key: 'PK-1' });
    // Another supplier with no payee key, as the request's has none: the supplier alone tells them apart.
    const plain = await organisation();
    await period(plain);
    await expect(reserve(plain, { supplier_id: org.supplier })).rejects.toEqual(refusedBy('held_for_its_request'));
  });

  it.each([
    ['VALIDATING', []],
    ['APPROVAL_REQUIRED', ['APPROVAL_REQUIRED']],
    ['APPROVED', ['APPROVAL_REQUIRED', 'APPROVED']],
    ['INSTRUCTION_READY', ['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY']],
  ])('keeps its capacity while the request is %s: released only once it has ended', async (_status, path) => {
    const org = await organisation();
    await period(org);
    const request = await requestOf(org, 'REQUIRE_APPROVAL');
    const id = await add(org, reservationRow(org, request));
    await moveRequest(org, request, ...path);
    for (const state of ['RELEASED', 'BLOCKED_UNKNOWN', 'FINALISED']) {
      await expect(change(org, id, moveTo(state))).rejects.toEqual(refusedBy('held_for_its_request'));
    }
    // Cancelled (from VALIDATING, by way of its decided status).
    await moveRequest(org, request, ...(path.length === 0 ? ['APPROVAL_REQUIRED'] : []), 'CANCELLED');
    await change(org, id, moveTo('RELEASED'));
    expect((await stateOf(org, id)).state).toBe('RELEASED');
  });

  it('follows a payment only once the request is handed off: never blocked or finalised for one ended without', async () => {
    const org = await organisation();
    await period(org);
    const request = await requestOf(org, 'REQUIRE_APPROVAL');
    const id = await add(org, reservationRow(org, request));
    await moveRequest(org, request, 'APPROVAL_REQUIRED', 'EXPIRED');
    for (const state of ['BLOCKED_UNKNOWN', 'FINALISED']) {
      await expect(change(org, id, moveTo(state))).rejects.toEqual(refusedBy('held_for_its_request'));
    }
  });
});

/** The split total for the supplier (and payee key) given, since `since`, as a decision reads it (D5). */
const splitOf = (org: Org, supplierId: string, payeeKey: string | null, since = AT) =>
  inOrg(org, (tx) => splitHeld(tx, { supplierId, payeeKey, since }));

describe('the split total (`splitHeld`, D5)', () => {
  it('adds up the supplier’s reservations still holding capacity, reserved since the window began', async () => {
    const org = await organisation();
    await period(org);
    await reserve(org);
    await moved(org, 'FINALISED');
    await moved(org, 'RELEASED');
    const other = await organisation();
    await period(other);
    await reserve(other);

    // HELD and FINALISED count, RELEASED never; another organisation's never.
    expect(await splitOf(org, org.supplier, null)).toBe(50_000n);
    // The window's first instant counts; one reserved before it doesn't.
    expect(await splitOf(org, org.supplier, null, new Date(AT.getTime() + 1))).toBe(0n);
  });

  it('counts the payee key’s under another supplier record, and the supplier’s own under any key or none', async () => {
    const org = await organisation('payee-1');
    await period(org);
    await reserve(org, { payee_key: 'payee-1' });
    // The key moved to a new supplier record past the app, as a re-created supplier would take it.
    await database
      .as('admin')
      .query('update suppliers.suppliers set payee_key = null where org_id = $1 and id = $2', [org.id, org.supplier]);
    await reserve(org);
    const recreated = await seedRows(database.as('admin'), AT).supplier(org.id, 'payee-1');

    expect(await splitOf(org, recreated.id, 'payee-1')).toBe(25_000n);
    expect(await splitOf(org, org.supplier, null)).toBe(50_000n);
    // Given a new key, the supplier still counts its own, whatever key each was made under.
    expect(await splitOf(org, org.supplier, 'payee-2')).toBe(50_000n);
    // Another organisation's supplier may hold the same key (keys are per organisation): its orders never count.
    const other = await organisation('payee-1');
    await period(other);
    await reserve(other, { payee_key: 'payee-1' });
    expect(await splitOf(org, recreated.id, 'payee-1')).toBe(25_000n);
  });
});

describe('the tenant wall', () => {
  it("keeps every organisation's zones, periods and reservations to itself", async () => {
    const org = await organisation();
    const other = await organisation();
    await period(org);
    await reserve(org);
    const seen = await inOrg(other, async (tx) => [
      ...(await tx.selectFrom('limit_reservations.agent_zones').select('org_id').execute()),
      ...(await tx.selectFrom('limit_reservations.agent_periods').select('org_id').execute()),
      ...(await tx.selectFrom('limit_reservations.reservations').select('org_id').execute()),
    ]);
    expect(seen).toEqual([]);
  });

  it("refuses writing another organisation's", async () => {
    const org = await organisation();
    const other = await organisation();
    await period(org);
    const request = await requestOf(org);
    for (const write of [
      (tx: Tx) =>
        tx
          .insertInto('limit_reservations.agent_zones')
          .values({ org_id: org.id, agent_id: randomUUID(), time_zone: 'Asia/Dubai', created_at: AT })
          .execute(),
      (tx: Tx) =>
        tx
          .insertInto('limit_reservations.agent_periods')
          .values({ org_id: org.id, agent_id: org.agent, month: '2026-12', created_at: AT })
          .execute(),
    ]) {
      await expect(inOrg(other, write)).rejects.toThrow(/row-level security/);
    }
    // A reservation's guard runs first, and finds no such request behind the wall.
    await expect(
      inOrg(other, (tx) =>
        tx.insertInto('limit_reservations.reservations').values(reservationRow(org, request)).execute(),
      ),
    ).rejects.toEqual(refusedBy('held_for_its_request'));
  });
});

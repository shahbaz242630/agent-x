// D2: an agent's monthly periods and its reservations (0040), on the real
// migrated schema, as the app role. Reserving through them comes with D4 and
// its forced lock tests with it; this holds the tables' own rules: one period
// an agent a month, locked and never changed, a lock a second request waits
// on; a reservation born HELD, moved only along its machine, settled once at
// its end, changed in nothing else; under its agent's own mandate and in a
// period that exists; one a request; and no other organisation's rows, no
// deletes.
import { createDatabase, type Database, type DatabaseTransaction, withTenant } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger, waitUntilBlocked } from '@agentx/testing';
import type { Insertable, Updateable } from 'kysely';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { RESERVATION } from '../domain/reservation.ts';
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
  readonly mandate: string;
  readonly supplier: string;
}

/**
 * An organisation with an agent, a supplier and the agent's mandate on a
 * funding source, made past the app in one statement, as the steps that add
 * them are tested elsewhere: only the rows a reservation's keys point at.
 */
const organisation = async (): Promise<Org> => {
  const org: Org = { id: randomUUID(), agent: randomUUID(), mandate: randomUUID(), supplier: randomUUID() };
  const ids = { source: randomUUID(), link: randomUUID(), version: randomUUID(), supplierVersion: randomUUID() };
  await database.as('admin').query(
    `with o as (insert into directory.orgs (org_id) values ($1) returning org_id),
     a as (insert into agents.agents (org_id, id, name, owner, status, scopes, created_at)
       select org_id, $2, 'Purchasing agent', $2, 'ACTIVE', 'requests:write', $8 from o returning org_id),
     l as (insert into funding_sources.links (org_id, id, started_by, partner, session_ref, expires_at, created_at)
       select org_id, $5, $2, 'fake', 'session-1', '2027-10-08T08:00:00Z', $8 from a returning org_id),
     s as (insert into funding_sources.sources (org_id, id, link_id, partner, external_ref, status, availability,
         consent_status, account_consent_id, consent_expires_at, currency, limit_period, max_payment_minor,
         max_period_minor, max_period_payments, holder_name, account_type, hint, partner_changed_at, created_at)
       select org_id, $4, $5, 'fake', $11, 'ACTIVE', 'ACTIVE', 'Authorized', 'consent-1',
         '2027-10-06T08:00:00Z', 'AED', 'month', 5000000, 20000000, 100, 'Acme Trading LLC', 'sme', 'AE…1234', $8, $8
       from l returning org_id),
     su as (insert into suppliers.suppliers (org_id, id, status, current_version_id, payee_key, created_at)
       select org_id, $7, 'UNVERIFIED', $9, null, $8 from s returning org_id),
     sv as (insert into suppliers.supplier_versions (org_id, id, supplier_id, version, display_name, contacts,
         phone_ciphertext, contacts_key_version, phone_since, source_kind, source_ref, entered_by, entered_at)
       select org_id, $9, $7, 1, 'Gulf Office Supplies LLC', 'phone', pg_catalog.decode(pg_catalog.repeat('00', 40), 'hex'),
         1, $8, 'registry', 'trade-licence-1', $7, $8 from su returning org_id),
     m as (insert into mandates.mandates (org_id, id, agent_id, time_zone, split_window_hours, status,
         pending_version_id, created_at)
       select org_id, $3, $2, 'Asia/Dubai', 24, 'PENDING_ACCEPTANCE', $6, $8 from sv returning org_id)
     insert into mandates.versions (org_id, id, mandate_id, version, purpose, currency, per_order_limit_minor,
       monthly_limit_minor, approval_threshold_minor, supplier_ids, funding_source_id, split_check, consent_limits,
       terms_hash, drafted_by, drafted_at)
     select org_id, $6, $3, 1, 'Office supplies', 'AED', 500000, 2000000, 100000, $7, $4, 'on', 'strict', $10, $2, $8
     from m`,
    [
      org.id,
      org.agent,
      org.mandate,
      ids.source,
      ids.link,
      ids.version,
      org.supplier,
      AT,
      ids.supplierVersion,
      'a'.repeat(64),
      `acct-${ids.source}`,
    ],
  );
  return org;
};

const inOrg = <Result>(org: Org, work: (tx: Tx) => Promise<Result>) => withTenant(app, org.id, work);

/** The agent's period for the month, added if it isn't there, as D4 adds it. */
const period = (org: Org, month = MONTH, agent = org.agent) =>
  inOrg(org, (tx) =>
    tx
      .insertInto('limit_reservations.agent_periods')
      .values({ org_id: org.id, agent_id: agent, month, created_at: AT })
      .onConflict((conflict) => conflict.doNothing())
      .execute(),
  );

/** A HELD reservation in the agent's month, with any column given otherwise. */
const reservationRow = (org: Org, overrides: Partial<ReservationRow> = {}): ReservationRow => ({
  org_id: org.id,
  id: randomUUID(),
  request_id: randomUUID(),
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

const reserve = async (org: Org, row: ReservationRow): Promise<string> => {
  await inOrg(org, (tx) => tx.insertInto('limit_reservations.reservations').values(row).execute());
  return row.id;
};

const change = (org: Org, id: string, values: Updateable<LimitReservationsTables['limit_reservations.reservations']>) =>
  inOrg(org, (tx) => tx.updateTable('limit_reservations.reservations').set(values).where('id', '=', id).execute());

/** The values that move a reservation to `state`: settled as it reaches an end. */
const moveTo = (state: string) => ({ state, settled_at: state === 'FINALISED' || state === 'RELEASED' ? LATER : null });

/** A reservation moved through the states given, each in its own statement. */
const moved = async (org: Org, ...states: string[]): Promise<string> => {
  const id = await reserve(org, reservationRow(org));
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

/** The path from HELD to each state, along the machine. */
const PATH_TO: Readonly<Record<string, readonly string[]>> = {
  HELD: [],
  BLOCKED_UNKNOWN: ['BLOCKED_UNKNOWN'],
  FINALISED: ['FINALISED'],
  RELEASED: ['RELEASED'],
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<LimitReservationsTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
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
    const id = await reserve(org, reservationRow(org));
    expect(await stateOf(org, id)).toEqual({ state: 'HELD', settled_at: null });
    for (const state of ['FINALISED', 'RELEASED', 'BLOCKED_UNKNOWN']) {
      await expect(reserve(org, reservationRow(org, moveTo(state)))).rejects.toEqual(refusedBy('reservation_moves'));
    }
  });

  it('moves along its machine, and no other way', async () => {
    const org = await organisation();
    await period(org);
    for (const from of RESERVATION.states) {
      for (const to of RESERVATION.states.filter((state) => state !== from)) {
        const id = await moved(org, ...(PATH_TO[from] ?? []));
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
    ]) {
      await expect(change(org, id, values)).rejects.toEqual(DENIED);
    }
    await expect(
      inOrg(org, (tx) => tx.deleteFrom('limit_reservations.reservations').where('id', '=', id).execute()),
    ).rejects.toEqual(DENIED);
    await expect(inOrg(org, (tx) => tx.deleteFrom('limit_reservations.agent_periods').execute())).rejects.toEqual(
      DENIED,
    );
  });

  it('is one a request', async () => {
    const org = await organisation();
    await period(org);
    const request = randomUUID();
    await reserve(org, reservationRow(org, { request_id: request }));
    await expect(reserve(org, reservationRow(org, { request_id: request }))).rejects.toEqual(
      refusedBy('one_reservation_a_request'),
    );
  });

  it("is under its agent's own mandate, in a period of that agent that exists", async () => {
    const org = await organisation();
    const other = await organisation();
    await period(org);
    // Another agent's mandate, or one of another organisation.
    await expect(reserve(org, reservationRow(org, { agent_id: randomUUID() }))).rejects.toEqual(
      refusedBy('under_its_agents_mandate'),
    );
    await expect(reserve(org, reservationRow(org, { mandate_id: other.mandate }))).rejects.toEqual(
      refusedBy('under_its_agents_mandate'),
    );
    // A month with no period row: no reservation without its lock target.
    await expect(reserve(org, reservationRow(org, { month: '2026-11' }))).rejects.toEqual(
      refusedBy('in_its_agents_period'),
    );
  });

  it('holds a whole amount above zero, in a currency the deployment allows', async () => {
    const org = await organisation();
    await period(org);
    await expect(reserve(org, reservationRow(org, { amount_minor: 0n }))).rejects.toThrow(/check constraint/);
    await expect(reserve(org, reservationRow(org, { currency: 'USD' }))).rejects.toThrow(/foreign key/);
    await expect(reserve(org, reservationRow(org, { payee_key: 'a payee key' }))).rejects.toThrow(/check constraint/);
  });
});

describe('the tenant wall', () => {
  it("keeps every organisation's periods and reservations to itself", async () => {
    const org = await organisation();
    const other = await organisation();
    await period(org);
    await reserve(org, reservationRow(org));
    const seen = await inOrg(other, async (tx) => [
      ...(await tx.selectFrom('limit_reservations.agent_periods').select('org_id').execute()),
      ...(await tx.selectFrom('limit_reservations.reservations').select('org_id').execute()),
    ]);
    expect(seen).toEqual([]);
    // Nor written as another's.
    await expect(
      inOrg(other, (tx) =>
        tx
          .insertInto('limit_reservations.agent_periods')
          .values({ org_id: org.id, agent_id: org.agent, month: '2026-12', created_at: AT })
          .execute(),
      ),
    ).rejects.toThrow(/row-level security/);
  });
});

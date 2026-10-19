// L5c-1: the background downloads' tables (0053) on the real migrated schema,
// as the app role: a download and its months inside the organisation's own
// wall, a month moved only along `file_moves` (born waiting, a try counted by
// each claim alone, never changed once ready or failed), and nothing deleted
// or changed past the columns a month moves.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Record<string, never>>;

const ORG = '0199a0f0-0000-7000-8000-00000000ae01';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000ae02';
const ADMIN = '0199a0f0-0000-7000-8000-00000000ae03';
const SHA = 'a'.repeat(64);

let number = 0;
/** A new export ID, so no two tests share a download. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0xae10 + number).toString(16).padStart(12, '0')}`;
};

const asApp = <T>(orgId: string, work: (tx: Kysely<Record<string, never>>) => Promise<T>): Promise<T> =>
  withTenant(app, orgId, (tx) => work(tx));

/** A download of two months, asked for in the organisation's wall: its ID. */
async function asked(orgId = ORG): Promise<string> {
  const id = newId();
  await asApp(orgId, async (tx) => {
    await sql`insert into activity_exports.exports (org_id, id, requested_by, range_from, range_to, format)
              values (${orgId}, ${id}, ${ADMIN}, '2026-08-15T00:00Z', '2026-09-15T00:00Z', 'ndjson')`.execute(tx);
    await sql`insert into activity_exports.files (org_id, export_id, month, state, attempts)
              values (${orgId}, ${id}, '2026-08-01', 'waiting', 0), (${orgId}, ${id}, '2026-09-01', 'waiting', 0)`.execute(
      tx,
    );
  });
  return id;
}

/** Runs one change to the download's August file as the app, in its wall. */
const change = (id: string, set: ReturnType<typeof sql>) =>
  asApp(ORG, (tx) =>
    sql`update activity_exports.files set ${set} where org_id = ${ORG} and export_id = ${id} and month = '2026-08-01'`.execute(
      tx,
    ),
  );

const claim = (id: string, lease = '15 minutes') =>
  change(
    id,
    sql`state = 'building', attempts = attempts + 1, building_until = pg_catalog.clock_timestamp() + ${lease}::interval`,
  );

const made = (id: string) =>
  change(
    id,
    sql`state = 'ready', building_until = null, requests = 3, bytes = 120, sha256 = ${SHA}, ready_at = pg_catalog.clock_timestamp()`,
  );

/** The August file as it stands, read past the walls. */
const august = async (id: string) =>
  (
    await database
      .as('admin')
      .query("select state, attempts from activity_exports.files where export_id = $1 and month = '2026-08-01'", [id])
  )[0];

/** The trigger's refusal, named by its constraint. */
const MOVES = { constraint: 'file_moves' };

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Record<string, never>>(database.connection('app'), testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe("a download and its months, in the organisation's wall (0053)", () => {
  it('are added in its wall and seen by no other organisation', async () => {
    const id = await asked();
    const count = (orgId: string) =>
      asApp(orgId, async (tx) => {
        const { rows } = await sql<{ n: number }>`select
            (select count(*)::int from activity_exports.exports where id = ${id})
          + (select count(*)::int from activity_exports.files where export_id = ${id}) as n`.execute(tx);
        return rows[0]?.n;
      });

    expect(await count(ORG)).toBe(3);
    expect(await count(OTHER_ORG)).toBe(0);
    await expect(
      asApp(OTHER_ORG, (tx) =>
        sql`insert into activity_exports.exports (org_id, id, requested_by, range_from, range_to, format)
            values (${ORG}, ${newId()}, ${ADMIN}, '2026-08-15T00:00Z', '2026-09-15T00:00Z', 'csv')`.execute(tx),
      ),
    ).rejects.toThrow(/row-level security/);
    await expect(
      asApp(OTHER_ORG, (tx) =>
        sql`insert into activity_exports.files (org_id, export_id, month, state, attempts)
            values (${ORG}, ${id}, '2026-10-01', 'waiting', 0)`.execute(tx),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('refuses a range running backwards or past 366 days, an actor half named, a month not its first day', async () => {
    const add = (from: string, to: string, actor = sql`null, null`) =>
      asApp(ORG, (tx) =>
        sql`insert into activity_exports.exports (org_id, id, requested_by, range_from, range_to, actor_type, actor_id, format)
            values (${ORG}, ${newId()}, ${ADMIN}, ${from}::timestamptz, ${to}::timestamptz, ${actor}, 'csv')`.execute(
          tx,
        ),
      );

    await expect(add('2026-09-01T00:00Z', '2026-08-01T00:00Z')).rejects.toThrow(/range_runs_forward/);
    await expect(add('2025-01-01T00:00Z', '2026-01-03T00:00Z')).rejects.toThrow(/range_runs_forward/);
    await expect(add('2026-08-01T00:00Z', '2026-09-01T00:00Z', sql`'user', null`)).rejects.toThrow(/actor_whole/);
    const id = await asked();
    await expect(
      asApp(ORG, (tx) =>
        sql`insert into activity_exports.files (org_id, export_id, month, state, attempts)
            values (${ORG}, ${id}, '2026-10-02', 'waiting', 0)`.execute(tx),
      ),
    ).rejects.toThrow(/files_month_check/);
  });

  it('are never deleted, a download never changed, nor a month moved to another download or month', async () => {
    const id = await asked();

    await expect(
      asApp(ORG, (tx) => sql`delete from activity_exports.files where export_id = ${id}`.execute(tx)),
    ).rejects.toThrow(/permission denied/);
    await expect(
      asApp(ORG, (tx) => sql`delete from activity_exports.exports where id = ${id}`.execute(tx)),
    ).rejects.toThrow(/permission denied/);
    await expect(
      asApp(ORG, (tx) => sql`update activity_exports.exports set format = 'csv' where id = ${id}`.execute(tx)),
    ).rejects.toThrow(/permission denied/);
    await expect(change(id, sql`month = '2026-07-01'`)).rejects.toThrow(/permission denied/);
  });
});

describe('a month moved only along file_moves (0053)', () => {
  it('is born waiting and never tried', async () => {
    const id = await asked();
    const born = (state: string, attempts: number) =>
      asApp(ORG, (tx) =>
        sql`insert into activity_exports.files (org_id, export_id, month, state, attempts, building_until)
            values (${ORG}, ${id}, '2026-10-01', ${state}, ${attempts},
                    case when ${state} = 'building' then pg_catalog.clock_timestamp() end)`.execute(tx),
      );

    await expect(born('building', 1)).rejects.toMatchObject(MOVES);
    await expect(born('waiting', 1)).rejects.toMatchObject(MOVES);
  });

  it('is claimed with one try counted, its lease renewed, given back, claimed again, then made ready', async () => {
    const id = await asked();

    await claim(id);
    expect(await august(id)).toEqual({ state: 'building', attempts: 1 });
    await change(id, sql`building_until = pg_catalog.clock_timestamp() + interval '30 minutes'`);
    expect(await august(id)).toEqual({ state: 'building', attempts: 1 });
    await change(id, sql`state = 'waiting', building_until = null`);
    await claim(id);
    await made(id);

    expect(await august(id)).toEqual({ state: 'ready', attempts: 2 });
  });

  it('is claimed again over a builder whose lease ran out, one more try counted, but never over a live lease', async () => {
    const id = await asked();
    await claim(id, '1 millisecond');
    await asApp(ORG, (tx) => sql`select pg_catalog.pg_sleep(0.01)`.execute(tx));

    await claim(id);
    expect(await august(id)).toEqual({ state: 'building', attempts: 2 });
    await expect(claim(id)).rejects.toMatchObject(MOVES);
  });

  it('is lost to a builder whose lease ran out: no renewal, no file made, none given back; a failure still ends it', async () => {
    const lapsed = async () => {
      const id = await asked();
      await claim(id, '1 millisecond');
      await asApp(ORG, (tx) => sql`select pg_catalog.pg_sleep(0.01)`.execute(tx));
      return id;
    };
    const id = await lapsed();

    await expect(
      change(id, sql`building_until = pg_catalog.clock_timestamp() + interval '15 minutes'`),
    ).rejects.toMatchObject(MOVES);
    await expect(made(id)).rejects.toMatchObject(MOVES);
    await expect(change(id, sql`state = 'waiting', building_until = null`)).rejects.toMatchObject(MOVES);
    expect(await august(id)).toEqual({ state: 'building', attempts: 1 });

    const ended = await lapsed();
    await change(ended, sql`state = 'failed', building_until = null, failure = 'ACTIVITY_EXPORT_FAILED'`);
    expect(await august(ended)).toEqual({ state: 'failed', attempts: 1 });
  });

  it('is failed while still waiting, never tried, once its download is given up', async () => {
    const id = await asked();

    await change(id, sql`state = 'failed', failure = 'ACTIVITY_EXPORT_GIVEN_UP'`);
    expect(await august(id)).toEqual({ state: 'failed', attempts: 0 });
  });

  it('refuses a claim counting no try or two, and a try counted by anything but a claim', async () => {
    const id = await asked();

    await expect(
      change(id, sql`state = 'building', building_until = pg_catalog.clock_timestamp()`),
    ).rejects.toMatchObject(MOVES);
    await expect(
      change(id, sql`state = 'building', attempts = 2, building_until = pg_catalog.clock_timestamp()`),
    ).rejects.toMatchObject(MOVES);
    await expect(change(id, sql`attempts = 1`)).rejects.toMatchObject(MOVES);
    await claim(id);
    await expect(change(id, sql`state = 'waiting', building_until = null, attempts = 0`)).rejects.toMatchObject(MOVES);
  });

  it('is made ready or failed only from building, its facts with it, and never changes again', async () => {
    const ready = await asked();
    const failed = await asked();

    await expect(made(ready)).rejects.toMatchObject(MOVES);
    await claim(ready);
    await expect(change(ready, sql`state = 'ready', building_until = null`)).rejects.toThrow(/ready_has_its_facts/);
    await made(ready);
    await claim(failed);
    await expect(change(failed, sql`state = 'failed', building_until = null`)).rejects.toThrow(/failed_has_its_reason/);
    await change(failed, sql`state = 'failed', building_until = null, failure = 'ACTIVITY_EXPORT_STORE_FAILED'`);

    for (const id of [ready, failed]) {
      await expect(claim(id)).rejects.toMatchObject(MOVES);
      await expect(change(id, sql`state = 'waiting', building_until = null`)).rejects.toMatchObject(MOVES);
    }
    await expect(change(ready, sql`sha256 = ${'b'.repeat(64)}`)).rejects.toMatchObject(MOVES);
    expect(await august(ready)).toEqual({ state: 'ready', attempts: 1 });
  });
});

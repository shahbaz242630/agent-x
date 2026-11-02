// The lease's own statements against a real Postgres (0068, 4D2e D).
import { createDatabase, type Database } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger, waitUntilQueued } from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { jobsBeating, releaseJobLease, takeJobLease } from './job-lease.ts';
import type { PlatformControlsTables } from './tables.ts';

const server = inject('postgres');
const A = '0199a0f0-0000-7000-8000-00000000aaaa';
const B = '0199a0f0-0000-7000-8000-00000000bbbb';
const TERM = 60;

let database: TestDatabase;
let app: Database<PlatformControlsTables>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<PlatformControlsTables>(
    { ...database.connection('app'), tls: 'disable', maxConnections: 4 },
    testLogger(),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  await database
    .as('admin')
    .query(
      "update platform_controls.job_lease set holder = null, until = '-infinity', renewed_at = null, beating_at = null",
    );
});

const WAITING = `select pid from pg_catalog.pg_stat_activity
  where datname = pg_catalog.current_database() and pg_catalog.cardinality(pg_catalog.pg_blocking_pids(pid)) > 0`;

const row = async () =>
  (
    await database.as('admin').query<{ holder: string | null; left: number; beaten: boolean }>(
      `select holder, extract(epoch from until - pg_catalog.now())::float8 as left, beating_at is not null as beaten
         from platform_controls.job_lease`,
    )
  )[0];

describe(`the jobs' lease (Postgres ${server.version})`, () => {
  it('is born free, one row, and its holder keeps it against another', async () => {
    expect(await database.as('admin').query('select name, holder from platform_controls.job_lease')).toEqual([
      { name: 'jobs', holder: null },
    ]);
    expect(await takeJobLease(app, A, false, TERM)).toBe(true);
    expect(await takeJobLease(app, B, false, TERM)).toBe(false);
    expect((await row())?.holder).toBe(A);
    expect(await takeJobLease(app, A, false, TERM)).toBe(true);
    expect((await row())?.left).toBeGreaterThan(TERM - 10);
  });

  it('passes to another only once its term has ended, on the database clock; the old holder then has nothing', async () => {
    await takeJobLease(app, A, false, TERM);
    await database
      .as('admin')
      .query("update platform_controls.job_lease set until = pg_catalog.now() + interval '5 seconds'");
    expect(await takeJobLease(app, B, false, TERM)).toBe(false);
    await database
      .as('admin')
      .query("update platform_controls.job_lease set until = pg_catalog.now() - interval '1 millisecond'");
    expect(await takeJobLease(app, B, false, TERM)).toBe(true);
    expect(await takeJobLease(app, A, false, TERM)).toBe(false);
  });

  it('a release frees it at once, and a holder that lost it can release nothing of another', async () => {
    await takeJobLease(app, A, false, TERM);
    await releaseJobLease(app, B);
    expect((await row())?.holder).toBe(A);
    await releaseJobLease(app, A);
    expect((await row())?.holder).toBeNull();
    expect(await takeJobLease(app, B, false, TERM)).toBe(true);
  });

  it('forced: a taker waiting behind another taking the free lease gets nothing when that commits', async () => {
    const first = await database.connect('app');
    await first.query('begin');
    try {
      await first.query(
        `update platform_controls.job_lease set holder = $1, until = pg_catalog.now() + interval '60 seconds'
         where name = 'jobs' and (holder = $1 or until < pg_catalog.now())`,
        [A],
      );
      const second = takeJobLease(app, B, false, TERM);
      await waitUntilQueued(database.as('admin'), 1);
      await first.query('commit');
      expect(await second).toBe(false);
      expect((await row())?.holder).toBe(A);
    } finally {
      await first.end();
    }
  });

  it('forced: a taker during a release not yet committed waits for nothing and gets nothing; its next try gets it', async () => {
    await takeJobLease(app, A, false, TERM);
    const leaving = await database.connect('app');
    await leaving.query('begin');
    try {
      await leaving.query(
        "update platform_controls.job_lease set holder = null, until = '-infinity' where name = 'jobs' and holder = $1",
        [A],
      );
      // Its snapshot still shows the lease held, so it never queues behind the release: a renewal never waits on one.
      expect(await takeJobLease(app, B, false, TERM)).toBe(false);
      await leaving.query('commit');
      expect(await takeJobLease(app, B, false, TERM)).toBe(true);
      expect((await row())?.holder).toBe(B);
    } finally {
      await leaving.end();
    }
  });

  it.each([
    ['its lock wait', { statementMs: 5000, lockMs: 100 }, /lock timeout/],
    ['the statement', { statementMs: 100, lockMs: 5000 }, /statement timeout/],
  ])(
    'forced: a session sitting on the row: %s ends the take, and frees its connection',
    async (_what, limits, error) => {
      const sitting = await database.connect('admin');
      await sitting.query('begin');
      await sitting.query('select name from platform_controls.job_lease for update');
      try {
        await expect(takeJobLease(app, A, false, TERM, limits)).rejects.toThrow(error);
        await expect(releaseJobLease(app, A, limits)).resolves.toBeUndefined();
        expect(await database.as('admin').query(WAITING)).toEqual([]);
      } finally {
        await sitting.query('rollback');
        await sitting.end();
      }
    },
  );

  it('forced: a release behind a session sitting on the row held by this holder ends too', async () => {
    await takeJobLease(app, A, false, TERM);
    const sitting = await database.connect('admin');
    await sitting.query('begin');
    await sitting.query('select name from platform_controls.job_lease for update');
    try {
      await expect(releaseJobLease(app, A, { statementMs: 5000, lockMs: 100 })).rejects.toThrow(/lock timeout/);
      expect(await database.as('admin').query(WAITING)).toEqual([]);
    } finally {
      await sitting.query('rollback');
      await sitting.end();
    }
  });

  it('forced: left to its own limits, a take behind a session sitting on the row gives up inside the process deadline', async () => {
    const sitting = await database.connect('admin');
    await sitting.query('begin');
    await sitting.query('select name from platform_controls.job_lease for update');
    const started = performance.now();
    try {
      await expect(takeJobLease(app, A, false, TERM)).rejects.toThrow(/lock timeout/);
      expect(performance.now() - started).toBeGreaterThanOrEqual(4_500);
      expect(performance.now() - started).toBeLessThan(10_000);
    } finally {
      await sitting.query('rollback');
      await sitting.end();
    }
  });

  it('its limits end with its transaction: the connection goes back as it came', async () => {
    const one = createDatabase<PlatformControlsTables>(
      { ...database.connection('app'), tls: 'disable', maxConnections: 1 },
      testLogger(),
    );
    try {
      await takeJobLease(one, A, false, TERM, { statementMs: 1234, lockMs: 567 });
      const { rows } = await sql<{ statement: string; lock: string }>`
        select pg_catalog.current_setting('statement_timeout') as statement,
               pg_catalog.current_setting('lock_timeout') as lock`.execute(one);
      expect(rows[0]?.statement).not.toBe('1234ms');
      expect(rows[0]?.lock).not.toBe('567ms');
    } finally {
      await one.destroy();
    }
  });

  it('many at once on a free lease: exactly one wins', async () => {
    const holders = Array.from(
      { length: 4 },
      (_unused, index) => `0199a0f0-0000-7000-8000-00000000000${String(index)}`,
    );
    const won = await Promise.all(holders.map((holder) => takeJobLease(app, holder, false, TERM)));
    expect(won.filter(Boolean)).toHaveLength(1);
  });

  it('moves the heartbeat only when told to, and only for the holder; a release leaves it', async () => {
    expect(await jobsBeating(app, 300)).toBe(false);
    await takeJobLease(app, A, false, TERM);
    expect((await row())?.beaten).toBe(false);
    expect(await jobsBeating(app, 300)).toBe(false);

    await takeJobLease(app, B, true, TERM);
    expect((await row())?.beaten).toBe(false);

    await takeJobLease(app, A, true, TERM);
    expect(await jobsBeating(app, 300)).toBe(true);
    await releaseJobLease(app, A);
    expect(await jobsBeating(app, 300)).toBe(true);
  });

  it('reads a heartbeat past the limit as stopped, and a renewal not beating lets it go stale', async () => {
    await takeJobLease(app, A, true, TERM);
    await database
      .as('admin')
      .query("update platform_controls.job_lease set beating_at = pg_catalog.now() - interval '301 seconds'");
    await takeJobLease(app, A, false, TERM);
    expect(await jobsBeating(app, 300)).toBe(false);
    expect(await jobsBeating(app, 400)).toBe(true);
  });

  it('the app may not add or delete a row, nor change its name', async () => {
    const session = database.as('app');
    await expect(
      session.query("insert into platform_controls.job_lease (name, until) values ('jobs', pg_catalog.now())"),
    ).rejects.toThrow(/permission denied/);
    await expect(session.query('delete from platform_controls.job_lease')).rejects.toThrow(/permission denied/);
    await expect(session.query("update platform_controls.job_lease set name = 'other'")).rejects.toThrow(
      /permission denied/,
    );
  });
});

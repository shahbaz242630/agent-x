// The lease's process side over the real row (0068, 4D2e D): short terms on a real Postgres. job-lease.db.test.ts holds
// the statements; leadership.test.ts every timing on a clock it moves.
import { type PlatformControlsTables, releaseJobLease, takeJobLease } from '@agentx/core/modules/platform-controls';
import { createDatabase, type Database, timedRoundTrips } from '@agentx/platform/db';
import { createTestDatabase, LogCapture, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it, vi } from 'vitest';

import { createLeadership, type Leadership, withinDeadline } from './background.ts';

const server = inject('postgres');
const A = '0199a0f0-0000-7000-8000-00000000aaaa';
const B = '0199a0f0-0000-7000-8000-00000000bbbb';
const OTHER = '0199a0f0-0000-7000-8000-00000000cccc';

/** Short enough to run here; the term stays three renewals, as in life. */
const RENEW_MS = 100;
const TERM_MS = 300;

let database: TestDatabase;
let app: Database<PlatformControlsTables>;
let capture: LogCapture;
const started: Leadership[] = [];

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
  capture = new LogCapture();
  await database.as('admin').query("update platform_controls.job_lease set holder = null, until = '-infinity'");
});

afterEach(async () => {
  await Promise.all(started.splice(0).map((one) => one.stop()));
});

function aProcess(holder: string, answering: () => boolean = () => true) {
  const one = createLeadership({
    store: {
      take: (beating) =>
        answering()
          ? takeJobLease(app, holder, beating, TERM_MS / 1000)
          : Promise.reject(new Error('the connection was lost')),
      release: () => releaseJobLease(app, holder),
    },
    logger: testLogger(capture),
    notLeadingAfterMs: 500,
    renewEveryMs: RENEW_MS,
    termMs: TERM_MS,
    retryAfterMs: 50,
  });
  started.push(one);
  return one;
}

const said = (event: string) => capture.lines().filter((line) => line.event === event);
const withinTime = <T>(work: Promise<T>, ms: number) => withinDeadline(work, ms, undefined);

describe(`a process and the lease's row (Postgres ${server.version})`, () => {
  it('two never both lead: expiry hands over on the real clock, the old holder having let go first', async () => {
    let answering = true;
    const a = aProcess(A, () => answering);
    const b = aProcess(B);
    await a.start(() => false);
    await b.start(() => false);
    expect([a.leading(), b.leading()]).toEqual([true, false]);

    answering = false;
    const end = Date.now() + 1500;
    let handedOver = false;
    while (Date.now() < end && !handedOver) {
      expect(a.leading() && b.leading()).toBe(false);
      handedOver = b.leading();
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(handedOver).toBe(true);
    expect(a.leading()).toBe(false);
    expect(said('jobs.lease_lost')).toHaveLength(1);
  });

  it('a lost lease aborts a run through its signal: the row forged, the next renewal refused', async () => {
    const a = aProcess(A);
    await a.start(() => false);
    const seen: AbortSignal[] = [];
    const run = a
      .onlyWhileLeading({
        name: 'anchor_check',
        run: (signal) =>
          new Promise<void>((resolve) => {
            if (signal === undefined) throw new Error('a job always has a signal here');
            seen.push(signal);
            signal.addEventListener('abort', () => {
              resolve();
            });
          }),
      })
      .run(new AbortController().signal);
    await vi.waitFor(() => {
      expect(seen).toHaveLength(1);
    });

    await database.as('admin').query("update platform_controls.job_lease set holder = $1, until = 'infinity'", [OTHER]);
    await run;
    expect(seen[0]?.aborted).toBe(true);
    expect(a.leading()).toBe(false);
  });

  it('forged for good: the process says so as an error, once a stretch, and again if it lasts', async () => {
    await database.as('admin').query("update platform_controls.job_lease set holder = $1, until = 'infinity'", [OTHER]);
    const a = aProcess(A);
    await a.start(() => false);
    expect(a.leading()).toBe(false);
    expect(said('jobs.lease_held_elsewhere')).toHaveLength(1);

    await vi.waitFor(
      () => {
        expect(said('jobs.not_leading').length).toBeGreaterThanOrEqual(2);
      },
      { timeout: 3000, interval: 50 },
    );
    expect(said('jobs.not_leading')[0]).toEqual(expect.objectContaining({ level: 'error' }));
    expect(said('jobs.lease_held_elsewhere')).toHaveLength(1);
    expect(a.leading()).toBe(false);
  });

  it('its row deleted: the same error', async () => {
    const admin = database.as('admin');
    await admin.query('delete from platform_controls.job_lease');
    try {
      const a = aProcess(A);
      await a.start(() => false);
      await vi.waitFor(
        () => {
          expect(said('jobs.not_leading')).not.toHaveLength(0);
        },
        { timeout: 3000, interval: 50 },
      );
    } finally {
      await admin.query("insert into platform_controls.job_lease (name, until) values ('jobs', '-infinity')");
    }
  });

  it('forced: a session sitting on the row never takes the pool: one try out at most, and requests still answer', async () => {
    const small = createDatabase<PlatformControlsTables>(
      { ...database.connection('app'), tls: 'disable', maxConnections: 3 },
      testLogger(),
    );
    const sitting = await database.connect('admin');
    await sitting.query('begin');
    await sitting.query('select name from platform_controls.job_lease for update');
    const limits = { statementMs: 400, lockMs: 200 };
    const one = createLeadership({
      store: {
        take: (beating) => takeJobLease(small, A, beating, TERM_MS / 1000, limits),
        release: () => releaseJobLease(small, A, limits),
      },
      logger: testLogger(capture),
      notLeadingAfterMs: 60_000,
      renewEveryMs: RENEW_MS,
      termMs: TERM_MS,
      tryWithinMs: 500,
      retryAfterMs: 50,
    });
    try {
      const begun = one.start(() => false);
      const waiting = () =>
        database.as('admin').query<{ pid: number }>(
          `select pid from pg_catalog.pg_stat_activity
           where datname = pg_catalog.current_database()
             and pg_catalog.cardinality(pg_catalog.pg_blocking_pids(pid)) > 0`,
        );
      let most = 0;
      const until = Date.now() + 2500;
      while (Date.now() < until) {
        most = Math.max(most, (await waiting()).length);
        // Every connection but the one try's is free: as many reads as that at once, at once.
        const reads = Array.from({ length: 2 }, () => withinTime(timedRoundTrips(small, 1), 1000));
        await Promise.all(reads);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      await begun;
      expect(most).toBeLessThanOrEqual(1);
      // Several rounds did run, and each was ended by the database's limit, not left to pile up.
      expect(said('jobs.lease_renew_failed').length).toBeGreaterThanOrEqual(4);
      expect(one.leading()).toBe(false);

      await sitting.query('commit');
      await vi.waitFor(() => {
        expect(one.leading()).toBe(true);
      });
    } finally {
      await one.stop();
      await sitting.end();
      await small.destroy();
    }
  });

  it('the holder releases on stop, and the next takes it at its next try', async () => {
    const a = aProcess(A);
    const b = aProcess(B);
    await a.start(() => false);
    await b.start(() => false);
    await a.stop();
    expect(await database.as('admin').query('select holder from platform_controls.job_lease')).toEqual([
      { holder: null },
    ]);
    await vi.waitFor(() => {
      expect(b.leading()).toBe(true);
    });
  });
});

// PM4 (0086): the request expiry reads only its index, in pages that stop at their size, on
// the real tables as the app role. 0086 fills `waits_until` for a waiting request made
// before 0073 from its age and the shortest wait, the very time the job read it by, so
// which requests expire, and when, is unchanged; the job's read is then one range of
// 0074's index, soonest first, its plan held here by EXPLAIN (ANALYZE): the index alone,
// every row it reads a due one, no more than a page.
import { readFileSync } from 'node:fs';

import { createOutbox } from '@agentx/core/modules/notifications';
import { requestExpiryDue, requestsDueToExpireRead } from '@agentx/core/modules/spend-requests';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import type { HandoffWorldTables } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type World } from './mandate-world.helper.test.ts';
import { createOrgWorkRediscovery, markedOrganisations, withOrgWork } from './org-work.ts';
import { createRequestExpiry } from './request-expiry.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0x0086_0000_0000);
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'request_expiry_index',
  registry: () => registry,
  decisions: () => decisions,
});
const { ready, ask, statusOf, waitChosen } = shared;

const admin = () => database.as('admin');
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** 0086 whole, as the migration ran it: as the owner, whom the tenant wall binds too. */
const fill = readFileSync(new URL('../../../db/migrations/0086_waits_until_filled.sql', import.meta.url), 'utf8');
// eslint-disable-next-line agentx/no-string-built-sql -- the migration's own fixed text, read from its file
const filled = () => database.as('owner').query(fill);

/** What the request's row says of its wait, read past its signed state. */
async function rowOf(id: string) {
  const [row] = await admin().query<{ waits_until: Date | null; created_at: Date }>(
    'select waits_until, created_at from spend_requests.requests where id = $1',
    [id],
  );
  if (row === undefined) throw new Error('no request');
  return row;
}

/** As a request made before 0073 was: no `waits_until` on its row. */
const madeBefore0073 = (id: string) =>
  admin().query('update spend_requests.requests set waits_until = null where id = $1', [id]);

const markOf = async (org: string) =>
  (
    await admin().query<{ due_at: Date }>(
      "select due_at from directory.org_work where org_id = $1 and job = 'request_expiry'",
      [org],
    )
  )[0];

/** The request expiry as job-list.ts makes it: its organisations from its marks, settled after each run. */
function requestExpiry(most?: number) {
  const marks = markedOrganisations({
    job: 'request_expiry',
    nextDue: requestExpiryDue,
    database: app,
    logger: testLogger(capture),
    clock,
  });
  return withOrgWork(
    [marks],
    createRequestExpiry({
      list: marks.list,
      database: app,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      ...(most === undefined ? {} : { most }),
    }),
  );
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  clock = new FixedClock(new Date());
  capture = new LogCapture();
  const logger = testLogger(capture);
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
  await admin().query('delete from directory.org_work');
});

describe("0086 fills a waiting request's missing wait, behind each organisation's wall", () => {
  it('from its age and the shortest wait, in every organisation; one with its own, and one not waiting, as they were', async () => {
    const one = await ready();
    const two = await ready();
    const older = await ask(one.acting, one.w);
    const otherOrg = await ask(two.acting, two.w);
    const kept = await ask(one.acting, one.w);
    const allowed = await ask(one.acting, one.w, { amount: AED(50_000n), supplierId: one.w.suppliers[1] ?? '' });
    await madeBefore0073(older.id);
    await madeBefore0073(otherOrg.id);
    const keptBefore = (await rowOf(kept.id)).waits_until;

    await filled();

    for (const id of [older.id, otherOrg.id]) {
      const row = await rowOf(id);
      expect(row.waits_until).toEqual(new Date(row.created_at.getTime() + 24 * HOUR));
    }
    expect((await rowOf(kept.id)).waits_until).toEqual(keptBefore);
    expect((await rowOf(allowed.id)).waits_until).toBeNull();
    // Each name was for its one statement: the owner's session names none after.
    const [setting] = await database
      .as('owner')
      .query<{ org: string | null }>("select nullif(pg_catalog.current_setting('app.org_id', true), '') as org");
    expect(setting?.org ?? null).toBeNull();
  });

  it('marks an organisation whose row it filled due a day on at the latest, never moving a mark later', async () => {
    const { w, acting } = await ready();
    const older = await ask(acting, w);
    await madeBefore0073(older.id);
    await admin().query('delete from directory.org_work');

    await filled();

    const due = (await markOf(w.org))?.due_at.getTime() ?? 0;
    const { now } = (await admin().query<{ now: Date }>('select pg_catalog.now() as now'))[0] ?? { now: new Date(0) };
    expect(due).toBeLessThanOrEqual(now.getTime() + 24 * HOUR);
    expect(due).toBeGreaterThan(now.getTime() + 24 * HOUR - MINUTE);
  });
});

describe('which requests expire, and when, unchanged by the fill', () => {
  it('one made before 0073 sealing 72 hours: due by its age a day on, judged by its seal, expired as that ends', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await madeBefore0073(waiting.id);
    await filled();
    const { created_at: created } = await rowOf(waiting.id);
    const job = requestExpiry();

    clock.advanceBy(created.getTime() + 24 * HOUR + MINUTE - clock.now().getTime());
    await job.run();
    // A candidate by its row, its sealed 72 hours not yet out: left, and visited each run until they are.
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect((await markOf(w.org))?.due_at).toEqual(clock.now());

    // The hourly look leaves the mark the visit settled: no miss said.
    clock.advanceBy(HOUR);
    await createOrgWorkRediscovery({
      list: () => Promise.resolve([w.org]),
      database: app,
      logger: testLogger(capture),
      clock,
    }).run();
    expect(lines('org_work.unmarked')).toEqual([]);

    clock.advanceBy(48 * HOUR);
    await job.run();
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
    expect(await markOf(w.org)).toBeUndefined();
  });

  it('one made before 0073 sealing 24 hours is expired 24 hours on, as by its age before', async () => {
    const { w, acting } = await ready();
    await waitChosen(w, 24);
    const waiting = await ask(acting, w);
    await madeBefore0073(waiting.id);
    await filled();
    clock.advanceBy(24 * HOUR + MINUTE);

    await requestExpiry().run();

    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
  });

  it('five due and one not, two a run: the soonest first, every due one expired by the third run, the other waiting', async () => {
    const { w, acting } = await ready();
    const later = await ask(acting, w);
    await waitChosen(w, 24);
    const due: Awaited<ReturnType<typeof ask>>[] = [];
    for (let each = 0; each < 5; each += 1) due.push(await ask(acting, w));
    const job = requestExpiry(2);
    clock.advanceBy(24 * HOUR + MINUTE);

    const expiredBy = async () =>
      (await Promise.all(due.map(async ({ id }) => (await statusOf(w, id)) === 'EXPIRED'))).filter(Boolean).length;
    await job.run();
    expect(await expiredBy()).toBe(2);
    // Soonest first: the first two asked, whose waits end first.
    expect([await statusOf(w, due[0]?.id ?? ''), await statusOf(w, due[1]?.id ?? '')]).toEqual(['EXPIRED', 'EXPIRED']);
    await job.run();
    expect(await expiredBy()).toBe(4);
    await job.run();
    expect(await expiredBy()).toBe(5);
    expect(await statusOf(w, later.id)).toBe('APPROVAL_REQUIRED');
  });
});

describe("the job's read: one range of 0074's index, every row read a due one, no more than a page", () => {
  /** Every node of a JSON plan, flat. */
  const nodes = (plan: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>>[] => [
    plan,
    ...((plan.Plans as Readonly<Record<string, unknown>>[] | undefined) ?? []).flatMap(nodes),
  ];

  /**
   * The read as the job runs it, as the app inside the organisation's wall, and its plan. A table this small is read
   * whole cheaper than by any index, so the plain and bitmap scans are set aside for the plan alone (as 0081's test):
   * what this holds is that the index bounds the read to the due rows, a page of them, which the read with 0073's
   * second branch (a waiting row with no `waits_until`, by its age) could not.
   */
  const planned = (w: World, now: Date, most: number, after?: string) =>
    withTenant(app, w.org, async (tx) => {
      const read = requestsDueToExpireRead(tx, w.org, now, most, after);
      const rows = (await read.execute()).map(({ id }) => id);
      // The statement as the job sends it, its parameters bound, with fixed words before it (this package has no
      // kysely of its own to write them with).
      const compiled = read.compile();
      const run = (words: string, parameters: readonly unknown[] = []) =>
        tx.executeQuery<{ 'QUERY PLAN': [{ Plan: Record<string, unknown> }] }>({ ...compiled, sql: words, parameters });
      await run('set local enable_seqscan = off');
      await run('set local enable_bitmapscan = off');
      const explained = await run(`explain (analyze, format json) ${compiled.sql}`, compiled.parameters);
      const plan = explained.rows[0]?.['QUERY PLAN'][0].Plan ?? {};
      return {
        rows,
        scans: nodes(plan).filter((node) => node['Relation Name'] === 'requests'),
      };
    });

  /** A world with three requests due (24 hours) behind two not (72), and one allowed; another organisation's due too. */
  async function seeded() {
    const other = await ready();
    await waitChosen(other.w, 24);
    await ask(other.acting, other.w);
    const { w, acting } = await ready();
    const notDue = [await ask(acting, w), await ask(acting, w)];
    await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    await waitChosen(w, 24);
    const due = [await ask(acting, w), await ask(acting, w), await ask(acting, w)];
    const [server] = await admin().query<{ now: Date }>('select pg_catalog.now() as now');
    return { w, due, notDue, at: new Date((server?.now.getTime() ?? 0) + 48 * HOUR) };
  }

  it('reads the due rows alone, soonest first, through the index on waits_until', async () => {
    const { w, due, at } = await seeded();

    const { rows, scans } = await planned(w, at, 100);

    expect(rows).toEqual(due.map(({ id }) => id));
    expect(scans).toHaveLength(1);
    expect(scans[0]).toMatchObject({
      'Node Type': 'Index Scan',
      'Index Name': 'requests_waiting_until',
      'Actual Rows': 3,
    });
    expect(scans[0]?.['Index Cond']).toMatch(/waits_until <=/);
    expect(scans[0]?.['Rows Removed by Filter'] ?? 0).toBe(0);
  });

  it('stops at its page: a page of two reads no more than the next row past it', async () => {
    const { w, due, at } = await seeded();

    const first = await planned(w, at, 2);
    expect(first.rows).toEqual(due.slice(0, 2).map(({ id }) => id));
    expect(first.scans[0]?.['Index Name']).toBe('requests_waiting_until');
    expect(first.scans[0]?.['Actual Rows']).toBeLessThanOrEqual(3);

    // The next page starts in the index past the last one: the place is that row's own, read by its key.
    const next = await planned(w, at, 2, first.rows.at(-1));
    expect(next.rows).toEqual(due.slice(2).map(({ id }) => id));
    const range = next.scans.find((scan) => scan['Index Name'] === 'requests_waiting_until');
    expect(range?.['Index Cond']).toMatch(/waits_until/);
    expect(range?.['Actual Rows']).toBe(1);
    expect(next.scans.filter((scan) => scan['Index Name'] !== 'requests_waiting_until')).toEqual([
      expect.objectContaining({ 'Actual Rows': 1 }),
    ]);
  });

  it('a page after a request that is not there ends the pages', async () => {
    const { w, at } = await seeded();
    const { rows } = await planned(w, at, 2, '0190f000-0000-7000-8000-000000000000');
    expect(rows).toEqual([]);
  });
});

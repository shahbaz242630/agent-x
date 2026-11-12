// The two expiries following their marks (4D2e D8, 0073), on the real tables as the app role:
// where each mark comes from, each settled to when its rows next need a visit, the
// request's `waits_until` held to its sealed wait, a cap that only delays, the hourly
// look and 0073's first marks. Every race is forced with a held read, never left to
// chance. The seam itself (listing, settling, the page's statement) is
// org-work-switch.db.test.ts's.
import { readFileSync } from 'node:fs';

import { withSignedStates } from '@agentx/core/modules/audit';
import { mandateExpiryDue, mandateOf } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { checkHoldings, NO_PAYMENTS, requestExpiryDue } from '@agentx/core/modules/spend-requests';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it, onTestFinished } from 'vitest';

import type { Gate } from './fair-lanes.ts';
import type { HandoffWorldTables } from './handoff-world.helper.test.ts';
import { createMandateExpiry } from './mandate-expiry.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type World } from './mandate-world.helper.test.ts';
import { createOrgWorkRediscovery, markedOrganisations, withOrgWork } from './org-work.ts';
import { createRequestExpiry } from './request-expiry.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xd8a0_0000_0000);
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
/** The jobs' own period (REQUEST_EXPIRY_EVERY_MS, MANDATE_EXPIRY_EVERY_MS): the tests move the clock a run at a time. */
const RUN = 5 * MINUTE;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'org_work_expiry',
  registry: () => registry,
  decisions: () => decisions,
});
const { ready, ask, statusOf, waitChosen, quiet } = shared;

const admin = () => database.as('admin');
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

type ExpiryJob = 'request_expiry' | 'mandate_expiry';

async function markOf(org: string, job: ExpiryJob) {
  const [row] = await admin().query<{ due_at: Date; marks: string }>(
    'select due_at, marks from directory.org_work where org_id = $1 and job = $2',
    [org, job],
  );
  return row;
}

/** What the request's row says of its wait, read past its signed state, and when its decision was sealed. */
async function waitOf(id: string) {
  const [row] = await admin().query<{ waits_until: Date | null; created_at: Date; decided_at: Date }>(
    `select r.waits_until, r.created_at, e.recorded_at as decided_at from spend_requests.requests r
       join audit.events e on e.org_id = r.org_id and e.subject_id = r.id and e.action = 'spend_request.decided'
      where r.id = $1`,
    [id],
  );
  if (row === undefined) throw new Error('no request');
  return row;
}

/** The jobs' clock moved on to `at`. */
const moveTo = (at: Date) => {
  clock.advanceBy(at.getTime() - clock.now().getTime());
};

/** The server's time now: the triggers' marks are its clock's. */
const serverNow = async () =>
  (await admin().query<{ now: Date }>('select pg_catalog.now() as now'))[0]?.now.getTime() ?? 0;

/** Past the app: the request's unsealed `waits_until` set as SQL `to` reads it, against the row's own. */
const waitsUntilMoved = (id: string, to: string) =>
  // eslint-disable-next-line agentx/no-string-built-sql -- `to` is fixed text from each test
  admin().query(`update spend_requests.requests set waits_until = ${to} where id = $1`, [id]);

const requestMarks = ({ most, reads }: { most?: number; reads?: Gate } = {}) =>
  markedOrganisations({
    job: 'request_expiry',
    nextDue: requestExpiryDue,
    database: app,
    logger: testLogger(capture),
    clock,
    ...(most === undefined ? {} : { most }),
    ...(reads === undefined ? {} : { reads }),
  });

const mandateMarks = ({ most, reads }: { most?: number; reads?: Gate } = {}) =>
  markedOrganisations({
    job: 'mandate_expiry',
    nextDue: mandateExpiryDue,
    database: app,
    logger: testLogger(capture),
    clock,
    ...(most === undefined ? {} : { most }),
    ...(reads === undefined ? {} : { reads }),
  });

/** The request expiry as job-list.ts makes it: its organisations from its marks, settled after each run. */
function requestExpiry(most?: number) {
  const marks = requestMarks(most === undefined ? {} : { most });
  return withOrgWork(
    [marks],
    createRequestExpiry({ list: marks.list, database: app, keys, ids, clock, logger: testLogger(capture) }),
  );
}

/** The mandate expiry as job-list.ts makes it. */
function mandateExpiry(most?: number) {
  const marks = mandateMarks(most === undefined ? {} : { most });
  return withOrgWork(
    [marks],
    createMandateExpiry({
      list: marks.list,
      database: app,
      keys,
      ids,
      clock,
      outbox: createOutbox({ ids, clock }),
      logger: testLogger(capture),
    }),
  );
}

/** A gate that lets each read through only once `letGo` is called: a settle's read held, so a race is forced. */
function heldGate() {
  let letGo = (): void => undefined;
  const held = new Promise<void>((resolve) => {
    letGo = resolve;
  });
  let waiting = 0;
  const gate: Gate = {
    run: async (_key, work) => {
      waiting += 1;
      await held;
      return work();
    },
  };
  return {
    gate,
    letGo: () => {
      letGo();
    },
    waiting: () => waiting,
  };
}

/** Until `held` has a read waiting at it: the settle has listed and is reading. */
async function untilWaiting(waiting: () => number): Promise<void> {
  for (let turn = 0; turn <= 200; turn += 1) {
    if (waiting() > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('the settle never reached its read');
}

/** A world whose mandate, in force, ends at `endsAt`: approval above AED 1,000, as `ready`'s. */
async function endingAt(endsAt: Date) {
  const w = await shared.world();
  const mandateId = await shared.inForce(registry, w, { approvalThreshold: AED(100_000n), endsAt });
  return { w, mandateId };
}

const mandateStatus = (w: World, id: string) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const read = await mandateOf(tx, states, { orgId: w.org, id }, 'share');
    return read.outcome === 'found' ? read.mandate.status : read.outcome;
  });

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
  // The marks are read across organisations: each test starts with none, so it sees its own alone.
  await admin().query('delete from directory.org_work');
});

describe('a request waiting for approval: its wait on its row, and its mark', () => {
  it('its insert writes when it may expire, never after its sealed wait ends; any other decision writes none', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    expect([waiting.status, allowed.status]).toEqual(['APPROVAL_REQUIRED', 'APPROVED']);

    const { waits_until: until, decided_at: decided } = await waitOf(waiting.id);
    const sealedEnd = decided.getTime() + 72 * HOUR;
    // Written from the same clock a moment before the decision's time is sealed from it.
    expect(until?.getTime()).toBeLessThanOrEqual(sealedEnd);
    expect(until?.getTime()).toBeGreaterThan(sealedEnd - 5_000);
    expect((await waitOf(allowed.id)).waits_until).toBeNull();
  });

  it("carries the wait chosen when it was decided: 24 hours' requests are due 24 hours on", async () => {
    const { w, acting } = await ready();
    await waitChosen(w, 24);
    const waiting = await ask(acting, w);
    const { waits_until: until, decided_at: decided } = await waitOf(waiting.id);
    expect(until?.getTime()).toBeLessThanOrEqual(decided.getTime() + 24 * HOUR);
    expect(until?.getTime()).toBeGreaterThan(decided.getTime() + 24 * HOUR - 5_000);
  });

  it('marks its expiry a day on, the shortest wait, from its transaction; an allowed one marks no expiry', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    expect(await markOf(w.org, 'request_expiry')).toBeUndefined();

    const started = await serverNow();
    await ask(acting, w);
    const due = (await markOf(w.org, 'request_expiry'))?.due_at.getTime() ?? 0;
    expect(due).toBeGreaterThanOrEqual(started + 24 * HOUR);
    expect(due).toBeLessThanOrEqual((await serverNow()) + 24 * HOUR);
  });
});

describe("the request expiry's due read", () => {
  it('the soonest of those waiting; none for any other', async () => {
    const { w, acting } = await ready();
    const dueOf = () =>
      withTenant(app, w.org, async (tx) => (await requestExpiryDue(tx, w.org).execute())[0]?.due ?? null);

    await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    expect(await dueOf()).toBeNull();

    const longer = await ask(acting, w);
    expect(await dueOf()).toEqual((await waitOf(longer.id)).waits_until);

    await waitChosen(w, 24);
    const shorter = await ask(acting, w);
    expect(await dueOf()).toEqual((await waitOf(shorter.id)).waits_until);
  });
});

describe('the request expiry follows its marks', () => {
  it('visited a day on, its mark moves to the wait its decision sealed; expired as that ends, then the mark goes', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const { waits_until: until } = await waitOf(waiting.id);
    const job = requestExpiry();

    // Not due: no visit, nothing settled.
    const marked = await markOf(w.org, 'request_expiry');
    await job.run();
    expect(await markOf(w.org, 'request_expiry')).toEqual(marked);

    clock.advanceBy(24 * HOUR + MINUTE);
    await job.run();
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect((await markOf(w.org, 'request_expiry'))?.due_at).toEqual(until);

    moveTo(new Date((until?.getTime() ?? 0) - MINUTE));
    await job.run();
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');

    clock.advanceBy(RUN);
    await job.run();
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
    expect(await markOf(w.org, 'request_expiry')).toBeUndefined();
  });

  it('its soonest wait bounds the mark: one of 24 hours after one of 72 brings it forward, and is expired first', async () => {
    const { w, acting } = await ready();
    const longer = await ask(acting, w);
    await waitChosen(w, 24);
    const shorter = await ask(acting, w);
    const job = requestExpiry();
    clock.advanceBy(24 * HOUR + MINUTE);

    await job.run();

    expect(await statusOf(w, shorter.id)).toBe('EXPIRED');
    expect(await statusOf(w, longer.id)).toBe('APPROVAL_REQUIRED');
    expect((await markOf(w.org, 'request_expiry'))?.due_at).toEqual((await waitOf(longer.id)).waits_until);
  });

  it('a wait moved sooner past the app is only a visit early: judged by its seal, it waits on, then expires', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await waitsUntilMoved(waiting.id, "waits_until - interval '48 hours'");
    const { decided_at: decided } = await waitOf(waiting.id);
    const job = requestExpiry();

    clock.advanceBy(24 * HOUR + MINUTE);
    await job.run();
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    // Due already, it is settled as due now, so it waits behind any due before it.
    expect((await markOf(w.org, 'request_expiry'))?.due_at).toEqual(clock.now());

    moveTo(new Date(decided.getTime() + 72 * HOUR + MINUTE));
    await job.run();
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
  });
});

describe("the request's wait on its row, held to its seal by the holdings check", () => {
  // Through the test's own log, so the alarm a mismatch raises is seen.
  const checked = (w: World) =>
    withSignedStates(app, w.org, { keys, ids, logger: testLogger(capture) }, (tx, states) =>
      checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }, NO_PAYMENTS),
    );

  it.each([
    ['as written', null, 0],
    ['moved sooner', "waits_until - interval '1 day'", 0],
    ['moved later within the minute its clock may step back', "waits_until + interval '30 seconds'", 0],
    ['taken away: 0086 filled every waiting one, and the expiry reads none without it', 'null', 1],
    [
      'moved later past that minute: it would hide the request from the expiry',
      "waits_until + interval '2 minutes'",
      1,
    ],
    ['moved a month later', "waits_until + interval '30 days'", 1],
  ])('%s', async (_what, to, mismatched) => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    if (to !== null) await waitsUntilMoved(waiting.id, to);
    expect(await checked(w)).toMatchObject({ requests: 1, mismatched, tampered: 0 });
    if (mismatched > 0) expect(lines('audit.integrity_failed')).not.toEqual([]);
  });

  it('a request no longer waiting is not held to it', async () => {
    const { w, acting } = await ready();
    await waitChosen(w, 24);
    const waiting = await ask(acting, w);
    clock.advanceBy(24 * HOUR + MINUTE);
    await requestExpiry().run();
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
    await waitsUntilMoved(waiting.id, "waits_until + interval '30 days'");
    expect(await checked(w)).toMatchObject({ mismatched: 0 });
  });
});

describe('the mandate expiry follows its marks', () => {
  it('marked as it comes into force; visited, its mark moves to its end; expired then, and the mark goes', async () => {
    const endsAt = new Date(clock.now().getTime() + 2 * HOUR);
    const { w, mandateId } = await endingAt(endsAt);
    expect((await markOf(w.org, 'mandate_expiry'))?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
    const job = mandateExpiry();

    await job.run();
    expect((await markOf(w.org, 'mandate_expiry'))?.due_at).toEqual(endsAt);

    clock.advanceBy(HOUR);
    const settled = await markOf(w.org, 'mandate_expiry');
    await job.run();
    expect(await markOf(w.org, 'mandate_expiry')).toEqual(settled);
    expect(await mandateStatus(w, mandateId)).toBe('ACTIVE');

    moveTo(new Date(endsAt.getTime() + MINUTE));
    await job.run();
    expect(await mandateStatus(w, mandateId)).toBe('EXPIRED');
    expect(await markOf(w.org, 'mandate_expiry')).toBeUndefined();
  });

  it("the soonest end of the organisation's mandates in force bounds the mark", async () => {
    const sooner = new Date(clock.now().getTime() + HOUR);
    const { w } = await endingAt(new Date(clock.now().getTime() + 3 * HOUR));
    await shared.secondAgent(registry, w, { approvalThreshold: AED(100_000n), endsAt: sooner });

    await mandateExpiry().run();

    expect((await markOf(w.org, 'mandate_expiry'))?.due_at).toEqual(sooner);
  });

  it('suspended, it is marked again at once; one with no end has its mark taken away', async () => {
    const endsAt = new Date(clock.now().getTime() + 2 * HOUR);
    const { w, mandateId } = await endingAt(endsAt);
    const job = mandateExpiry();
    await job.run();
    const settled = await markOf(w.org, 'mandate_expiry');

    await shared.movedPastTheUseCase(w, mandateId, 'suspend');
    const marked = await markOf(w.org, 'mandate_expiry');
    expect(BigInt(marked?.marks ?? '0')).toBeGreaterThan(BigInt(settled?.marks ?? '0'));
    expect(marked?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
    await job.run();
    // Suspended, it still expires at its end.
    expect((await markOf(w.org, 'mandate_expiry'))?.due_at).toEqual(endsAt);

    const none = await ready();
    await job.run();
    expect(await markOf(none.w.org, 'mandate_expiry')).toBeUndefined();
  });
});

describe('a cap that only delays: every organisation due is visited within ceil(due / cap) runs', () => {
  it('five requests due across five organisations, two a run: each expired by the third run', async () => {
    const orgs: { w: World; id: string }[] = [];
    for (let n = 0; n < 5; n += 1) {
      const { w, acting } = await ready();
      await waitChosen(w, 24);
      orgs.push({ w, id: (await ask(acting, w)).id });
    }
    const job = requestExpiry(2);
    clock.advanceBy(24 * HOUR + MINUTE);

    const expiredBy: number[] = [];
    for (let run = 1; run <= 3; run += 1) {
      await job.run();
      for (const [at, { w, id }] of orgs.entries()) {
        if (expiredBy[at] === undefined && (await statusOf(w, id)) === 'EXPIRED') expiredBy[at] = run;
      }
      clock.advanceBy(RUN);
    }
    expect(expiredBy.toSorted()).toEqual([1, 1, 2, 2, 3]);
  });

  it('organisations visited and still due go behind those due before them: two stuck never keep three from expiring', async () => {
    const stuck: World[] = [];
    for (let n = 0; n < 2; n += 1) {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      // Its row says due a month ago, its seal 72 hours: visited every run, and never expired here.
      await waitsUntilMoved(waiting.id, "waits_until - interval '30 days'");
      await admin().query(
        `update directory.org_work set due_at = due_at - interval '30 days' where org_id = $1 and job = 'request_expiry'`,
        [w.org],
      );
      stuck.push(w);
    }
    const due: { w: World; id: string }[] = [];
    for (let n = 0; n < 3; n += 1) {
      const { w, acting } = await ready();
      await waitChosen(w, 24);
      due.push({ w, id: (await ask(acting, w)).id });
    }
    const job = requestExpiry(2);
    clock.advanceBy(24 * HOUR + MINUTE);

    // The first run takes the two due longest, the stuck: each settled as due now, behind the three.
    for (let run = 1; run <= 3; run += 1) {
      await job.run();
      clock.advanceBy(RUN);
    }
    for (const { w, id } of due) expect(await statusOf(w, id)).toBe('EXPIRED');
  });

  it('five mandates ending at once across five organisations, two a run: each expired within three runs of its end', async () => {
    const endsAt = new Date(clock.now().getTime() + HOUR);
    const orgs: { w: World; mandateId: string }[] = [];
    for (let n = 0; n < 5; n += 1) orgs.push(await endingAt(endsAt));
    const job = mandateExpiry(2);
    // Their first visits, from their marks made in force: three runs settle all five to their end.
    for (let run = 1; run <= 3; run += 1) {
      await job.run();
      clock.advanceBy(RUN);
    }
    for (const { w } of orgs) expect((await markOf(w.org, 'mandate_expiry'))?.due_at).toEqual(endsAt);

    moveTo(new Date(endsAt.getTime() + MINUTE));
    const expiredBy: number[] = [];
    for (let run = 1; run <= 3; run += 1) {
      await job.run();
      for (const [at, { w, mandateId }] of orgs.entries()) {
        if (expiredBy[at] === undefined && (await mandateStatus(w, mandateId)) === 'EXPIRED') expiredBy[at] = run;
      }
      clock.advanceBy(RUN);
    }
    expect(expiredBy.toSorted()).toEqual([1, 1, 2, 2, 3]);
  });
});

describe('a settle holds no mark while it reads: a commit then is at once, and its mark stands (forced)', () => {
  it("an agent's decision while the request expiry's settle reads", async () => {
    const { w, acting } = await ready();
    await ask(acting, w);
    clock.advanceBy(24 * HOUR + MINUTE);
    const held = heldGate();
    const marks = requestMarks({ reads: held.gate });
    expect(await marks.list()).toEqual([w.org]);
    const listed = await markOf(w.org, 'request_expiry');
    const settling = marks.settle();
    onTestFinished(async () => {
      held.letGo();
      await settling;
    });
    await untilWaiting(held.waiting);

    // A decision carries a 5 s lock_timeout: had the settle held the mark, its commit would wait or fail.
    const during = await ask(acting, w);
    expect(during.status).toBe('APPROVAL_REQUIRED');
    const made = await markOf(w.org, 'request_expiry');
    expect(BigInt(made?.marks ?? '0')).toBeGreaterThan(BigInt(listed?.marks ?? '0'));

    held.letGo();
    await settling;
    expect(await markOf(w.org, 'request_expiry')).toEqual(made);
  });

  it("a mandate suspended while the mandate expiry's settle reads", async () => {
    const { w, mandateId } = await endingAt(new Date(clock.now().getTime() + 2 * HOUR));
    const held = heldGate();
    const marks = mandateMarks({ reads: held.gate });
    expect(await marks.list()).toEqual([w.org]);
    const listed = await markOf(w.org, 'mandate_expiry');
    const settling = marks.settle();
    onTestFinished(async () => {
      held.letGo();
      await settling;
    });
    await untilWaiting(held.waiting);

    await shared.movedPastTheUseCase(w, mandateId, 'suspend');
    const made = await markOf(w.org, 'mandate_expiry');
    expect(BigInt(made?.marks ?? '0')).toBeGreaterThan(BigInt(listed?.marks ?? '0'));

    held.letGo();
    await settling;
    expect(await markOf(w.org, 'mandate_expiry')).toEqual(made);
  });
});

describe('the hourly look holds both to their rows', () => {
  it('a mark lost is written for when its rows say, and said once', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const endsAt = new Date(clock.now().getTime() + 2 * HOUR);
    const ending = await endingAt(endsAt);
    await admin().query(`delete from directory.org_work where job in ('request_expiry', 'mandate_expiry')`);

    await createOrgWorkRediscovery({
      list: () => Promise.resolve([w.org, ending.w.org]),
      database: app,
      logger: testLogger(capture),
    }).run();

    expect((await markOf(w.org, 'request_expiry'))?.due_at).toEqual((await waitOf(waiting.id)).waits_until);
    expect((await markOf(ending.w.org, 'mandate_expiry'))?.due_at).toEqual(endsAt);
    expect(lines('org_work.unmarked').map(({ job, late }) => [job, late])).toEqual([
      ['request_expiry', false],
      ['mandate_expiry', false],
    ]);
  });
});

describe("0074, the expiry's index, built apart from 0073's brief locks", () => {
  it("leaves the waiting requests' index on waits_until, and 0042's gone", async () => {
    const rows = await admin().query<{ indexname: string; indexdef: string }>(
      `select indexname, indexdef from pg_catalog.pg_indexes
        where schemaname = 'spend_requests' and indexname in ('requests_waiting_until', 'waiting_for_approval')`,
    );
    expect(rows).toEqual([
      {
        indexname: 'requests_waiting_until',
        indexdef:
          "CREATE INDEX requests_waiting_until ON spend_requests.requests USING btree (org_id, waits_until) WHERE (status = 'APPROVAL_REQUIRED'::text)",
      },
    ]);
  });
});

describe("0073's first marks, for rows written before its triggers", () => {
  // Its last statement, as the migration ran it: the owner can't read the rows through their tenant walls.
  const migration = readFileSync(new URL('../../../db/migrations/0073_expiry_marks.sql', import.meta.url), 'utf8');
  const firstMarks = migration.slice(migration.indexOf('INSERT INTO directory.org_work'));

  it('marks every organisation due now for both expiries, leaving a mark that stands as it was', async () => {
    const one = await ready();
    const two = await ready();
    await admin().query('delete from directory.org_work');
    await admin().query(
      `insert into directory.org_work (org_id, job, due_at) values ($1, 'request_expiry', pg_catalog.now() + interval '1 day')`,
      [two.w.org],
    );
    const standing = await markOf(two.w.org, 'request_expiry');
    const started = await serverNow();

    // eslint-disable-next-line agentx/no-string-built-sql -- the migration's own fixed text, read from its file
    await database.as('owner').query(firstMarks);

    for (const job of ['request_expiry', 'mandate_expiry'] as const) {
      const due = (await markOf(one.w.org, job))?.due_at.getTime() ?? 0;
      expect(due).toBeGreaterThanOrEqual(started);
      expect(due).toBeLessThanOrEqual(await serverNow());
    }
    expect(await markOf(two.w.org, 'request_expiry')).toEqual(standing);
    expect(await markOf(two.w.org, 'mandate_expiry')).toBeDefined();
  });
});

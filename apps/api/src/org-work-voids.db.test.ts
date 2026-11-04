// The request voids following their marks (4D2e D9, 0075), on the real tables as the app
// role: every cause a void may give marks the job as its stop is written (a walk of
// VOID_CAUSES), a source's consent marks it for when it ends, each visit settles the mark
// to what the rows next need, the hourly look holds the mark to the rows, and the
// marks' commits against the signed writes and the settle, forced. The waiting
// rejections' and the carry rest's are their jobs' own tests (policy-waiting.db.test.ts,
// mandate-carry.db.test.ts); 0075's locks are migrate.db.test.ts's.
import { readFileSync } from 'node:fs';

import { AGENTS } from '@agentx/core/modules/agents';
import { type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { policyOf, setPolicy } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { SPEND_REQUESTS, VOID_CAUSES, type VoidCause } from '@agentx/core/modules/spend-requests';
import { SUPPLIERS } from '@agentx/core/modules/suppliers';
import { createDatabase, type Database, type DatabaseTransaction } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import type { Gate } from './fair-lanes.ts';
import type { HandoffWorldTables } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import { createOrgWorkRediscovery, markedOrganisations, withOrgWork } from './org-work.ts';
import { createRequestVoids, requestVoidsDue } from './request-voids.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';
import { choiceDetails } from './suspensions.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xd9a0_0000_0000);

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'org_work_voids',
  registry: () => registry,
  decisions: () => decisions,
});
const { ready, ask, statusOf, mandateIdOf, moved, signed, STOPS, quiet } = shared;

const admin = () => database.as('admin');
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The organisation's mark of the voids, if any. */
async function markOf(org: string) {
  const [row] = await admin().query<{ due_at: Date; marks: string }>(
    `select due_at, marks from directory.org_work where org_id = $1 and job = 'request_voids'`,
    [org],
  );
  return row;
}

/** The server's time now: the triggers' marks are its clock's. */
const serverNow = async () =>
  (await admin().query<{ now: Date }>('select pg_catalog.now() as now'))[0]?.now.getTime() ?? 0;

/** The organisation's voids mark taken away: what a write since must make again. */
const unmarked = (w: World) =>
  admin().query(`delete from directory.org_work where org_id = $1 and job = 'request_voids'`, [w.org]);

const voidsMarks = (reads?: Gate) =>
  markedOrganisations({
    job: 'request_voids',
    nextDue: requestVoidsDue,
    database: app,
    logger: testLogger(capture),
    clock,
    ...(reads === undefined ? {} : { reads }),
  });

/** The request voids as job-list.ts makes them: their organisations from their marks, settled after each run. */
function voids(reads?: Gate) {
  const marks = voidsMarks(reads);
  return withOrgWork(
    [marks],
    createRequestVoids({ list: marks.list, database: app, keys, ids, clock, logger: testLogger(capture) }),
  );
}

/** The void's causes, as the request's newest event keeps them. */
async function causesOf(w: World, id: string) {
  const newest = (await shared.eventsAbout(w.org, id, SPEND_REQUESTS.subject)).at(-1);
  expect(newest).toMatchObject({ action: 'spend_request.voided' });
  return String(newest?.details.causes).split(',');
}

type Stop = (w: World, mandateId: string) => Promise<unknown>;

/**
 * Every cause a void may give (VOID_CAUSES), and each way voidCauses reaches it: a stop chosen to cancel, or a row
 * moved to a new version. A consent run out by time is its own test below: no write makes it.
 */
const WAYS: Readonly<Record<VoidCause, readonly (readonly [string, Stop])[]>> = {
  ORG_FROZEN: [['the organisation frozen', (w, mandateId) => moved(w, mandateId, 'organization', 'cancel')]],
  AGENT_SUSPENDED: [['the agent suspended', STOPS['the agent suspended']]],
  MANDATE_NOT_IN_FORCE: [
    ['the mandate suspended', STOPS['the mandate suspended']],
    ['the mandate superseded', STOPS['the mandate superseded']],
    ['the mandate revoked', (w, mandateId) => shared.movedPastTheUseCase(w, mandateId, 'revoke')],
    ['the mandate expired', (w, mandateId) => shared.movedPastTheUseCase(w, mandateId, 'expire')],
  ],
  SOURCE_NOT_USABLE: [
    ['the source suspended', STOPS['the source suspended by the organisation']],
    [
      'the bank ending its consent',
      (w) => shared.partnerSays(w, { availability: 'UNAVAILABLE', consentStatus: 'Revoked' }),
    ],
  ],
  SUPPLIER_NOT_VERIFIED: [['the supplier suspended', STOPS['the supplier suspended']]],
  SUPPLIER_CHANGED: [['the supplier’s details changed', STOPS['the supplier’s details changed']]],
};

const EVERY_WAY = VOID_CAUSES.flatMap((cause) => WAYS[cause].map(([what, stop]) => [what, cause, stop] as const));

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

describe('every cause a void may give marks the voids as its stop commits', () => {
  it('walks every member of VOID_CAUSES, each by at least one way', () => {
    expect(new Set(EVERY_WAY.map(([, cause]) => cause))).toEqual(new Set(VOID_CAUSES));
  });

  it.each(EVERY_WAY)(
    '%s marks it at once; visited, voided %s, then the mark settles past now',
    async (_what, cause, stop) => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      await unmarked(w);

      await stop(w, await mandateIdOf(w));

      const mark = await markOf(w.org);
      expect(mark?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
      await voids().run();
      expect(await statusOf(w, waiting.id)).toBe('DENIED');
      expect(await causesOf(w, waiting.id)).toContain(cause);
      // Nothing stopped is left: due as its source's consent ends, or none once the source has ended.
      const [source] = await admin().query<{ status: string }>(
        'select status from funding_sources.sources where id = $1',
        [w.source],
      );
      expect((await markOf(w.org))?.due_at).toEqual(source?.status === 'ENDED' ? undefined : w.state.consentExpiresAt);
    },
  );
});

describe('the voids follow their marks', () => {
  it('a stop that pauses marks it too; visited, nothing moves, and the mark settles to the consent’s end', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await unmarked(w);

    await moved(w, await mandateIdOf(w), 'agent', 'pause');
    expect(await markOf(w.org)).toBeDefined();
    await voids().run();

    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect((await markOf(w.org))?.due_at).toEqual(w.state.consentExpiresAt);
  });

  /**
   * A lift chosen to cancel, past its use case: the organisation unfrozen, or the supplier verified again, its
   * requests cancelled (CANCEL_BRAKES' cancelsIfChosen). The use case voids the first 20 itself and leaves the rest to
   * the job; made past it, every request here is that rest.
   */
  const LIFTS = {
    organization: (w: World) =>
      signed(w, (tx, states) =>
        states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'unfreeze', {
          actor: OPERATOR,
          action: 'organization.unfreeze',
          details: choiceDetails('cancel'),
        }),
      ),
    supplier: (w: World) =>
      signed(w, (tx, states) =>
        states.changeStatus(tx, SUPPLIERS, { orgId: w.org, id: w.suppliers[0] ?? '' }, 'reactivate_verified', {
          actor: OPERATOR,
          action: 'supplier.reactivate_verified',
          details: choiceDetails('cancel'),
        }),
      ),
  } as const;

  it.each([
    ['organization', 'ORG_FROZEN'],
    ['supplier', 'SUPPLIER_NOT_VERIFIED'],
  ] as const)(
    'the %s paused, then lifted with its requests cancelled, standing again: marked at once, the rest voided (%s)',
    async (which, cause) => {
      const { w, acting } = await ready();
      const made = [
        await ask(acting, w),
        await ask(acting, w, { orderReference: 'INV-2' }),
        await ask(acting, w, { orderReference: 'INV-3' }),
      ];
      await moved(w, await mandateIdOf(w), which, 'pause');
      await voids().run();
      expect((await markOf(w.org))?.due_at).toEqual(w.state.consentExpiresAt);

      await LIFTS[which](w);
      expect((await markOf(w.org))?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
      await voids().run();

      expect(await Promise.all(made.map(({ id }) => statusOf(w, id)))).toEqual(['DENIED', 'DENIED', 'DENIED']);
      expect(await causesOf(w, made[0]?.id ?? '')).toContain(cause);
    },
  );

  it('a stop chosen to cancel, lifted before the run: its mark stands, and the request is voided', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const mandateId = await mandateIdOf(w);
    await unmarked(w);

    await moved(w, mandateId, 'agent', 'cancel');
    await moved(w, mandateId, 'agent', 'resume');
    await voids().run();

    expect(await statusOf(w, waiting.id)).toBe('DENIED');
    expect(await causesOf(w, waiting.id)).toEqual(['AGENT_SUSPENDED']);
  });

  it('a source made marks it; visited, the mark moves to its consent’s end; then its lapse logged and voided', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    expect(await markOf(w.org)).toBeDefined();

    await voids().run();
    expect((await markOf(w.org))?.due_at).toEqual(w.state.consentExpiresAt);
    // Not due before its end: a run then leaves it as it stands.
    clock.advanceBy(w.state.consentExpiresAt.getTime() - clock.now().getTime() - 60_000);
    const before = await markOf(w.org);
    await voids().run();
    expect(await markOf(w.org)).toEqual(before);
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');

    clock.advanceBy(60_000);
    await voids().run();
    expect(lines('consent_lapse.recorded')).toHaveLength(1);
    expect(await statusOf(w, waiting.id)).toBe('DENIED');
    expect(await causesOf(w, waiting.id)).toEqual(['SOURCE_NOT_USABLE']);
    // The lapse's own write marked it again: the next visit finds nothing left, and the mark goes.
    await voids().run();
    expect(await markOf(w.org)).toBeUndefined();
    expect(lines('consent_lapse.recorded')).toHaveLength(1);
  });

  it('a consent renewed, its source still active, marks it; visited, the mark moves to the new end', async () => {
    const { w } = await ready();
    await voids().run();
    expect((await markOf(w.org))?.due_at).toEqual(w.state.consentExpiresAt);
    const renewed = new Date(w.state.consentExpiresAt.getTime() + 30 * 24 * 60 * 60_000);

    await shared.partnerSays(w, { consentExpiresAt: renewed });
    expect((await markOf(w.org))?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
    await voids().run();

    expect((await markOf(w.org))?.due_at).toEqual(renewed);
  });

  it('a request left past its share keeps the organisation due, visited each run until none is left', async () => {
    const { w, acting } = await ready();
    const made = [await ask(acting, w), await ask(acting, w, { orderReference: 'INV-2' })];
    await STOPS['the agent suspended'](w);
    const marks = voidsMarks();
    const job = withOrgWork(
      [marks],
      createRequestVoids({ list: marks.list, database: app, keys, ids, clock, logger: testLogger(capture), most: 1 }),
    );

    await job.run();
    expect((await markOf(w.org))?.due_at.getTime()).toBeLessThanOrEqual(clock.now().getTime());
    await job.run();

    expect(await Promise.all(made.map(({ id }) => statusOf(w, id)))).toEqual(['DENIED', 'DENIED']);
    expect((await markOf(w.org))?.due_at).toEqual(w.state.consentExpiresAt);
  });
});

describe('the hourly look holds the voids’ mark to their rows', () => {
  const lookAt = (w: World) =>
    createOrgWorkRediscovery({
      list: () => Promise.resolve([w.org]),
      database: app,
      logger: testLogger(capture),
      clock,
    });

  it('a world made and visited leaves nothing unmarked, late or to clear', async () => {
    const { w, acting } = await ready();
    await ask(acting, w);
    // Each of the three jobs visited once, as 0075 and the writes left them due.
    await voids().run();
    await admin().query(
      `delete from directory.org_work where org_id = $1 and job in ('waiting_rejections', 'carry_rest', 'mandate_expiry')`,
      [w.org],
    );

    await lookAt(w).run();

    expect(lines('org_work.unmarked')).toEqual([]);
    expect(lines('org_work.rediscovered')).toEqual([
      expect.objectContaining({ organisations: 1, unmarked: 0, late: 0, cleared: 0, failed: 0 }),
    ]);
  });

  it('a mark lost on a stopped request is written now and said; one lost on a consent is written for its end', async () => {
    const stopped = await ready();
    await ask(stopped.acting, stopped.w);
    await STOPS['the agent suspended'](stopped.w);
    const standing = await ready();
    await unmarked(stopped.w);
    await unmarked(standing.w);

    await lookAt(stopped.w).run();
    await lookAt(standing.w).run();

    expect((await markOf(stopped.w.org))?.due_at.getTime()).toBeLessThanOrEqual(clock.now().getTime());
    expect((await markOf(standing.w.org))?.due_at).toEqual(standing.w.state.consentExpiresAt);
    expect(lines('org_work.unmarked').filter(({ job }) => job === 'request_voids')).toHaveLength(2);
  });

  it('a consent run out with its lapse not yet logged is work on its own, with no request: written due now', async () => {
    const { w } = await ready();
    clock.advanceBy(w.state.consentExpiresAt.getTime() - clock.now().getTime() + 60_000);
    await unmarked(w);

    await lookAt(w).run();

    expect((await markOf(w.org))?.due_at.getTime()).toBeLessThanOrEqual(clock.now().getTime());
    await voids().run();
    expect(lines('consent_lapse.recorded')).toHaveLength(1);
  });
});

describe('the marks in COMMIT, against the signed writes and the settle (forced)', () => {
  it('two signed writes marking the voids and the rejections in opposite order: the second waits at the head, both keep', async () => {
    const { w } = await ready();
    const mandateId = await mandateIdOf(w);
    await admin().query('delete from directory.org_work where org_id = $1', [w.org]);
    let letGo = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      letGo = resolve;
    });
    let sayMoved = (): void => undefined;
    const movedFirst = new Promise<void>((resolve) => {
      sayMoved = resolve;
    });
    const change = { actor: OPERATOR, details: {} } as const;

    // The voids, then the rejections.
    const voidsFirst = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        ...change,
        action: 'agent.suspended',
      });
      sayMoved();
      await held;
      await policySetIn(tx, states, w, null);
    });
    await Promise.race([movedFirst, voidsFirst]);
    // The rejections, then the voids: it reaches the head behind the one above.
    const rejectionsFirst = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await policySetIn(tx, states, w, mandateId);
      await states.changeStatus(tx, SOURCES, { orgId: w.org, id: w.source }, 'suspend', {
        ...change,
        action: 'funding_source.suspended',
      });
    });
    await waitUntilQueued(admin(), 1);
    letGo();
    await Promise.all([voidsFirst, rejectionsFirst]);

    const rows = await admin().query<{ job: string; marks: string }>(
      `select job, marks from directory.org_work where org_id = $1 and job in ('request_voids', 'waiting_rejections')`,
      [w.org],
    );
    // Each transaction marked each job at least once: two writes each, none lost to the other's.
    expect(Object.fromEntries(rows.map(({ job, marks }) => [job, BigInt(marks) >= 2n]))).toEqual({
      request_voids: true,
      waiting_rejections: true,
    });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('a settle holds no mark while it reads: a stop commits at once, its mark stands, and the next run voids', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    let letGo = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      letGo = resolve;
    });
    let waitingAt = 0;
    const gate: Gate = {
      run: async (_key, work) => {
        waitingAt += 1;
        await held;
        return work();
      },
    };

    const running = voids(gate).run();
    for (let turn = 0; waitingAt === 0 && turn <= 200; turn += 1) await new Promise((r) => setTimeout(r, 5));
    expect(waitingAt).toBe(1);
    // The run found nothing stopped; the stop commits now, its mark moved while the settle has yet to read.
    await STOPS['the agent suspended'](w);
    letGo();
    await running;

    expect((await markOf(w.org))?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
    await voids().run();
    expect(await statusOf(w, waiting.id)).toBe('DENIED');
  });
});

/** The organisation's policy, or its mandate's, set past the use case in a transaction already open: a version made. */
async function policySetIn(
  tx: DatabaseTransaction<HandoffWorldTables>,
  states: SignedStates,
  w: World,
  mandateId: string | null,
) {
  const read = await policyOf(tx, states, { orgId: w.org, id: mandateId ?? w.org }, 'change');
  return setPolicy(tx, states, {
    orgId: w.org,
    existing: read.outcome === 'found' ? read : null,
    scope: mandateId === null ? 'organization' : 'mandate',
    mandateId,
    versionId: ids.next(),
    rules: {
      currency: 'AED',
      perOrderCap: null,
      monthlyCap: AED(5_000_000n),
      approvalThreshold: null,
      supplierIds: null,
    },
    madeBy: w.admin.membershipId,
    madeAt: clock.now(),
    actor: { type: 'user', id: w.admin.userId },
    details: {},
  });
}

describe("0076's first marks, for rows written before 0075's triggers", () => {
  // Its last statement, as the migration ran it: the owner can't read the rows through their tenant walls.
  const migration = readFileSync(new URL('../../../db/migrations/0076_void_first_marks.sql', import.meta.url), 'utf8');
  const firstMarks = migration.slice(migration.indexOf('INSERT INTO directory.org_work'));
  const JOBS = ['request_voids', 'waiting_rejections', 'carry_rest'];

  it('marks every organisation due now for the three jobs, leaving a mark that stands as it was', async () => {
    const one = await ready();
    const two = await ready();
    await admin().query('delete from directory.org_work');
    await admin().query(
      `insert into directory.org_work (org_id, job, due_at) values ($1, 'request_voids', pg_catalog.now() + interval '1 day')`,
      [two.w.org],
    );
    const standing = await markOf(two.w.org);
    const started = await serverNow();

    // eslint-disable-next-line agentx/no-string-built-sql -- the migration's own fixed text, read from its file
    await database.as('owner').query(firstMarks);

    const marked = await admin().query<{ org_id: string; job: string; due_at: Date }>(
      'select org_id, job, due_at from directory.org_work where org_id = any($1::uuid[])',
      [[one.w.org, two.w.org]],
    );
    expect(
      marked
        .filter(({ org_id }) => org_id === one.w.org)
        .map(({ job }) => job)
        .toSorted(),
    ).toEqual(JOBS.toSorted());
    for (const { due_at } of marked.filter(({ org_id }) => org_id === one.w.org)) {
      expect(due_at.getTime()).toBeGreaterThanOrEqual(started);
      expect(due_at.getTime()).toBeLessThanOrEqual(await serverNow());
    }
    expect(await markOf(two.w.org)).toEqual(standing);
    expect(marked.filter(({ org_id }) => org_id === two.w.org)).toHaveLength(3);
  });
});

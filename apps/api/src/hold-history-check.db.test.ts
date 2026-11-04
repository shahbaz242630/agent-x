// The whole history checked while an integrity hold stands (Phase 2 D1c), on
// the real migrated schema, as the app role: a stand-in growing table (built
// as a module builds one, with `liveStatuses`), its rows sealed as a module
// seals them, and the database's owner as the attacker. The job checks a held
// organisation's every row, ended ones too, a batch at a time across runs,
// and records it once whole; a record tampered with starts it again; a CLEAR
// organisation, or one already checked, is left alone; an organisation list
// that can't be read is logged as an error (Phase 2 E2c).
import { readFileSync } from 'node:fs';

import { type CheckedTable, holdHistoryDue, markHoldsWith, withSignedStates } from '@agentx/core/modules/audit';
import { markOrgWork, markOrgWorkNow } from '@agentx/core/modules/directory';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import type { HandoffWorldTables } from './handoff-world.helper.test.ts';
import { createHoldHistoryCheck } from './hold-history-check.ts';
import { createOrgWorkRediscovery, markedOrganisations, withOrgWork } from './org-work.ts';
import type { UseCaseTables } from './use-case-work.ts';

/** A stand-in growing table: a status sealed, checked at clearing in its LIVE rows alone. */
const REQUESTS = {
  table: 'probe.requests',
  subject: 'spend_request',
  fields: [{ column: 'status', type: 'text' }],
  liveStatuses: ['LIVE'],
} as const satisfies CheckedTable;

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  'grant usage on schema probe to agentx_app',
  'create table probe.requests (org_id uuid not null, id uuid not null, status text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))',
  'alter table probe.requests enable row level security',
  'alter table probe.requests force row level security',
  `create policy tenant_isolation on probe.requests ${TENANT_POLICY}`,
  'grant select, insert on probe.requests to agentx_app',
  'grant update (status, state_version, state_event_id) on probe.requests to agentx_app',
];

type Tables = UseCaseTables &
  OrganizationsTables & {
    'probe.requests': { org_id: string; id: string; status: string; state_version?: number; state_event_id?: string };
  };

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xd1c0_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
/** Each test's own lines: the hold's are said through these. */
const services = () => ({ keys, ids, logger: testLogger(capture) });

let capture: LogCapture;
let org: string;
let owner: OwnerTamper;
/** The newest investigation recorded in the test, if any. */
let latest: string | undefined;
const ADMIN = { type: 'user' as const, id: '0199a0f0-0000-7000-8000-0000000000ad' };

/** Adds a request in the status given and seals it, as a module does. */
async function request(status: 'LIVE' | 'ENDED'): Promise<string> {
  const id = ids.next();
  await withSignedStates(app, org, services(), async (tx, states) => {
    await tx.insertInto('probe.requests').values({ org_id: org, id, status }).execute();
    await states.record(
      tx,
      REQUESTS,
      { orgId: org, id },
      'new',
      { status },
      {
        actor: OPERATOR,
        action: 'spend_request.created',
        details: {},
      },
    );
  });
  return id;
}

/** The admin's investigation of the hold as it stands, recorded: its ID. */
async function investigated(): Promise<string> {
  const id = ids.next();
  const recorded = await withSignedStates(app, org, services(), (tx, states) =>
    states.recordInvestigation(tx, org, { id, actor: ADMIN, conclusion: 'CAUSE_REMOVED', reference: 'INC-7' }),
  );
  if (recorded.outcome !== 'recorded') throw new Error('the hold should be HELD');
  return id;
}

/**
 * A request changed past the app and read, then put back: the organisation
 * HELD, its cause removed, and investigated unless `investigate` is false.
 */
async function held(investigate = true): Promise<void> {
  const id = await request('ENDED');
  const saved = await owner.saveRow(id);
  await owner.setColumn(id, 'status', 'LIVE');
  await withSignedStates(app, org, services(), (tx, states) =>
    states.verifiedState(tx, REQUESTS, { orgId: org, id }, 'share'),
  );
  await owner.restoreRow(saved);
  if (investigate) latest = await investigated();
}

const holdNow = () => withSignedStates(app, org, services(), (tx, states) => states.holdRecord(tx, org));

/** Whether the whole history was checked after the newest investigation. */
const checked = () =>
  withSignedStates(app, org, services(), (tx, states) => states.historyChecked(tx, org, latest ?? ids.next()));

const job = (batch = 2, batchesARun = 1, tables: readonly CheckedTable[] = [REQUESTS]) =>
  createHoldHistoryCheck({
    list: () => Promise.resolve([org]),
    database: app,
    keys,
    ids,
    logger: testLogger(capture),
    tables,
    batch,
    batchesARun,
  });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  owner = await tamperAsOwner(database, REQUESTS, org);
  latest = undefined;
});

afterEach(async () => {
  await owner.end();
});

describe(`the whole history checked while a hold stands (Phase 2 D1c, Postgres ${server.version})`, () => {
  it('checks every row, ended ones too, a batch at a time across runs, and records it once whole', async () => {
    await request('LIVE');
    await request('ENDED');
    await held();
    await request('ENDED');
    const checking = job();

    // Four rows, two a batch, one batch a run: the second run takes the last of them.
    await checking.run();
    expect(await checked()).toBe('unchecked');
    await checking.run();

    expect(await checked()).toBe('checked');
    expect(lines('hold_history.checked')).toEqual([expect.objectContaining({ objects: 4 })]);
    // Checked already: a later run records nothing more.
    await checking.run();
    expect(lines('hold_history.checked')).toHaveLength(1);
  });

  it('starts again from the beginning when a batch finds a record tampered with, and records nothing till it is whole', async () => {
    const first = await request('ENDED');
    await held();
    const saved = await owner.saveRow(first);
    await owner.setColumn(first, 'status', 'GONE');
    const checking = job(10);

    await checking.run();
    expect(await checked()).toBe('unchecked');
    expect(lines('hold_history.tampered')).toEqual([
      expect.objectContaining({ subjectType: 'spend_request', findings: 1 }),
    ]);

    await owner.restoreRow(saved);
    await checking.run();
    expect(await checked()).toBe('checked');
  });

  it('finds a row deleted from the log, and keeps the hold unchecked', async () => {
    await held();
    const gone = await request('ENDED');
    await owner.deleteRow(gone);

    await job(10).run();

    expect(await checked()).toBe('unchecked');
    expect(lines('hold_history.tampered')).toHaveLength(1);
  });

  it('waits for an investigation of the hold, so the check runs once its cause is declared removed (D1c review)', async () => {
    await request('ENDED');
    await held(false);
    const checking = job(10);

    await checking.run();
    expect(lines('hold_history.checked')).toEqual([]);

    latest = await investigated();
    await checking.run();
    expect(await checked()).toBe('checked');
  });

  it('checks again after a newer investigation of the same hold', async () => {
    await held();
    const checking = job(10);
    await checking.run();
    expect(await checked()).toBe('checked');

    latest = await investigated();
    expect(await checked()).toBe('unchecked');
    await checking.run();
    expect(await checked()).toBe('checked');
    expect(lines('hold_history.checked')).toHaveLength(2);
  });

  it('leaves a CLEAR organisation alone', async () => {
    await request('ENDED');

    await job(10).run();

    expect(await holdNow()).toMatchObject({ outcome: 'clear' });
    expect(lines('hold_history.checked')).toEqual([]);
  });

  it('stops when told to, and goes on from where it got to', async () => {
    await request('ENDED');
    await request('ENDED');
    await held();
    const checking = job(1, 1);
    const stop = new AbortController();
    stop.abort();

    await checking.run(stop.signal);
    expect(await checked()).toBe('unchecked');
    for (let run = 0; run < 4; run += 1) await checking.run();

    expect(await checked()).toBe('checked');
    expect(lines('hold_history.checked')).toEqual([expect.objectContaining({ objects: 3 })]);
  });

  it('does nothing when no table grows', async () => {
    await held();

    await job(10, 1, []).run();

    expect(await checked()).toBe('unchecked');
  });

  it('logs an organisation list that can’t be read as an error, which the integrity-runs alert counts, and checks nothing (E2c)', async () => {
    await request('ENDED');
    await held();

    await createHoldHistoryCheck({
      list: () => Promise.reject(new Error('the directory is down')),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      tables: [REQUESTS],
    }).run();

    expect(lines('hold_history.run_failed')).toEqual([expect.objectContaining({ level: 'error' })]);
    expect(await checked()).toBe('unchecked');
  });
});

describe(`the hold history on its marks (4D2e D10, Postgres ${server.version})`, () => {
  /** The same database as the marks read it: their hourly look reads every job's rows. */
  let marksApp: Database<HandoffWorldTables>;
  const admin = () => database.as('admin');
  const markOf = async () =>
    (
      await admin().query<{ due_at: Date; marks: string }>(
        `select due_at, marks from directory.org_work where org_id = $1 and job = 'hold_history'`,
        [org],
      )
    )[0];
  const serverNow = async () =>
    (await admin().query<{ now: Date }>('select pg_catalog.now() as now'))[0]?.now.getTime() ?? 0;
  const markingAsBooted = () => {
    markHoldsWith((tx, orgId) => markOrgWorkNow(tx, orgId, 'hold_history'));
  };

  /** The job as job-list.ts makes it: its organisations from its marks, settled after each run. */
  const onMarks = () => {
    const marks = markedOrganisations({
      job: 'hold_history',
      nextDue: holdHistoryDue,
      database: marksApp,
      logger: testLogger(capture),
    });
    return withOrgWork(
      [marks],
      createHoldHistoryCheck({
        list: marks.list,
        database: app,
        keys,
        ids,
        logger: testLogger(capture),
        tables: [REQUESTS],
        batch: 10,
        batchesARun: 1,
      }),
    );
  };

  beforeAll(() => {
    marksApp = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
    markingAsBooted();
  });

  afterAll(async () => {
    markHoldsWith(undefined);
    await marksApp.destroy();
  });

  it('a hold set marks its history due at once, in its own transaction; a finding under it marks nothing more', async () => {
    await request('LIVE');
    expect(await markOf()).toBeUndefined();

    const before = await serverNow();
    await held(false);
    const mark = await markOf();
    expect(mark?.due_at.getTime()).toBeGreaterThanOrEqual(before);
    expect(mark?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());

    // Another record found under the standing hold: no hold set, so no mark made.
    await held(false);
    expect((await holdNow()).outcome).toBe('held');
    expect(await markOf()).toEqual(mark);
  });

  it('the job visits a held organisation on its mark, checks its whole history, and keeps it due while the hold stands', async () => {
    await request('LIVE');
    await held();
    const job = onMarks();

    await job.run();

    expect(await checked()).toBe('checked');
    expect(lines('hold_history.checked')).toEqual([expect.objectContaining({ objects: 2 })]);
    // Still held: due now, so visited each run until the hold is cleared.
    expect((await markOf())?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
  });

  it('its due read is now while held, and none for an organisation clear: a mark there goes at the visit', async () => {
    const dueOf = async () =>
      (await withSignedStates(app, org, services(), (tx) => holdHistoryDue(tx, org, NOW).executeTakeFirst()))?.due;
    const NOW = new Date('2026-11-04T08:00:00.000Z');
    expect(await dueOf()).toBeNull();
    await markOrgWork(marksApp, org, 'hold_history', new Date(Date.now() - 60_000));

    await onMarks().run();

    expect(await markOf()).toBeUndefined();
    await held(false);
    expect(await dueOf()).toEqual(NOW);
  });

  it('given no way to mark, a hold set marks nothing, and the hourly look writes it and says so', async () => {
    markHoldsWith(undefined);
    try {
      await held(false);
    } finally {
      markingAsBooted();
    }
    expect(await markOf()).toBeUndefined();

    await createOrgWorkRediscovery({
      list: () => Promise.resolve([org]),
      database: marksApp,
      logger: testLogger(capture),
    }).run();

    expect(lines('org_work.unmarked')).toEqual([expect.objectContaining({ job: 'hold_history', late: false })]);
    expect(await markOf()).toBeDefined();
  });

  it('a hold set while its mark is held by a settle waits for it, after the head, and both go through (forced)', async () => {
    const later = new Date(Date.now() + 3_600_000);
    await markOrgWork(marksApp, org, 'hold_history', later);
    const standing = await markOf();
    const holder = await database.connect('admin');
    await holder.query('begin');
    // As a settle holds a page of marks, from its statement to its commit.
    await holder.query(`select 1 from directory.org_work where org_id = $1 and job = 'hold_history' for update`, [org]);
    const holding = held(false);
    try {
      await waitUntilQueued(admin(), 1);
      await holder.query('commit');
    } finally {
      await holder.end();
    }
    await within(10_000, holding, 'the hold');

    expect((await holdNow()).outcome).toBe('held');
    const mark = await markOf();
    expect(BigInt(mark?.marks ?? '0')).toBe(BigInt(standing?.marks ?? '0') + 1n);
    expect(mark?.due_at.getTime()).toBeLessThan(later.getTime());
    expect(lines('audit.integrity_failed').filter((line) => line.check === 'hold')).toEqual([]);
  });

  it('a hold set while its mark is held past the mark’s limit still commits; the miss is said, and the hourly look marks it (forced)', async () => {
    // Another transaction making the same mark, uncommitted: the hold's mark waits on its row past 500 ms.
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query(
      `insert into directory.org_work (org_id, job, due_at) values ($1, 'hold_history', pg_catalog.now())`,
      [org],
    );
    try {
      await within(10_000, held(false), 'the hold');
    } finally {
      await holder.query('rollback');
      await holder.end();
    }

    expect((await holdNow()).outcome).toBe('held');
    expect(lines('org_work.hold_mark_skipped')).toEqual([expect.objectContaining({ level: 'warn', orgId: org })]);
    expect(lines('audit.integrity_failed').filter((line) => line.check === 'hold')).toEqual([]);
    expect(await markOf()).toBeUndefined();
    await createOrgWorkRediscovery({
      list: () => Promise.resolve([org]),
      database: marksApp,
      logger: testLogger(capture),
    }).run();
    expect(lines('org_work.unmarked')).toEqual([expect.objectContaining({ job: 'hold_history', late: false })]);
    expect(await markOf()).toBeDefined();
  });

  it('a mark for an organisation the directory does not list makes nothing, and fails nothing', async () => {
    const unlisted = ids.next();
    await withSignedStates(app, org, services(), (tx) => markOrgWorkNow(tx, unlisted, 'hold_history'));
    expect(await admin().query('select 1 from directory.org_work where org_id = $1', [unlisted])).toEqual([]);
  });
});

describe("0078's first marks, for rows and holds from before 0077", () => {
  // Its last statement, as the migration ran it: the owner can't read the rows through their tenant walls.
  const migration = readFileSync(
    new URL('../../../db/migrations/0078_reset_download_hold_first_marks.sql', import.meta.url),
    'utf8',
  );
  const firstMarks = migration.slice(migration.indexOf('INSERT INTO directory.org_work'));
  const JOBS = ['background_downloads', 'factor_removals', 'hold_history'];
  const admin = () => database.as('admin');
  const marksOf = (orgId: string) =>
    admin().query<{ job: string; due_at: Date; marks: string }>(
      'select job, due_at, marks from directory.org_work where org_id = $1 order by job',
      [orgId],
    );

  it('marks every organisation due now for the three jobs, leaving a mark that stands as it was', async () => {
    const other = ids.next();
    await withSignedStates(app, other, services(), (tx, states) =>
      createOrganization(tx, states, { id: other, name: 'Gulf Supplies LLC', actor: OPERATOR }),
    );
    await admin().query(
      `insert into directory.org_work (org_id, job, due_at) values ($1, 'hold_history', pg_catalog.now() + interval '1 day')`,
      [other],
    );
    const [standing] = await marksOf(other);
    const [{ now: started } = { now: new Date(0) }] = await admin().query<{ now: Date }>(
      'select pg_catalog.now() as now',
    );

    // eslint-disable-next-line agentx/no-string-built-sql -- the migration's own fixed text, read from its file
    await database.as('owner').query(firstMarks);

    const marked = await marksOf(org);
    expect(marked.map(({ job }) => job)).toEqual(JOBS);
    const [{ now: ended } = { now: new Date(0) }] = await admin().query<{ now: Date }>(
      'select pg_catalog.now() as now',
    );
    for (const { due_at } of marked) {
      expect(due_at.getTime()).toBeGreaterThanOrEqual(started.getTime());
      expect(due_at.getTime()).toBeLessThanOrEqual(ended.getTime());
    }
    const others = await marksOf(other);
    expect(others.map(({ job }) => job)).toEqual(JOBS);
    expect(others.find(({ job }) => job === 'hold_history')).toEqual(standing);
  });
});

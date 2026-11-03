// directory.org_work (0072), proved on Postgres itself: how a deferred trigger with
// WHEN behaves, what limits hold inside COMMIT, that no mark is ever lost, and which
// orders can deadlock. A table of the test's own carries triggers written as 0072's
// are, calling the real function, as the app role: real rows in the real tables are
// org-work.db.test.ts's in apps/api. Every race is forced with a held transaction.
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  type TestClient,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { markOrgWork, settleOrgWork } from './org-work.ts';
import type { DirectoryTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<DirectoryTables>;
let next = 0;
let org: string;
/** The times a test writes into marks by hand: any will do, the triggers' own come from Postgres. */
const clock = new FixedClock(new Date('2026-11-03T09:00:00Z'));
const anHourOn = () => new Date(clock.now().getTime() + 3_600_000);

const clients: TestClient[] = [];

/** A connection of its own for `role`, closed after each test. */
async function connected(role: 'app' | 'admin' | 'backup' = 'app'): Promise<TestClient> {
  const client = await database.connect(role);
  clients.push(client);
  return client;
}

const admin = () => database.as('admin');

/** The organisation's marks, by job. */
async function marksOf(orgId = org): Promise<Record<string, { due_at: Date; marks: string }>> {
  const rows = await admin().query<{ job: string; due_at: Date; marks: string }>(
    'select job, due_at, marks from directory.org_work where org_id = $1',
    [orgId],
  );
  return Object.fromEntries(rows.map(({ job, ...rest }) => [job, rest]));
}

/** A write's row in the test's table: a transaction's statement, marked or not by its status. */
const write = (client: TestClient, status: string) =>
  client.query('insert into audit.marked_rows (org_id, status) values ($1, $2) returning id', [org, status]);

/** The two statuses mark one job each, so a transaction chooses the order it marks them in. */
const HAND_OFF = 'APPROVED';
const CHECK = 'SUBMITTED';

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<DirectoryTables>(
    { ...database.connection('app'), tls: 'disable', maxConnections: 4 },
    testLogger(),
  );
  const owner = database.as('owner');
  await owner.query(
    `create table audit.marked_rows (
       id bigint generated always as identity primary key, org_id uuid not null, status text not null)`,
  );
  await owner.query('grant select, insert, update on audit.marked_rows to agentx_app, agentx_backup');
  await owner.query(
    `create constraint trigger marks_a after insert or update on audit.marked_rows
       deferrable initially deferred for each row when (new.status = 'APPROVED')
       execute function directory.mark_org_work('hand_off', '0 seconds')`,
  );
  await owner.query(
    `create constraint trigger marks_b after insert or update on audit.marked_rows
       deferrable initially deferred for each row when (new.status = 'SUBMITTED')
       execute function directory.mark_org_work('payment_check', '10 minutes')`,
  );
}, 60_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  next += 1;
  org = `0199a0f0-0000-7000-8000-${String(next).padStart(12, '0')}`;
  await admin().query('insert into directory.orgs (org_id) values ($1)', [org]);
  return async () => {
    for (const client of clients.splice(0)) await client.end();
  };
});

describe('a deferred trigger with WHEN', () => {
  it('makes no mark until COMMIT, and none on a rollback', async () => {
    const one = await connected();
    await one.query('begin');
    await write(one, HAND_OFF);
    expect(await one.query('select 1 from directory.org_work where org_id = $1', [org])).toEqual([]);
    await one.query('rollback');
    expect(await marksOf()).toEqual({});

    await one.query('begin');
    await write(one, HAND_OFF);
    await one.query('commit');
    expect(Object.keys(await marksOf())).toEqual(['hand_off']);
  });

  it('makes none for a row its condition leaves out', async () => {
    const one = await connected();
    await write(one, 'DENIED');
    expect(await marksOf()).toEqual({});
  });

  it('reads WHEN as the row is written, not at COMMIT: a row moved on in the transaction still marks', async () => {
    const one = await connected();
    await one.query('begin');
    const [row] = await write(one, HAND_OFF);
    await one.query(`update audit.marked_rows set status = 'HANDED_OFF' where id = $1`, [row?.id]);
    await one.query('commit');
    expect(Object.keys(await marksOf())).toEqual(['hand_off']);
  });

  it('reads WHEN as the row is written the other way too: a row moved into it marks, once', async () => {
    const one = await connected();
    await one.query('begin');
    const [row] = await write(one, 'VALIDATING');
    await one.query(`update audit.marked_rows set status = 'APPROVED' where id = $1`, [row?.id]);
    await one.query('commit');
    const before = (await marksOf()).hand_off?.marks ?? '';
    await one.query(`update audit.marked_rows set status = 'HANDED_OFF' where id = $1`, [row?.id]);
    expect((await marksOf()).hand_off?.marks).toBe(before);
  });

  it('moves marks once a row written, each commit or within one, and keeps the earlier due time', async () => {
    const one = await connected();
    await write(one, CHECK);
    const first = (await marksOf()).payment_check;
    await one.query('begin');
    await write(one, CHECK);
    await write(one, CHECK);
    await one.query('commit');
    const second = (await marksOf()).payment_check;
    expect(BigInt(second?.marks ?? '0') - BigInt(first?.marks ?? '0')).toBe(2n);
    // Later transactions' `now() + 10 minutes` are later: the earlier stands.
    expect(second?.due_at).toEqual(first?.due_at);
  });

  it('due is the wait from the transaction, as its arguments say', async () => {
    const one = await connected();
    await one.query('begin');
    const [start] = await one.query<{ now: Date }>('select pg_catalog.now() as now');
    await write(one, CHECK);
    await write(one, HAND_OFF);
    await one.query('commit');
    const marks = await marksOf();
    expect(marks.payment_check?.due_at.getTime()).toBe((start?.now.getTime() ?? 0) + 10 * 60_000);
    expect(marks.hand_off?.due_at.getTime()).toBe(start?.now.getTime());
  });

  it('the backup role reads the marks, as it reads every table it must copy', async () => {
    const one = await connected();
    await write(one, HAND_OFF);
    const backup = await connected('backup');
    expect(await backup.query('select job from directory.org_work where org_id = $1', [org])).toEqual([
      { job: 'hand_off' },
    ]);
  });

  it('runs with the rights of who wrote the row: refused marking, the whole write is refused and nothing kept', async () => {
    // The backup role may write the test's table, and has no right on the marks. Nothing but the mark stops it.
    const other = await connected('backup');
    await other.query('begin');
    await write(other, HAND_OFF);
    await expect(other.query('commit')).rejects.toMatchObject({ code: '42501' });
    const kept = await admin().query('select 1 from audit.marked_rows where org_id = $1', [org]);
    expect(kept).toEqual([]);
  });
});

describe('the limits inside COMMIT, a mark held by another session', () => {
  /** A session holding the row a commit's mark needs. */
  async function holdingTheMark(job = 'hand_off'): Promise<TestClient> {
    await markOrgWork(app, org, job as 'hand_off', clock.now());
    const holder = await connected('admin');
    await holder.query('begin');
    await holder.query('select 1 from directory.org_work where org_id = $1 and job = $2 for update', [org, job]);
    return holder;
  }

  it('statement_timeout does not reach it: the commit waits past it, and goes on once let go', async () => {
    const holder = await holdingTheMark();
    const one = await connected();
    await one.query('begin');
    await one.query(`select pg_catalog.set_config('statement_timeout', '200ms', true)`);
    await write(one, HAND_OFF);
    const committing = one.query('commit');
    await waitUntilQueued(admin(), 1);
    // Five times the limit, on the server's own clock: the wait is still there.
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    expect(await waitUntilQueued(admin(), 1)).toHaveLength(1);
    await holder.query('commit');
    await expect(committing).resolves.toBeDefined();
    expect(await admin().query('select 1 from audit.marked_rows where org_id = $1', [org])).toHaveLength(1);
  });

  it('lock_timeout does: the commit fails, and nothing it wrote is kept', async () => {
    await holdingTheMark();
    const one = await connected();
    await one.query('begin');
    await one.query(`select pg_catalog.set_config('lock_timeout', '200ms', true)`);
    await write(one, HAND_OFF);
    await expect(one.query('commit')).rejects.toMatchObject({ code: '55P03' });
    expect(await admin().query('select 1 from audit.marked_rows where org_id = $1', [org])).toEqual([]);
  });

  it('transaction_timeout, from Postgres 17, ends the connection, and nothing it wrote is kept', async () => {
    const [{ version } = { version: 0 }] = await admin().query<{ version: number }>(
      `select pg_catalog.current_setting('server_version_num')::integer as version`,
    );
    // No such setting on 16, which we also support: only lock_timeout and the deadlock detector hold there.
    if (version < 170_000) return;
    await holdingTheMark();
    const one = await connected();
    await one.query('begin');
    await one.query(`select pg_catalog.set_config('transaction_timeout', '200ms', true)`);
    await write(one, HAND_OFF);
    await expect(one.query('commit')).rejects.toBeDefined();
    expect(await admin().query('select 1 from audit.marked_rows where org_id = $1', [org])).toEqual([]);
  });

  it('a crash while it waits keeps nothing, the write or the mark', async () => {
    const holder = await holdingTheMark();
    const before = (await marksOf()).hand_off?.marks;
    const one = await connected();
    await one.query('begin');
    await write(one, HAND_OFF);
    const committing = one.query('commit');
    await waitUntilQueued(admin(), 1);
    // Heard before the end is sent: the commit can fail before that call answers, and must not go unheard.
    const failed = expect(committing).rejects.toBeDefined();
    await admin().query('select pg_catalog.pg_terminate_backend($1)', [one.pid]);
    await failed;
    await holder.query('commit');
    expect(await admin().query('select 1 from audit.marked_rows where org_id = $1', [org])).toEqual([]);
    expect((await marksOf()).hand_off?.marks).toBe(before);
  });
});

describe('no mark is ever lost', () => {
  const job = 'hand_off';
  const settled = (marks: string, due: Date | null = null) => settleOrgWork(app, { orgId: org, job, marks }, due);

  /** A mark made as a commit makes it, and what a job would read before it looks. */
  async function aMark(): Promise<string> {
    const one = await connected();
    await write(one, HAND_OFF);
    return (await marksOf())[job]?.marks ?? '';
  }

  it('with no later mark, settling takes it away', async () => {
    expect(await settled(await aMark())).toBe(true);
    expect(await marksOf()).toEqual({});
  });

  it('with no later mark and more due, settling moves it there and keeps it', async () => {
    const marks = await aMark();
    const later = anHourOn();
    expect(await settled(marks, later)).toBe(true);
    expect(await marksOf()).toEqual({ [job]: { marks, due_at: later } });
  });

  it('a mark made since the read moves marks, so neither a delete nor an update takes effect', async () => {
    const marks = await aMark();
    const made = (await marksOf())[job]?.due_at;
    await aMark();
    expect(await settled(marks)).toBe(false);
    expect(await settled(marks, anHourOn())).toBe(false);
    const after = (await marksOf())[job];
    expect(after?.marks).toBe(String(BigInt(marks) + 1n));
    expect(after?.due_at).toEqual(made);
  });

  it('settling only touches its own job and its own organisation, to take it away or to move it', async () => {
    const marks = await aMark();
    const made = (await marksOf())[job]?.due_at;
    expect(await settleOrgWork(app, { orgId: org, job: 'payment_check', marks }, null)).toBe(false);
    expect(await settleOrgWork(app, { orgId: org, job: 'payment_check', marks }, anHourOn())).toBe(false);
    const other = '0199a0f0-0000-7000-8000-ffffffffffff';
    await admin().query('insert into directory.orgs (org_id) values ($1) on conflict do nothing', [other]);
    expect(await settleOrgWork(app, { orgId: other, job, marks }, null)).toBe(false);
    expect(await settleOrgWork(app, { orgId: other, job, marks }, anHourOn())).toBe(false);
    expect((await marksOf())[job]).toEqual({ marks, due_at: made });
  });

  it('a mark deleted and made again never reads as the one read before: marks starts from the clock', async () => {
    const marks = await aMark();
    expect(await settled(marks)).toBe(true);
    const again = await aMark();
    expect(again).not.toBe(marks);
    expect(BigInt(again) > BigInt(marks)).toBe(true);
    expect(await settled(marks)).toBe(false);
    expect((await marksOf())[job]?.marks).toBe(again);
  });

  it('a settle waiting behind a commit marking the row sees the marks that commit left, and does nothing', async () => {
    const marks = await aMark();
    // A committing writer's position: it has moved marks and not ended.
    const writer = await connected();
    await writer.query('begin');
    await writer.query('update directory.org_work set marks = marks + 1 where org_id = $1 and job = $2', [org, job]);
    const settling = settled(marks);
    await waitUntilQueued(admin(), 1);
    await writer.query('commit');
    expect(await settling).toBe(false);
    expect((await marksOf())[job]?.marks).toBe(String(BigInt(marks) + 1n));
  });

  it('a commit marking behind a delete makes the mark anew', async () => {
    const marks = await aMark();
    const remover = await connected();
    await remover.query('begin');
    await remover.query('delete from directory.org_work where org_id = $1 and job = $2', [org, job]);
    const one = await connected();
    await one.query('begin');
    await write(one, HAND_OFF);
    const committing = one.query('commit');
    await waitUntilQueued(admin(), 1);
    await remover.query('commit');
    await committing;
    expect(BigInt((await marksOf())[job]?.marks ?? '0') > BigInt(marks)).toBe(true);
  });

  it('a commit marking behind a delete that rolls back still moves marks', async () => {
    const marks = await aMark();
    const remover = await connected();
    await remover.query('begin');
    await remover.query('delete from directory.org_work where org_id = $1 and job = $2', [org, job]);
    const one = await connected();
    await one.query('begin');
    await write(one, HAND_OFF);
    const committing = one.query('commit');
    await waitUntilQueued(admin(), 1);
    await remover.query('rollback');
    await committing;
    expect((await marksOf())[job]?.marks).toBe(String(BigInt(marks) + 1n));
  });

  it('a job that crashes after reading leaves the mark: it never settled', async () => {
    const marks = await aMark();
    const job2 = await connected();
    await job2.query('select marks from directory.org_work where org_id = $1', [org]);
    await job2.end();
    clients.splice(clients.indexOf(job2), 1);
    expect((await marksOf())[job]?.marks).toBe(marks);
  });

  it('marking by hand makes one, and against one standing moves marks and brings due forward only', async () => {
    const soon = new Date(clock.now().getTime() + 60_000);
    await markOrgWork(app, org, job, soon);
    const first = (await marksOf())[job];
    expect(first?.due_at).toEqual(soon);
    await markOrgWork(app, org, job, new Date(soon.getTime() + 60_000));
    const later = (await marksOf())[job];
    expect(later?.due_at).toEqual(soon);
    expect(later?.marks).toBe(String(BigInt(first?.marks ?? '0') + 1n));
    const sooner = new Date(soon.getTime() - 30_000);
    await markOrgWork(app, org, job, sooner);
    expect((await marksOf())[job]?.due_at).toEqual(sooner);
  });
});

describe('two transactions marking two jobs in opposite order', () => {
  /** A transaction that will mark `first` then `second`, its rows written and not committed. */
  async function marking(first: string, second: string): Promise<TestClient> {
    const one = await connected();
    await one.query('begin');
    await write(one, first);
    await write(one, second);
    return one;
  }

  /** Two sessions holding one job's mark each, so both commits start, then cross as they are let go. */
  async function holding(): Promise<{ handOff: TestClient; check: TestClient }> {
    await markOrgWork(app, org, 'hand_off', clock.now());
    await markOrgWork(app, org, 'payment_check', clock.now());
    const handOff = await connected('admin');
    await handOff.query('begin');
    await handOff.query(`select 1 from directory.org_work where org_id = $1 and job = 'hand_off' for update`, [org]);
    const check = await connected('admin');
    await check.query('begin');
    await check.query(`select 1 from directory.org_work where org_id = $1 and job = 'payment_check' for update`, [org]);
    return { handOff, check };
  }

  it('with no lock between them can deadlock inside COMMIT: one is refused whole, the other kept', async () => {
    const held = await holding();
    const one = await marking(HAND_OFF, CHECK);
    const two = await marking(CHECK, HAND_OFF);
    const committed = [one, two].map((client) =>
      client.query('commit').then(
        () => 'kept',
        (error: unknown) => (error as { code?: string }).code,
      ),
    );
    await waitUntilQueued(admin(), 2);
    await held.handOff.query('commit');
    await held.check.query('commit');
    expect((await Promise.all(committed)).toSorted()).toEqual(['40P01', 'kept']);
    expect(await admin().query('select 1 from audit.marked_rows where org_id = $1', [org])).toHaveLength(2);
  });

  it("with a lock both take first, as every signed write takes its chain's head, the second waits there", async () => {
    // Taken as ADR-006 has it, ahead of the commit; the real head's own test is the real tables' (apps/api).
    const head = `select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('head:' || $1, 0))`;
    const one = await connected();
    await one.query('begin');
    await one.query(head, [org]);
    await write(one, HAND_OFF);
    await write(one, CHECK);
    const two = await connected();
    await two.query('begin');
    const queued = two.query(head, [org]);
    await waitUntilQueued(admin(), 1);
    await one.query('commit');
    await queued;
    await write(two, CHECK);
    await write(two, HAND_OFF);
    await two.query('commit');
    expect(await admin().query('select 1 from audit.marked_rows where org_id = $1', [org])).toHaveLength(4);
  });

  it('a settle or a hand mark takes one row in its own transaction, so it can wait behind a commit, never cross it', async () => {
    const held = await holding();
    const one = await marking(HAND_OFF, CHECK);
    const committing = one.query('commit');
    await waitUntilQueued(admin(), 1);
    // The commit waits for hand_off; a settle of payment_check holds nothing it needs next once it has ended.
    const marks = (await marksOf()).payment_check?.marks ?? '';
    const settling = settleOrgWork(app, { orgId: org, job: 'payment_check', marks }, null);
    await waitUntilQueued(admin(), 2);
    await held.check.query('commit');
    expect(await settling).toBe(true);
    await held.handOff.query('commit');
    await committing;
    expect(await admin().query('select 1 from audit.marked_rows where org_id = $1', [org])).toHaveLength(2);
    expect(Object.keys(await marksOf()).toSorted()).toEqual(['hand_off', 'payment_check']);
  });
});

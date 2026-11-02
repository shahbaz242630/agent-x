// 4D2e D5: a hold that couldn't be recorded, kept outside the process. Each
// "process" here is a fresh copy of the modules, with a memory and a pool of its
// own, so what one knows only in memory another can't see: that, and a restart,
// are what the table is for. How the hold itself behaves is with-signed-states.db.test.ts's.
import { sealState, stateSealDetails } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  type TestSession,
  waitUntilQueued,
} from '@agentx/testing';
import type { Transaction } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it, vi } from 'vitest';

import { createAuditTrail, recordHoldEvent } from './audit-trail.ts';
import type { SignedStates } from './signed-states.ts';
import type { AuditTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<AuditTables>;
let attacker: TestSession;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x900);
const trail = createAuditTrail({ keys, ids });

let capture: LogCapture;
const services = () => ({ keys, ids, logger: testLogger(capture) });

let number = 0;
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x9000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;

const OPERATOR = { type: 'system' as const, id: 'test-operator' };

/** An organisation as the app makes one: in the directory (unless not), its hold CLEAR as its first state. */
async function newOrganisation(listed = true): Promise<string> {
  const orgId = newId();
  if (listed) await attacker.query('insert into directory.orgs (org_id) values ($1)', [orgId]);
  const subject = { type: 'integrity_hold', id: orgId, version: 1 };
  const seal = sealState(keys, { orgId, subject, fields: [['status', 'CLEAR']] });
  await withTenant(app, orgId, (tx) =>
    recordHoldEvent(trail, tx, orgId, {
      actor: OPERATOR,
      action: 'integrity_hold.created',
      subject,
      details: { ...stateSealDetails(seal) },
    }),
  );
  return orgId;
}

const pools: { destroy(): Promise<void> }[] = [];

/** A process of its own: a fresh copy of the modules, so nothing in another's memory, or this one's before a restart. */
async function aProcess() {
  vi.resetModules();
  const [signed, platform] = await Promise.all([import('./with-signed-states.ts'), import('@agentx/platform/db')]);
  const pool = platform.createDatabase<AuditTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
  pools.push(pool);
  return {
    pool,
    platform,
    poll: () => signed.pollHoldsWaiting(pool, services()),
    hold: (failure: string | undefined, orgId = org) => signed.holdOrganisation(pool, orgId, services(), failure),
    /** How the hold reads: Tx A reads it with the head's lock, last of all. */
    read: (lock: 'none' | 'head', orgId = org) =>
      signed.withSignedStates(pool, orgId, services(), (tx, states) => states.integrityHold(tx, orgId, lock)),
    work: <T>(work: (tx: Transaction<AuditTables>, states: SignedStates) => Promise<T>) =>
      signed.withSignedStates(pool, org, services(), work),
  };
}

const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const notRecorded = () => lines('audit.integrity_failed').filter(({ reason }) => reason === 'not_recorded');
const rowGone = () => lines('audit.integrity_failed').filter(({ reason }) => reason === 'row_gone');

/** The organisation's hold events, oldest first. */
async function holdEvents(orgId = org): Promise<{ action: string; details: Record<string, unknown> }[]> {
  const rows = await attacker.query<{ action: string; details: string }>(
    "select action, details from audit.events where org_id = $1 and subject_type = 'integrity_hold' order by seq",
    [orgId],
  );
  return rows.map(({ action, details }) => ({ action, details: JSON.parse(details) as Record<string, unknown> }));
}
const actions = async (orgId = org) => (await holdEvents(orgId)).map(({ action }) => action);
const ONE_SET = ['integrity_hold.created', 'integrity_hold.set'];

const waitingRows = (orgId = org) =>
  attacker.query<{ reason: string }>('select reason from directory.holds_waiting where org_id = $1', [orgId]);

/** The head's lock held by a session of the test's own while `work` runs: a hold trying meanwhile runs out its 5 s. */
async function withHeadLocked<T>(work: () => Promise<T>): Promise<T> {
  const locker = await database.connect('admin');
  try {
    await locker.query('begin');
    await locker.query('select seq from audit.heads where org_id = $1 for no key update', [org]);
    return await work();
  } finally {
    await locker.query('rollback');
    await locker.end();
  }
}

/** A hold that couldn't be recorded: one process's, with its row, and nothing yet in the log. */
async function leftWaiting(by: Awaited<ReturnType<typeof aProcess>>): Promise<void> {
  await withHeadLocked(() => by.hold('head'));
  expect(await actions()).toEqual(['integrity_hold.created']);
}

/** The table refusing every insert, or delete, while `work` runs. */
async function withTableRefusing(what: 'insert' | 'delete', work: () => Promise<void>): Promise<void> {
  const owner = database.as('owner');
  await owner.query(
    "create function directory.refuse() returns trigger language plpgsql as $$ begin raise exception 'refused'; end $$",
  );
  // eslint-disable-next-line agentx/no-string-built-sql -- `what` is this test's own word, one of two.
  await owner.query(
    `create trigger refuse before ${what} on directory.holds_waiting for each row execute function directory.refuse()`,
  );
  try {
    await work();
  } finally {
    await owner.query('drop trigger refuse on directory.holds_waiting');
    await owner.query('drop function directory.refuse()');
  }
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<AuditTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
  attacker = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  await attacker.query('delete from directory.holds_waiting');
  org = await newOrganisation();
});

afterEach(async () => {
  await Promise.all(pools.splice(0).map((pool) => pool.destroy()));
});

describe(`holds waiting: another process (4D2e D5, Postgres ${server.version})`, () => {
  it("a hold that couldn't be written is seen by another process's Tx A", async () => {
    const finder = await aProcess();
    await leftWaiting(finder);
    expect(await waitingRows()).toEqual([{ reason: 'chain' }]);
    expect(notRecorded()).toHaveLength(1);

    const other = await aProcess();

    expect(await other.read('head')).toEqual({ outcome: 'tampered', sign: 'chain' });
    // The stated limit: without the head's lock, it learns of it at its next poll.
    expect(await other.read('none')).toMatchObject({ outcome: 'clear' });
    await withHeadLocked(() => other.poll());
    expect(await withHeadLocked(() => other.read('none'))).toEqual({ outcome: 'tampered', sign: 'chain' });
  });

  it('survives a restart: read by Tx A, and recorded by the next process', async () => {
    await leftWaiting(await aProcess());

    const restarted = await aProcess();
    expect(await restarted.read('head')).toEqual({ outcome: 'tampered', sign: 'chain' });
    await restarted.poll();

    expect(await restarted.read('none')).toMatchObject({ outcome: 'held', version: 2 });
    expect(await actions()).toEqual(ONE_SET);
    // A row says the sign and no more: what was found is in the line of the process that found it.
    expect((await holdEvents()).at(-1)?.details).toMatchObject({
      reason: 'chain',
      foundOn: 'hold_waiting',
      objectId: org,
      findings: 1,
    });
    expect(await waitingRows()).toEqual([]);
  });

  it('polled while the head stays locked: kept in the process, and recorded by a later try', async () => {
    await leftWaiting(await aProcess());
    const restarted = await aProcess();
    await withHeadLocked(() => restarted.poll());
    expect(notRecorded()).toHaveLength(2);
    expect(await waitingRows()).toEqual([{ reason: 'chain' }]);
    // The row there already stands: a second try keeps it without complaint.
    expect(lines('audit.hold_not_kept')).toEqual([]);

    // In the table all along, so no alarm that it went, and the next poll has nothing new to try.
    await restarted.poll();
    expect(await actions()).toEqual(['integrity_hold.created']);

    await restarted.hold(undefined);
    expect(await actions()).toEqual(ONE_SET);
    expect(rowGone()).toEqual([]);
  });

  it("reads as waiting here from the poll on, while that poll's own try is still queued on the head", async () => {
    await leftWaiting(await aProcess());
    const other = await aProcess();

    await withHeadLocked(async () => {
      const polling = other.poll();
      await waitUntilQueued(attacker, 1);
      expect(await other.read('none')).toEqual({ outcome: 'tampered', sign: 'chain' });
      return { polling };
    }).then(({ polling }) => polling);

    expect(await actions()).toEqual(ONE_SET);
  });

  it('is recorded and the row cleared once', async () => {
    const finder = await aProcess();
    await leftWaiting(finder);

    await finder.hold(undefined);

    expect(await waitingRows()).toEqual([]);
    expect(await actions()).toEqual(ONE_SET);
    // By the one that found it, with all it knew.
    expect((await holdEvents()).at(-1)?.details).toMatchObject({
      reason: 'chain',
      foundOn: 'audit_chain',
      chainFailure: 'head',
    });
    const other = await aProcess();
    await finder.poll();
    await other.poll();
    await finder.hold(undefined);
    expect(await actions()).toEqual(ONE_SET);
    expect(lines('audit.integrity_hold_set')).toHaveLength(1);
    expect(rowGone()).toEqual([]);
  });

  it('two processes both picking it up record one hold', async () => {
    await leftWaiting(await aProcess());
    const [one, two] = [await aProcess(), await aProcess()];
    const before = notRecorded().length;

    await withHeadLocked(async () => {
      const polls = [one.poll(), two.poll()];
      await waitUntilQueued(attacker, 2);
      return polls;
    }).then((polls) => Promise.all(polls));

    expect(await actions()).toEqual(ONE_SET);
    expect(lines('audit.integrity_hold_set')).toHaveLength(1);
    expect(notRecorded()).toHaveLength(before);
    expect(await waitingRows()).toEqual([]);
  });

  it('a row for one organisation stops nobody else', async () => {
    const neighbour = await newOrganisation();
    await leftWaiting(await aProcess());
    const other = await aProcess();

    expect(await other.read('head', neighbour)).toMatchObject({ outcome: 'clear' });
    await other.poll();

    expect(await other.read('head', neighbour)).toMatchObject({ outcome: 'clear' });
    expect(await actions(neighbour)).toEqual(['integrity_hold.created']);
    expect(await actions()).toEqual(ONE_SET);
  });

  it("recording one organisation's hold leaves another's row where it is", async () => {
    const neighbour = await newOrganisation();
    await attacker.query("insert into directory.holds_waiting (org_id, reason) values ($1, 'seal')", [neighbour]);
    const finder = await aProcess();
    await leftWaiting(finder);

    await finder.hold(undefined);

    expect(await waitingRows()).toEqual([]);
    expect(await waitingRows(neighbour)).toEqual([{ reason: 'seal' }]);
  });

  it("the row goes with the hold's own transaction: a row that can't go leaves the hold unrecorded", async () => {
    const finder = await aProcess();
    await leftWaiting(finder);
    await withTableRefusing('delete', () => finder.hold(undefined));
    expect(await actions()).toEqual(['integrity_hold.created']);
    expect(await waitingRows()).toEqual([{ reason: 'chain' }]);
  });
});

describe(`holds waiting: forged and deleted rows (4D2e D5, Postgres ${server.version})`, () => {
  /** What the app role itself could write. */
  const forge = (reason: string, orgId = org) =>
    database.as('app').query('insert into directory.holds_waiting (org_id, reason) values ($1, $2)', [orgId, reason]);

  it('a forged row naming a sign: a wait, and a hold attempt that sets it, never a clear', async () => {
    await forge('seal');
    const other = await aProcess();

    expect(await other.read('head')).toEqual({ outcome: 'tampered', sign: 'seal' });
    await other.poll();

    expect(await other.read('head')).toMatchObject({ outcome: 'held', version: 2 });
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ reason: 'seal', foundOn: 'hold_waiting' });
  });

  it('a row naming no sign is a row not as the app writes one: still a wait, recorded as such', async () => {
    await forge('nonsense');
    const other = await aProcess();

    expect(await other.read('head')).toEqual({ outcome: 'tampered', sign: 'row' });
    await other.poll();

    expect((await holdEvents()).at(-1)?.details).toMatchObject({ reason: 'row' });
    expect((await holdEvents()).at(-1)?.details).not.toHaveProperty('chainFailure');
  });

  it('a row beside a verified hold changes nothing, and goes', async () => {
    const other = await aProcess();
    await other.hold('head');
    await forge('seal');
    expect(await other.read('head')).toMatchObject({ outcome: 'held', version: 2 });

    await other.poll();

    expect(await actions()).toEqual(ONE_SET);
    expect(await waitingRows()).toEqual([]);
    expect(await other.read('head')).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('the table refuses a row for no organisation, a reason that is not a word, and any change', async () => {
    await expect(forge('seal', newId())).rejects.toMatchObject({ code: '23503' });
    await expect(forge('Not A Word')).rejects.toMatchObject({ code: '23514' });
    await forge('seal');
    await expect(
      database.as('app').query("update directory.holds_waiting set reason = 'log' where org_id = $1", [org]),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('a row deleted before its hold is recorded: the process that found it records it, with the alarm', async () => {
    const finder = await aProcess();
    await leftWaiting(finder);
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);

    await finder.poll();

    expect(await actions()).toEqual(ONE_SET);
    expect(rowGone()).toEqual([expect.objectContaining({ level: 'error', orgId: org, check: 'hold' })]);
  });

  it('a row deleted: so does a process that only polled it, and meeting a locked head it writes the row again', async () => {
    await leftWaiting(await aProcess());
    const other = await aProcess();
    await withHeadLocked(() => other.poll());
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);

    await withHeadLocked(() => other.poll());
    expect(await waitingRows()).toEqual([{ reason: 'chain' }]);
    expect(rowGone()).toEqual([]);

    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);
    await other.poll();
    expect(await actions()).toEqual(ONE_SET);
    expect(rowGone()).toHaveLength(1);
  });

  it('a row gone because another process recorded the hold: nothing is said, and the entry goes', async () => {
    const finder = await aProcess();
    await leftWaiting(finder);
    await (await aProcess()).poll();
    expect(await actions()).toEqual(ONE_SET);

    await finder.poll();

    expect(await actions()).toEqual(ONE_SET);
    expect(rowGone()).toEqual([]);
    // No entry left to try: a later poll takes no lock at all.
    await withHeadLocked(() => finder.poll());
    expect(notRecorded()).toHaveLength(1);
  });
});

describe(`holds waiting: the database in trouble (4D2e D5, Postgres ${server.version})`, () => {
  it("a row that can't be written: said, kept in the process alone, and recorded there all the same", async () => {
    // Not in the directory, so the key refuses the row.
    org = await newOrganisation(false);
    const finder = await aProcess();
    await leftWaiting(finder);
    expect(await waitingRows()).toEqual([]);
    expect(lines('audit.hold_not_kept')).toEqual([
      expect.objectContaining({ level: 'error', orgId: org, reason: 'chain' }),
    ]);
    // The stated limit of the fallback: this process alone knows.
    expect(await (await aProcess()).read('head')).toMatchObject({ outcome: 'clear' });

    await finder.poll();

    expect(await actions()).toEqual(ONE_SET);
    // It never had a row to lose.
    expect(rowGone()).toEqual([]);
  });

  it('a row written once the table takes it again, by the next poll of the process holding it', async () => {
    const finder = await aProcess();
    await withTableRefusing('insert', () => leftWaiting(finder));
    expect(await waitingRows()).toEqual([]);

    await withHeadLocked(() => finder.poll());

    expect(await waitingRows()).toEqual([{ reason: 'chain' }]);
    expect(await (await aProcess()).read('head')).toEqual({ outcome: 'tampered', sign: 'chain' });
  });

  it('a hold kept here alone that a later poll finds a row for: that row deleted is the alarm', async () => {
    const finder = await aProcess();
    await withTableRefusing('insert', () => leftWaiting(finder));
    await attacker.query("insert into directory.holds_waiting (org_id, reason) values ($1, 'chain')", [org]);
    await finder.poll();
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);

    await finder.poll();

    expect(await actions()).toEqual(ONE_SET);
    expect(rowGone()).toHaveLength(1);
  });

  it("a poll that can't read the table says so, throws nothing, and leaves what it holds", async () => {
    const finder = await aProcess();
    await leftWaiting(finder);
    await finder.pool.destroy();

    await finder.poll();

    expect(lines('audit.holds_waiting_unread')).toEqual([expect.objectContaining({ level: 'warn' })]);
    expect(await waitingRows()).toEqual([{ reason: 'chain' }]);
    // Destroyed already: the sweep after the test has one less to end.
    pools.splice(pools.indexOf(finder.pool), 1);
  });

  it('a poll leaves a hold being recorded to the one recording it, rather than queue on the head beside it', async () => {
    const finder = await aProcess();
    await withHeadLocked(async () => {
      const recording = finder.hold('head');
      await waitUntilQueued(attacker, 1);
      await attacker.query("insert into directory.holds_waiting (org_id, reason) values ($1, 'seal')", [org]);
      await finder.poll();
      return { recording };
    }).then(({ recording }) => recording);

    expect(await actions()).toEqual(ONE_SET);
    expect(await waitingRows()).toEqual([]);
    expect(notRecorded()).toEqual([]);
  });

  it('a poll leaves a row gone to the try already under way, as well', async () => {
    const finder = await aProcess();
    await leftWaiting(finder);
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);

    await withHeadLocked(async () => {
      const retrying = finder.hold(undefined);
      await waitUntilQueued(attacker, 1);
      await finder.poll();
      return { retrying };
    }).then(({ retrying }) => retrying);

    expect(await actions()).toEqual(ONE_SET);
    expect(rowGone()).toEqual([]);
    expect(notRecorded()).toHaveLength(1);
  });
});

describe(`holds waiting: few trips (4D2e D5, Postgres ${server.version})`, () => {
  it('a poll of an empty table, with nothing waiting here, is one trip', async () => {
    const quiet = await aProcess();
    const times = quiet.platform.noStatementTimes();

    await quiet.platform.timingStatements(times, () => quiet.poll());

    expect(times.trips).toBe(1);
    expect(capture.lines()).toEqual([]);
  });

  it("Tx A's read of the row shares the trip of the head's lock, and reads it once that lock is held", async () => {
    const reader = await aProcess();
    const times = reader.platform.noStatementTimes();

    const check = await reader.work((tx, states) =>
      reader.platform.timingStatements(times, () => states.integrityHold(tx, org, 'head')),
    );
    expect(check).toMatchObject({ outcome: 'clear' });
    // The head's lock with the row, then the hold: as many as before there was a row to read.
    expect(times.trips).toBe(2);

    const waiting = withHeadLocked(async () => {
      const deciding = reader.read('head');
      await waitUntilQueued(attacker, 1);
      // Left while the decision waited for the lock: its read comes after, so it sees it.
      await attacker.query("insert into directory.holds_waiting (org_id, reason) values ($1, 'seal')", [org]);
      return { deciding };
    });
    expect(await (await waiting).deciding).toEqual({ outcome: 'tampered', sign: 'seal' });
  });
});

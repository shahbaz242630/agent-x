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
import type * as Waiting from './holds-waiting.ts';
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
async function aProcess(maxConnections = 4) {
  vi.resetModules();
  const [signed, platform] = await Promise.all([import('./with-signed-states.ts'), import('@agentx/platform/db')]);
  const pool = platform.createDatabase<AuditTables>({ ...database.connection('app'), maxConnections }, testLogger());
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
    /** A finding of this process's own, on a record of that organisation. */
    findOn: (orgId: string, id: string) =>
      signed.withSignedStates(pool, orgId, services(), (_, states) => {
        states.mismatch('membership', { orgId, id });
        return Promise.resolve();
      }),
  };
}

const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const notRecorded = () => lines('audit.integrity_failed').filter(({ reason }) => reason === 'not_recorded');
const rowGone = () => lines('audit.integrity_failed').filter(({ reason }) => reason === 'row_gone');
const fromRow = () => lines('audit.integrity_failed').filter(({ reason }) => reason === 'from_row');

/** A row as anyone with the app's rights could write it, by default naming what `head`'s failure names. */
const plant = (reason: string, orgId = org, subjectType = 'audit_chain', objectId = orgId) =>
  database
    .as('app')
    .query('insert into directory.holds_waiting (org_id, subject_type, object_id, reason) values ($1, $2, $3, $4)', [
      orgId,
      subjectType,
      objectId,
      reason,
    ]);

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

const rowsNamedElsewhere = () =>
  attacker.query<{ object_id: string }>('select object_id from directory.holds_waiting where org_id = $1', [org]);

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

/** The hold cleared by its own steps, as an admin's clearing does once all is whole: its investigation first. */
async function clearTheHold(by: Awaited<ReturnType<typeof aProcess>>): Promise<void> {
  const actor = { type: 'user' as const, id: newId() };
  await by.work(async (tx, states) => {
    const recorded = await states.recordInvestigation(tx, org, {
      id: newId(),
      actor,
      conclusion: 'CAUSE_REMOVED',
      reference: 'INC-000001',
    });
    if (recorded.outcome !== 'recorded') throw new Error('not investigated');
    await states.verifyAll(tx, org, [], 1);
    const cleared = await states.clearIntegrityHold(tx, org, {
      actor,
      holdEventId: recorded.investigation.holdEventId,
      investigationId: recorded.investigation.id,
      stepUp: { stepUpChallengeId: newId() },
    });
    if (cleared.outcome !== 'cleared') throw new Error(`not cleared: ${cleared.outcome}`);
  });
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

/** The table's checks on the row's naming dropped while `work` runs: a row can still reach us so, past the app. */
async function withChecksDropped(work: () => Promise<void>): Promise<void> {
  const owner = database.as('owner');
  const checks = await owner.query<{ name: string; definition: string }>(
    "select conname as name, pg_get_constraintdef(oid) as definition from pg_constraint where conrelid = 'directory.holds_waiting'::regclass and contype = 'c' and conname <> 'holds_waiting_reason_check'",
  );
  /* eslint-disable agentx/no-string-built-sql -- names and definitions Postgres gave back for this table. */
  for (const { name } of checks) await owner.query(`alter table directory.holds_waiting drop constraint ${name}`);
  try {
    await work();
  } finally {
    await attacker.query('delete from directory.holds_waiting');
    for (const { name, definition } of checks) {
      await owner.query(`alter table directory.holds_waiting add constraint ${name} ${definition}`);
    }
  }
  /* eslint-enable agentx/no-string-built-sql */
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
    // The row names the record as the process that found it would: clearing checks the same.
    expect((await holdEvents()).at(-1)?.details).toMatchObject({
      reason: 'chain',
      foundOn: 'audit_chain',
      objectId: org,
      findings: 1,
    });
    expect(await waitingRows()).toEqual([]);
    // Set from its row alone: the line the integrity alert reads, not only a warning.
    expect(fromRow()).toEqual([
      expect.objectContaining({ level: 'error', orgId: org, subjectType: 'audit_chain', objectId: org }),
    ]);
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
    // Its finder recorded it, whose alarm is already up.
    expect(fromRow()).toEqual([]);
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
    await plant('seal', neighbour);
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
  it('a forged row naming a sign: a wait, and a hold attempt that sets it, never a clear', async () => {
    await plant('seal');
    const other = await aProcess();

    expect(await other.read('head')).toEqual({ outcome: 'tampered', sign: 'seal' });
    await other.poll();

    expect(await other.read('head')).toMatchObject({ outcome: 'held', version: 2 });
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ reason: 'seal', foundOn: 'audit_chain' });
    expect(fromRow()).toHaveLength(1);
  });

  it('a row naming no sign is a row not as the app writes one: still a wait, recorded as such', async () => {
    await plant('nonsense');
    const other = await aProcess();

    expect(await other.read('head')).toEqual({ outcome: 'tampered', sign: 'row' });
    await other.poll();

    expect((await holdEvents()).at(-1)?.details).toMatchObject({ reason: 'row' });
    expect((await holdEvents()).at(-1)?.details).not.toHaveProperty('chainFailure');
  });

  it('a row beside a verified hold changes nothing, and goes', async () => {
    const other = await aProcess();
    await other.hold('head');
    await plant('seal');
    expect(await other.read('head')).toMatchObject({ outcome: 'held', version: 2 });

    await other.poll();

    expect(await actions()).toEqual(ONE_SET);
    expect(await waitingRows()).toEqual([]);
    expect(await other.read('head')).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('the table refuses a row for no organisation, a reason that is not a word, and any change', async () => {
    await expect(plant('seal', newId())).rejects.toMatchObject({ code: '23503' });
    await expect(plant('Not A Word')).rejects.toMatchObject({ code: '23514' });
    await expect(plant('seal', org, 'Not A Type')).rejects.toMatchObject({ code: '23514' });
    await expect(plant('seal', org, 'agent', '')).rejects.toMatchObject({ code: '23514' });
    await plant('seal');
    await expect(
      database.as('app').query("update directory.holds_waiting set reason = 'log' where org_id = $1", [org]),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('the table refuses an ID or a type the app could never write (no finding names anything else)', async () => {
    const id = newId();
    for (const bad of ['a\nb', 'x', id.toUpperCase(), `${id}\n`, `${id}0`, ` ${id}`]) {
      await expect(plant('seal', org, 'agent', bad)).rejects.toMatchObject({ code: '23514' });
    }
    // The audit log's own limit on a type, 63 characters.
    await expect(plant('seal', org, 'a'.repeat(64), id)).rejects.toMatchObject({ code: '23514' });
    await plant('seal', org, 'a'.repeat(63), id);
  });

  it.each([
    ['control characters in its ID', 'agent', 'a\nb'],
    ['an ID that is no UUID', 'membership', 'not-a-uuid'],
    ['an ID in capitals', 'membership', '0199A0F0-0000-7000-8000-000000000001'],
    ['a type the log refuses', 'A Type', '0199a0f0-0000-7000-8000-000000000001'],
  ])(
    'a row with %s, its check dropped, is still caution: a hold under a fixed name, with the alarm',
    async (_, type, id) => {
      await withChecksDropped(async () => {
        await plant('seal', org, type, id);
        const other = await aProcess();
        expect(await other.read('head')).toEqual({ outcome: 'tampered', sign: 'seal' });

        await other.poll();

        expect(await other.read('head')).toMatchObject({ outcome: 'held', version: 2 });
        expect((await holdEvents()).at(-1)?.details).toMatchObject({
          reason: 'row',
          foundOn: 'audit_chain',
          objectId: org,
        });
        expect(await waitingRows()).toEqual([]);
        expect(notRecorded()).toEqual([]);
        expect(fromRow()).toEqual([
          expect.objectContaining({ level: 'error', orgId: org, subjectType: 'audit_chain', objectId: org }),
        ]);
      });
    },
  );

  it('such a row meeting a locked head waits on: no row of another name, and it goes when the hold is recorded', async () => {
    await withChecksDropped(async () => {
      await plant('seal', org, 'agent', 'a\nb');
      const other = await aProcess();
      await withHeadLocked(() => other.poll());
      expect(notRecorded()).toHaveLength(1);
      expect(await attacker.query('select object_id from directory.holds_waiting where org_id = $1', [org])).toEqual([
        { object_id: 'a\nb' },
      ]);

      await other.hold(undefined);

      expect(await actions()).toEqual(ONE_SET);
      expect(await waitingRows()).toEqual([]);
    });
  });

  it('two such rows are two entries: both go, by their own names, the second as the hold it already is', async () => {
    await withChecksDropped(async () => {
      await plant('seal', org, 'agent', 'a\nb');
      await plant('seal', org, 'agent', 'c\nd');

      await (await aProcess()).poll();

      expect(await actions()).toEqual(ONE_SET);
      expect(await waitingRows()).toEqual([]);
    });
  });

  it('such a row meeting a hold on another record stays as it is: no row of the fixed name, and the alarm', async () => {
    await withChecksDropped(async () => {
      const other = await aProcess();
      await plant('seal', org, 'membership', newId());
      await other.poll();
      expect(await waitingRows()).toEqual([]);
      await plant('seal', org, 'agent', 'a\nb');

      await other.poll();

      expect(await attacker.query('select object_id from directory.holds_waiting where org_id = $1', [org])).toEqual([
        { object_id: 'a\nb' },
      ]);
      expect(fromRow()).toHaveLength(2);
    });
  });

  it('such a row deleted before its hold is recorded: the alarm, and the hold all the same', async () => {
    await withChecksDropped(async () => {
      await plant('seal', org, 'agent', 'a\nb');
      const other = await aProcess();
      await withHeadLocked(() => other.poll());
      await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);

      await other.poll();

      expect(await actions()).toEqual(ONE_SET);
      expect(rowGone()).toHaveLength(1);
      expect(await waitingRows()).toEqual([]);
    });
  });

  it('a second record is a row of its own: Tx A waits on either, and each hold names its own', async () => {
    const [first, second] = [newId(), newId()];
    await plant('holding', org, 'spend_request', first);
    await plant('seal', org, 'membership', second);
    const other = await aProcess();
    expect(await other.read('head')).toMatchObject({ outcome: 'tampered' });

    await other.poll();

    const named = (await holdEvents()).at(-1)?.details.objectId;
    expect(await actions()).toEqual(ONE_SET);
    expect([first, second]).toContain(named);
    const left = named === first ? second : first;
    // The hold names one: the other stays, and repeated polls add nothing to the log.
    const rows = () =>
      attacker.query<{ object_id: string }>('select object_id from directory.holds_waiting where org_id = $1', [org]);
    expect(await rows()).toEqual([{ object_id: left }]);
    await other.poll();
    expect(await actions()).toEqual(ONE_SET);
    expect(await rows()).toEqual([{ object_id: left }]);
    expect(await other.read('head')).toMatchObject({ outcome: 'held', version: 2 });

    await clearTheHold(other);
    expect(await other.read('head')).toMatchObject({ outcome: 'tampered' });
    await other.poll();

    // Its own hold now, for its own investigation and check.
    expect(await actions()).toEqual([...ONE_SET, 'integrity_hold.cleared', 'integrity_hold.set']);
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ objectId: left });
    expect(await rows()).toEqual([]);
  });

  it('a finding meeting a hold on another record writes its row with that transaction, and is the next hold', async () => {
    const other = await aProcess();
    await other.hold('head');
    const found = newId();

    await other.work((_, states) => {
      states.mismatch('membership', { orgId: org, id: found });
      return Promise.resolve();
    });

    const rows = () =>
      attacker.query<{ subject_type: string; object_id: string; reason: string }>(
        'select subject_type, object_id, reason from directory.holds_waiting where org_id = $1',
        [org],
      );
    expect(await rows()).toEqual([{ subject_type: 'membership', object_id: found, reason: 'holding' }]);
    expect(notRecorded()).toEqual([]);
    expect(await actions()).toEqual(ONE_SET);
    // Found again: the row there stands.
    await other.work((_, states) => {
      states.mismatch('membership', { orgId: org, id: found });
      return Promise.resolve();
    });
    expect(await rows()).toHaveLength(1);
    expect(notRecorded()).toEqual([]);

    await clearTheHold(other);
    await (await aProcess()).poll();

    expect(await actions()).toEqual([...ONE_SET, 'integrity_hold.cleared', 'integrity_hold.set']);
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ foundOn: 'membership', objectId: found });
    expect(await rows()).toEqual([]);
  });

  it("such a row that can't be written fails its transaction: the finding waits here, and is written by the next try", async () => {
    const other = await aProcess();
    await other.hold('head');
    const found = newId();

    await withTableRefusing('insert', () =>
      other.work((_, states) => {
        states.mismatch('membership', { orgId: org, id: found });
        return Promise.resolve();
      }),
    );
    expect(notRecorded()).toHaveLength(1);
    expect(lines('audit.hold_not_kept')).toHaveLength(1);
    expect(await waitingRows()).toEqual([]);

    await other.hold(undefined);

    expect(await waitingRows()).toEqual([{ reason: 'holding' }]);
    expect(await actions()).toEqual(ONE_SET);
  });

  it('a finding this process alone holds, meeting a hold on another record, is not lost: its row is written', async () => {
    const finder = await aProcess();
    await withTableRefusing('insert', () => leftWaiting(finder));
    expect(await waitingRows()).toEqual([]);
    // The hold another process sets names a record of its own.
    const another = newId();
    await plant('seal', org, 'membership', another);
    await (await aProcess()).poll();
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ objectId: another });

    await finder.hold(undefined);

    expect(await waitingRows()).toEqual([{ reason: 'chain' }]);
    expect(await actions()).toEqual(ONE_SET);
  });

  it('a hold recorded for one record leaves what waits here for another', async () => {
    const finder = await aProcess();
    await leftWaiting(finder);

    const found = newId();
    await withHeadLocked(() =>
      finder.work((_, states) => {
        states.mismatch('membership', { orgId: org, id: found });
        return Promise.resolve();
      }),
    );
    await finder.hold('head');

    // The first was recorded; the second still waits, here and in its row.
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ foundOn: 'audit_chain' });
    expect(await waitingRows()).toEqual([{ reason: 'holding' }]);
    await finder.poll();
    expect(await waitingRows()).toEqual([{ reason: 'holding' }]);
    await clearTheHold(finder);
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ foundOn: 'membership', objectId: found });
  });

  it("a row gone by the time it is tried takes away that record's entry alone", async () => {
    const finder = await aProcess(1);
    await leftWaiting(finder);
    const gone = newId();
    await plant('seal', org, 'membership', gone);
    const locker = await database.connect('admin');
    await locker.query('begin');
    await locker.query('lock table directory.holds_waiting in access exclusive mode');
    const polling = finder.poll();
    await waitUntilQueued(attacker, 1);
    const gate = finder.platform.withTenant(finder.pool, org, () =>
      attacker.query('delete from directory.holds_waiting where object_id = $1', [gone]),
    );
    await locker.query('rollback');
    await locker.end();
    await gate;
    await polling;

    expect(await actions()).toEqual(['integrity_hold.created']);
    expect(await finder.read('none')).toEqual({ outcome: 'tampered', sign: 'chain' });
  });

  it('a real finding whose row is deleted just before its try is not lost: the row comes back', async () => {
    const finder = await aProcess(1);
    await finder.hold('head');
    await finder.work((_, states) => {
      states.mismatch('membership', { orgId: org, id: newId() });
      return Promise.resolve();
    });
    expect(await waitingRows()).toEqual([{ reason: 'holding' }]);
    // Its rest over: the next poll reads its row and tries it.
    for (let poll = 0; poll < 12; poll += 1) await finder.poll();
    const locker = await database.connect('admin');
    await locker.query('begin');
    await locker.query('lock table directory.holds_waiting in access exclusive mode');
    const polling = finder.poll();
    await waitUntilQueued(attacker, 1);
    const gate = finder.platform.withTenant(finder.pool, org, () =>
      attacker.query('delete from directory.holds_waiting where org_id = $1', [org]),
    );
    await locker.query('rollback');
    await locker.end();
    await gate;
    await polling;

    expect(await waitingRows()).toEqual([{ reason: 'holding' }]);
    expect(await actions()).toEqual(ONE_SET);
  });

  it('forged rows an operator deletes under a hold on another record stay deleted: the alarm once, in each process', async () => {
    const [one, two] = [await aProcess(), await aProcess()];
    await one.hold('head');
    await plant('seal', org, 'membership', newId());
    await plant('seal', org, 'membership', newId());
    await one.poll();
    await two.poll();
    expect(await rowsNamedElsewhere()).toHaveLength(2);

    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);

    // Past their rest in both processes, and a good way on.
    for (let poll = 0; poll < 16; poll += 1) {
      await one.poll();
      await two.poll();
      expect(await rowsNamedElsewhere()).toEqual([]);
    }
    expect(rowGone()).toHaveLength(4);
    expect(await actions()).toEqual(ONE_SET);
  });

  it("a finding of this process's own, its row deleted under a hold on another record, has it written back", async () => {
    const finder = await aProcess();
    await finder.hold('head');
    await finder.work((_, states) => {
      states.mismatch('membership', { orgId: org, id: newId() });
      return Promise.resolve();
    });
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);

    for (let poll = 0; poll < 13; poll += 1) await finder.poll();

    expect(await rowsNamedElsewhere()).toHaveLength(1);
    expect(rowGone()).toEqual([]);
    expect(await actions()).toEqual(ONE_SET);
  });

  /** A poll of `by`, its one connection held back behind `between`, which runs after the read and before the try. */
  async function pollWithThisBetween(by: Awaited<ReturnType<typeof aProcess>>, between: () => Promise<unknown>) {
    const locker = await database.connect('admin');
    await locker.query('begin');
    await locker.query('lock table directory.holds_waiting in access exclusive mode');
    const polling = by.poll();
    await waitUntilQueued(attacker, 1);
    const gate = by.platform.withTenant(by.pool, org, between);
    await locker.query('rollback');
    await locker.end();
    await gate;
    await polling;
  }

  it('a row gone before its try, the hold naming another record: the alarm, the entry forgotten, the row left deleted', async () => {
    const other = await aProcess();
    await other.hold('head');
    const frozen = await aProcess(1);
    await plant('seal', org, 'membership', newId());

    await pollWithThisBetween(frozen, () =>
      attacker.query('delete from directory.holds_waiting where org_id = $1', [org]),
    );

    expect(rowGone()).toEqual([expect.objectContaining({ level: 'error', orgId: org, check: 'hold' })]);
    expect(await rowsNamedElsewhere()).toEqual([]);
    await frozen.poll();
    expect(rowGone()).toHaveLength(1);
  });

  it('a row gone before its try because the hold now names it: the usual way, nothing said', async () => {
    const other = await aProcess();
    const frozen = await aProcess(1);
    await plant('chain');

    await pollWithThisBetween(frozen, () => other.hold('head'));

    expect(await actions()).toEqual(ONE_SET);
    expect(rowGone()).toEqual([]);
    expect(fromRow()).toEqual([]);
    await frozen.poll();
    expect(rowGone()).toEqual([]);
  });

  it("a process holding a record that another recorded lets it go, though another record's row stands", async () => {
    const stale = await aProcess();
    await leftWaiting(stale);
    const other = await aProcess();
    await other.hold('head');
    expect(await waitingRows()).toEqual([]);
    const next = newId();
    await plant('seal', org, 'membership', next);

    await stale.poll();
    await clearTheHold(other);
    // Its next request has nothing of the first to set again: Tx A reads the row standing, and that is what is recorded.
    expect(await stale.read('head')).toEqual({ outcome: 'tampered', sign: 'seal' });
    await stale.poll();

    const sets = (await holdEvents()).filter(({ action }) => action === 'integrity_hold.set');
    expect(sets.map(({ details }) => details.objectId)).toEqual([org, next]);
  });

  it('frozen between the read and its try: a row gone by then, its hold not naming it, is not held over, and is the alarm', async () => {
    await plant('seal');
    const frozen = await aProcess(1);
    const locker = await database.connect('admin');
    await locker.query('begin');
    await locker.query('lock table directory.holds_waiting in access exclusive mode');
    // The read is on the one connection; the gate queues for it ahead of the try.
    const polling = frozen.poll();
    await waitUntilQueued(attacker, 1);
    const gate = frozen.platform.withTenant(frozen.pool, org, () =>
      attacker.query('delete from directory.holds_waiting where org_id = $1', [org]),
    );
    await locker.query('rollback');
    await locker.end();
    await gate;
    await polling;

    expect(await actions()).toEqual(['integrity_hold.created']);
    expect(fromRow()).toEqual([]);
    expect(rowGone()).toEqual([expect.objectContaining({ level: 'error', orgId: org, check: 'hold' })]);
    expect(await frozen.read('none')).toMatchObject({ outcome: 'clear' });
  });

  it('frozen likewise, with another record still waiting: only the row gone goes unheld', async () => {
    const [gone, stays] = [newId(), newId()];
    await plant('seal', org, 'membership', gone);
    await plant('seal', org, 'membership', stays);
    const frozen = await aProcess(1);
    const locker = await database.connect('admin');
    await locker.query('begin');
    await locker.query('lock table directory.holds_waiting in access exclusive mode');
    const polling = frozen.poll();
    await waitUntilQueued(attacker, 1);
    const gate = frozen.platform.withTenant(frozen.pool, org, () =>
      attacker.query('delete from directory.holds_waiting where object_id = $1', [gone]),
    );
    await locker.query('rollback');
    await locker.end();
    await gate;
    await polling;

    expect((await holdEvents()).at(-1)?.details).toMatchObject({ objectId: stays });
  });

  it('a row for the record the hold names goes, though a row for another comes before it', async () => {
    const other = await aProcess();
    await other.hold('head');
    const elsewhere = newId();
    await plant('seal', org, 'membership', elsewhere);
    await plant('seal');

    await other.poll();

    const rows = await attacker.query<{ object_id: string }>(
      'select object_id from directory.holds_waiting where org_id = $1',
      [org],
    );
    expect(rows).toEqual([{ object_id: elsewhere }]);
    expect(await actions()).toEqual(ONE_SET);
  });

  it('only a row naming both the type and the ID of what the hold names goes with it', async () => {
    const [named, another] = [newId(), newId()];
    await plant('seal', org, 'membership', named);
    await (await aProcess()).poll();
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ foundOn: 'membership', objectId: named });

    await plant('seal', org, 'membership', another);
    await plant('seal', org, 'agent', named);
    await plant('seal', org, 'membership', named);
    await (await aProcess()).poll();

    const rows = await attacker.query<{ subject_type: string; object_id: string }>(
      'select subject_type, object_id from directory.holds_waiting where org_id = $1 order by subject_type',
      [org],
    );
    expect(rows).toEqual([
      { subject_type: 'agent', object_id: named },
      { subject_type: 'membership', object_id: another },
    ]);
    expect(await actions()).toEqual(ONE_SET);
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
    await plant('chain');
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

  it('a hold kept while the read was on its way is new to that read, not a row gone', async () => {
    let readDone = (): void => undefined;
    let release = (): void => undefined;
    const read = new Promise<void>((resolve) => {
      readDone = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.doMock('./holds-waiting.ts', async (actual) => {
      const real = await actual<typeof Waiting>();
      return {
        ...real,
        holdsWaiting: async (...read: Parameters<typeof real.holdsWaiting>) => {
          const rows = await real.holdsWaiting(...read);
          readDone();
          await gate;
          return rows;
        },
      };
    });
    const slow = await aProcess();
    vi.doUnmock('./holds-waiting.ts');

    const polling = slow.poll();
    await read;
    await leftWaiting(slow);
    release();
    await polling;

    expect(rowGone()).toEqual([]);
    expect(await actions()).toEqual(['integrity_hold.created']);
    expect(await waitingRows()).toEqual([{ reason: 'chain' }]);
  });

  it('a poll leaves a hold being recorded to the one recording it, rather than queue on the head beside it', async () => {
    const finder = await aProcess();
    await withHeadLocked(async () => {
      const recording = finder.hold('head');
      await waitUntilQueued(attacker, 1);
      await plant('seal');
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

describe(`holds waiting: a poll is bounded (4D2e D5, Postgres ${server.version})`, () => {
  /** Rows for a few records of an organisation, each a new ID. */
  const plantMany = async (rows: number, orgId = org) => {
    for (let row = 0; row < rows; row += 1) await plant('seal', orgId, 'membership', newId());
  };
  /** As many rows in one statement, for a table past what a few inserts make. */
  const plantInBulk = (rows: number, orgId: string) =>
    database
      .as('admin')
      .query(
        "insert into directory.holds_waiting (org_id, subject_type, object_id, reason) select $1, 'membership', gen_random_uuid()::text, 'seal' from generate_series(1, $2::int)",
        [orgId, rows],
      );
  const tripsOf = async (by: Awaited<ReturnType<typeof aProcess>>) => {
    const times = by.platform.noStatementTimes();
    await by.platform.timingStatements(times, () => by.poll());
    return times.trips;
  };

  it('a try that fails ends that organisation’s turn: one wait on its locked head, not one a row, and others still go', async () => {
    const neighbour = await newOrganisation();
    await plantMany(3);
    await plant('seal', neighbour);
    const other = await aProcess();

    await withHeadLocked(() => other.poll());

    expect(notRecorded()).toHaveLength(1);
    expect(await actions()).toEqual(['integrity_hold.created']);
    expect(await actions(neighbour)).toEqual(ONE_SET);
  });

  it('tries at most four holds a poll, and the rest come next, whichever organisation has the most rows', async () => {
    const organisations = [org, await newOrganisation(), await newOrganisation(), await newOrganisation()];
    const [crowded = '', ...few] = organisations;
    await plantMany(5, crowded);
    for (const one of few) await plant('seal', one);
    const other = await aProcess();

    await other.poll();

    // One an organisation first: all four reached, whatever the crowd.
    expect(fromRow()).toHaveLength(4);
    for (const one of organisations) expect(await actions(one)).toEqual(ONE_SET);
    expect(await waitingRows(crowded)).toHaveLength(4);

    await other.poll();

    // The four left, each a record not the one held.
    expect(fromRow()).toHaveLength(8);
    expect(await waitingRows(crowded)).toHaveLength(4);
    expect(await actions(crowded)).toEqual(ONE_SET);
  });

  it('starts after the organisation it last tried, so the same few are not always the first reached', async () => {
    const organisations = [org];
    for (let more = 0; more < 5; more += 1) organisations.push(await newOrganisation());
    for (const one of organisations) await plantMany(2, one);
    const other = await aProcess();

    await other.poll();
    expect(fromRow()).toHaveLength(4);

    await other.poll();

    // The two the first poll didn't reach, by ID order.
    for (const one of organisations.toSorted()) expect(await actions(one)).toEqual(ONE_SET);
  });

  it('a row on a record not the one held raises the alarm once a process, and rests, then is tried again', async () => {
    const other = await aProcess();
    await other.hold('head');
    const elsewhere = newId();
    await plant('seal', org, 'membership', elsewhere);

    await other.poll();

    expect(fromRow()).toEqual([
      expect.objectContaining({ level: 'error', orgId: org, subjectType: 'membership', objectId: elsewhere }),
    ]);
    // Nor does a request, or the anchor check, try it meanwhile: both would wait on this head.
    await withHeadLocked(async () => {
      expect(await other.read('none')).toMatchObject({ outcome: 'held' });
      await other.hold(undefined);
    });
    expect(notRecorded()).toEqual([]);
    expect(await waitingRows()).toEqual([{ reason: 'seal' }]);

    // Twelve polls, about a minute, of one trip each: a read alone.
    for (let poll = 0; poll < 12; poll += 1) expect(await tripsOf(other)).toBe(1);
    expect(await tripsOf(other)).toBeGreaterThan(1);
    // Said once only.
    expect(fromRow()).toHaveLength(1);
    expect(await tripsOf(other)).toBe(1);

    // Another process's own first sight is its own to say.
    await (await aProcess()).poll();
    expect(fromRow()).toHaveLength(2);
    expect(await actions()).toEqual(ONE_SET);
  });

  it('resting ends once a read here finds the hold clear: the row is the next hold, with no minute to wait', async () => {
    const other = await aProcess();
    await other.hold('head');
    const elsewhere = newId();
    await plant('seal', org, 'membership', elsewhere);
    await other.poll();
    await clearTheHold(other);
    // Cleared, and nothing yet read: it rests on.
    expect(await tripsOf(other)).toBe(1);

    // No head's lock: this process's memory alone says so, as caution.
    expect(await other.read('none')).toEqual({ outcome: 'tampered', sign: 'seal' });

    expect((await holdEvents()).at(-1)?.details).toMatchObject({ foundOn: 'membership', objectId: elsewhere });
    expect(await waitingRows()).toEqual([]);
    expect(fromRow()).toHaveLength(2);
  });

  it('a row resting, deleted: not judged gone until its rest is over, and then the alarm, with the row left deleted', async () => {
    const other = await aProcess();
    await other.hold('head');
    await plant('seal', org, 'membership', newId());
    await other.poll();
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);

    for (let poll = 0; poll < 12; poll += 1) expect(await tripsOf(other)).toBe(1);
    expect(await waitingRows()).toEqual([]);
    expect(rowGone()).toEqual([]);

    await other.poll();
    expect(await waitingRows()).toEqual([]);
    expect(rowGone()).toEqual([expect.objectContaining({ level: 'error', orgId: org, check: 'hold' })]);
    expect(await actions()).toEqual(ONE_SET);
    // Forgotten: nothing more to try, or to say.
    expect(await tripsOf(other)).toBe(1);
    expect(rowGone()).toHaveLength(1);
  });

  it('at the limit of what it reads: says so, and judges no row gone', async () => {
    const neighbour = await newOrganisation();
    const finder = await aProcess();
    await leftWaiting(finder);
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);
    await plantInBulk(1000, neighbour);

    await finder.poll();

    expect(lines('audit.holds_waiting_past_limit')).toEqual([expect.objectContaining({ level: 'error', rows: 1000 })]);
    // Not one read: it may stand past the limit.
    expect(rowGone()).toEqual([]);
    expect(await actions()).toEqual(['integrity_hold.created']);
    expect(await waitingRows(neighbour)).toHaveLength(999);
  });

  it('many rows, under the limit: said, with what is kept here, and a row gone is still judged', async () => {
    const neighbour = await newOrganisation();
    const finder = await aProcess();
    await leftWaiting(finder);
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);
    await plantInBulk(99, neighbour);

    await finder.poll();

    expect(lines('audit.holds_waiting_past_limit')).toEqual([]);
    expect(rowGone()).toHaveLength(1);
    await plant('seal', neighbour);
    await plant('seal', neighbour, 'agent', newId());
    await (await aProcess()).poll();
    expect(lines('audit.holds_waiting_past_limit')).toEqual([
      expect.objectContaining({ level: 'error', rows: 100, atReadLimit: false }),
    ]);
    expect(await actions()).toEqual(ONE_SET);
  });

  it('what rows add to memory stays at the bound, said each poll it lasts, and every row still comes in turn', async () => {
    await plantInBulk(505, org);
    const other = await aProcess();
    const past = () => lines('audit.holds_waiting_past_memory');
    const kept = () => lines('audit.holds_waiting_past_limit').at(-1)?.kept;
    const named = () => new Set(fromRow().map(({ objectId }) => objectId));

    await other.poll();

    expect(kept()).toBe(500);
    expect(past()).toEqual([expect.objectContaining({ level: 'error', rowsLeft: 5, kept: 500 })]);
    let polls = 1;
    for (let poll = 0; poll < 200 && named().size < 500; poll += 1) {
      await other.poll();
      polls += 1;
    }
    expect(named().size).toBe(500);
    expect(kept()).toBeLessThanOrEqual(500);
    expect(past().length).toBeGreaterThan(1);
    expect(past().length).toBeLessThanOrEqual(polls);

    // No silent gap: rows left with no alarm of their own while the hold stands, and each poll says the table is long.
    const spoke = lines('audit.holds_waiting_past_limit').length;
    await other.poll();
    expect(lines('audit.holds_waiting_past_limit').slice(spoke)).toEqual([
      expect.objectContaining({ level: 'error', rows: 504, kept: 500, atReadLimit: false }),
    ]);

    // While the hold stands no place comes free; each clear frees one, and a row left out comes in.
    for (let cleared = 0; cleared < 6; cleared += 1) {
      await clearTheHold(other);
      expect(await other.read('none')).not.toMatchObject({ outcome: 'clear' });
      await other.poll();
      expect(kept()).toBeLessThanOrEqual(500);
    }
    expect(named().size).toBe(505);
  }, 180_000);

  it('past the bound, an organisation with none here keeps one, so it reads as waiting, though it has to wait its turn', async () => {
    const crowded = await newOrganisation();
    await plantInBulk(600, crowded);
    const other = await aProcess();
    // Two polls: the first's hold frees a place, the next fills it, so the bound is full before this one's rows come.
    await other.poll();
    await other.poll();
    expect(lines('audit.holds_waiting_past_limit').at(-1)).toMatchObject({ kept: 500 });
    await plant('seal', org, 'membership', newId());
    await plant('seal', org, 'membership', newId());

    await other.poll();

    // One of its two, past the bound; the other left in the table.
    expect(lines('audit.holds_waiting_past_limit').at(-1)).toMatchObject({ kept: 501 });
    expect(await other.read('none')).not.toMatchObject({ outcome: 'clear' });
  });

  it('what a process found itself takes no place from what rows may add', async () => {
    const finder = await aProcess();
    await leftWaiting(finder);
    await plantInBulk(120, await newOrganisation());

    await finder.poll();

    expect(lines('audit.holds_waiting_past_limit').at(-1)).toMatchObject({ rows: 121, kept: 120 });
  });

  it('a finding this process made itself is never left out for the bound', async () => {
    const crowded = await newOrganisation();
    await plantInBulk(600, crowded);
    await plant('seal');
    const other = await aProcess();
    await other.poll();
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);
    await other.hold('head');
    await other.work((_, states) => {
      states.mismatch('membership', { orgId: org, id: newId() });
      return Promise.resolve();
    });

    expect(await waitingRows()).toEqual([{ reason: 'holding' }]);
  });

  it('rows left out are said for each poll that leaves them out, and not once none is', async () => {
    const crowded = await newOrganisation();
    await plantInBulk(600, crowded);
    const other = await aProcess();
    await other.poll();
    expect(lines('audit.holds_waiting_past_memory')).toHaveLength(1);

    const another = await aProcess();
    await another.poll();
    await attacker.query('delete from directory.holds_waiting');
    // With no rows read, none is left out: back under it, though the entries here only go four a poll.
    await other.poll();
    expect(lines('audit.holds_waiting_past_memory')).toHaveLength(2);
    // An operator's delete stands, in every process that held them, whatever hold they meet.
    for (let poll = 0; poll < 3; poll += 1) {
      await other.poll();
      await another.poll();
      expect(await waitingRows(crowded)).toEqual([]);
    }
    await plantInBulk(600, crowded);
    await other.poll();

    expect(lines('audit.holds_waiting_past_memory')).toHaveLength(3);
    await other.poll();
    expect(lines('audit.holds_waiting_past_memory')).toHaveLength(4);
  });

  describe('what a process found itself, at its bound', () => {
    /** A process whose bound on its own findings is one, as 5,000 real transactions would make it: the bound is its module's. */
    async function aProcessBoundAtOne() {
      vi.doMock('./holds-waiting.ts', async (actual) => ({ ...(await actual<typeof Waiting>()), MOST_KEPT_OWN: 1 }));
      const bound = await aProcess();
      vi.doUnmock('./holds-waiting.ts');
      return bound;
    }
    const found = (by: Awaited<ReturnType<typeof aProcess>>, id: string, orgId = org) => by.findOn(orgId, id);
    const past = () => lines('audit.holds_waiting_past_memory');

    it('the next is in the table and not here, said, and a poll brings it in', async () => {
      const bound = await aProcessBoundAtOne();
      await bound.hold('head');
      const [first, second] = [newId(), newId()];
      // The chain's entry went with its hold, so the first is the one here, at the bound.
      await found(bound, first);
      expect(past()).toEqual([]);
      // Past it: this one's row alone carries it.
      await found(bound, second);
      expect(past()).toEqual([expect.objectContaining({ level: 'error', orgId: org, ownLeft: 1, kept: 1 })]);
      expect((await rowsNamedElsewhere()).map(({ object_id: id }) => id).toSorted()).toEqual(
        [first, second].toSorted(),
      );

      await bound.poll();

      // Back in, from its row: only what wasn't here is new to the poll.
      expect(fromRow()).toEqual([expect.objectContaining({ objectId: second })]);
    });

    it('past the bound, Tx A still refuses on the row alone, with no hold recorded yet', async () => {
      const bound = await aProcessBoundAtOne();
      await withHeadLocked(async () => {
        await found(bound, newId());
        await found(bound, newId());
      });
      expect(past()).toHaveLength(1);
      expect(await rowsNamedElsewhere()).toHaveLength(2);
      expect(await actions()).toEqual(['integrity_hold.created']);

      expect(await (await aProcess()).read('head')).toMatchObject({ outcome: 'tampered', sign: 'holding' });
    });

    it('an organisation with nothing else here keeps its one, so it reads as waiting', async () => {
      const bound = await aProcessBoundAtOne();
      await withHeadLocked(() => found(bound, newId()));
      const neighbour = await newOrganisation();
      const elsewhere = org;
      org = neighbour;
      await withHeadLocked(() => found(bound, newId(), neighbour));

      await withHeadLocked(async () => {
        expect(await bound.read('none', neighbour)).toEqual({ outcome: 'tampered', sign: 'holding' });
        expect(await bound.read('none', elsewhere)).toEqual({ outcome: 'tampered', sign: 'holding' });
      });
      expect(past()).toEqual([]);
    });

    it('with no row to carry it, a finding is kept here whatever the bound', async () => {
      const bound = await aProcessBoundAtOne();
      await withTableRefusing('insert', () =>
        withHeadLocked(async () => {
          await found(bound, newId());
          await found(bound, newId());
        }),
      );
      expect(past()).toEqual([]);
      expect(lines('audit.hold_not_kept')).toHaveLength(2);
      expect(await rowsNamedElsewhere()).toEqual([]);

      // Each written in its turn, as each is tried: the first the hold, the second its row.
      await bound.hold(undefined);
      await bound.hold(undefined);
      expect(await actions()).toEqual(ONE_SET);
      expect(await rowsNamedElsewhere()).toHaveLength(1);
    });

    it('said at most once for each poll in which one is left out', async () => {
      const bound = await aProcessBoundAtOne();
      await bound.hold('head');
      await found(bound, newId());
      await found(bound, newId());
      await found(bound, newId());
      // Two left out since the last poll: said once.
      expect(past()).toHaveLength(1);

      await bound.poll();
      // A poll alone leaves none of them out: nothing said.
      expect(past()).toHaveLength(1);

      await found(bound, newId());
      await found(bound, newId());
      expect(past()).toHaveLength(2);
    });
  });

  it('a crowded organisation hides no other: the next poll reads after it, nothing judged gone till a whole read', async () => {
    const finder = await aProcess();
    await leftWaiting(finder);
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [org]);
    const crowded = await newOrganisation();
    const hidden = await newOrganisation();
    // Past the limit by enough that the holds this test's polls set don't bring it back under.
    await plantInBulk(1010, crowded);
    await plant('seal', hidden);
    const spoke = () => lines('audit.holds_waiting_past_limit');

    await finder.poll();
    expect(await actions(hidden)).toEqual(['integrity_hold.created']);
    expect(spoke().at(-1)).toMatchObject({ rows: 1000, atReadLimit: true });

    await finder.poll();
    expect(await actions(hidden)).toEqual(ONE_SET);
    // A short page after a long one: the table is still long, and it says so.
    expect(spoke()).toHaveLength(2);
    expect(spoke().at(-1)).toMatchObject({ rows: 1, atReadLimit: false });

    await finder.poll();
    expect(rowGone()).toEqual([]);
    expect(await actions()).toEqual(['integrity_hold.created']);

    // The table shrunk: the page after the crowded one judges nothing, as it didn't start from the beginning.
    await attacker.query('delete from directory.holds_waiting where org_id = $1', [crowded]);
    await finder.poll();
    expect(rowGone()).toEqual([]);
    const spokenWhileLong = spoke().length;
    expect(spokenWhileLong).toBe(4);

    // From the beginning, under the limit: judging resumes, and the line goes quiet.
    await finder.poll();
    expect(spoke()).toHaveLength(spokenWhileLong);
    // The crowded one's rows, deleted too, say so as each is reached.
    expect(rowGone().filter(({ orgId }) => orgId === org)).toHaveLength(1);
    expect(await actions()).toEqual(ONE_SET);
  });

  it('a table past the limit is read to the limit alone', async () => {
    const neighbour = await newOrganisation();
    await plantInBulk(1500, neighbour);
    await plant('seal');
    const other = await aProcess();

    await other.poll();

    // Read at most the limit, whatever the table holds.
    expect(lines('audit.holds_waiting_past_limit')).toEqual([expect.objectContaining({ rows: 1000 })]);
    expect(await other.read('head')).toMatchObject({ outcome: expect.stringMatching('tampered|held') as string });
  });

  it('past the limit, Tx A reads the row of its own organisation, which the poll may never reach', async () => {
    await plantInBulk(1500, await newOrganisation());
    await plant('seal');

    expect(await (await aProcess()).read('head')).toEqual({ outcome: 'tampered', sign: 'seal' });
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
      await plant('seal');
      return { deciding };
    });
    expect(await (await waiting).deciding).toEqual({ outcome: 'tampered', sign: 'seal' });
  });
});

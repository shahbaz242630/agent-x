// Statements sent together on one trip (4D2d P16), against a real Postgres, each
// way it can go wrong forced: pg's pipelining, young in 8.23, carries money here.
import { createTestDatabase, LogCapture, type TestDatabase, testLogger, waitUntilQueued } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';
import { noStatementTimes, timingStatements } from './statement-times.ts';
import { sendTogether, withTenant } from './tenant.ts';

interface Tables {
  'probe.parents': { id: number };
  'probe.children': { id: number; parent: number };
  'probe.locked': { id: number; n: number };
}

const ORG = '0199a000-0000-7000-8000-00000000000a';
const server = inject('postgres');
let database: TestDatabase;
let db: Kysely<Tables>;

const opened: Kysely<Tables>[] = [];
const oneConnection = (applicationName: string) => {
  const made = createDatabase<Tables>(
    { ...database.connection('admin'), applicationName, maxConnections: 1 },
    testLogger(new LogCapture()),
  );
  opened.push(made);
  return made;
};

const parent = (on: Kysely<Tables>, id: number) => on.insertInto('probe.parents').values({ id });
const child = (on: Kysely<Tables>, id: number, of: number) =>
  on.insertInto('probe.children').values({ id, parent: of });
const parentsAmong = async (ids: readonly number[]) =>
  (await db.selectFrom('probe.parents').select('id').where('id', 'in', ids).execute()).length;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  const admin = database.as('admin');
  await admin.query('create schema probe');
  await admin.query('create table probe.parents (id int primary key)');
  await admin.query('create table probe.children (id int primary key, parent int not null references probe.parents)');
  await admin.query('create table probe.locked (id int primary key, n int not null)');
  await admin.query('insert into probe.locked values (1, 0)');
  db = oneConnection('send-together');
});

afterAll(async () => {
  await Promise.all(opened.map((made) => made.destroy()));
  await database.drop();
});

describe(`statements sent together (4D2d P16, Postgres ${server.version})`, () => {
  it('runs them in the order given, each seeing the one before, and answers each', async () => {
    const answers = await withTenant(db, ORG, (tx) =>
      sendTogether(tx, [
        parent(tx, 1).returning('id'),
        child(tx, 1, 1),
        tx.selectFrom('probe.children').select('parent').where('id', '=', 1),
      ]),
    );
    expect(answers.map(({ rows }) => rows)).toEqual([[{ id: 1 }], [], [{ parent: 1 }]]);
  });

  it('counts as one trip', async () => {
    const times = noStatementTimes();
    const trips = await withTenant(db, ORG, (tx) =>
      timingStatements(times, async () => {
        await sendTogether(tx, [parent(tx, 2), parent(tx, 3), parent(tx, 4)]);
        return times.trips;
      }),
    );
    expect(trips).toBe(1);
  });

  it('fails with the first failure, keeps nothing, and its connection works on', async () => {
    await expect(
      withTenant(db, ORG, (tx) => sendTogether(tx, [parent(tx, 10), child(tx, 10, 999), parent(tx, 11)])),
    ).rejects.toMatchObject({ code: '23503' });
    expect(await parentsAmong([10, 11])).toBe(0);
  });

  it('keeps nothing when what comes after them fails', async () => {
    await expect(
      withTenant(db, ORG, async (tx) => {
        await sendTogether(tx, [parent(tx, 12), parent(tx, 13)]);
        throw new Error('a check after the trip');
      }),
    ).rejects.toThrow('a check after the trip');
    expect(await parentsAmong([12, 13])).toBe(0);
  });

  it('waits on a lock in order, and the statement behind it reads what the wait let in', async () => {
    const holder = await database.connect('admin');
    try {
      await holder.query('begin');
      await holder.query('update probe.locked set n = 7 where id = 1');
      const reads = withTenant(db, ORG, (tx) => {
        const row = tx.selectFrom('probe.locked').select('n').where('id', '=', 1);
        return sendTogether(tx, [row.forUpdate(), row]);
      });
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');
      expect((await reads).map(({ rows }) => rows)).toEqual([[{ n: 7 }], [{ n: 7 }]]);
    } finally {
      await holder.end();
    }
  });

  it('fails every statement when the connection is killed under a lock wait, none left hanging, and the next gets a new one', async () => {
    const killed = oneConnection('send-together-killed');
    const holder = await database.connect('admin');
    try {
      await holder.query('begin');
      await holder.query('update probe.locked set n = n where id = 1');
      const sent = withTenant(killed, ORG, (tx) => {
        const row = tx.selectFrom('probe.locked').select('n').where('id', '=', 1);
        return sendTogether(tx, [row.forUpdate(), row, row]);
      });
      const failed = expect(sent).rejects.toThrow();
      await waitUntilQueued(database.as('admin'), 1);
      await database
        .as('admin')
        .query(
          "select pg_catalog.pg_terminate_backend(pid) from pg_catalog.pg_stat_activity where application_name = 'send-together-killed'",
        );
      await failed;
      await holder.query('rollback');
      const answers = await withTenant(killed, ORG, (tx) =>
        sendTogether(tx, [tx.selectFrom('probe.locked').select('id')]),
      );
      expect(answers[0].rows).toEqual([{ id: 1 }]);
    } finally {
      await holder.end();
    }
  });

  it('refuses outside a transaction, where a failure would keep what went before it', async () => {
    await expect(sendTogether(db as never, [db.selectFrom('probe.locked').select('id')])).rejects.toThrow(
      'only inside a transaction',
    );
    expect(await parentsAmong([1])).toBe(1);
  });
});

// FX-RACE proven on real transactions (race.ts, lock-wait.ts): the barrier
// really lines transactions up, so a missing lock shows as a lost update or an
// overspent limit every time rather than now and then; the ADR-006 patterns
// hold under the same race; a scripted pair taking locks in opposite orders
// deadlocks, and in one order it doesn't. Each party is the app role on a
// connection of its own.
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { BarrierBroken, race } from '../race.ts';
import { waitUntilBlocked } from './lock-wait.ts';
import { createTestDatabase, type TestClient, type TestDatabase } from './test-database.ts';

const server = inject('postgres');
let database: TestDatabase;
let opened: TestClient[] = [];

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  const owner = database.as('owner');
  await owner.query('create schema race');
  await owner.query('create table race.counters (id int primary key, value int not null)');
  await owner.query('create table race.reservations (party int primary key)');
  await owner.query('grant usage on schema race to agentx_app');
  await owner.query('grant select, insert, update, delete on race.counters, race.reservations to agentx_app');
});

beforeEach(async () => {
  const owner = database.as('owner');
  await owner.query('delete from race.reservations');
  await owner.query('delete from race.counters');
  // Row 1 is a counter; row 2 is the headroom left under a limit of 3.
  await owner.query('insert into race.counters (id, value) values (1, 0), (2, 3)');
});

afterEach(async () => {
  await Promise.all(opened.map((client) => client.end()));
  opened = [];
});

afterAll(async () => {
  await database.drop();
});

/** A connection of its own for each party, as the app role; returns party → connection. */
async function parties(count: number): Promise<(party: number) => TestClient> {
  const clients = await Promise.all(Array.from({ length: count }, () => database.connect('app')));
  opened.push(...clients);
  return (party) => {
    const client = clients[party];
    if (client === undefined) throw new Error(`No connection for party ${party}`);
    return client;
  };
}

/** Runs `work` in a transaction on the client: committed if it resolves, rolled back if it throws. */
async function inTransaction<T>(client: TestClient, work: () => Promise<T>): Promise<T> {
  await client.query('begin');
  try {
    const result = await work();
    await client.query('commit');
    return result;
  } catch (error) {
    await client.query('rollback');
    throw error;
  }
}

async function valueOf(id: number): Promise<number | undefined> {
  const [row] = await database
    .as('owner')
    .query<{ value: number }>('select value from race.counters where id = $1', [id]);
  return row?.value;
}

async function reservations(): Promise<number> {
  const [row] = await database.as('owner').query<{ count: string }>('select count(*) as count from race.reservations');
  return Number(row?.count);
}

const statuses = (outcomes: readonly PromiseSettledResult<unknown>[]): string[] =>
  outcomes.map((outcome) => outcome.status);

const reasons = (outcomes: readonly PromiseSettledResult<unknown>[]): unknown[] =>
  outcomes.flatMap((outcome): unknown[] => (outcome.status === 'rejected' ? [outcome.reason as unknown] : []));

describe(`FX-RACE the barrier lines real transactions up (Postgres ${server.version})`, () => {
  it('makes every party read before any writes, so a read-then-write loses all but one update', async () => {
    const clientOf = await parties(8);
    const outcomes = await race(8, (party, sync) =>
      inTransaction(clientOf(party), async () => {
        const [row] = await clientOf(party).query<{ value: number }>('select value from race.counters where id = 1');
        await sync();
        await clientOf(party).query('update race.counters set value = $1 where id = 1', [(row?.value ?? 0) + 1]);
      }),
    );
    expect(statuses(outcomes)).toEqual(Array.from({ length: 8 }, () => 'fulfilled'));
    expect(await valueOf(1)).toBe(1);
  });

  it('loses nothing in the same race when the write is one atomic statement', async () => {
    const clientOf = await parties(8);
    await race(8, (party, sync) =>
      inTransaction(clientOf(party), async () => {
        await sync();
        await clientOf(party).query('update race.counters set value = value + 1 where id = 1');
      }),
    );
    expect(await valueOf(1)).toBe(8);
  });
});

describe('FX-RACE a limit under N parallel requests (the SEC-LIM-01 shape)', () => {
  /** Reserves one unit of headroom if any is left. `lock` reads it FOR NO KEY UPDATE, as ADR-006 §6 requires. */
  const reserve =
    (clientOf: (party: number) => TestClient, lock: boolean) => (party: number, sync: () => Promise<void>) =>
      inTransaction(clientOf(party), async () => {
        const client = clientOf(party);
        let rows: { value: number }[];
        if (lock) {
          await sync();
          rows = await client.query<{ value: number }>(
            'select value from race.counters where id = 2 for no key update',
          );
        } else {
          rows = await client.query<{ value: number }>('select value from race.counters where id = 2');
          await sync();
        }
        const left = rows[0]?.value ?? 0;
        if (left < 1) return 'refused';
        await client.query('update race.counters set value = $1 where id = 2', [left - 1]);
        await client.query('insert into race.reservations (party) values ($1)', [party]);
        return 'reserved';
      });

  it('never goes over when the headroom is read FOR NO KEY UPDATE', async () => {
    const clientOf = await parties(8);
    const outcomes = await race(8, reserve(clientOf, true));
    const results = outcomes.map((outcome) => (outcome.status === 'fulfilled' ? outcome.value : 'failed'));
    expect(results.filter((result) => result === 'reserved')).toHaveLength(3);
    expect(results.filter((result) => result === 'refused')).toHaveLength(5);
    expect(await reservations()).toBe(3);
    expect(await valueOf(2)).toBe(0);
  });

  it('catches a limit check that reads without a lock: every party spends the same headroom', async () => {
    const clientOf = await parties(8);
    const outcomes = await race(8, reserve(clientOf, false));
    expect(statuses(outcomes)).toEqual(Array.from({ length: 8 }, () => 'fulfilled'));
    expect(await reservations()).toBe(8);
  });
});

describe('FX-RACE scripted pairs (the SEC-AV-04 shape)', () => {
  const lockRow = (client: TestClient, id: number) =>
    client.query('select value from race.counters where id = $1 for no key update', [id]);

  it('deadlocks a pair taking two locks in opposite orders, and Postgres aborts exactly one with 40P01', async () => {
    const clientOf = await parties(2);
    const outcomes = await race(2, (party, sync) => {
      const [first, second] = party === 0 ? [1, 2] : [2, 1];
      return inTransaction(clientOf(party), async () => {
        await lockRow(clientOf(party), first);
        await sync();
        await lockRow(clientOf(party), second);
      });
    });
    expect(statuses(outcomes).sort()).toEqual(['fulfilled', 'rejected']);
    expect(reasons(outcomes).map((reason) => (reason as { code?: string }).code)).toEqual(['40P01']);
  });

  it('runs the same pair in one lock order without a deadlock: the second waits for the first, then sees its write', async () => {
    const clientOf = await parties(2);
    const monitor = database.as('app');
    let waitedFor: number[] = [];
    let secondSaw: number | undefined;
    const outcomes = await race(2, (party, sync) =>
      inTransaction(clientOf(party), async () => {
        const client = clientOf(party);
        if (party === 0) {
          await lockRow(client, 1);
          await sync();
          // Party 1 has now queued behind our lock on row 1; only then do we go on.
          waitedFor = await waitUntilBlocked(monitor, clientOf(1).pid);
          await client.query('update race.counters set value = 10 where id in (1, 2)');
        } else {
          await sync();
          await lockRow(client, 1);
          const [row] = await client.query<{ value: number }>(
            'select value from race.counters where id = 2 for no key update',
          );
          secondSaw = row?.value;
          await client.query('update race.counters set value = value + 1 where id in (1, 2)');
        }
      }),
    );
    expect(statuses(outcomes)).toEqual(['fulfilled', 'fulfilled']);
    expect(waitedFor).toEqual([clientOf(0).pid]);
    expect(secondSaw).toBe(10);
    expect([await valueOf(1), await valueOf(2)]).toEqual([11, 11]);
  });

  it('times the barrier out, instead of hanging, when a party waits for a lock one at the barrier holds', async () => {
    const clientOf = await parties(2);
    const outcomes = await race(
      2,
      (party, sync) =>
        inTransaction(clientOf(party), async () => {
          await lockRow(clientOf(party), 1);
          await sync();
        }),
      { timeoutMs: 500 },
    );
    const [first, second] = reasons(outcomes);
    expect(first).toBeInstanceOf(BarrierBroken);
    expect((first as Error).message).toMatch(/^The barrier timed out after 500 ms with 1 of 2 parties arrived/);
    // The party that was stuck got the lock once the other rolled back, then found the barrier broken.
    expect(second).toBe(first);
    expect(await valueOf(1)).toBe(0);
  });

  it('says so when a process it watches is not waiting for a lock', async () => {
    const idle = await database.connect('app');
    opened.push(idle);
    await expect(waitUntilBlocked(database.as('app'), idle.pid, { timeoutMs: 100 })).rejects.toThrow(
      `Server process ${idle.pid} was not waiting for a lock within 100 ms`,
    );
  });
});

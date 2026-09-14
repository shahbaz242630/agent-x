// FX-RACE proven on real transactions (race.ts, lock-wait.ts): the barrier
// really lines transactions up, so a missing lock shows as a lost update or an
// overspent limit every time rather than now and then; the ADR-006 limit
// pattern holds under the same race, and the two ways of breaking it are
// caught; a lock the test holds lines up code that can't call a barrier; a
// scripted pair taking locks in opposite orders deadlocks, and in one order it
// doesn't. Each party is the app role on a connection of its own.
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { BarrierBroken, failures, race, successes } from '../race.ts';
import { waitUntilBlocked, waitUntilQueued } from './lock-wait.ts';
import { createTestDatabase, type TestClient, type TestDatabase } from './test-database.ts';

const server = inject('postgres');
let database: TestDatabase;
let opened: TestClient[] = [];

/** The limit in the ADR-006 tests: at most 3 reservations in the period. */
const LIMIT = 3;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  const owner = database.as('owner');
  await owner.query('create schema race');
  await owner.query('create table race.counters (id int primary key, value int not null)');
  // As in ADR-006: the period row is only a lock target; the reservation rows are the truth.
  await owner.query('create table race.periods (id int primary key)');
  await owner.query('create table race.reservations (party int primary key)');
  await owner.query('grant usage on schema race to agentx_app');
  await owner.query(
    'grant select, insert, update, delete on race.counters, race.periods, race.reservations to agentx_app',
  );
});

beforeEach(async () => {
  const owner = database.as('owner');
  await owner.query('delete from race.reservations');
  await owner.query('delete from race.periods');
  await owner.query('delete from race.counters');
  await owner.query('insert into race.counters (id, value) values (1, 0), (2, 0)');
  await owner.query('insert into race.periods (id) values (1)');
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

/** Every outcome's status, in party order. */
const statuses = (outcomes: readonly PromiseSettledResult<unknown>[]): string[] =>
  outcomes.map((outcome) => outcome.status);

const all = (count: number, status: string): string[] => Array.from({ length: count }, () => status);

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
    expect(statuses(outcomes)).toEqual(all(8, 'fulfilled'));
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

describe('FX-RACE a limit under N parallel requests (the SEC-LIM-01 shape, ADR-006 §7)', () => {
  type Reserve = (client: TestClient, party: number, sync: () => Promise<void>) => Promise<'reserved' | 'refused'>;

  /** Adds the party's reservation if the count it was given is under the limit. */
  const reserveIf = async (client: TestClient, party: number, taken: number): Promise<'reserved' | 'refused'> => {
    if (taken >= LIMIT) return 'refused';
    await client.query('insert into race.reservations (party) values ($1)', [party]);
    return 'reserved';
  };

  /** ADR-006 §7: lock the period row, then count in a separate statement, which sees every committed reservation. */
  const lockThenCount: Reserve = async (client, party, sync) => {
    await sync();
    await client.query('select 1 from race.periods where id = 1 for no key update');
    const [row] = await client.query<{ taken: string }>('select count(*) as taken from race.reservations');
    return reserveIf(client, party, Number(row?.taken));
  };

  /** Broken: counts with no lock at all. */
  const countWithoutLock: Reserve = async (client, party, sync) => {
    const [row] = await client.query<{ taken: string }>('select count(*) as taken from race.reservations');
    await sync();
    return reserveIf(client, party, Number(row?.taken));
  };

  /**
   * Broken, as ADR-006 §7 warns: the count is folded into the locking
   * statement, whose snapshot was taken before it waited for the lock.
   */
  const countInTheLockingStatement: Reserve = async (client, party, sync) => {
    await sync();
    const [row] = await client.query<{ taken: string }>(
      'select (select count(*) from race.reservations) as taken from race.periods where id = 1 for no key update',
    );
    return reserveIf(client, party, Number(row?.taken));
  };

  const raceOf = async (reserve: Reserve): Promise<PromiseSettledResult<'reserved' | 'refused'>[]> => {
    const clientOf = await parties(8);
    return race(8, (party, sync) => inTransaction(clientOf(party), () => reserve(clientOf(party), party, sync)));
  };

  it('never goes over when the period row is locked and the count is a separate statement', async () => {
    const results = successes(await raceOf(lockThenCount));
    expect(results.filter((result) => result === 'reserved')).toHaveLength(LIMIT);
    expect(results.filter((result) => result === 'refused')).toHaveLength(8 - LIMIT);
    expect(await reservations()).toBe(LIMIT);
  });

  it('catches a count taken with no lock: every party spends the same headroom', async () => {
    expect(successes(await raceOf(countWithoutLock))).toEqual(all(8, 'reserved'));
    expect(await reservations()).toBe(8);
  });

  it('catches a count folded into the locking statement: each party counts from before it waited', async () => {
    expect(successes(await raceOf(countInTheLockingStatement))).toEqual(all(8, 'reserved'));
    expect(await reservations()).toBe(8);
  });

  it('lines up code that can’t call a barrier by holding the lock it takes first, until every party has queued', async () => {
    const clientOf = await parties(8);
    const gate = await database.connect('app');
    opened.push(gate);
    await gate.query('begin');
    await gate.query('select 1 from race.periods where id = 1 for update');
    // The parties run the ADR-006 pattern with no barrier: the first lock they take is the one the gate holds.
    const running = race(8, (party) =>
      inTransaction(clientOf(party), () => lockThenCount(clientOf(party), party, () => Promise.resolve())),
    );
    const queued = await waitUntilQueued(database.as('app'), 8);
    expect(queued).toHaveLength(8);
    await gate.query('commit');
    const results = successes(await running);
    expect(results.filter((result) => result === 'reserved')).toHaveLength(LIMIT);
    expect(await reservations()).toBe(LIMIT);
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
    expect(failures(outcomes).map((reason) => (reason as { code?: string }).code)).toEqual(['40P01']);
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
    const [first, second] = failures(outcomes);
    expect(first).toBeInstanceOf(BarrierBroken);
    expect((first as Error).message).toMatch(/^The barrier timed out after 500 ms with 1 of 2 parties arrived/);
    // The party that was stuck got the lock once the other rolled back, then found the barrier broken.
    expect(second).toBe(first);
    expect(await valueOf(1)).toBe(0);
  });

  it('says so when a process it watches is not waiting for a lock, or too few are queued', async () => {
    const idle = await database.connect('app');
    opened.push(idle);
    const monitor = database.as('app');
    await expect(waitUntilBlocked(monitor, idle.pid, { timeoutMs: 100 })).rejects.toThrow(
      `Server process ${idle.pid} was not waiting for a lock within 100 ms`,
    );
    await expect(waitUntilQueued(monitor, 1, { timeoutMs: 100 })).rejects.toThrow(
      '0 of 1 sessions were waiting for a lock after 100 ms',
    );
  });

  it('counts only the sessions of the monitor’s own database, not other test files’ waits', async () => {
    const other = await createTestDatabase(server, { schema: 'empty' });
    try {
      await other.as('owner').query('create table elsewhere (id int primary key)');
      await other.as('owner').query('insert into elsewhere values (1)');
      const holder = await other.connect('owner');
      const waiter = await other.connect('owner');
      await holder.query('begin');
      await holder.query('select id from elsewhere for update');
      const waiting = waiter.query('select id from elsewhere for update');
      await waitUntilBlocked(other.as('owner'), waiter.pid);
      await expect(waitUntilQueued(database.as('app'), 1, { timeoutMs: 100 })).rejects.toThrow(
        '0 of 1 sessions were waiting for a lock after 100 ms',
      );
      await holder.query('commit');
      await waiting;
    } finally {
      await other.drop();
    }
  });
});

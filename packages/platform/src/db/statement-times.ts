// Where a decision's time goes, as the running API sees it (4D2d, PL-38): the
// wait for a connection, each round trip and the commit, summed for the work
// run inside timingStatements. The laptop's answer stopped being enough on
// Azure (S165), so the numbers ride on the decision's own log line. Nothing
// here reads a statement's text or values, only how long it took.
import { AsyncLocalStorage } from 'node:async_hooks';

import { type Kysely, sql } from 'kysely';

export interface StatementTimes {
  /** The wait for a free connection, and the opening of a new one when one was opened. */
  poolWaitMs: number;
  /** The round trips, the commit's among them. */
  trips: number;
  /** All the round trips' time as the API sees it, its own delay too; the commit's and a statement's lock wait inside. */
  databaseMs: number;
  slowestTripMs: number;
  commitMs: number;
  /** The round trip that asks for the supplier's row lock, its wait inside: within databaseMs (PL-62, 4D2e A). */
  supplierLockMs: number;
  /** The round trip that asks for the audit chain's head, its wait inside: within databaseMs. */
  headLockMs: number;
}

export const noStatementTimes = (): StatementTimes => ({
  poolWaitMs: 0,
  trips: 0,
  databaseMs: 0,
  slowestTripMs: 0,
  commitMs: 0,
  supplierLockMs: 0,
  headLockMs: 0,
});

const timing = new AsyncLocalStorage<StatementTimes>();

/** Runs `work`, adding what its statements take to `times`: a retried attempt's too. */
export function timingStatements<T>(times: StatementTimes, work: () => Promise<T>): Promise<T> {
  return timing.run(times, work);
}

/** `work`, its time added when work is being timed; a failed one took its time too. */
async function measured<T>(work: () => Promise<T>, add: (times: StatementTimes, took: number) => void): Promise<T> {
  const times = timing.getStore();
  if (times === undefined) return work();
  const started = performance.now();
  try {
    return await work();
  } finally {
    add(times, performance.now() - started);
  }
}

/** One round trip. */
export function timedTrip<T>(send: () => Promise<T>, kind: 'commit' | 'statement' = 'statement'): Promise<T> {
  return measured(send, (times, took) => {
    times.trips += 1;
    times.databaseMs += took;
    times.slowestTripMs = Math.max(times.slowestTripMs, took);
    if (kind === 'commit') times.commitMs += took;
  });
}

/** The wait for a pool's connection. */
export function timedPoolWait<T>(connect: () => Promise<T>): Promise<T> {
  return measured(connect, (times, took) => {
    times.poolWaitMs += took;
  });
}

/** A statement that asks for a contended lock, its time added under that lock's name as well as its trip's. */
export function timedLock<T>(lock: 'supplierLockMs' | 'headLockMs', asks: () => Promise<T>): Promise<T> {
  return measured(asks, (times, took) => {
    times[lock] += took;
  });
}

/** A tenth of a millisecond is all a log line needs. */
const tenths = (ms: number): number => Math.round(ms * 10) / 10;

export const statementTimesForLog = (times: StatementTimes): StatementTimes => ({
  poolWaitMs: tenths(times.poolWaitMs),
  trips: times.trips,
  databaseMs: tenths(times.databaseMs),
  slowestTripMs: tenths(times.slowestTripMs),
  commitMs: tenths(times.commitMs),
  supplierLockMs: tenths(times.supplierLockMs),
  headLockMs: tenths(times.headLockMs),
});

/**
 * How long `trips` round trips to the database took, in order, on one
 * connection. Its first statement isn't among them: it carries the connection's check.
 */
export function timedRoundTrips<Schema>(database: Kysely<Schema>, trips: number): Promise<number[]> {
  return database.connection().execute(async (connection) => {
    await sql`select 1`.execute(connection);
    const taken: number[] = [];
    for (let trip = 0; trip < trips; trip += 1) {
      const started = performance.now();
      await sql`select 1`.execute(connection);
      taken.push(performance.now() - started);
    }
    return taken;
  });
}

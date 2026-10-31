// Where a decision's time goes, as the running API sees it (4D2d, PL-38): the
// wait for a connection, each round trip and the commit, summed for the work
// run inside timingStatements. The laptop's answer stopped being enough on
// Azure (S165), so the numbers ride on the decision's own log line. Nothing
// here reads a statement's text or values, only how long it took.
import { AsyncLocalStorage } from 'node:async_hooks';

import { type Kysely, sql } from 'kysely';

export interface StatementTimes {
  poolWaitMs: number;
  /** The round trips, the commit's among them. */
  trips: number;
  /** All the round trips' time, the commit's among it; a lock's wait is inside its statement's. */
  databaseMs: number;
  slowestTripMs: number;
  commitMs: number;
}

export const noStatementTimes = (): StatementTimes => ({
  poolWaitMs: 0,
  trips: 0,
  databaseMs: 0,
  slowestTripMs: 0,
  commitMs: 0,
});

const timing = new AsyncLocalStorage<StatementTimes>();

/** Runs `work`, adding what its statements take to `times`: a retried attempt's too. */
export function timingStatements<T>(times: StatementTimes, work: () => Promise<T>): Promise<T> {
  return timing.run(times, work);
}

/** One round trip, counted when work is being timed; a failed one took its time too. */
export async function timedTrip<T>(send: () => Promise<T>, kind: 'commit' | 'statement' = 'statement'): Promise<T> {
  const times = timing.getStore();
  if (times === undefined) return send();
  const started = performance.now();
  try {
    return await send();
  } finally {
    const took = performance.now() - started;
    times.trips += 1;
    times.databaseMs += took;
    times.slowestTripMs = Math.max(times.slowestTripMs, took);
    if (kind === 'commit') times.commitMs += took;
  }
}

/** The wait for a pool's connection, counted when work is being timed. */
export async function timedPoolWait<T>(connect: () => Promise<T>): Promise<T> {
  const times = timing.getStore();
  if (times === undefined) return connect();
  const started = performance.now();
  try {
    return await connect();
  } finally {
    times.poolWaitMs += performance.now() - started;
  }
}

/** A tenth of a millisecond is all a log line needs. */
const tenths = (ms: number): number => Math.round(ms * 10) / 10;

export const statementTimesForLog = (times: StatementTimes): StatementTimes => ({
  poolWaitMs: tenths(times.poolWaitMs),
  trips: times.trips,
  databaseMs: tenths(times.databaseMs),
  slowestTripMs: tenths(times.slowestTripMs),
  commitMs: tenths(times.commitMs),
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

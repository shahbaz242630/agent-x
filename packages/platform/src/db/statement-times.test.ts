import { LogCapture, testLogger } from '@agentx/testing';
import { DummyDriver, Kysely, PostgresAdapter, PostgresIntrospector, PostgresQueryCompiler } from 'kysely';
import type pg from 'pg';
import { describe, expect, it } from 'vitest';

import { PINNED_SEARCH_PATH_VALUE } from './search-path.ts';
import {
  noStatementTimes,
  statementTimesForLog,
  timedPoolWait,
  timedRoundTrips,
  timedTrip,
  timingStatements,
} from './statement-times.ts';
import { tenantCheckedDialect, withTenant } from './tenant.ts';

const ORG = '0199a000-0000-7000-8000-00000000000a';

describe('timing statements', () => {
  it('counts each trip, the slowest and the commit apart, and sums the time', async () => {
    const times = noStatementTimes();
    await timingStatements(times, async () => {
      await timedTrip(() => new Promise((resolve) => setTimeout(resolve, 5)));
      await timedTrip(() => Promise.resolve());
      await timedTrip(() => Promise.resolve(), 'commit');
    });
    expect(times.trips).toBe(3);
    expect(times.slowestTripMs).toBeGreaterThan(1);
    expect(times.databaseMs).toBeGreaterThanOrEqual(times.slowestTripMs);
    expect(times.commitMs).toBeLessThan(times.slowestTripMs);
  });

  it('counts a failed trip and lets its failure through', async () => {
    const times = noStatementTimes();
    await expect(timingStatements(times, () => timedTrip(() => Promise.reject(new Error('refused'))))).rejects.toThrow(
      'refused',
    );
    expect(times.trips).toBe(1);
  });

  it('counts nothing outside timed work, and answers as usual', async () => {
    await expect(timedTrip(() => Promise.resolve('answer'))).resolves.toBe('answer');
    await expect(timedPoolWait(() => Promise.resolve('connection'))).resolves.toBe('connection');
  });

  it('adds the wait for a connection, a failed wait too', async () => {
    const times = noStatementTimes();
    await timingStatements(times, async () => {
      await timedPoolWait(() => new Promise((resolve) => setTimeout(resolve, 5)));
      await expect(timedPoolWait(() => Promise.reject(new Error('none free')))).rejects.toThrow('none free');
    });
    expect(times.poolWaitMs).toBeGreaterThan(1);
    expect(times.trips).toBe(0);
  });

  it('keeps two pieces of timed work apart when they run together', async () => {
    const first = noStatementTimes();
    const second = noStatementTimes();
    await Promise.all([
      timingStatements(first, async () => {
        await timedTrip(() => Promise.resolve());
        await timedTrip(() => Promise.resolve());
      }),
      timingStatements(second, () => timedTrip(() => Promise.resolve())),
    ]);
    expect([first.trips, second.trips]).toEqual([2, 1]);
  });

  it('rounds to a tenth of a millisecond for the log', () => {
    expect(
      statementTimesForLog({ poolWaitMs: 0.04, trips: 3, databaseMs: 12.345, slowestTripMs: 9.96, commitMs: 2.25 }),
    ).toEqual({ poolWaitMs: 0, trips: 3, databaseMs: 12.3, slowestTripMs: 10, commitMs: 2.3 });
  });
});

describe('the checked driver under timing', () => {
  /** A pool of one stand-in connection that answers a transaction's start, its statements and its commit. */
  function database() {
    const client = {
      query: (text: string) => {
        const answer = (rows: readonly unknown[]) => ({ rows, rowCount: rows.length, command: 'SELECT' });
        const state = answer([{ org_id: '', search_path: PINNED_SEARCH_PATH_VALUE }]);
        // A transaction's start answers each of its statements in turn; its commit's read-back needs no rows.
        return Promise.resolve(
          text.startsWith('start transaction') ? [answer([]), state, answer([{ org_id: ORG }])] : answer([]),
        );
      },
      release: () => undefined,
    };
    const pool = { connect: () => Promise.resolve(client) } as unknown as pg.Pool;
    const logger = testLogger(new LogCapture());
    return new Kysely<unknown>({ dialect: tenantCheckedDialect(pool, logger, 2) });
  }

  it('counts a transaction start and its commit', async () => {
    const times = noStatementTimes();
    await timingStatements(times, () => withTenant(database(), ORG, () => Promise.resolve('kept')));
    expect(times.trips).toBe(2);
  });
});

describe('timed round trips', () => {
  it('times the asked number of trips, leaving out the first', async () => {
    const database = new Kysely<unknown>({
      dialect: {
        createAdapter: () => new PostgresAdapter(),
        createDriver: () => new DummyDriver(),
        createIntrospector: (db) => new PostgresIntrospector(db),
        createQueryCompiler: () => new PostgresQueryCompiler(),
      },
    });
    const taken = await timedRoundTrips(database, 4);
    expect(taken).toHaveLength(4);
    expect(taken.every((ms) => ms >= 0)).toBe(true);
  });
});

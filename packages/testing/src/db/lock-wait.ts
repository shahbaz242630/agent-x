// FX-RACE, lining up in the database: Postgres reports who is waiting for
// whom (pg_blocking_pids), and these helpers ask it, from a session other than
// the ones being watched.
// - waitUntilBlocked: a scripted step that should queue behind another
//   transaction's lock has really queued, so the script can move on. A barrier
//   can't say, because a party stuck in a statement never reaches one.
// - waitUntilQueued: every party of a race is waiting behind the lock the test
//   holds. It lines up code that can't call a barrier: the test holds the lock
//   the code takes first (say, the organisation row), waits until all parties
//   queue, and then lets go.
import { setTimeout as sleep } from 'node:timers/promises';

import { DEFAULT_WAIT_MS } from '../race.ts';
import type { TestSession } from './test-database.ts';

const POLL_MS = 10;

/** How long to wait. Default 10 seconds. */
interface WaitOptions {
  readonly timeoutMs?: number;
}

/**
 * Waits until the server process `pid` is waiting for a lock, and returns the
 * processes it is waiting for, so the test can check they are the ones it
 * expects. Rejects if that doesn't happen within the timeout.
 */
export async function waitUntilBlocked(
  monitor: TestSession,
  pid: number,
  options: WaitOptions = {},
): Promise<number[]> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_WAIT_MS;
  const deadline = performance.now() + timeoutMs;
  for (;;) {
    const rows = await monitor.query<{ blockers: number[] }>('select pg_catalog.pg_blocking_pids($1) as blockers', [
      pid,
    ]);
    const blockers = rows.flatMap((row) => row.blockers);
    if (blockers.length > 0) return blockers;
    if (performance.now() >= deadline) {
      throw new Error(`Server process ${pid} was not waiting for a lock within ${timeoutMs} ms`);
    }
    await sleep(POLL_MS);
  }
}

/**
 * Waits until at least `count` sessions of the monitor's database are waiting
 * for a lock, and returns their process IDs. Parties that queue for the same
 * row wait one behind another, not all behind its holder, so any wait counts.
 * Rejects if that doesn't happen within the timeout.
 */
export async function waitUntilQueued(
  monitor: TestSession,
  count: number,
  options: WaitOptions = {},
): Promise<number[]> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_WAIT_MS;
  const deadline = performance.now() + timeoutMs;
  for (;;) {
    const rows = await monitor.query<{ pid: number }>(
      `select a.pid from pg_catalog.pg_stat_activity a
       where a.datname = pg_catalog.current_database()
         and pg_catalog.cardinality(pg_catalog.pg_blocking_pids(a.pid)) > 0
       order by a.pid`,
    );
    if (rows.length >= count) return rows.map((row) => row.pid);
    if (performance.now() >= deadline) {
      throw new Error(`${rows.length} of ${count} sessions were waiting for a lock after ${timeoutMs} ms`);
    }
    await sleep(POLL_MS);
  }
}

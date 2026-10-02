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
// - holdNamedLock: holds a lock no row stands for (@agentx/platform/db's
//   holdTransactionLock), as a party part-way through its work would.
import { setTimeout as sleep } from 'node:timers/promises';

import { DEFAULT_WAIT_MS } from '../race.ts';
import type { TestSession } from './test-database.ts';

const POLL_MS = 10;

/** How long to wait. Default 10 seconds. */
interface WaitOptions {
  readonly timeoutMs?: number;
}

/**
 * Asks `check` every POLL_MS until it returns the process IDs it looks for,
 * and rejects with `failure`'s message once the timeout has run out.
 */
async function poll(
  options: WaitOptions,
  check: () => Promise<number[] | undefined>,
  failure: (timeoutMs: number) => string,
): Promise<number[]> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_WAIT_MS;
  const deadline = performance.now() + timeoutMs;
  for (;;) {
    const found = await check();
    if (found !== undefined) return found;
    if (performance.now() >= deadline) throw new Error(failure(timeoutMs));
    await sleep(POLL_MS);
  }
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
  return poll(
    options,
    async () => {
      const rows = await monitor.query<{ blockers: number[] }>('select pg_catalog.pg_blocking_pids($1) as blockers', [
        pid,
      ]);
      const blockers = rows.flatMap((row) => row.blockers);
      return blockers.length > 0 ? blockers : undefined;
    },
    (timeoutMs) => `Server process ${pid} was not waiting for a lock within ${timeoutMs} ms`,
  );
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
  // The last look's count, for the message if the wait runs out.
  let waiting = 0;
  return poll(
    options,
    async () => {
      const rows = await monitor.query<{ pid: number }>(
        `select a.pid from pg_catalog.pg_stat_activity a
       where a.datname = pg_catalog.current_database()
         and pg_catalog.cardinality(pg_catalog.pg_blocking_pids(a.pid)) > 0
       order by a.pid`,
      );
      waiting = rows.length;
      return rows.length >= count ? rows.map((row) => row.pid) : undefined;
    },
    (timeoutMs) => `${waiting} of ${count} sessions were waiting for a lock after ${timeoutMs} ms`,
  );
}

/**
 * Takes the named lock (holdTransactionLock's, named by lockName) in the
 * client's open transaction, held until it ends, as a party part-way through
 * its work holds it.
 */
export async function holdNamedLock(client: TestSession, name: string): Promise<void> {
  await client.query('select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [name]);
}

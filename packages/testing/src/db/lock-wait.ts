// FX-RACE, scripted steps: a script that starts a statement it expects to
// queue behind another transaction's lock needs to know it really has queued
// before it moves on; a barrier can't say, because a party stuck in a
// statement never reaches one. Postgres reports who is waiting for whom
// (pg_blocking_pids), so this asks it, from a session other than the one
// being watched.
import { setTimeout as sleep } from 'node:timers/promises';

import type { TestSession } from './test-database.ts';

const POLL_MS = 10;

/**
 * Waits until the server process `pid` is waiting for a lock, and returns the
 * processes it is waiting for. Rejects if that doesn't happen within
 * `timeoutMs` (default 10 seconds).
 */
export async function waitUntilBlocked(
  monitor: TestSession,
  pid: number,
  options: { readonly timeoutMs?: number } = {},
): Promise<number[]> {
  const timeoutMs = options.timeoutMs ?? 10_000;
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

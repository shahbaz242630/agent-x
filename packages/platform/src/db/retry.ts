// ADR-006 §6: a deadlock or serialisation failure retries the whole
// transaction a bounded number of times. Safe because no partner call ever
// runs inside a transaction (ADR-007), so a retry repeats only database work
// that the failure already rolled back. Each retry is logged, so a test
// (SEC-AV-04) can assert that none happened, and a rise shows in the logs.
import { randomInt } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import type { Logger } from '../observability/index.ts';

/**
 * What Postgres fails one party of a deadlock with, and a serialisable
 * transaction that lost a race, by the name each retry's line gives (the
 * logger blanks a bare code like 40P01 as it would a token).
 */
const RETRIED: Readonly<Record<string, string>> = { '40P01': 'deadlock', '40001': 'serialization_failure' };
/** Tries of one transaction, the first included. */
export const MOST_TRIES = 3;
/** The line written for each retry: its operation, the failure's name, and which try failed. */
export const TRANSACTION_RETRIED = 'db.transaction_retried';

/** The SQLSTATE an error carries, on itself or on its cause (a driver's error may be wrapped once). */
function sqlStateOf(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const { code, cause } = error as { code?: unknown; cause?: unknown };
  if (typeof code === 'string') return code;
  return typeof cause === 'object' && cause !== null && typeof (cause as { code?: unknown }).code === 'string'
    ? (cause as { code: string }).code
    : undefined;
}

/** Whether a failed transaction may be tried again: a deadlock or a serialisation failure, nothing else. */
export function isRetryable(error: unknown): boolean {
  const code = sqlStateOf(error);
  return code !== undefined && Object.hasOwn(RETRIED, code);
}

/** A short wait before trying again, longer each time, with jitter so two parties don't collide again in step. */
const pauseBefore = (tryNumber: number): Promise<void> => sleep(tryNumber * randomInt(10, 50));

/**
 * Runs `transaction` (one whole transaction, opened and committed inside it)
 * and tries it again after a deadlock or a serialisation failure, up to
 * MOST_TRIES in all, logging each retry. Any other error, or the last try's,
 * is thrown as it was.
 */
export async function retryingTransaction<T>(
  logger: Logger,
  operation: string,
  transaction: () => Promise<T>,
  pause: (tryNumber: number) => Promise<void> = pauseBefore,
): Promise<T> {
  for (let tryNumber = 1; ; tryNumber += 1) {
    try {
      return await transaction();
    } catch (error) {
      if (tryNumber >= MOST_TRIES || !isRetryable(error)) throw error;
      logger.warn(TRANSACTION_RETRIED, { operation, failure: RETRIED[sqlStateOf(error) ?? ''], try: tryNumber });
      await pause(tryNumber);
    }
  }
}

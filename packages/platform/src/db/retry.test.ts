// ADR-006 §6: a deadlock or serialisation failure retries the whole
// transaction, bounded, and logs each retry; nothing else is retried.
import { LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { isRetryable, MOST_TRIES, retryingTransaction, TRANSACTION_RETRIED } from './retry.ts';

function capture() {
  const lines = new LogCapture();
  return { lines, logger: testLogger(lines) };
}

/** An error as the driver gives one, with its SQLSTATE. */
const failure = (code: string) => Object.assign(new Error('could not serialize access'), { code });
const noPause = () => Promise.resolve();

describe('retryingTransaction', () => {
  it.each([
    ['40P01', 'deadlock'],
    ['40001', 'serialization_failure'],
  ])('tries a transaction failed with %s again, logging the retry as a %s', async (code, name) => {
    const { lines, logger } = capture();
    const pauses: number[] = [];
    let tries = 0;

    const result = await retryingTransaction(
      logger,
      'spend_requests.create',
      () => {
        tries += 1;
        return tries === 1 ? Promise.reject(failure(code)) : Promise.resolve('done');
      },
      (tryNumber) => {
        pauses.push(tryNumber);
        return Promise.resolve();
      },
    );

    expect(result).toBe('done');
    expect(tries).toBe(2);
    expect(pauses).toEqual([1]);
    expect(lines.lines().filter(({ event }) => event === TRANSACTION_RETRIED)).toEqual([
      expect.objectContaining({ level: 'warn', operation: 'spend_requests.create', failure: name, try: 1 }),
    ]);
  });

  it('tries three times in all', () => {
    expect(MOST_TRIES).toBe(3);
  });

  it(`gives up after ${String(MOST_TRIES)} tries, throwing the last failure`, async () => {
    const { lines, logger } = capture();
    let tries = 0;
    const last = failure('40P01');

    await expect(
      retryingTransaction(
        logger,
        'op',
        () => {
          tries += 1;
          return Promise.reject(tries === MOST_TRIES ? last : failure('40P01'));
        },
        noPause,
      ),
    ).rejects.toBe(last);
    expect(tries).toBe(MOST_TRIES);
    expect(lines.lines().filter(({ event }) => event === TRANSACTION_RETRIED)).toHaveLength(MOST_TRIES - 1);
  });

  it.each([
    ['a unique violation', failure('23505')],
    ['a lock wait past the statement limit', failure('57014')],
    ['an error with no code', new Error('boom')],
  ])('never tries again after %s', async (_what, error) => {
    const { lines, logger } = capture();
    let tries = 0;

    await expect(
      retryingTransaction(
        logger,
        'op',
        () => {
          tries += 1;
          return Promise.reject(error);
        },
        noPause,
      ),
    ).rejects.toBe(error);
    expect(tries).toBe(1);
    expect(lines.lines()).toEqual([]);
  });

  it('runs a transaction that succeeds once, with no line', async () => {
    const { lines, logger } = capture();

    await expect(retryingTransaction(logger, 'op', () => Promise.resolve(7), noPause)).resolves.toBe(7);
    expect(lines.lines()).toEqual([]);
  });
});

describe('isRetryable', () => {
  it('reads the code on the error, as the driver gives it', () => {
    expect(isRetryable(failure('40P01'))).toBe(true);
    expect(isRetryable(failure('40001'))).toBe(true);
    expect(isRetryable(failure('toString'))).toBe(false);
    expect(isRetryable({ code: 40001 })).toBe(false);
    expect(isRetryable(null)).toBe(false);
    expect(isRetryable('40P01')).toBe(false);
  });
});

import { TooManyEventsToRead } from '@agentx/core/modules/audit';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { LogCapture, SequentialIds, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { braked, createUseCaseWork, movedAsRead, UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

describe('movedAsRead', () => {
  it('lets a move the read allowed through', () => {
    expect(() => {
      movedAsRead({ outcome: 'changed' }, "an agent read as ACTIVE didn't suspend");
    }).not.toThrow();
  });

  it.each(['not_allowed', 'missing', 'stale'])(
    'throws, never answers, a move refused as %s: something past the app is at work',
    (outcome) => {
      expect(() => {
        movedAsRead({ outcome }, "an agent read as ACTIVE didn't suspend");
      }).toThrow(new Error(`an agent read as ACTIVE didn't suspend: ${outcome}`));
    },
  );
});

describe('braked: a brake that couldn’t take hold', () => {
  const failing = (code: string) => () => Promise.reject(Object.assign(new Error('failed'), { code }));

  it.each([
    ['a lock wait run out', '55P03'],
    ['a statement past its limit', '57014'],
    ['a deadlock lost', '40P01'],
  ])('answers %s busy, and raises the alarm', async (_, code) => {
    const capture = new LogCapture();

    expect(await braked(testLogger(capture), ORG, 'corr-1', failing(code))).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'ORGANISATION_BUSY',
    });
    expect(capture.lines()).toMatchObject([
      { event: 'brake.not_applied', level: 'error', orgId: ORG, correlationId: 'corr-1' },
    ]);
  });

  it('throws anything else as it was, with no alarm', async () => {
    const capture = new LogCapture();

    await expect(braked(testLogger(capture), ORG, 'corr-1', failing('23505'))).rejects.toThrow('failed');
    expect(capture.lines()).toEqual([]);
  });

  it('answers what the write answered', async () => {
    const written = { outcome: 'conflict' } as const;
    expect(await braked(testLogger(), ORG, 'corr-1', () => Promise.resolve(written))).toBe(written);
  });
});

class OwnRefused extends UseCaseRefused {}
class OtherRefused extends UseCaseRefused {}
const ORG = '0199a0f0-0000-7000-8000-0000000000ad';

/** The use case's work over a database that throws `error` as its transaction opens: the work's throw, without Postgres. */
const refusingWith = (error: Error) =>
  createUseCaseWork({
    database: {
      transaction: () => {
        throw error;
      },
    } as unknown as Database<UseCaseTables>,
    keys: {} as KeyProvider,
    ids: new SequentialIds(1),
    logger: testLogger(),
    Refusal: OwnRefused,
  });

describe('a use case answers its own area’s refusals alone', () => {
  it('answers its own as a plain outcome', async () => {
    const work = refusingWith(new OwnRefused(409, 'SUPPLIER_CHANGE_WAITING'));
    expect(await work.answered(ORG, ORG, () => Promise.resolve({}))).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'SUPPLIER_CHANGE_WAITING',
    });
  });

  it('throws another area’s, never answering it', async () => {
    const other = new OtherRefused(403, 'FORBIDDEN');
    await expect(refusingWith(other).answered(ORG, ORG, () => Promise.resolve({}))).rejects.toBe(other);
  });
});

describe('a write bounded by the history it reads (the two-person rule, a supplier’s versions)', () => {
  const key = {} as IdempotentRequest;
  const noWork = () => Promise.resolve({ status: 201, resourceId: ORG });

  it('answers a history past its read’s cap as HISTORY_TOO_LONG', async () => {
    const work = refusingWith(new TooManyEventsToRead(10_000));
    expect(await work.historyBounded({ orgId: ORG }, key, ORG, noWork)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'HISTORY_TOO_LONG',
    });
  });

  it('answers its own refusal as the write does, and throws anything else', async () => {
    expect(
      await refusingWith(new OwnRefused(403, 'FORBIDDEN')).historyBounded({ orgId: ORG }, key, ORG, noWork),
    ).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    const broken = new Error('the connection dropped');
    await expect(refusingWith(broken).historyBounded({ orgId: ORG }, key, ORG, noWork)).rejects.toBe(broken);
  });
});

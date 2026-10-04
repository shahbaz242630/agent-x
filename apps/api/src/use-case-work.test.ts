import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { SequentialIds, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createUseCaseWork, movedAsRead, UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

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

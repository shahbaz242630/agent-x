// The one rule a settled payment's bank word contradicts it by (rail map §4):
// as the bank check alerts on it, and as the exception list reads it from a
// row's kept word (S196 decision), whatever the bank's proof of no debit.
import { describe, expect, it } from 'vitest';

import { type PaymentState, PROVIDER_STATUSES } from '../../providers/index.ts';
import { isSettled, TRANSACTION } from '../../transactions/index.ts';
import { CONTRADICTING, contradictedNow, contradicts } from './contradiction.ts';

const STATES: readonly PaymentState[] = ['PROCESSING', 'SUCCEEDED', 'FAILED', 'UNKNOWN'];

describe('contradicts: a settled payment the bank goes back on (rail map §4)', () => {
  it.each([
    ['SUCCEEDED', ['FAILED', 'UNKNOWN']],
    ['REVERSED', ['FAILED', 'UNKNOWN']],
    ['FAILED', ['PROCESSING', 'SUCCEEDED']],
    ['CANCELLED', ['PROCESSING', 'SUCCEEDED']],
  ] as const)('a %s payment is contradicted by %j alone', (status, by) => {
    expect(STATES.filter((state) => contradicts(status, state))).toEqual(
      STATES.filter((state) => (by as readonly PaymentState[]).includes(state)),
    );
  });

  it('gives a bank rejection the same verdict proven or not, for every settled status', () => {
    for (const status of TRANSACTION.states.filter(isSettled)) {
      expect(contradicts(status, 'FAILED')).toBe(contradicts(status, 'UNKNOWN'));
    }
  });
});

describe('contradictedNow: the word a row keeps still contradicting it (S196 decision)', () => {
  it('reads a paid one the bank now rejects, and a failed one the bank now credits or has under way', () => {
    expect(contradictedNow('SUCCEEDED', 'Rejected')).toBe(true);
    expect(contradictedNow('REVERSED', 'Rejected')).toBe(true);
    expect(contradictedNow('FAILED', 'AcceptedCreditSettlementCompleted')).toBe(true);
    expect(contradictedNow('CANCELLED', 'Pending')).toBe(true);
  });

  it('reads none once the bank agrees, before it has spoken, or past what the rail map names', () => {
    expect(contradictedNow('SUCCEEDED', 'AcceptedCreditSettlementCompleted')).toBe(false);
    expect(contradictedNow('FAILED', 'Rejected')).toBe(false);
    expect(contradictedNow('SUCCEEDED', null)).toBe(false);
    expect(contradictedNow('SUCCEEDED', 'Mislaid')).toBe(false);
  });

  it('reads none for a payment still under way, whatever the bank says', () => {
    for (const status of TRANSACTION.states.filter((one) => !isSettled(one))) {
      expect(PROVIDER_STATUSES.filter((word) => contradictedNow(status, word))).toEqual([]);
    }
  });

  it('lists, for a query, exactly the pairs it reads as contradicted', () => {
    expect(CONTRADICTING).toEqual([
      ['SUCCEEDED', ['Rejected']],
      [
        'FAILED',
        ['Pending', 'AcceptedSettlementCompleted', 'AcceptedWithoutPosting', 'AcceptedCreditSettlementCompleted'],
      ],
      [
        'CANCELLED',
        ['Pending', 'AcceptedSettlementCompleted', 'AcceptedWithoutPosting', 'AcceptedCreditSettlementCompleted'],
      ],
      ['REVERSED', ['Rejected']],
    ]);
  });
});

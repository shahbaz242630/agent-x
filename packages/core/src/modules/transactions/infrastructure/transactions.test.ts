// A transaction's table description (0058): the statuses clearing the
// integrity hold checks every row of are exactly those not settled. A paid one
// is checked among the newest rows or by the history batches (4D2e Stage F,
// decision 5), so a long history of payments never stops a hold clearing.
import { describe, expect, it } from 'vitest';

import { isSettled, TRANSACTION } from '../domain/transaction.ts';
import { TRANSACTIONS } from './transactions.ts';

describe('transactions, as the signed state reads them', () => {
  it('are checked in every row before a hold is cleared while their outcome is unsettled, and no other', () => {
    expect(TRANSACTIONS.liveStatuses).toEqual(TRANSACTION.states.filter((state) => !isSettled(state)));
    expect(TRANSACTIONS.liveStatuses).not.toContain('SUCCEEDED');
  });
});

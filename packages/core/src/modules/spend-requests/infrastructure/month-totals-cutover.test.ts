// GM-1a: what the cutover answers from the organisation's log alone, before it
// reads any request (the opening itself is proven on the migrated schema,
// apps/api/src/month-totals.db.test.ts).
import { describe, expect, it } from 'vitest';

import type { HistoryCheck, SignedStates } from '../../audit/index.ts';
import { cutOverMonthTotals } from './month-totals-cutover.ts';

/** A transaction any use of which would fail: the answers below come from the log's read alone. */
const NONE = null as never;
const ORG = '0199a0f0-0000-7000-8000-000000000003';

/** Signed states whose one read, the organisation's newest cutover or creation event, answers `history`. */
const statesReading = (history: HistoryCheck) =>
  ({ historyOf: () => Promise.resolve(history) }) as unknown as SignedStates;

const neverCalled = () => Promise.reject(new Error('nothing is read or recorded'));
const cutOver = (history: HistoryCheck) =>
  cutOverMonthTotals(NONE, statesReading(history), ORG, {
    payments: neverCalled,
    record: neverCalled,
    at: new Date(0),
  });

describe('the cutover, from the log alone', () => {
  it('does nothing for an organisation cut over already', async () => {
    const event = {
      seq: 2n,
      recordedAt: new Date(0),
      event: {
        actor: { type: 'system', id: 'api' },
        action: 'month_totals.cutover',
        subject: { type: 'month_totals', id: ORG, version: 1 },
        details: {},
      },
    };
    expect(await cutOver({ outcome: 'read', events: [event] } as unknown as HistoryCheck)).toEqual({
      outcome: 'already',
    });
  });

  it('opens nothing over a log that cannot be believed (its alarm raised by the read)', async () => {
    expect(await cutOver({ outcome: 'tampered', sign: 'log' })).toEqual({ outcome: 'tampered' });
  });
});

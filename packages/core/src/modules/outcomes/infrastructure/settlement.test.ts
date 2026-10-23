import { describe, expect, it } from 'vitest';

import { TRANSACTION } from '../../transactions/index.ts';
import { settlementOf } from './settlement.ts';

describe('what a payment’s outcome does to what its request holds (Phase 4 C3; ADR-006 §10–§11)', () => {
  it('holds as it was while under way, spends it on success, blocks it while unknown, gives it back after a proven end', () => {
    expect(Object.fromEntries(TRANSACTION.states.map((status) => [status, settlementOf(status)]))).toEqual({
      SUBMISSION_PENDING: { holds: 'following', reservation: null, releasesClaim: false },
      SUBMITTED: { holds: 'following', reservation: null, releasesClaim: false },
      PROCESSING: { holds: 'following', reservation: null, releasesClaim: false },
      SUCCEEDED: { holds: 'spent', reservation: 'FINALISED', releasesClaim: false },
      // A reversal gives no capacity back in the MVP (PRD §3.1), and the invoice stays paid.
      REVERSED: { holds: 'spent', reservation: 'FINALISED', releasesClaim: false },
      // Possibly paid: still uses capacity and still blocks the order (SEC-LIM-02).
      UNKNOWN: { holds: 'blocked', reservation: 'BLOCKED_UNKNOWN', releasesClaim: false },
      FAILED: { holds: 'ended', reservation: 'RELEASED', releasesClaim: true },
      CANCELLED: { holds: 'ended', reservation: 'RELEASED', releasesClaim: true },
    });
  });
});

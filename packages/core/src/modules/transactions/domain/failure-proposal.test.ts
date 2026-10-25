// Phase 4 gate H10 (decision 38; 0066): a proposal to mark a payment failed, as 0066's status guard holds it.
import { describe, expect, it } from 'vitest';

import { FAILURE_PROPOSAL, type FailureProposalEvent } from './failure-proposal.ts';

// A record of every event, so one added to the machine can't be left out here.
const EVENTS = Object.keys({ withdraw: true, confirm: true, end: true } satisfies Record<
  FailureProposalEvent,
  true
>) as FailureProposalEvent[];

describe('a failure proposal’s machine (H10)', () => {
  it('is born OPEN', () => {
    expect(FAILURE_PROPOSAL.initial).toBe('OPEN');
  });

  it.each([
    ['withdraw', 'WITHDRAWN'],
    ['confirm', 'CONFIRMED'],
    ['end', 'ENDED'],
  ] as const)('moves OPEN by %s to %s', (event, to) => {
    expect(FAILURE_PROPOSAL.transition('OPEN', event)).toMatchObject({ ok: true, to });
  });

  // Withdrawn, confirmed or ended is the proposal's last word: a second admin confirms only the open one.
  it.each(['WITHDRAWN', 'CONFIRMED', 'ENDED'] as const)('never moves %s again', (from) => {
    expect(EVENTS.filter((event) => FAILURE_PROPOSAL.transition(from, event).ok)).toEqual([]);
  });
});

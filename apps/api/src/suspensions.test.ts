// Where a pause's choice is read (PAUSE_EVENTS: the request-voids job's query
// and its verified judging) against the statuses voidCauses lets a pause hold
// (PAUSED_IN): one table changed without the other would have the job's
// filter and its judging disagree (C3b's review).
import { PAUSED_IN } from '@agentx/core/modules/spend-requests';
import { describe, expect, it } from 'vitest';

import { choiceIn, PAUSE_EVENTS } from './suspensions.ts';

describe('choiceIn', () => {
  it('reads a pause recorded as a pause, and anything else as a cancel: none, older events, a value past the app', () => {
    expect(choiceIn({ pendingRequests: 'pause', pendingStatementVersion: 1 })).toBe('pause');
    expect(choiceIn({ pendingRequests: 'cancel' })).toBe('cancel');
    expect(choiceIn({})).toBe('cancel');
    expect(choiceIn(undefined)).toBe('cancel');
    expect(choiceIn({ pendingRequests: 'PAUSE' })).toBe('cancel');
  });
});

describe('PAUSE_EVENTS', () => {
  it.each(Object.entries(PAUSED_IN))(
    'reads a pause for %s in exactly the statuses voidCauses holds one in',
    (which, statuses) => {
      expect(Object.keys(PAUSE_EVENTS[which as keyof typeof PAUSED_IN]).toSorted()).toEqual([...statuses].toSorted());
    },
  );
});

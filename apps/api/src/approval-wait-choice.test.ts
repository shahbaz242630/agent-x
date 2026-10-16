// Phase 3 E6: the approval wait an organisation policy version's event keeps,
// and how the change keeps it with its words' version.
import { describe, expect, it } from 'vitest';

import { waitChoiceDetails, waitChoiceIn } from './approval-wait-choice.ts';

describe('the approval wait a policy version keeps (E6)', () => {
  it('keeps the hours with the version of the words confirmed', () => {
    expect(waitChoiceDetails(24)).toEqual({ approvalWaitHours: 24, approvalWaitStatementVersion: 1 });
  });

  it('reads each wait offered, and none for a version from before E6 or a value never offered', () => {
    expect(waitChoiceIn({ approvalWaitHours: 24 })).toBe(24);
    expect(waitChoiceIn({ approvalWaitHours: 48 })).toBe(48);
    expect(waitChoiceIn({ approvalWaitHours: 72 })).toBe(72);
    expect(waitChoiceIn({ monthlyCapChoice: 'amount' })).toBeNull();
    expect(waitChoiceIn(undefined)).toBeNull();
    expect(waitChoiceIn({ approvalWaitHours: 36 })).toBeNull();
    expect(waitChoiceIn({ approvalWaitHours: '24' })).toBeNull();
  });
});

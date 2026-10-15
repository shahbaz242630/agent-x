// Phase 3 E2 (decision 15): the organisation's monthly cap choice as its
// version's event keeps it, and as its body names it.
import { describe, expect, it } from 'vitest';

import { capChoiceDetails, capChoiceIn, MONTHLY_CAP_CHOICE } from './monthly-cap-choice.ts';

describe('the monthly cap choice (E2)', () => {
  it('reads back each choice its event keeps, with the words’ version', () => {
    for (const choice of ['amount', 'none'] as const) {
      expect(capChoiceDetails(choice)).toEqual({ monthlyCapChoice: choice, monthlyCapStatementVersion: 1 });
      expect(capChoiceIn(capChoiceDetails(choice))).toBe(choice);
    }
  });

  it('reads none recorded, or anything else, as no choice: never a default', () => {
    for (const details of [undefined, {}, { monthlyCapChoice: 'default' }, { monthlyCapChoice: null }]) {
      expect(capChoiceIn(details)).toBeNull();
    }
  });

  it('names its words in the body’s description, and takes only the two choices', () => {
    expect(MONTHLY_CAP_CHOICE.description).toContain('there is no default');
    expect(MONTHLY_CAP_CHOICE.safeParse('none').success).toBe(true);
    expect(MONTHLY_CAP_CHOICE.safeParse('default').success).toBe(false);
  });
});

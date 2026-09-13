import { describe, expect, it } from 'vitest';

import { systemClock } from './clock.ts';

describe('systemClock', () => {
  it('returns the current time, as a new Date on every call', () => {
    // eslint-disable-next-line no-restricted-syntax -- this test checks the real clock against real time
    const before = Date.now();
    const first = systemClock.now();
    // eslint-disable-next-line no-restricted-syntax -- this test checks the real clock against real time
    const after = Date.now();

    expect(first.getTime()).toBeGreaterThanOrEqual(before);
    expect(first.getTime()).toBeLessThanOrEqual(after);
    expect(systemClock.now()).not.toBe(first);
  });
});

import { describe, expect, it } from 'vitest';

import {
  OWN_KEY_CLOCK_TOLERANCE_MS,
  OWN_KEY_WINDOW_MS,
  ownKeyExempts,
  REGISTERING_SECONDS,
  STEPPED_UP_SECONDS,
  TICKET_SECONDS,
} from './passkey-addition.ts';

const RECORDED = new Date('2026-11-26T09:00:00.000Z');
const at = (ms: number) => new Date(RECORDED.getTime() + ms);

describe('SA6 B6-3d: a key confirmed is the person’s own addition only as recorded', () => {
  it('exempts a key confirmed from just before the record to its window’s end, inclusive', () => {
    for (const after of [-OWN_KEY_CLOCK_TOLERANCE_MS, 0, 1, OWN_KEY_WINDOW_MS - 1, OWN_KEY_WINDOW_MS]) {
      expect(ownKeyExempts({ recordedAt: RECORDED, usedBefore: false }, at(after))).toBe(true);
    }
  });

  it('never exempts a key confirmed past the window, or before the record and its tolerance', () => {
    for (const after of [-OWN_KEY_CLOCK_TOLERANCE_MS - 1, -60_000, OWN_KEY_WINDOW_MS + 1, 7 * 24 * 3_600_000]) {
      expect(ownKeyExempts({ recordedAt: RECORDED, usedBefore: false }, at(after))).toBe(false);
    }
  });

  it('never exempts without a record, or with a record another copy used', () => {
    expect(ownKeyExempts({ recordedAt: undefined, usedBefore: false }, at(0))).toBe(false);
    expect(ownKeyExempts({ recordedAt: RECORDED, usedBefore: true }, at(0))).toBe(false);
  });

  it('holds the window at 15 minutes and the tolerance at 5 seconds', () => {
    expect(OWN_KEY_WINDOW_MS).toBe(900_000);
    expect(OWN_KEY_CLOCK_TOLERANCE_MS).toBe(5_000);
  });

  it('holds the ticket to 2 minutes, the step-up’s wait to 5, and the key’s making to 5', () => {
    expect({ TICKET_SECONDS, STEPPED_UP_SECONDS, REGISTERING_SECONDS }).toEqual({
      TICKET_SECONDS: 120,
      STEPPED_UP_SECONDS: 300,
      REGISTERING_SECONDS: 300,
    });
  });
});

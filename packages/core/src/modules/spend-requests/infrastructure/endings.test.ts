// AT13d (review of #756): a request's capacity kept at its end once its sealed approval (or decision) is past what the
// signed states' digest remembers, an hour short of the digest's own margin so the two clocks never let one through.
import { describe, expect, it } from 'vitest';

import { DIGEST_FORGET_MARGIN_MS } from '../../audit/index.ts';
import { APPROVAL_HORIZON_MS } from '../domain/voids.ts';
import { capacityKept, sealedAtOf } from './endings.ts';

const SEALED = new Date('2026-11-21T08:00:00.000Z');
const HOUR = 3_600_000;
/** When it is kept from: the horizon and the digest's margin, less an hour for the clocks. */
const FROM = APPROVAL_HORIZON_MS + DIGEST_FORGET_MARGIN_MS - HOUR;
const after = (ms: number) => new Date(SEALED.getTime() + ms);

describe('capacityKept', () => {
  it('is 7 days, a day and less an hour from the seal: as wide as the digest forgets, erring on keeping', () => {
    expect(FROM).toBe(7 * 24 * HOUR + 23 * HOUR);
    expect(DIGEST_FORGET_MARGIN_MS).toBe(24 * HOUR);
  });

  it.each([
    ['at its seal', 0, false],
    ['within the horizon', 6 * 24 * HOUR, false],
    ['past the horizon, the digest still remembering', APPROVAL_HORIZON_MS + HOUR, false],
    ['a millisecond short', FROM - 1, false],
    ['at the boundary', FROM, true],
    ['past it', FROM + 1, true],
    ['a month on', 30 * 24 * HOUR, true],
  ])('%s: %s', (_what, ms, kept) => {
    expect(capacityKept(SEALED, after(ms))).toBe(kept);
  });

  it('ages from the seal it is given, never the other way about', () => {
    expect(capacityKept(after(FROM), SEALED)).toBe(false);
  });
});

describe('sealedAtOf', () => {
  const decision = { decidedAt: SEALED, approvedAt: after(5 * HOUR) };

  it('ages an approved or ready request by its sealed approval', () => {
    expect(sealedAtOf('APPROVED', decision)).toEqual(after(5 * HOUR));
    expect(sealedAtOf('INSTRUCTION_READY', decision)).toEqual(after(5 * HOUR));
  });

  it('ages one waiting for approval by its sealed decision, though an approval it was rolled back from was signed', () => {
    expect(sealedAtOf('APPROVAL_REQUIRED', decision)).toEqual(SEALED);
  });
});

// Decision 49: how a guard function's body is read against the bodies known, without a
// database (coming-bodies.db.test.ts reads a live one). Fail-closed: a coming body is
// accepted only as an exact hash for its own function, and never in place of the one held.
import { describe, expect, it } from 'vitest';

import { bodyReads, knownBodies } from './schema-guard.ts';

const GUARD = 'state_rules.guard_status';
const NOW = 'a'.repeat(64);
const NEXT = 'b'.repeat(64);
const OTHER = 'c'.repeat(64);
const WRITTEN = new Map([[GUARD, NOW]]);

describe('bodyReads', () => {
  const held = knownBodies(WRITTEN, [], [{ function: GUARD, body: NEXT }]);

  it.each([
    ['the body its migration wrote', GUARD, NOW, 'as written'],
    ['the coming body exactly', GUARD, NEXT, 'coming'],
    ['any other body', GUARD, OTHER, 'other'],
    ['the coming hash in other letters', GUARD, NEXT.toUpperCase(), 'other'],
    ['a function this image does not know, whatever its body', 'audit.planted', NEXT, 'unknown'],
  ])('reads %s', (_what, name, body, reads) => {
    expect(bodyReads({ name, body }, held)).toBe(reads);
  });

  it('with nothing coming, any body but the written one is the alarm', () => {
    expect(bodyReads({ name: GUARD, body: NEXT }, knownBodies(WRITTEN, [], []))).toBe('other');
  });
});

describe('knownBodies', () => {
  it("keeps a coming body to its own function: another function's body is the alarm", () => {
    const held = knownBodies(
      new Map([
        [GUARD, NOW],
        ['state_rules.guard_made_once', OTHER],
      ]),
      [],
      [{ function: GUARD, body: NEXT }],
    );
    expect(bodyReads({ name: 'state_rules.guard_made_once', body: NEXT }, held)).toBe('other');
  });

  it("takes a coming trigger's new function as known, held to its body", () => {
    const held = knownBodies(WRITTEN, [{ function: 'directory.coming_mark', body: NEXT }], []);
    expect(bodyReads({ name: 'directory.coming_mark', body: NEXT }, held)).toBe('as written');
    expect(bodyReads({ name: 'directory.coming_mark', body: OTHER }, held)).toBe('other');
  });

  it("makes a coming trigger's other body for a known function coming, beside the one held, never in its place", () => {
    const held = knownBodies(WRITTEN, [{ function: GUARD, body: NEXT }], []);
    expect(bodyReads({ name: GUARD, body: NOW }, held)).toBe('as written');
    expect(bodyReads({ name: GUARD, body: NEXT }, held)).toBe('coming');
  });

  it('lists nothing as coming that is the body held now', () => {
    const held = knownBodies(WRITTEN, [{ function: GUARD, body: NOW }], [{ function: GUARD, body: NOW }]);
    expect(held.coming.size).toBe(0);
  });

  it('holds several coming bodies for one function, each exactly', () => {
    const held = knownBodies(
      WRITTEN,
      [],
      [
        { function: GUARD, body: NEXT },
        { function: GUARD, body: OTHER },
      ],
    );
    expect([...(held.coming.get(GUARD) ?? [])]).toEqual([NEXT, OTHER]);
  });
});

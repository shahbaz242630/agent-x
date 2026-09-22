import { describe, expect, it } from 'vitest';

import { checkName, ORGANIZATION, OrganizationRefused } from './organization.ts';

function problemsOf(name: string): readonly string[] {
  try {
    checkName(name);
    return [];
  } catch (error) {
    if (error instanceof OrganizationRefused) return error.problems;
    throw error;
  }
}

const LENGTH = 'the name is 1 to 200 characters';
const INVISIBLE = 'the name holds a control, format or unassigned character';
const SPACE = 'the name starts or ends with a space';

/** A letter outside the Basic Multilingual Plane, two UTF-16 units: MATHEMATICAL SCRIPT CAPITAL A. */
const WIDE = String.fromCodePoint(0x1d49c);

describe('the organization machine', () => {
  it('starts ACTIVE, and moves only by freeze and unfreeze, in the order 0008’s status guard lists them', () => {
    expect(ORGANIZATION.states).toEqual(['ACTIVE', 'FROZEN']);
    expect(ORGANIZATION.initial).toBe('ACTIVE');
    expect(ORGANIZATION.moves).toEqual([
      { from: 'ACTIVE', to: 'FROZEN' },
      { from: 'FROZEN', to: 'ACTIVE' },
    ]);
  });

  it('refuses a freeze of a frozen organisation, and an unfreeze of an active one', () => {
    expect(ORGANIZATION.transition('FROZEN', 'freeze')).toEqual({ ok: false, problem: 'not_allowed', from: 'FROZEN' });
    expect(ORGANIZATION.transition('ACTIVE', 'unfreeze')).toEqual({
      ok: false,
      problem: 'not_allowed',
      from: 'ACTIVE',
    });
  });
});

describe("an organisation's name", () => {
  it.each([
    ['a plain name', 'Acme Trading LLC'],
    ['one character', 'A'],
    ['a name in Arabic', String.fromCodePoint(0x634, 0x631, 0x643, 0x629)],
    ['spaces inside it', 'Acme  Trading'],
    ['200 characters', 'a'.repeat(200)],
    ['200 characters of two UTF-16 units each, counted as the table counts them', WIDE.repeat(200)],
  ])('takes %s', (_, name) => {
    expect(problemsOf(name)).toEqual([]);
  });

  it.each([
    ['nothing', ''],
    ['201 characters', 'a'.repeat(201)],
    ['201 characters of two units each', WIDE.repeat(201)],
  ])('refuses %s', (_, name) => {
    expect(problemsOf(name)).toEqual([LENGTH]);
  });

  it.each([
    ['a control character', `Acme${String.fromCharCode(0x07)}`],
    ['a line break', `Acme${String.fromCharCode(0x0a)}Trading`],
    ['a right-to-left override, which could make one name read as another', `Acme${String.fromCharCode(0x202e)}CLL`],
    ['a zero-width space', `Ac${String.fromCharCode(0x200b)}me`],
    ['half a surrogate pair', `Acme${String.fromCharCode(0xd800)}`],
    ['a private-use character', `Acme${String.fromCharCode(0xe000)}`],
    ['an unassigned code point', `Acme${String.fromCharCode(0x0378)}`],
  ])('refuses %s', (_, name) => {
    expect(problemsOf(name)).toEqual([INVISIBLE]);
  });

  it.each([
    ['a space before it', ' Acme'],
    ['a space after it', 'Acme '],
    ['a no-break space after it', `Acme${String.fromCharCode(0xa0)}`],
  ])('refuses %s', (_, name) => {
    expect(problemsOf(name)).toEqual([SPACE]);
  });

  it('names every problem at once, and never the name itself', () => {
    const name = ` ${'Secret Holdings'.repeat(14)}${String.fromCharCode(0x07)}`;
    const refused = (() => {
      try {
        checkName(name);
      } catch (error) {
        return error;
      }
      throw new Error('The name should have been refused');
    })();

    expect(refused).toBeInstanceOf(OrganizationRefused);
    expect(refused).toMatchObject({
      name: 'OrganizationRefused',
      problems: [LENGTH, INVISIBLE, SPACE],
      message: `The organisation was refused: ${[LENGTH, INVISIBLE, SPACE].join('; ')}`,
    });
    expect((refused as Error).message).not.toContain('Secret');
  });
});

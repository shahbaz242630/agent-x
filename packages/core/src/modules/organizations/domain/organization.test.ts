import { describe, expect, it } from 'vitest';

import { ORGANIZATION, organizationName, OrganizationRefused } from './organization.ts';

function problemsOf(name: string): readonly string[] {
  try {
    organizationName(name);
    return [];
  } catch (error) {
    if (error instanceof OrganizationRefused) return error.problems;
    throw error;
  }
}

const LENGTH = 'the name is 1 to 200 characters';
const INVISIBLE = 'the name holds a control, format, invisible or unassigned character';
const SPACE = 'the name starts or ends with a space';
const UNREADABLE = 'the name has no letter or digit';
const STACKED = 'the name starts with a combining mark, or stacks more than 4 on one';

/** Text from code points, so no invisible character is ever written into this file. */
const text = (...points: number[]): string => String.fromCodePoint(...points);

/** A letter outside the Basic Multilingual Plane, two UTF-16 units: MATHEMATICAL SCRIPT CAPITAL A. */
const WIDE = text(0x1d49c);
const ZWNJ = 0x200c;
const ZWJ = 0x200d;
/** COMBINING LOW LINE, which composes with no letter, so NFC leaves it where it is. */
const LOW_LINE = 0x332;

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
    ['digits alone', '1990'],
    ['a name in Arabic', text(0x634, 0x631, 0x643, 0x629)],
    [
      'Arabic with its vowel marks, two on one letter (fatha and shadda, in the order NFC keeps them)',
      text(0x645, 0x64f, 0x62d, 0x64e, 0x645, 0x64e, 0x651, 0x62f),
    ],
    ['Persian with a zero-width non-joiner inside a word', text(0x645, 0x6cc, ZWNJ, 0x62e, 0x648, 0x627, 0x647, 0x645)],
    ['a Devanagari conjunct with a zero-width joiner after its virama', text(0x915, 0x94d, ZWJ, 0x937)],
    ['four combining marks on one character', `A${text(LOW_LINE, LOW_LINE, LOW_LINE, LOW_LINE)}`],
    ['spaces inside it', 'Acme  Trading'],
    ['200 characters', 'a'.repeat(200)],
    ['200 characters of two UTF-16 units each, counted as the table counts them', WIDE.repeat(200)],
  ])('takes %s', (_, name) => {
    expect(problemsOf(name)).toEqual([]);
    expect(organizationName(name)).toBe(name);
  });

  it('keeps a name composed (NFC), so two names that look the same are the same text', () => {
    const decomposed = `Cafe${text(0x301)}`;

    expect(organizationName(decomposed)).toBe(`Caf${text(0xe9)}`);
    expect(organizationName(decomposed)).toBe(organizationName(`Caf${text(0xe9)}`));
  });

  it.each([
    ['nothing', '', [LENGTH, UNREADABLE]],
    ['201 characters', 'a'.repeat(201), [LENGTH]],
    ['201 characters of two units each', WIDE.repeat(201), [LENGTH]],
  ])('refuses %s', (_, name, problems) => {
    expect(problemsOf(name)).toEqual(problems);
  });

  it.each([
    ['a control character', `Acme${text(0x07)}`],
    ['a line break', `Acme${text(0x0a)}Trading`],
    ['a line separator', `Acme${text(0x2028)}Trading`],
    ['a paragraph separator', `Acme${text(0x2029)}Trading`],
    ['a right-to-left override, which could make one name read as another', `Acme${text(0x202e)}CLL`],
    ['a zero-width space', `Ac${text(0x200b)}me`],
    ['a zero-width non-joiner at the start', `${text(ZWNJ)}Acme`],
    ['a zero-width joiner before a space', `Acme${text(ZWJ)} Trading`],
    ['a zero-width joiner between two emoji, which are no letters', `Acme ${text(0x1f468, ZWJ, 0x1f469)}`],
    ['a Hangul filler, a letter that shows as nothing', `Acme${text(0x3164)}`],
    ['a halfwidth Hangul filler', `Acme${text(0xffa0)}`],
    ['a Hangul choseong filler', `Acme${text(0x115f)}`],
    ['a variation selector', `Acme ${text(0x2764, 0xfe0f)}`],
    ['the blank braille pattern, which shows as a space', `Acme${text(0x2800)}Trading`],
    ['half a surrogate pair', `Acme${String.fromCharCode(0xd800)}`],
    ['a private-use character', `Acme${text(0xe000)}`],
    ['an unassigned code point', `Acme${text(0x0378)}`],
  ])('refuses %s', (_, name) => {
    expect(problemsOf(name)).toEqual([INVISIBLE]);
  });

  it.each([
    // A Hangul filler counts as a letter, so only its invisibility refuses it.
    ['nothing but Hangul fillers', text(0x3164, 0x3164), [INVISIBLE]],
    ['nothing but blank braille', text(0x2800), [INVISIBLE, UNREADABLE]],
    ['punctuation alone', '!!!', [UNREADABLE]],
    ['an emoji alone', text(0x1f642), [UNREADABLE]],
  ])('refuses %s', (_, name, problems) => {
    expect(problemsOf(name)).toEqual(problems);
  });

  it.each([
    ['a space before it', ' Acme'],
    ['a space after it', 'Acme '],
    ['a no-break space after it', `Acme${text(0xa0)}`],
  ])('refuses %s', (_, name) => {
    expect(problemsOf(name)).toEqual([SPACE]);
  });

  it.each([
    ['a combining mark on its own', text(0x301), [UNREADABLE, STACKED]],
    ['a combining mark first', `${text(LOW_LINE)}Acme`, [STACKED]],
    ['five combining marks on one character', `A${text(LOW_LINE, LOW_LINE, LOW_LINE, LOW_LINE, LOW_LINE)}`, [STACKED]],
    ['a letter carrying 199 of them', `A${text(LOW_LINE).repeat(199)}`, [STACKED]],
  ])('refuses %s', (_, name, problems) => {
    expect(problemsOf(name)).toEqual(problems);
  });

  it('names every problem at once, and never the name itself', () => {
    const name = ` ${'Secret Holdings'.repeat(14)}${text(0x07)}`;
    const refused = (() => {
      try {
        organizationName(name);
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

import { describe, expect, it } from 'vitest';

import { MOST_NAME_LENGTH, personName } from './person-name.ts';

describe('personName', () => {
  it('keeps a name as one line, its spaces single and trimmed', () => {
    expect(personName('  Sara   Al Mansoori ')).toBe('Sara Al Mansoori');
    expect(personName('سارة المنصوري')).toBe('سارة المنصوري');
  });

  it('turns control and reordering characters into spaces', () => {
    expect(personName('Sara\nAdmin\u0000')).toBe('Sara Admin');
    expect(personName('Sara\u202eniamdA')).toBe('Sara niamdA');
    expect(personName('A\u2066B\u2069C\u200fD\u0085E')).toBe('A B C D E');
  });

  it('takes nothing that isn’t a name: not text, empty, broken text or too long', () => {
    for (const value of [undefined, null, 42, {}, '', '   ', '\u0000\u202e', 'Sara\ud800']) {
      expect(personName(value)).toBeUndefined();
    }
    expect(personName('a'.repeat(MOST_NAME_LENGTH))).toHaveLength(MOST_NAME_LENGTH);
    expect(personName('a'.repeat(MOST_NAME_LENGTH + 1))).toBeUndefined();
  });
});

// Digits of any script read as 0–9 (S68; partner decision 8).
import { describe, expect, it } from 'vitest';

import { asciiDigits } from './digits.ts';

describe('digits of any script, as 0–9', () => {
  it.each([
    ['ASCII, unchanged', 'A0129', 'A0129'],
    ['Arabic-Indic', '٠١٢٣٤٥٦٧٨٩', '0123456789'],
    ['Extended Arabic-Indic and Devanagari', '۴۵ ६७', '45 67'],
    ['Tai Tham’s second run, touching its first', '᪀᪉᪐᪙', '0909'],
    ['the mathematical digits’ fifth run', '\u{1D7F6}\u{1D7FF}', '09'],
    ['letters, untouched', 'فاتورة', 'فاتورة'],
  ])('reads %s', (_what, text, expected) => {
    expect(asciiDigits(text)).toBe(expected);
  });
});

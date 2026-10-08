// Partner decisions 6 and 8 (Phase 2 D4r): a request's text checked as 0039
// checks it, and the bank reference an order reference becomes on the rail.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { askedText, BANK_REFERENCE_MOST, bankReferenceOf, SpendAskRefused } from './asked.ts';

const REQUEST_ID = '0199a0f0-0000-7000-8000-0000000000aa';
const OWN_REFERENCE = '0199a0f00000700080000000000000aa';

/** What the rail's creditor reference takes (rail map: `AECreditorReference`). */
const RAIL = /^[A-Za-z0-9 /?:().,'+-]{1,35}$/;

const problemsOf = (asked: { purpose: string; orderReference: string }): readonly string[] => {
  try {
    askedText(asked);
    return [];
  } catch (error) {
    if (error instanceof SpendAskRefused) return error.problems;
    throw error;
  }
};

describe("a request's purpose and order reference (decision 6)", () => {
  it('keeps any script, composed', () => {
    expect(askedText({ purpose: 'Cafe\u0301 supplies', orderReference: 'No\u0301 ١٢' })).toEqual({
      purpose: 'Café supplies',
      orderReference: 'Nó ١٢',
    });
  });

  it('takes an order reference of 100 characters, and a purpose of 200, not one more', () => {
    expect(problemsOf({ purpose: 'p'.repeat(200), orderReference: 'r'.repeat(100) })).toEqual([]);
    expect(problemsOf({ purpose: 'p'.repeat(201), orderReference: 'r'.repeat(101) })).toEqual([
      'the purpose is 1 to 200 characters',
      'the order reference is 1 to 100 characters',
    ]);
  });

  it.each([
    ['empty', ''],
    ['a control character', 'INV\u00001'],
    ['spaces at its ends', ' INV-1 '],
    ['no letter or digit', '#'],
  ])('refuses an order reference %s, naming it', (_what, orderReference) => {
    expect(problemsOf({ purpose: 'Paper', orderReference }).every((p) => p.startsWith('the order reference'))).toBe(
      true,
    );
    expect(problemsOf({ purpose: 'Paper', orderReference })).not.toEqual([]);
  });
});

describe('the bank reference an order reference becomes (decision 8)', () => {
  it.each([
    ['as written, when the rail carries it', "PO 1/2 (b),+?:.-'", "PO 1/2 (b),+?:.-'"],
    ['`_` as `-`', 'INV_22', 'INV-22'],
    ['`#` dropped', 'PO#1', 'PO1'],
    ['Arabic-Indic digits as 0–9', 'INV-١٢', 'INV-12'],
    ['Extended Arabic-Indic and Devanagari digits as 0–9', '۴۵ ६७', '45 67'],
    ['Tai Tham’s second run of digits as 0–9', 'A᪐᪙', 'A09'],
    ['full-width letters and digits as plain', 'ＩＮＶ１２', 'INV12'],
    ['accents dropped', 'Café-7', 'Cafe-7'],
    ['Arabic letters dropped, the spaces they leave made one', 'فاتورة ١٢ ب 3', '12 3'],
    ['cut to 35', 'A'.repeat(40), 'A'.repeat(35)],
    ['cut to 35, no space left at its end', `${'A'.repeat(34)} B`, 'A'.repeat(34)],
  ])('keeps %s', (_what, orderReference, expected) => {
    expect(bankReferenceOf(orderReference, REQUEST_ID)).toBe(expected);
  });

  it.each([
    ['all Arabic', 'فاتورة'],
    ['only what the rail drops, and dashes', '#_#'],
  ])('is the request’s own ID, its dashes taken out, when nothing usable is left: %s', (_what, orderReference) => {
    expect(bankReferenceOf(orderReference, REQUEST_ID)).toBe(OWN_REFERENCE);
  });

  it('is always one the rail takes, whatever the order reference', () => {
    fc.assert(
      fc.property(fc.string({ unit: 'binary', minLength: 1, maxLength: 100 }), (reference) => {
        const made = bankReferenceOf(reference, REQUEST_ID);
        expect(made).toMatch(RAIL);
        expect(made.length).toBeLessThanOrEqual(BANK_REFERENCE_MOST);
      }),
    );
  });

  it('leaves a reference the rail carries, with a letter or digit, as it is', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[A-Za-z0-9][A-Za-z0-9/?:().,'+-]{0,34}$/), (reference) => {
        expect(bankReferenceOf(reference, REQUEST_ID)).toBe(reference);
      }),
    );
  });
});

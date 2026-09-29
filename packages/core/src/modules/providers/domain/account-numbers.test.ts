// ADR-014 §3, PRD §6 (D1-1): an adapter's answers hold no account number,
// and a source keeps only a hint of one.
import { SENSITIVE_SAMPLES } from '@agentx/testing';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { SANDBOX_ACCOUNTS } from '../infrastructure/sandbox-accounts.ts';
import { AccountNumberLeak, accountHint, isUaeIban, withoutAccountNumbers } from './account-numbers.ts';

const IBANS = SANDBOX_ACCOUNTS.flatMap((account) => account.AccountIdentifiers.map((each) => each.Identification));
const [IBAN = ''] = IBANS;

/** A UAE IBAN with valid check digits around any 19 digits (ISO 13616). */
function uaeIban(digits: string): string {
  // A is 10 and E is 14; the check digits make the whole 1 mod 97.
  const check = 98n - (BigInt(`${digits}101400`) % 97n);
  return `AE${String(check).padStart(2, '0')}${digits}`;
}

const leaks = (answer: unknown, known: readonly string[] = []): boolean => {
  try {
    withoutAccountNumbers(answer, known);
    return false;
  } catch (error) {
    expect(error).toBeInstanceOf(AccountNumberLeak);
    return true;
  }
};

describe('withoutAccountNumbers (D1-1)', () => {
  it('gives a clean answer back as it was', () => {
    const answer = { holderName: 'Jasmine AI FZ-LLC', hint: 'AE…6026', at: new Date(0), limit: 5_000_000n, n: 100 };
    expect(withoutAccountNumbers(answer, IBANS)).toBe(answer);
  });

  it.each(IBANS)('finds the sandbox IBAN %s however it is written, even with no account numbers named', (iban) => {
    const spaced = iban.replace(/(.{4})/g, '$1 ').trim();
    for (const text of [iban, spaced, iban.toLowerCase(), `paid from ${iban}.`, `${iban}XYZ`]) {
      expect(leaks({ note: text })).toBe(true);
    }
  });

  it('finds the documentation IBANs the log checks plant', () => {
    for (const text of [SENSITIVE_SAMPLES.uaeIban, SENSITIVE_SAMPLES.spacedUaeIban, SENSITIVE_SAMPLES.lowercaseIban]) {
      expect(leaks(text)).toBe(true);
    }
  });

  it('finds an IBAN in groups with a word run on after it, and the shortest IBANs (15 characters)', () => {
    const spaced = SENSITIVE_SAMPLES.lowercaseIban.replace(/(.{4})/g, '$1 ').trim();
    expect(leaks({ note: `${spaced} paid` })).toBe(true);
    // The IBAN registry's own example for Norway.
    expect(leaks({ note: ['NO93', '8601', '1117', '947'].join('') })).toBe(true);
  });

  it('looks in keys, arrays and nested objects, and at numbers written out', () => {
    expect(leaks({ [IBAN]: 'x' })).toBe(true);
    expect(leaks({ a: [{ b: [IBAN] }] })).toBe(true);
    expect(leaks({ account: 76394720046026 }, [IBAN])).toBe(true);
    expect(leaks({ account: 76394720046026n }, [IBAN])).toBe(true);
  });

  it('finds 8 characters in a row of a known account number, not 7', () => {
    expect(leaks({ note: `…${IBAN.slice(9, 17)}…` }, [IBAN])).toBe(true);
    expect(leaks({ note: `…${IBAN.slice(9, 16)}…` }, [IBAN])).toBe(false);
    expect(leaks({ note: IBAN.slice(-8).split('').join(' ') }, [IBAN])).toBe(true);
  });

  it('lets through what only looks like an IBAN: bad check digits, UUIDs, references', () => {
    const wrong = `AE${String((Number(IBAN.slice(2, 4)) + 1) % 100).padStart(2, '0')}${IBAN.slice(4)}`;
    expect(leaks({ note: wrong })).toBe(false);
    expect(
      leaks({ id: '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', ref: 'fake-consent-00000000-0000-7000-8000-000000000001' }),
    ).toBe(false);
  });

  it('never says which number it found', () => {
    const refused = ((): unknown => {
      try {
        return withoutAccountNumbers({ note: IBAN }, [IBAN]);
      } catch (error) {
        return error;
      }
    })();
    expect(refused).toBeInstanceOf(AccountNumberLeak);
    expect(String(refused)).not.toContain(IBAN.slice(-4));
  });

  it('finds any valid UAE IBAN', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^\d{19}$/), fc.string({ maxLength: 20 }), (digits, around) => {
        expect(leaks({ note: `${around} ${uaeIban(digits)} ${around}` })).toBe(true);
      }),
    );
  });
});

describe('isUaeIban (D1-2)', () => {
  it('takes a UAE IBAN with valid check digits, in groups or lower case', () => {
    for (const iban of IBANS) expect(isUaeIban(iban)).toBe(true);
    expect(isUaeIban(IBAN.toLowerCase().replace(/(.{4})/g, '$1 '))).toBe(true);
  });

  it('refuses bad check digits, another country, and the wrong length', () => {
    expect(isUaeIban(`AE00${IBAN.slice(4)}`)).toBe(false);
    expect(isUaeIban(SENSITIVE_SAMPLES.lowercaseIban)).toBe(false);
    expect(isUaeIban(IBAN.slice(0, 22))).toBe(false);
    expect(isUaeIban(`${IBAN}0`)).toBe(false);
    expect(isUaeIban('')).toBe(false);
  });
});

describe('accountHint (D1-1)', () => {
  it('keeps the country and the last four characters', () => {
    expect(accountHint(IBAN)).toBe(`AE…${IBAN.slice(-4)}`);
    expect(accountHint('ae12 9991 6763 9472 0046 026')).toBe('AE…6026');
  });

  it('is never itself an account number', () => {
    for (const iban of IBANS) expect(leaks({ hint: accountHint(iban) }, IBANS)).toBe(false);
  });

  it.each(['', '12345678901', 'AE12', 'AE12-9991-6763'])('refuses %j', (text) => {
    expect(() => accountHint(text)).toThrow(RangeError);
  });
});

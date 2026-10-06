// BR-21 (Carry-Forward, E2-2 note a): a supplier's free text never keeps an IBAN.
import { describe, expect, it } from 'vitest';

import { type SupplierDetails, SupplierDetailsRefused } from '../domain/supplier.ts';
import { ACCOUNT_NUMBER_KEPT, keptSupplierDetails } from './kept-details.ts';

const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: 'accounts@gulfoffice.example', tradeLicence: 'CN-1234567' },
  source: { kind: 'registry', ref: 'DED-CN-1234567' },
};

/** The standard example UAE IBAN (valid check digits), joined and in groups. */
const IBAN = 'AE070331234567890123456';
const GROUPED = 'AE07 0331 2345 6789 0123 456';

const refused = (details: SupplierDetails): readonly string[] => {
  try {
    keptSupplierDetails(details);
  } catch (error) {
    if (error instanceof SupplierDetailsRefused) return error.problems;
    throw error;
  }
  throw new Error('Not refused');
};

describe('keptSupplierDetails', () => {
  it('keeps details with no account number in them, as supplierDetails keeps them', () => {
    expect(keptSupplierDetails(DETAILS)).toEqual(DETAILS);
  });

  it.each([
    ['as the source’s reference', { ...DETAILS, source: { kind: 'registry', ref: IBAN } }],
    ['as the trade licence', { ...DETAILS, contacts: { ...DETAILS.contacts, tradeLicence: IBAN } }],
    ['in groups in the name', { ...DETAILS, displayName: `Glide ${GROUPED}` }],
  ] as const)('refuses an IBAN %s, never saying the number or where', (_where, details) => {
    const problems = refused(details);

    expect(problems).toEqual([ACCOUNT_NUMBER_KEPT]);
    expect(problems.join(' ')).not.toContain('0331');
  });

  it('keeps a long reference whose check digits fail: a registry number is never taken for an IBAN', () => {
    const notAnIban = 'AE000331234567890123456';

    expect(keptSupplierDetails({ ...DETAILS, source: { kind: 'registry', ref: notAnIban } }).source.ref).toBe(
      notAnIban,
    );
  });

  it('gives the details’ own problems first, unchanged', () => {
    expect(refused({ ...DETAILS, contacts: { ...DETAILS.contacts, phone: '050' } })).toEqual([
      expect.stringContaining('the phone'),
    ]);
  });
});

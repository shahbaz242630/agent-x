// ADR-012 §1, the partner's Stage E choices (S69; E1-1): a supplier's
// status, and the details a version may hold.
import { describe, expect, it } from 'vitest';

import { contactsHeld, SUPPLIER, type SupplierDetails, SupplierDetailsRefused, supplierDetails } from './supplier.ts';

const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: 'Accounts@GulfOffice.example', tradeLicence: 'CN-1234567' },
  source: { kind: 'registry', ref: 'DED-CN-1234567' },
};

const refused = (details: SupplierDetails): readonly string[] => {
  try {
    supplierDetails(details);
  } catch (error) {
    if (error instanceof SupplierDetailsRefused) return error.problems;
    throw error;
  }
  throw new Error('Not refused');
};

describe('a supplier’s status (E1-1)', () => {
  it('starts UNVERIFIED, and moves only as 0032’s guard lists', () => {
    expect(SUPPLIER.initial).toBe('UNVERIFIED');
    expect(SUPPLIER.moves.map(({ from, to }) => `${from}>${to}`).sort()).toEqual([
      'SUSPENDED>UNVERIFIED',
      'SUSPENDED>VERIFIED',
      'UNVERIFIED>SUSPENDED',
      'UNVERIFIED>VERIFIED',
      'VERIFIED>SUSPENDED',
      'VERIFIED>UNVERIFIED',
    ]);
  });

  it('is verified only from UNVERIFIED: a suspended supplier is never verified past its brake', () => {
    expect(SUPPLIER.transition('SUSPENDED', 'verify')).toEqual({
      ok: false,
      problem: 'not_allowed',
      from: 'SUSPENDED',
    });
    expect(SUPPLIER.transition('UNVERIFIED', 'verify')).toEqual({ ok: true, from: 'UNVERIFIED', to: 'VERIFIED' });
  });
});

describe('a version’s details (E1-1)', () => {
  it('are kept with the name composed and the email in lower case', () => {
    expect(supplierDetails({ ...DETAILS, displayName: 'Café Supplies' })).toEqual({
      displayName: 'Café Supplies',
      contacts: { phone: '+971501234567', email: 'accounts@gulfoffice.example', tradeLicence: 'CN-1234567' },
      source: { kind: 'registry', ref: 'DED-CN-1234567' },
    });
  });

  it('need only a name, a phone and a source: the email and the trade licence are optional', () => {
    const bare = { ...DETAILS, contacts: { phone: '+971501234567', email: null, tradeLicence: null } };

    expect(supplierDetails(bare).contacts).toEqual({ phone: '+971501234567', email: null, tradeLicence: null });
  });

  it.each([
    ['a name no one can see', { ...DETAILS, displayName: String.fromCharCode(0x200b) }, 'the name holds a control'],
    ['a name too long', { ...DETAILS, displayName: 'x'.repeat(101) }, 'the name is 1 to 100 characters'],
    ['a local phone', { ...DETAILS, contacts: { ...DETAILS.contacts, phone: '0501234567' } }, 'the phone'],
    ['a phone with spaces', { ...DETAILS, contacts: { ...DETAILS.contacts, phone: '+971 50 123 4567' } }, 'the phone'],
    ['a phone too long', { ...DETAILS, contacts: { ...DETAILS.contacts, phone: '+9715012345678901' } }, 'the phone'],
    ['two addresses', { ...DETAILS, contacts: { ...DETAILS.contacts, email: 'a@b.example,c@d.example' } }, 'email'],
    ['an address of two @', { ...DETAILS, contacts: { ...DETAILS.contacts, email: 'a@b@c.example' } }, 'email'],
    ['an address with a space', { ...DETAILS, contacts: { ...DETAILS.contacts, email: 'a b@c.example' } }, 'email'],
    ['an address past ASCII', { ...DETAILS, contacts: { ...DETAILS.contacts, email: 'ä@c.example' } }, 'email'],
    ['a licence with a space', { ...DETAILS, contacts: { ...DETAILS.contacts, tradeLicence: 'CN 1' } }, 'licence'],
    ['a licence too long', { ...DETAILS, contacts: { ...DETAILS.contacts, tradeLicence: '1'.repeat(51) } }, 'licence'],
    ['a source of no kind', { ...DETAILS, source: { kind: 'a_friend' as 'registry', ref: 'x' } }, 'the source is'],
    ['a source’s reference too long', { ...DETAILS, source: { kind: 'registry', ref: 'x'.repeat(201) } }, 'reference'],
    ['a source’s reference with a space', { ...DETAILS, source: { kind: 'registry', ref: 'a b' } }, 'reference'],
  ] as const)('refuse %s, naming the problem, never the value', (_case, details, problem) => {
    const problems = refused(details);

    expect(problems).toContainEqual(expect.stringContaining(problem));
    expect(problems.join(' ')).not.toContain('@c.example');
  });

  it('hold each contact at its own byte bound: the longest of each is accepted, one more is not', () => {
    const longest = {
      ...DETAILS,
      contacts: {
        phone: `+9${'1'.repeat(14)}`,
        email: `${'a'.repeat(64)}@${'b'.repeat(189)}`,
        tradeLicence: 'L'.repeat(50),
      },
    };

    expect(() => supplierDetails(longest)).not.toThrow();
    expect(refused({ ...longest, contacts: { ...longest.contacts, email: `${'a'.repeat(65)}@b` } })).toEqual([
      'the email is not one address',
    ]);
    expect(refused({ ...longest, contacts: { ...longest.contacts, email: `a@${'b'.repeat(190)}` } })).toEqual([
      'the email is not one address',
    ]);
  });
});

describe('which contacts a version holds (E1-1)', () => {
  it.each([
    [{ phone: '+971501234567', email: null, tradeLicence: null }, 'phone'],
    [{ phone: '+971501234567', email: 'a@b.example', tradeLicence: null }, 'phone email'],
    [{ phone: '+971501234567', email: null, tradeLicence: 'CN-1' }, 'phone licence'],
    [{ phone: '+971501234567', email: 'a@b.example', tradeLicence: 'CN-1' }, 'phone email licence'],
  ] as const)('is always the phone, then the others given: %j is %s', (contacts, held) => {
    expect(contactsHeld(contacts)).toBe(held);
  });
});

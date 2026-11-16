// 6D2: a supplier's details, its IBAN and a call-back note are checked by the
// API's own rules before anything is sent, and the page says why a supplier
// can't be verified yet in the API's order.
import { describe, expect, it } from 'vitest';

import { ApiError } from './api.ts';
import {
  coolingOff,
  decidesTheTry,
  isCallNote,
  isUaeIban,
  type NewSupplier,
  newSupplierBody,
  newSupplierProblems,
  notYetVerifiable,
  type Supplier,
} from './suppliers.ts';

describe('isUaeIban', () => {
  it.each([
    ['a UAE IBAN', 'AE070331234567890123456', true],
    ['with spaces, as printed', 'AE07 0331 2345 6789 0123 456', true],
    ['in lower case', 'ae070331234567890123456', true],
    ['in full-width digits', 'AE０７0331234567890123456', true],
    ['with a wrong check digit', 'AE080331234567890123456', false],
    ['one digit short', 'AE07033123456789012345', false],
    ['another country’s', 'GB82WEST12345698765432', false],
    ['another country’s, digits only and valid check digits', 'GB590331234567890123456', false],
    ['one digit short, with valid check digits', 'AE93033123456789012345', false],
    ['a letter among the digits', 'AE07033123456789012345X', false],
    ['nothing', '', false],
  ])('%s', (_what, iban, fine) => {
    expect(isUaeIban(iban)).toBe(fine);
  });
});

describe('isCallNote', () => {
  it.each([
    ['a plain note', 'Spoke to Sara in accounts', true],
    ['500 characters', 'a'.repeat(500), true],
    ['501 characters', 'a'.repeat(501), false],
    ['a phone number in it', 'Called 050 123 4567', false],
    ['an account number in it', 'Confirmed 0331234567890', false],
    ['six digits, not a long number', 'Ticket 123456', true],
    ['seven digits, a long number', 'Ticket 1234567', false],
    ['a space at the end', 'Spoke to Sara ', false],
    ['nothing', '', false],
  ])('%s', (_what, note, fine) => {
    expect(isCallNote(note)).toBe(fine);
  });
});

const TYPED: NewSupplier = {
  displayName: 'Gulf Traders',
  phone: '+971501234567',
  email: '',
  tradeLicence: '',
  sourceKind: 'official_website',
  sourceRef: 'https://gulf.example',
  remittanceEmail: 'on',
};

describe('a new supplier', () => {
  it('has no problems when every rule is kept, the optional ones left empty', () => {
    expect(newSupplierProblems(TYPED)).toEqual([]);
    expect(newSupplierBody(TYPED)).toEqual({
      displayName: 'Gulf Traders',
      phone: '+971501234567',
      source: { kind: 'official_website', ref: 'https://gulf.example' },
      remittanceEmail: 'on',
    });
  });

  it.each([
    ['a phone not in international form', { phone: '0501234567' }, 'phone'],
    ['a phone starting +0', { phone: '+0501234567' }, 'phone'],
    ['a source with a space', { sourceRef: 'DED 12345' }, 'sourceRef'],
    ['a source of 201 characters', { sourceRef: 'a'.repeat(201) }, 'sourceRef'],
    ['two @ in an email', { email: 'a@b@c' }, 'email'],
    ['a licence starting with /', { tradeLicence: '/12' }, 'tradeLicence'],
    ['a name with a space at the end', { displayName: 'Gulf ' }, 'displayName'],
  ])('finds %s', (_what, change, field) => {
    expect(newSupplierProblems({ ...TYPED, ...change })).toEqual([field]);
  });
});

const PAYEE = { registrationId: 'r', payeeHint: 'AE…3456', nameCheck: 'partial', maskedName: null } as const;
const SUPPLIER: Supplier = {
  id: 's',
  status: 'UNVERIFIED',
  displayName: 'Gulf Traders',
  changeWaiting: false,
  coolingOffUntil: '2026-11-16T00:00:00.000Z',
  verifiedBy: null,
  version: 1,
  phone: '+971501234567',
  phoneSince: '2026-10-01T00:00:00.000Z',
  email: null,
  tradeLicence: null,
  source: { kind: 'registry', ref: 'DED/1' },
  enteredBy: 'm',
  enteredAt: '2026-10-01T00:00:00.000Z',
  payee: PAYEE,
  remittanceEmail: 'off',
  pendingChange: null,
};
const ENDS = Date.parse('2026-11-16T00:00:00.000Z');

describe('notYetVerifiable', () => {
  it('lets it be tried from the moment its cooling-off ends, not before', () => {
    expect(coolingOff(SUPPLIER, ENDS - 1)).toBe(true);
    expect(notYetVerifiable(SUPPLIER, ENDS - 1)).toBe('suppliers.verify.coolingOff');
    expect(coolingOff(SUPPLIER, ENDS)).toBe(false);
    expect(notYetVerifiable(SUPPLIER, ENDS)).toBeUndefined();
  });

  it.each([
    ['verified already', { status: 'VERIFIED' }, undefined],
    ['suspended', { status: 'SUSPENDED' }, undefined],
    ['a change waiting, first', { changeWaiting: true, payee: null }, 'suppliers.verify.changeWaiting'],
    ['no payee', { payee: null }, 'suppliers.verify.noPayee'],
    ['no cooling-off begun', { coolingOffUntil: null }, 'suppliers.verify.coolingOff'],
    ['a name that doesn’t match', { payee: { ...PAYEE, nameCheck: 'no_match' } }, 'suppliers.verify.noMatch'],
    [
      'no cooling-off begun, before a name that doesn’t match',
      { coolingOffUntil: null, payee: { ...PAYEE, nameCheck: 'no_match' } },
      'suppliers.verify.coolingOff',
    ],
  ] as const)('says why for %s', (_what, change, why) => {
    expect(notYetVerifiable({ ...SUPPLIER, ...change }, ENDS)).toBe(why);
  });
});

describe('decidesTheTry', () => {
  it.each([
    ['no answer at all', new TypeError('Failed to fetch'), false, false],
    ['a 5xx', new ApiError(503, 'UNAVAILABLE'), false, false],
    ['a session that ended', new ApiError(401, 'UNAUTHENTICATED'), false, false],
    ['the first request still being worked on', new ApiError(409, 'IDEMPOTENCY_KEY_BUSY'), false, false],
    ['a change waiting', new ApiError(409, 'SUPPLIER_CHANGE_WAITING'), false, false],
    ['any other refusal', new ApiError(409, 'PAYEE_REGISTRATIONS_SPENT'), false, true],
    ['a retry: the supplier gone', new ApiError(404, 'NOT_FOUND'), true, true],
    ['a retry: the payee taken', new ApiError(409, 'SUPPLIER_PAYEE_TAKEN'), true, true],
    ['a retry: a session that ended', new ApiError(401, 'UNAUTHENTICATED'), true, false],
    ['a retry: a gate before the stored answer', new ApiError(409, 'STATEMENT_CHANGED'), true, false],
  ])('%s', (_what, error, retry, decided) => {
    expect(decidesTheTry(error, retry)).toBe(decided);
  });
});

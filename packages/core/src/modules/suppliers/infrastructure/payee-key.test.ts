// ADR-014 §3, SEC-DATA-07 (E2-1): a payee's key, from the partner's one
// source: its identity, or our fingerprint HMAC(payee-index, org ‖ IBAN), or
// none. The IBAN itself goes no further than the fingerprint.
import { createHash } from 'node:crypto';

import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { describe, expect, it } from 'vitest';

import { AccountNumberLeak, SANDBOX_ACCOUNTS } from '../../providers/index.ts';
import { noAccountNumberIn, normalisedIban, payeeFingerprint, payeeIndexMessage, payeeKeyOf } from './payee-key.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const [IBAN = ''] = SANDBOX_ACCOUNTS.flatMap((account) =>
  account.AccountIdentifiers.map((each) => each.Identification),
);
const ORG = '0199a0f0-0000-7000-8000-00000000e2a1';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000e2a2';

/** The IBAN as a person might type it: in groups of four, in lower case. */
const typed = IBAN.toLowerCase().replaceAll(/(.{4})/g, '$1 ');
/** And with full-width digits and a no-break space, as a phone's keyboard might give it. */
const fullWidth = `${IBAN.slice(0, 4)}${String.fromCodePoint(0xa0)}${IBAN.slice(4).replaceAll(/\d/g, (digit) => String.fromCodePoint(0xff10 + Number(digit)))}`;

describe('the IBAN a fingerprint is taken of (E2-1)', () => {
  it('is the IBAN in capitals with no spaces, however it was typed', () => {
    expect(IBAN).toMatch(/^AE\d{21}$/);
    expect(normalisedIban(typed)).toBe(IBAN);
    expect(normalisedIban(fullWidth)).toBe(IBAN);
  });

  it('refuses anything but a UAE IBAN with valid check digits, never naming it', () => {
    const wrongCheck = `AE00${IBAN.slice(4)}`;
    for (const text of [wrongCheck, 'GB82WEST12345698765432', IBAN.slice(0, 22), '']) {
      expect(() => normalisedIban(text)).toThrow(new RangeError('Not a UAE IBAN'));
    }
  });
});

describe('our fingerprint of an account (E2-1)', () => {
  it('is the payee-index key’s MAC of a label, the organisation and the IBAN, each written with its length', () => {
    expect(payeeIndexMessage(ORG.toUpperCase(), typed)).toEqual(['payee-index', ORG, IBAN]);
    const { key, keyVersion } = payeeFingerprint(keys, ORG, typed);
    expect(keyVersion).toBe(1);
    expect(key).toMatch(/^[0-9a-f]{64}$/);
    expect(keys.verifyMac('payee-index', 1, ['payee-index', ORG, IBAN], Buffer.from(key ?? '', 'hex'))).toBe(true);
    // Not some other key's, nor the parts glued together.
    expect(keys.verifyMac('request-hash', 1, ['payee-index', ORG, IBAN], Buffer.from(key ?? '', 'hex'))).toBe(false);
    expect(keys.verifyMac('payee-index', 1, [`payee-index${ORG}${IBAN}`], Buffer.from(key ?? '', 'hex'))).toBe(false);
  });

  it('is the same for the same account however typed, and another organisation’s is another', () => {
    const fingerprint = payeeFingerprint(keys, ORG, IBAN);
    expect(payeeFingerprint(keys, ORG.toUpperCase(), fullWidth)).toEqual(fingerprint);
    expect(payeeFingerprint(keys, OTHER_ORG, IBAN).key).not.toBe(fingerprint.key);
  });

  it('holds nothing of the IBAN, nor its plain SHA-256 (SEC-PAY-05)', () => {
    const { key } = payeeFingerprint(keys, ORG, IBAN);
    expect(key).not.toContain(IBAN.slice(-8));
    expect(key).not.toBe(createHash('sha256').update(IBAN).digest('hex'));
  });
});

describe('the payee key a registration keeps (E2-1)', () => {
  const fingerprint = payeeFingerprint(keys, ORG, IBAN);

  it('is the partner’s own identity, with no key version, for a partner that gives a stable one', () => {
    expect(payeeKeyOf('partner', { payeeIdentity: 'fake-payee-1' }, null)).toEqual({
      key: 'fake-payee-1',
      keyVersion: null,
    });
    // Its identity, never our fingerprint beside it.
    expect(payeeKeyOf('partner', { payeeIdentity: 'fake-payee-1' }, fingerprint)).toEqual({
      key: 'fake-payee-1',
      keyVersion: null,
    });
  });

  it('throws for a stable partner that gave none, or one the tables can’t hold', () => {
    for (const payeeIdentity of [null, '', 'has a space', 'x'.repeat(129), 'é']) {
      expect(() => payeeKeyOf('partner', { payeeIdentity }, fingerprint)).toThrow(/stable payee identity/);
    }
    expect(payeeKeyOf('partner', { payeeIdentity: '~'.repeat(128) }, null).key).toHaveLength(128);
  });

  it('throws for an identity holding an account number, never naming it (ADR-014 §3)', () => {
    for (const payeeIdentity of [IBAN, `payee-${IBAN.toLowerCase()}`, 'acct-1234567890', 'id:0123-4567-8901']) {
      expect(() => payeeKeyOf('partner', { payeeIdentity }, null)).toThrow(AccountNumberLeak);
      expect(() => noAccountNumberIn(payeeIdentity)).toThrow(new AccountNumberLeak());
    }
    // An opaque identity is kept: digits beside letters, a short run, an ID in the UUID form.
    for (const payeeIdentity of ['fake-payee-0123456789abcdef', 'ben-123456789', ORG, 'p1234567890q']) {
      expect(payeeKeyOf('partner', { payeeIdentity }, null)).toEqual({ key: payeeIdentity, keyVersion: null });
    }
  });

  it('keeps a hint of an account, and refuses one holding the account itself', () => {
    expect(noAccountNumberIn('AE…6026')).toBe('AE…6026');
    expect(noAccountNumberIn('Emirates NBD ••••6026')).toBe('Emirates NBD ••••6026');
    for (const hint of [IBAN, typed, fullWidth, '0331 2345 6789 0123', '٠١٢٣٤٥٦٧٨٩']) {
      expect(() => noAccountNumberIn(hint)).toThrow(AccountNumberLeak);
    }
  });

  it('is our fingerprint, with its key version, for a pass-through, whatever identity came back', () => {
    expect(payeeKeyOf('fingerprint', { payeeIdentity: 'fake-payee-1' }, fingerprint)).toEqual(fingerprint);
    expect(() => payeeKeyOf('fingerprint', { payeeIdentity: null }, null)).toThrow(RangeError);
    expect(() => payeeKeyOf('fingerprint', { payeeIdentity: null }, { key: null, keyVersion: null })).toThrow(
      RangeError,
    );
    expect(() =>
      payeeKeyOf('fingerprint', { payeeIdentity: null }, { key: fingerprint.key, keyVersion: null }),
    ).toThrow(RangeError);
  });

  it('is none where the partner has no source (R-13), whatever came back', () => {
    expect(payeeKeyOf('none', { payeeIdentity: 'fake-payee-1' }, fingerprint)).toEqual({ key: null, keyVersion: null });
  });
});

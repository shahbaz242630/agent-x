// A payee's key (ADR-014 §3, SEC-DATA-07): what makes one supplier per payee
// enforceable in an organisation (0033's `one_supplier_a_payee`), and what
// order claims and the split total are kept on. From one source per partner
// (domain/registration.ts's payeeKeySource): the partner's stable identity
// for the account, or our fingerprint, HMAC(payee-index, org_id ‖ normalised
// IBAN), taken during a pass-through in that request's memory, so only the
// fingerprint is ever stored, with its key's version. The payee-index key is
// never rotated in place: the IBANs aren't kept, so the fingerprints can't be
// taken again.
import type { KeyProvider } from '@agentx/platform/keys';

import { AccountNumberLeak, type BeneficiaryState, holdsAnAccountNumber, isUaeIban } from '../../providers/index.ts';
import type { PayeeKeySource } from '../domain/registration.ts';

/** A payee key as the tables hold it: printable ASCII, at most 128 characters. */
const PAYEE_KEY = /^[!-~]{1,128}$/;

/**
 * Gives `text` back, or throws AccountNumberLeak (which never names it) if it
 * holds an account number (holdsAnAccountNumber): what the partner gives as
 * a payee's identity or hint is kept as it is, and an account number never
 * is (ADR-014 §3), whatever an adapter let through.
 */
export function noAccountNumberIn(text: string): string {
  if (holdsAnAccountNumber(text)) throw new AccountNumberLeak();
  return text;
}

/** A partner with a stable payee identity gave none that can be kept: its answer breaks its contract. */
export class UnusablePayeeIdentity extends Error {
  constructor() {
    super('A partner with a stable payee identity gave none that can be kept');
    this.name = 'UnusablePayeeIdentity';
  }
}

/** A payee key and its key's version: null for a partner's own identity, and both null where there is none. */
export interface PayeeKey {
  readonly key: string | null;
  readonly keyVersion: number | null;
}

/** No payee key: a partner with only its hosted form and no stable identity (R-13). */
const NO_PAYEE_KEY: PayeeKey = { key: null, keyVersion: null };

/**
 * The IBAN as its fingerprint is taken of it: compatibility forms composed
 * (NFKC, so full-width digits are digits), every space taken out, in capitals.
 * Anything but a UAE IBAN with valid check digits is a RangeError, which
 * never names it.
 */
export function normalisedIban(text: string): string {
  const iban = text.normalize('NFKC').replaceAll(/\s/gu, '').toUpperCase();
  if (!isUaeIban(iban)) throw new RangeError('Not a UAE IBAN');
  return iban;
}

/**
 * What the payee-index key's MAC is taken over: a label, the organisation in
 * lower case and the normalised IBAN, each written with its length, so one
 * organisation's fingerprint is never another's.
 */
export const payeeIndexMessage = (orgId: string, iban: string): readonly [string, string, string] => [
  'payee-index',
  orgId.toLowerCase(),
  normalisedIban(iban),
];

/** Our fingerprint of the account, in hex, with the payee-index key's version. The IBAN goes no further. */
export function payeeFingerprint(keys: KeyProvider, orgId: string, iban: string): PayeeKey {
  const { keyVersion, mac } = keys.mac('payee-index', payeeIndexMessage(orgId, iban));
  return { key: Buffer.from(mac).toString('hex'), keyVersion };
}

/**
 * The registered payee's key, from the partner's one source: its identity
 * (which a partner with a stable one must give, and as the tables can hold
 * it, and never an account number: noAccountNumberIn), our fingerprint
 * (which a pass-through took), or none. Anything else throws, so a payee is
 * never kept with a key from another source than its partner's.
 */
export function payeeKeyOf(
  source: PayeeKeySource,
  beneficiary: Pick<BeneficiaryState, 'payeeIdentity'>,
  fingerprint: PayeeKey | null,
): PayeeKey {
  if (source === 'none') return NO_PAYEE_KEY;
  if (source === 'fingerprint') {
    const { key, keyVersion } = fingerprint ?? NO_PAYEE_KEY;
    if (key === null || keyVersion === null) {
      throw new RangeError('A pass-through registration takes its fingerprint, with its key version');
    }
    return { key, keyVersion };
  }
  const identity = beneficiary.payeeIdentity;
  if (identity === null || !PAYEE_KEY.test(identity)) {
    throw new UnusablePayeeIdentity();
  }
  return { key: noAccountNumberIn(identity), keyVersion: null };
}

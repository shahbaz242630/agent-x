// An organisation's suppliers (6D2): what one supplier's page reads (GET
// /v1/suppliers/:id: its details, its bank account as the payment partner
// described it, never an account number), the rules a new supplier's details,
// its bank details and a call-back note keep, and who may press what. The
// shapes and rules are the API's (suppliers.ts, the suppliers module); the
// roles only decide which buttons show, and the API checks again whatever is
// pressed.
import { useQuery } from '@tanstack/react-query';

import { api, ApiError, isIntegrityFailed, isRefusal, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import type { Role } from './session.tsx';
import { t, type TextKey } from './text.ts';
import { isKeptNote, isVisibleName } from './visible-name.ts';

type NameCheck = 'match' | 'partial' | 'no_match' | 'unavailable';
type SourceKind = 'registry' | 'official_website';
/** Whether a supplier is emailed when it is paid, as the API offers it (REMITTANCE_EMAILS): on first. */
export const REMITTANCE_EMAILS = ['on', 'off'] as const;
type RemittanceEmail = (typeof REMITTANCE_EMAILS)[number];

/** A supplier's bank account as the partner described it: what the call-back confirms, never the number. */
export interface Payee {
  readonly registrationId: string;
  readonly payeeHint: string | null;
  readonly nameCheck: NameCheck | null;
  readonly maskedName: string | null;
}

export interface Supplier {
  readonly id: string;
  readonly status: 'UNVERIFIED' | 'VERIFIED' | 'SUSPENDED';
  readonly displayName: string;
  readonly changeWaiting: boolean;
  readonly coolingOffUntil: string | null;
  /** The membership of the member who verified it. */
  readonly verifiedBy: string | null;
  readonly version: number;
  readonly phone: string;
  readonly phoneSince: string;
  readonly email: string | null;
  readonly tradeLicence: string | null;
  readonly source: { readonly kind: SourceKind; readonly ref: string };
  /** The membership of the member who entered its current details. */
  readonly enteredBy: string;
  readonly enteredAt: string;
  readonly payee: Payee | null;
  readonly remittanceEmail: RemittanceEmail;
  readonly pendingChange: { readonly version: number; readonly enteredAt: string; readonly payee: Payee | null } | null;
}

/** A registration of a supplier's bank details with the partner, as the API answers it. */
export interface Registration {
  readonly id: string;
  readonly supplierId: string;
  readonly status: 'STARTED' | 'REGISTERED' | 'FAILED' | 'UNKNOWN';
  readonly nameCheck: NameCheck | null;
  readonly maskedName: string | null;
  readonly payeeHint: string | null;
  readonly failure: 'invalid_details' | 'expired' | 'unknown' | null;
  readonly form: { readonly url: string; readonly expiresAt: string } | null;
}

/** Who may add a supplier (ADDING_ROLES), register its bank details and confirm them (REGISTERING_ROLES), and set its remittance email (REMITTANCE_ROLES): an admin. */
export const ADDING: readonly Role[] = ['admin'];
/** Who may verify a supplier (VERIFYING_ROLES) and withdraw new bank details waiting (WITHDRAWING_ROLES). */
export const VERIFYING: readonly Role[] = ['admin', 'approver'];

/** A supplier's address in the API. */
export const supplierAt = (id: string): string => `/v1/suppliers/${encodeURIComponent(id)}`;

/** One supplier with its details; asked for only by a UUID, as any other address names none (shown as not found). */
export function useSupplier(id: string, organization: string) {
  return useQuery({
    queryKey: ['suppliers', organization, 'one', id],
    enabled: isUuid(id),
    queryFn: () => api.get<Supplier>(supplierAt(id), { organization }),
  });
}

/** The most characters a supplier's name and an account holder's may have (SUPPLIER_NAME_MOST). */
export const NAME_MOST = 100;
/** The most characters a call-back note may have (CALL_NOTE_MOST). */
export const CALL_NOTE_MOST = 500;
/** The most characters a source's reference may have, and an IBAN typed with its spaces (the API's own bounds). */
export const SOURCE_REF_MOST = 200;
export const IBAN_MOST = 64;

// The API's own rules for a supplier's contacts (the suppliers module's supplierDetails), word for word.
const PHONE = /^\+[1-9][0-9]{7,14}$/;
const EMAIL = /^[!-?A-~]{1,64}@[!-?A-~]{1,189}$/;
const TRADE_LICENCE = /^[A-Za-z0-9][A-Za-z0-9/-]{0,49}$/;
const SOURCE_REF = /^[!-~]{1,200}$/;

/** What a new supplier is added with, as typed: the optional ones empty when not known. */
export interface NewSupplier {
  readonly displayName: string;
  readonly phone: string;
  readonly email: string;
  readonly tradeLicence: string;
  readonly sourceKind: SourceKind | null;
  readonly sourceRef: string;
  readonly remittanceEmail: RemittanceEmail | null;
}

/** Each part of a new supplier the API would refuse, by its field: checked before anything is sent. */
export function newSupplierProblems(typed: NewSupplier): readonly (keyof NewSupplier)[] {
  const problems: (keyof NewSupplier)[] = [];
  if (!isVisibleName(typed.displayName, NAME_MOST)) problems.push('displayName');
  if (!PHONE.test(typed.phone)) problems.push('phone');
  if (typed.email !== '' && !EMAIL.test(typed.email)) problems.push('email');
  if (typed.tradeLicence !== '' && !TRADE_LICENCE.test(typed.tradeLicence)) problems.push('tradeLicence');
  if (typed.sourceKind === null) problems.push('sourceKind');
  if (!SOURCE_REF.test(typed.sourceRef)) problems.push('sourceRef');
  if (typed.remittanceEmail === null) problems.push('remittanceEmail');
  return problems;
}

/** The add's body, as the API takes it: an optional detail not known is left out. */
export const newSupplierBody = (typed: NewSupplier) => ({
  displayName: typed.displayName,
  phone: typed.phone,
  ...(typed.email !== '' && { email: typed.email }),
  ...(typed.tradeLicence !== '' && { tradeLicence: typed.tradeLicence }),
  source: { kind: typed.sourceKind, ref: typed.sourceRef },
  remittanceEmail: typed.remittanceEmail,
});

/**
 * Whether text is a UAE IBAN with valid check digits, as the API takes one
 * (normalisedIban): full-width forms read as plain, spaces left out, any case;
 * AE, then 21 digits, the whole holding ISO 7064's mod-97 check.
 */
export function isUaeIban(text: string): boolean {
  const iban = text.normalize('NFKC').replaceAll(/\s/gu, '').toUpperCase();
  if (!/^AE\d{21}$/.test(iban)) return false;
  // The country and check digits moved to the end, each letter as its number (A = 10), the whole read as one number.
  const digits = Array.from(iban.slice(4) + iban.slice(0, 4), (character) => Number.parseInt(character, 36)).join('');
  return BigInt(digits) % 97n === 1n;
}

/** Whether an account holder's name is one the API takes (a visible name of 1 to 100). */
export const isHolderName = (name: string): boolean => isVisibleName(name, NAME_MOST);

/** Whether a call-back note is one the API keeps (callNote): one line of 1 to 500, no phone or account numbers. */
export const isCallNote = (note: string): boolean => isKeptNote(note, CALL_NOTE_MOST);

/** Whether the supplier's cooling-off is still running at `now`: verifying waits until it ends. */
export const coolingOff = (supplier: Supplier, now = Date.now()): boolean =>
  supplier.coolingOffUntil !== null && new Date(supplier.coolingOffUntil).getTime() > now;

/**
 * Why the supplier can't be verified yet, as the page says it before anyone
 * tries (the API's verificationProblem, in its order, less what only the API
 * can tell: the phone's age, the people rule); none when it may be tried.
 */
export function notYetVerifiable(supplier: Supplier, now = Date.now()): TextKey | undefined {
  if (supplier.status !== 'UNVERIFIED') return undefined;
  if (supplier.changeWaiting) return 'suppliers.verify.changeWaiting';
  if (supplier.payee === null) return 'suppliers.verify.noPayee';
  // None set is never taken as passed, as the API has it.
  if (supplier.coolingOffUntil === null || coolingOff(supplier, now)) return 'suppliers.verify.coolingOff';
  if (supplier.payee.nameCheck === 'no_match') return 'suppliers.verify.noMatch';
  return undefined;
}

/** The refusals a supplier's change can meet that the person can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'SUPPLIER_ADDS_SPENT',
  'SUPPLIER_REMITTANCE_UNCHANGED',
  'SUPPLIER_CHANGE_WAITING',
  'SUPPLIER_NO_CHANGE_WAITING',
  'SUPPLIER_PAYEE_TAKEN',
  'PAYEE_REGISTRATIONS_SPENT',
  'PAYEE_ROUTE_NOT_OFFERED',
  'PAYEE_CHANGE_NOT_YOURS',
  'SUPPLIER_NOT_UNVERIFIED',
  'SUPPLIER_NO_PAYEE',
  'SUPPLIER_COOLING_OFF',
  'SUPPLIER_NAME_MISMATCH',
  'SUPPLIER_CALL_NOTE_NEEDED',
  'SUPPLIER_PHONE_TOO_NEW',
  'VERIFIER_ENTERED_DETAILS',
  'VERIFIER_GRANTED_BY_ENTERER',
  'VERIFIER_TOO_NEW',
  'SOLO_PATH_LOCKED',
  'HISTORY_TOO_LONG',
  'STATEMENT_CHANGED',
  'STEP_UP_NOT_ASKED',
  'ORG_FROZEN',
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/**
 * What a refusal or failure of a supplier's change says: a record that failed
 * the integrity check, and the partner not answering, as themselves (each a
 * 503, so not refusals).
 */
export function supplierRefusal(error: unknown): string {
  if (isIntegrityFailed(error)) return t('suppliers.integrity');
  if (error instanceof ApiError && error.code === 'PARTNER_UNAVAILABLE') return t('suppliers.partnerUnavailable');
  return refusalText(error, REFUSALS, 'suppliers.refused');
}

/** The 4xx answers that leave a try undecided: the first request still being worked on, or too many tries at once. */
const UNDECIDED: ReadonlyMap<string, TextKey> = new Map([
  ['IDEMPOTENCY_KEY_BUSY', 'suppliers.bank.stillWorking'],
  ['RATE_LIMITED', 'suppliers.bank.tooMany'],
]);

/**
 * Whether a pass-through's answer decides it, so its key need not be kept: a
 * refusal that is the API's final word. No answer, a 5xx, an undecided 4xx,
 * and a 401 (the session gone, whatever was done) leave it held for Try again.
 */
export const decidesTheTry = (error: unknown): boolean =>
  isRefusal(error) && error.status !== 401 && !UNDECIDED.has(error.code);

/** What a pass-through's failure says: a deciding refusal as any; otherwise why it is held for Try again. */
export function passThroughFailure(error: unknown): string {
  if (decidesTheTry(error) || isIntegrityFailed(error)) return supplierRefusal(error);
  const undecided = error instanceof ApiError ? UNDECIDED.get(error.code) : undefined;
  return t(undecided ?? 'suppliers.bank.unanswered');
}

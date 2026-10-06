// A supplier (PRD §3 `Supplier` / `SupplierVersion`, ADR-012 §1, ADR-014 §3;
// BR-04, BR-21): a business an organisation's agents may ask to pay.
//
// Its status is UNVERIFIED until a second person verifies it (E3): a
// payment rests only on a VERIFIED supplier. Any change of its details takes
// it back to UNVERIFIED. SUSPENDED is the business's brake, from either; a
// suspended supplier comes back verified only if nothing changed while it
// was suspended (partner, S69). The database's status guard holds the same
// moves (0032).
//
// Its details are versions, each made once and never changed. A version's
// name is a visible name, as an organisation's; its contacts (a phone,
// required; an email and a trade licence number, optional: partner, S69) are
// kept encrypted, each checked here to a short alphabet of its own, so each
// has a byte bound (the B8-3 lesson). The details were checked against an
// independent source: a registry or the official website (ADR-012 §1).
import { DAY_MS, defineStateMachine, visibleName } from '../../../shared-kernel/index.ts';

export const SUPPLIER = defineStateMachine({
  name: 'supplier',
  states: ['UNVERIFIED', 'VERIFIED', 'SUSPENDED'],
  initial: 'UNVERIFIED',
  events: {
    verify: { from: ['UNVERIFIED'], to: 'VERIFIED' },
    unverify: { from: ['VERIFIED'], to: 'UNVERIFIED' },
    suspend: { from: ['UNVERIFIED', 'VERIFIED'], to: 'SUSPENDED' },
    reactivate: { from: ['SUSPENDED'], to: 'UNVERIFIED' },
    reactivate_verified: { from: ['SUSPENDED'], to: 'VERIFIED' },
  },
});

export type SupplierStatus = (typeof SUPPLIER.states)[number];

/**
 * How long a supplier's payee change cools off once its admin confirms it
 * (ADR-012 §1: 24 hours, never less; ADR-014 §3 step 4): no one may verify it
 * before then (E3).
 */
export const PAYEE_COOLING_OFF_MS = DAY_MS;

/** What a supplier's coming back from its brake rests on: the version verified, if any, and what is current and waiting. */
interface VerifiedState {
  readonly currentVersionId: string;
  readonly pendingVersionId: string | null;
  readonly verifiedVersionId: string | null;
}

/**
 * Whether a supplier is still verified: the version that was verified is the
 * current one, with no change waiting. Only then may it be VERIFIED (0032's
 * `verified_rests_on_its_version` holds the same), so a supplier suspended
 * before it was verified, or changed since, comes back UNVERIFIED.
 */
export const stillVerified = (supplier: VerifiedState): boolean =>
  supplier.verifiedVersionId !== null &&
  supplier.verifiedVersionId === supplier.currentVersionId &&
  supplier.pendingVersionId === null;

/** The event a suspended supplier comes back by: verified again only if it is still verified. */
export const reactivationOf = (supplier: VerifiedState): 'reactivate' | 'reactivate_verified' =>
  stillVerified(supplier) ? 'reactivate_verified' : 'reactivate';

/** Where the details were checked (ADR-012 §1): the trade or company registry, or the supplier's official website. */
export const SOURCE_KINDS = ['registry', 'official_website'] as const;
export type SourceKind = (typeof SOURCE_KINDS)[number];

/** A supplier's contacts, as a version holds them: the phone always, the others when given. */
export interface SupplierContacts {
  /** In international form, such as +971501234567. */
  readonly phone: string;
  /** In lower case. */
  readonly email: string | null;
  readonly tradeLicence: string | null;
}

/** The details a version is made of, as a member gives them. */
export interface SupplierDetails {
  readonly displayName: string;
  readonly contacts: SupplierContacts;
  readonly source: { readonly kind: SourceKind; readonly ref: string };
}

/** The details can't be a supplier's; `problems` say why, never what they were. */
export class SupplierDetailsRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The supplier's details were refused: ${problems.join('; ')}`);
    this.name = 'SupplierDetailsRefused';
    this.problems = problems;
  }
}

/** The most characters a supplier's name, or its payee's, may be once composed. */
export const SUPPLIER_NAME_MOST = 100;

/** A phone in international form (E.164): a plus, then 8 to 15 digits, the first not 0. */
const PHONE = /^\+[1-9][0-9]{7,14}$/;
/** An email: printable ASCII, one `@` between a local part and a domain, at most 254 characters. */
const EMAIL = /^[!-?A-~]{1,64}@[!-?A-~]{1,189}$/;
/** A trade licence number: letters, digits, `-` and `/`, starting with a letter or digit, at most 50. */
const TRADE_LICENCE = /^[A-Za-z0-9][A-Za-z0-9/-]{0,49}$/;
/** A source's reference (a registry number or the website's address): printable ASCII, at most 200. */
const SOURCE_REF = /^[!-~]{1,200}$/;

/**
 * The details as a version keeps them: the name composed (NFC), the email in
 * lower case; or `SupplierDetailsRefused` naming each problem. What an API
 * checks before anything is written, and the module's floor after it.
 */
export function supplierDetails(details: SupplierDetails): SupplierDetails {
  const { name, problems } = visibleName(details.displayName, SUPPLIER_NAME_MOST);
  const { phone, email, tradeLicence } = details.contacts;
  if (!PHONE.test(phone)) problems.push('the phone is not one in international form');
  if (email !== null && !EMAIL.test(email)) problems.push('the email is not one address');
  if (tradeLicence !== null && !TRADE_LICENCE.test(tradeLicence)) {
    problems.push('the trade licence number is not one');
  }
  if (!SOURCE_KINDS.includes(details.source.kind)) problems.push('the source is not a registry or official website');
  if (!SOURCE_REF.test(details.source.ref)) problems.push("the source's reference is not one");
  if (problems.length > 0) throw new SupplierDetailsRefused(problems);
  return {
    displayName: name,
    contacts: { phone, email: email?.toLowerCase() ?? null, tradeLicence },
    source: details.source,
  };
}

/** Which contacts a version holds, as it is kept and sealed: the phone first, then the others given, one space apart. */
export function contactsHeld(contacts: SupplierContacts): string {
  return [
    'phone',
    ...(contacts.email === null ? [] : ['email']),
    ...(contacts.tradeLicence === null ? [] : ['licence']),
  ].join(' ');
}

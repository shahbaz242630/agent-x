// Verifying a supplier (ADR-012 §1, ADR-014 §3; SEC-PAY-03, SEC-PAY-07; E3-2a):
// what must hold before a second person may mark it VERIFIED, the people
// rule aside (identity's two-person rule, E3-1).
//
// - It is UNVERIFIED, with no change waiting (a change waiting is the
//   enterer's to confirm or withdraw first), and its details carry a payee:
//   there is nothing to pay before.
// - Its cooling-off has passed (24 hours from its payee confirmed, E2-2b).
// - The partner's name check didn't say "no match"; any answer short of a
//   match (partial, unavailable, none) needs the verifier's written note of
//   the call-back (partner, S69 and S74).
// - The call-back went to a phone unchanged for 30 days, or to the phone the
//   supplier has had since it was added, which its enterer recorded as taken
//   from its independent source (a registry or its official website; ADR-012
//   §1: "unchanged for N days" applies when an existing supplier's contact
//   changes). Agent X can't check where that phone came from: the verifier's
//   tick and the call itself are what does.
// - The verifier ticked that they called the number on file and the supplier
//   confirmed the details (partner, S74). Their note says who they spoke to
//   and what was confirmed, never a number to call or to pay: it is kept in
//   the audit trail for good, where no account number may be (SEC-PAY-05).
import { DAY_MS, type ReasonCode, visibleName } from '../../../shared-kernel/index.ts';
import type { NameCheck } from './registration.ts';
import type { SupplierStatus } from './supplier.ts';

/** How long a supplier's phone must have been its own before a call-back to it counts (ADR-012 §1). */
export const CALL_BACK_UNCHANGED_DAYS = 30;
/** The most characters a call-back note may have. */
export const CALL_NOTE_MOST = 500;

/** Why a supplier can't be verified now, its people aside. */
export type VerificationProblem = Extract<
  ReasonCode,
  | 'SUPPLIER_NOT_UNVERIFIED'
  | 'SUPPLIER_CHANGE_WAITING'
  | 'SUPPLIER_NO_PAYEE'
  | 'SUPPLIER_COOLING_OFF'
  | 'SUPPLIER_NAME_MISMATCH'
  | 'SUPPLIER_CALL_NOTE_NEEDED'
  | 'SUPPLIER_PHONE_TOO_NEW'
>;

/** What verifying rests on: the supplier, its current version and payee, its first version, and the verifier's call-back. */
export interface VerificationFacts {
  readonly supplier: {
    readonly status: SupplierStatus;
    readonly pendingVersionId: string | null;
    readonly coolingOffUntil: Date | null;
  };
  /** The current version: its phone's start, and its payee reference (null for none yet). */
  readonly current: { readonly phoneSince: Date; readonly beneficiaryRef: string | null };
  /** The name check of the registration that gave the current payee: null when the partner gave none. */
  readonly nameCheck: NameCheck | null;
  /** When the supplier's first version was entered: a phone since then is the one from its independent source. */
  readonly firstEnteredAt: Date;
  /** The verifier's written note of the call-back, or null. */
  readonly note: string | null;
}

/**
 * Seven digits or more in a run, of any script (Arabic-Indic and fullwidth
 * too), spaces, dots, dashes, slashes or brackets between them allowed: a
 * phone, card or account number.
 */
const LONG_NUMBER = /\p{Nd}(?:[\s./()-]*\p{Nd}){6}/u;

/**
 * Whether a call-back note is one: 1 to 500 readable characters, no
 * controls, and no long number in it; composed (NFC) as it is kept.
 */
export function callNote(note: string): { readonly note: string; readonly problems: readonly string[] } {
  const { name, problems } = visibleName(note, CALL_NOTE_MOST, 'the note');
  if (LONG_NUMBER.test(name)) problems.push('the note holds a long number: leave phone and account numbers out');
  return { note: name, problems };
}

/**
 * The first reason the supplier can't be verified at `now`, its people
 * aside, or undefined when it may be: checked in the order a member would
 * fix them.
 */
export function verificationProblem(facts: VerificationFacts, now: Date): VerificationProblem | undefined {
  const { supplier, current } = facts;
  if (supplier.status !== 'UNVERIFIED') return 'SUPPLIER_NOT_UNVERIFIED';
  if (supplier.pendingVersionId !== null) return 'SUPPLIER_CHANGE_WAITING';
  if (current.beneficiaryRef === null) return 'SUPPLIER_NO_PAYEE';
  // A payee is confirmed with its cooling-off (E2-2b): none set is never taken as passed.
  if (supplier.coolingOffUntil === null || now.getTime() < supplier.coolingOffUntil.getTime()) {
    return 'SUPPLIER_COOLING_OFF';
  }
  if (facts.nameCheck === 'no_match') return 'SUPPLIER_NAME_MISMATCH';
  if (facts.nameCheck !== 'match' && facts.note === null) return 'SUPPLIER_CALL_NOTE_NEEDED';
  const fromItsSource = current.phoneSince.getTime() <= facts.firstEnteredAt.getTime();
  const settled = current.phoneSince.getTime() + CALL_BACK_UNCHANGED_DAYS * DAY_MS <= now.getTime();
  if (!fromItsSource && !settled) return 'SUPPLIER_PHONE_TOO_NEW';
  return undefined;
}

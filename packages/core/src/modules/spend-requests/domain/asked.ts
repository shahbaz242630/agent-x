// What an agent asks to pay, as text (PRD §3 `SpendRequest`; partner
// decisions 6 and 8, S93; Phase 2 D4r): the purpose and the supplier's own
// order reference, checked at the API's edge as 0039 checks them, and the
// bank reference that order reference becomes on the rail.
//
// The bank's reference: the rail's creditor reference holds 1 to 35 ASCII
// characters of `A-Za-z0-9 /?:().,'+-` (rail map), so an order reference
// written otherwise becomes its closest form there, by one fixed mapping:
// shown to the agent with its request (D4r) and made at hand-off (Phase 4),
// so the two never differ. In order:
// - compatibility forms and accents taken apart (NFKD): full-width and styled
//   letters become plain ones, é becomes e and an accent the rail drops;
// - every other decimal digit (Arabic-Indic ١٢, Devanagari, …) becomes 0–9;
// - `_` becomes `-`; anything else the rail can't carry (`#`, Arabic or other
//   non-Latin letters, symbols) is dropped;
// - spaces trimmed and runs of them made one, then cut to 35;
// - nothing left with a letter or digit: the request's own ID, its dashes
//   taken out (32 characters).
// The duplicate check never uses it: it compares `order_key` (decision 6).
import { asciiDigits, visibleName } from '../../../shared-kernel/index.ts';

/** The most characters a request's purpose may have: 0039's limit. */
export const REQUEST_PURPOSE_MOST = 200;

/** The most characters an order reference may have: 0039's limit (decision 6). */
export const ORDER_REFERENCE_MOST = 100;

/** The most characters the rail's creditor reference may have (rail map). */
export const BANK_REFERENCE_MOST = 35;

/** The request's text can't be kept; `problems` say why, never what it was. */
export class SpendAskRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The spend request's text was refused: ${problems.join('; ')}`);
    this.name = 'SpendAskRefused';
    this.problems = problems;
  }
}

/** An order reference as a request keeps it (composed, NFC); or `SpendAskRefused`. */
export function orderReferenceOf(orderReference: string): string {
  const { name, problems } = visibleName(orderReference, ORDER_REFERENCE_MOST, 'the order reference');
  if (problems.length > 0) throw new SpendAskRefused(problems);
  return name;
}

/** The purpose and order reference as a request keeps them (composed, NFC); or `SpendAskRefused`. */
export function askedText(asked: { readonly purpose: string; readonly orderReference: string }): {
  readonly purpose: string;
  readonly orderReference: string;
} {
  const purpose = visibleName(asked.purpose, REQUEST_PURPOSE_MOST, 'the purpose');
  const orderReference = visibleName(asked.orderReference, ORDER_REFERENCE_MOST, 'the order reference');
  const problems = [...purpose.problems, ...orderReference.problems];
  if (problems.length > 0) throw new SpendAskRefused(problems);
  return { purpose: purpose.name, orderReference: orderReference.name };
}

/** What the rail carries, and what it keeps of a reference. */
const RAIL_CHARACTER = /[A-Za-z0-9 /?:().,'+-]/;
const LETTER_OR_DIGIT = /[A-Za-z0-9]/;

/** One character of the reference, its digits ASCII already, as the rail carries it: itself, `-` for `_`, or nothing. */
function railFormOf(character: string): string {
  if (character === '_') return '-';
  return RAIL_CHARACTER.test(character) ? character : '';
}

/** The bank's reference for a request's order reference: see the top of this file. */
export function bankReferenceOf(orderReference: string, requestId: string): string {
  const carried = Array.from(asciiDigits(orderReference.normalize('NFKD')), railFormOf)
    .join('')
    .replace(/ +/g, ' ')
    .trim()
    .slice(0, BANK_REFERENCE_MOST)
    .trimEnd();
  return LETTER_OR_DIGIT.test(carried) ? carried : requestId.replaceAll('-', '');
}

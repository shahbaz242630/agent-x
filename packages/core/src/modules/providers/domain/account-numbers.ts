// Account numbers never leave the adapter (ADR-014 §3, PRD §6): the partner's
// account data carries the IBAN in full (rail map §2), so an adapter keeps
// only a hint of it, and checks everything it hands back before it does.
//
// The check is the adapter's last line, not its method: an adapter builds its
// answers field by field from what it may keep, then the check refuses any
// answer still holding an IBAN (any country's, with valid check digits) or
// any 8 characters in a row of an account number the partner gave it.
//
// Text is read as a person would read it (the S68 audit and its review), and
// failing closed: its Unicode compatibility forms folded (full-width digits
// are digits), a digit of any script read as its value (Arabic-Indic `٠`–`٩`
// are 0–9), a Cyrillic or Greek capital that looks like a Latin one read as
// it (`АЕ` is `AE`), and any run of anything else that is neither a letter
// nor a digit (spaces of every kind, marks, controls, punctuation) read as
// one space, so `AE12-9991-…`, `AE12:9991:…` or an IBAN grouped with
// non-breaking spaces is found as one grouped with spaces.

/** The characters of a known account number that, in a row, count as the number itself. */
const RUN = 8;
/**
 * A country, two check digits, then 11 to 30 letters or digits, joined or in
 * groups; found from every place it could start, so a run that begins
 * earlier never hides one inside it.
 */
const IBAN = /(?=([A-Z]{2}\d{2}(?: ?[A-Z\d]){11,30}))/g;
const UAE_IBAN_LENGTH = 23;
/** What may stand between an account number's groups: anything that is neither a letter nor a digit. */
const SEPARATORS = /[^\p{L}\p{Nd}]+/gu;

/**
 * An ID in the UUID form (8-4-4-4-12 hex): read as a gap, never as groups of
 * an IBAN. Joined by its dashes, one now and then would start with two
 * letters and two digits and pass the check digits by chance (1 in 97), so an
 * answer naming its own link would be refused. No IBAN takes that shape.
 */
const AN_ID =
  /(?<![\p{L}\p{Nd}])[\dA-Fa-f]{8}-[\dA-Fa-f]{4}-[\dA-Fa-f]{4}-[\dA-Fa-f]{4}-[\dA-Fa-f]{12}(?![\p{L}\p{Nd}])/gu;

/** A digit of any script. */
const ANY_DIGIT = /\p{Nd}/gu;

/**
 * A digit's value: Unicode keeps each script's digits 0 to 9 in a row, and
 * rows of them in runs (the mathematical digits' five), so the value is its
 * place counted from the start of its run.
 */
function digitValue(digit: string): string {
  const code = digit.codePointAt(0) ?? 0;
  let start = code;
  while (start > 0 && /\p{Nd}/u.test(String.fromCodePoint(start - 1))) start -= 1;
  return String((code - start) % 10);
}

/** Cyrillic and Greek capitals a reader takes for Latin ones. */
const LOOKALIKES: Readonly<Record<string, string>> = {
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  Х: 'X',
  У: 'Y',
  І: 'I',
  Ј: 'J',
  Ѕ: 'S',
  Α: 'A',
  Β: 'B',
  Ε: 'E',
  Ζ: 'Z',
  Η: 'H',
  Ι: 'I',
  Κ: 'K',
  Μ: 'M',
  Ν: 'N',
  Ο: 'O',
  Ρ: 'P',
  Τ: 'T',
  Υ: 'Y',
  Χ: 'X',
};
const LOOKALIKE = new RegExp(`[${Object.keys(LOOKALIKES).join('')}]`, 'gu');

/** The text as the checks read it: folded, upper case, each digit its value, lookalikes Latin, each run of anything else one space. */
const readable = (text: string): string =>
  text
    .normalize('NFKC')
    .toUpperCase()
    .replaceAll(ANY_DIGIT, digitValue)
    .replaceAll(LOOKALIKE, (letter) => LOOKALIKES[letter] ?? letter)
    .replaceAll(SEPARATORS, ' ');

/** An answer held an account number; the message never says which, or where. */
export class AccountNumberLeak extends Error {
  constructor() {
    super('An answer from the payment partner still held an account number');
    this.name = 'AccountNumberLeak';
  }
}

/** The text compacted for finding a number: read as a person would, every separator gone. */
const compact = (text: string): string => readable(text).replaceAll(' ', '');

/** An account number as given, compacted strictly: spaces and case aside, nothing else forgiven. */
const strictly = (text: string): string => text.replaceAll(' ', '').toUpperCase();

/** ISO 13616: the IBAN, its first four characters moved to the end and letters as numbers, is 1 mod 97. */
function checksumHolds(iban: string): boolean {
  const moved = iban.slice(4) + iban.slice(0, 4);
  let rest = 0;
  for (const character of moved) {
    const value = Number.parseInt(character, 36);
    rest = (rest * (value > 9 ? 100 : 10) + value) % 97;
  }
  return rest === 1;
}

/**
 * Whether a run the pattern found is an IBAN with valid check digits: the
 * whole run, the run up to any of its spaces (an IBAN in groups, then a
 * word), or a UAE IBAN's 23 characters (one with text run on after it). Only
 * these few, so a long reference that isn't an IBAN rarely passes by chance.
 */
function holdsAnIban(text: string): boolean {
  // IDs in the UUID form read as gaps here alone: the known numbers' runs, matched exactly, look inside them too.
  return [...readable(text.normalize('NFKC').replaceAll(AN_ID, ' ')).matchAll(IBAN)].some(([, found = '']) => {
    const candidates = [found, ...[...found.matchAll(/ /g)].map(({ index }) => found.slice(0, index))].map(compact);
    if (found.startsWith('AE')) candidates.push(compact(found).slice(0, UAE_IBAN_LENGTH));
    return candidates.some((candidate) => candidate.length >= 15 && checksumHolds(candidate));
  });
}

/** Every 8 characters in a row of each account number, compacted. */
function runsOf(accountNumbers: readonly string[]): Set<string> {
  const runs = new Set<string>();
  for (const number of accountNumbers.map(compact)) {
    for (let start = 0; start + RUN <= number.length; start += 1) runs.add(number.slice(start, start + RUN));
  }
  return runs;
}

/** Every text in a value, at any depth: strings, numbers written out, and the keys of objects (an array's too). */
function textsIn(value: unknown, texts: string[]): string[] {
  if (typeof value === 'string') texts.push(value);
  else if (typeof value === 'number' || typeof value === 'bigint') texts.push(String(value));
  else if (value !== null && typeof value === 'object' && !(value instanceof Date)) {
    for (const [key, each] of Object.entries(value)) {
      texts.push(key);
      textsIn(each, texts);
    }
  }
  return texts;
}

/**
 * Gives `answer` back unchanged, or throws AccountNumberLeak if any text in
 * it (a value or a key, at any depth, a number written out) holds an IBAN or
 * 8 characters in a row of one of `accountNumbers`, spaces and case aside.
 */
export function withoutAccountNumbers<T>(answer: T, accountNumbers: readonly string[]): T {
  const runs = [...runsOf(accountNumbers)];
  for (const text of textsIn(answer, [])) {
    const plain = compact(text);
    if (holdsAnIban(text) || runs.some((run) => plain.includes(run))) throw new AccountNumberLeak();
  }
  return answer;
}

/** Whether a text is a UAE IBAN (AE and 21 digits, spaces and case aside) with valid check digits: an account the rail can pay. */
export function isUaeIban(text: string): boolean {
  const number = strictly(text);
  return /^AE\d{21}$/.test(number) && checksumHolds(number);
}

/**
 * What may be kept of an account number: its country and its last four
 * characters (`AE…6026`), enough for a person to tell their accounts apart
 * (PRD §3's masked hint).
 */
export function accountHint(accountNumber: string): string {
  const number = strictly(accountNumber);
  if (!/^[A-Z]{2}[A-Z\d]{9,32}$/.test(number)) throw new RangeError('Not an account number an adapter can hint at');
  return `${number.slice(0, 2)}…${number.slice(-4)}`;
}

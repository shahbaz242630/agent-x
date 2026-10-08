// Digits of any script read as 0–9 (S68's account-number check; partner
// decision 8's bank reference): Arabic-Indic ٠–٩, Devanagari, and every other
// decimal digit Unicode names.

/** A decimal digit of any script. */
const ANY_DIGIT = /\p{Nd}/gu;

/**
 * A digit's value: Unicode keeps each script's digits 0 to 9 in a row, and
 * rows of them in runs (the mathematical digits' five, Tai Tham's two), so
 * the value is its place counted from the start of its run.
 */
function digitValue(digit: string): string {
  // Never undefined: each match is one code point.
  const code = Number(digit.codePointAt(0));
  let start = code;
  while (start > 0 && /\p{Nd}/u.test(String.fromCodePoint(start - 1))) start -= 1;
  return String((code - start) % 10);
}

/** The text with each decimal digit of any script as its ASCII digit, and nothing else changed. */
export const asciiDigits = (text: string): string => text.replaceAll(ANY_DIGIT, digitValue);

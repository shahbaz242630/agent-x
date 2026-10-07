// A verified row's fields, as the audit module's verifiedState gives them
// (canonical text, or null), read back into their kinds: for every module's
// authority tables alike (suppliers, their registrations, mandates).

/** A field's value as text or null, or undefined for one the fields don't hold at all. */
export type Field = string | null | undefined;

/** One of `words`, or undefined. */
export const oneOf = <const Word extends string>(words: readonly Word[], value: Field): Word | undefined =>
  words.find((word) => word === value);

/** One of `words` or null, or undefined for neither. */
export const oneOfOrNull = <const Word extends string>(
  words: readonly Word[],
  value: Field,
): Word | null | undefined => (value === null ? null : oneOf(words, value));

const WHOLE = /^[1-9][0-9]{0,9}$/;

/** A time, or null; undefined for a field missing or not a time. */
export const timeOf = (value: Field): Date | null | undefined => {
  if (value === null || value === undefined) return value;
  const time = new Date(value);
  return Number.isNaN(time.getTime()) ? undefined : time;
};

/** A whole number from 1, or null; undefined for a field missing or not one. */
export const wholeOf = (value: Field): number | null | undefined => {
  if (value === null || value === undefined) return value;
  return WHOLE.test(value) ? Number(value) : undefined;
};

const MINOR = /^[1-9][0-9]{0,18}$/;

/** An amount in minor units from 1 (a bigint column), or undefined for a field missing, null or not one. */
export const minorOf = (value: Field): bigint | undefined =>
  typeof value === 'string' && MINOR.test(value) ? BigInt(value) : undefined;

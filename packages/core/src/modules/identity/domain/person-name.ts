// A person's name as the login service gives it (decision 25): kept only to
// say who did what in the audit log, so it is taken as one line of plain
// text (plainLine), never as markup or control.
import { plainLine } from '../../../shared-kernel/index.ts';

/** The longest name kept, in UTF-16 units: the login service's own limit is 200. */
export const MOST_NAME_LENGTH = 200;

/** The name to keep, one line with single spaces, or undefined for none or one that isn't text or is too long. */
export const personName = (value: unknown): string | undefined => plainLine(value, MOST_NAME_LENGTH);

/** The name a profile gives: its full name, or its given and family names together, as personName keeps it. */
export const nameFromParts = (full: unknown, given: unknown, family: unknown): string | undefined =>
  personName(full) ?? personName([given, family].filter((part) => typeof part === 'string').join(' '));

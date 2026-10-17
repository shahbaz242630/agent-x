// A person's name as the login service gives it (decision 25): kept only to
// say who did what in the audit log, so it is taken as one line of plain
// text, never as markup or control. Control characters and the ones that
// reorder text on screen (bidi overrides and isolates) become spaces, so a
// name can't hide or rearrange the log line it stands in.

/** The longest name kept, in UTF-16 units: the login service's own limit is 200. */
export const MOST_NAME_LENGTH = 200;

// eslint-disable-next-line no-control-regex -- Taking control characters out is the point.
const NOT_TEXT = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/** The name to keep, one line with single spaces, or undefined for none or one that isn't text or is too long. */
export function personName(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.isWellFormed()) return undefined;
  const name = value.replace(NOT_TEXT, ' ').replace(/\s+/g, ' ').trim();
  return name.length === 0 || name.length > MOST_NAME_LENGTH ? undefined : name;
}

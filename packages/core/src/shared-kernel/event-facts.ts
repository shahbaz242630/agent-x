// The rules every audit event's action and details follow, on either chain:
// each organisation's (the `audit` module) and the platform's own
// (`platform-controls`). Audit rows are kept for years and can never be
// changed or deleted, so details are a few short facts: IDs and constants,
// never secrets, bank details or personal data (ADR-014 §3).
//
// Details are read from the caller once, checked, and kept in one canonical
// form, because an event's hash and MAC are computed over that form and
// recomputed from the stored row. A problem names the field, never its
// value, which could be anything a caller passed.

export type EventDetailValue = string | number | boolean | null;

/** A few facts about an event, by name: text, whole numbers, yes or no, or nothing. */
export type EventDetails = Readonly<Record<string, EventDetailValue>>;

const ACTION = /^[a-z][a-z_]*(?:\.[a-z][a-z_]*)+$/;
const ACTION_LENGTH = 100;
const DETAIL_KEY = /^[a-z][A-Za-z0-9]{0,62}$/;
// Control characters have no place in a short fact, and Postgres can't store NUL in text.
// eslint-disable-next-line no-control-regex -- Matching control characters is the point.
const CONTROL = /[\u0000-\u001f\u007f]/;
const DETAILS_COUNT = 32;
const DETAIL_TEXT_LENGTH = 1024;

/** Dotted lower-case words, object first: `organisation.created`, `platform.started`. */
export function actionProblems(action: string): string[] {
  return ACTION.test(action) && action.length <= ACTION_LENGTH
    ? []
    : [`action must be dotted lower-case words, at most ${ACTION_LENGTH} characters`];
}

type DetailEntry = readonly [string, unknown];

/** The details' entries, read once, or nothing if they aren't a plain object: whatever the caller's types claim. */
function plainEntries(details: unknown): readonly DetailEntry[] | undefined {
  if (
    typeof details !== 'object' ||
    details === null ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(details) as object | null)
  ) {
    return undefined;
  }
  return Object.entries(details);
}

function detailValueProblem(key: string, value: unknown): string | undefined {
  if (value === null || typeof value === 'boolean') return undefined;
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) ? undefined : `details.${key} must be a whole number`;
  }
  if (typeof value !== 'string') return `details.${key} must be text, a whole number, true, false or null`;
  if (value.length > DETAIL_TEXT_LENGTH) return `details.${key} is longer than ${DETAIL_TEXT_LENGTH} characters`;
  if (!value.isWellFormed() || CONTROL.test(value)) {
    return `details.${key} holds control characters or broken Unicode`;
  }
  return undefined;
}

/** Code-unit order of the keys, whatever order they were written in. */
const byKey = ([a]: DetailEntry, [b]: DetailEntry): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The details, read once from what the caller passed, checked, and given back
 * in key order and frozen; or the problems. `isSensitive` says which details
 * hold what an audit row must never keep, by name and value (the logger's own
 * rule for what it hides). It is asked only once every key is a plain name
 * and every value a plain fact, so a problem can quote the key.
 */
export function checkedDetails(
  details: unknown,
  isSensitive: (name: string, value: EventDetailValue) => boolean,
): { readonly problems: readonly string[]; readonly details: EventDetails } {
  const entries = plainEntries(details);
  if (entries === undefined) return { problems: ['details must be a plain object'], details: {} };
  if (entries.length > DETAILS_COUNT) {
    return { problems: [`details has more than ${DETAILS_COUNT} entries`], details: {} };
  }
  const problems = entries.flatMap(([key, value]) => {
    if (!DETAIL_KEY.test(key)) return ['details has a key that is not a camelCase name'];
    return detailValueProblem(key, value) ?? [];
  });
  if (problems.length > 0) return { problems, details: {} };
  const facts = entries as readonly (readonly [string, EventDetailValue])[];
  const sensitive = facts
    .filter(([name, value]) => isSensitive(name, value))
    .map(([key]) => `details.${key} looks like a secret or personal data, which audit rows never hold (ADR-014 §3)`);
  if (sensitive.length > 0) return { problems: sensitive, details: {} };
  return { problems: [], details: Object.freeze(Object.fromEntries([...facts].sort(byKey))) };
}

/** The details as JSON with their keys in order: the same facts always give the same text. */
export function canonicalDetails(details: EventDetails): string {
  return JSON.stringify(Object.fromEntries(Object.entries(details).sort(byKey)));
}

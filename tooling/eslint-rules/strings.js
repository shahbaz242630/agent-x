// Reading a string out of the syntax, for the rules that judge what a string
// says. A rule that looks only at whole literals is easy to walk past: the
// same text written as a template, or built with `+`, reads the same to
// Postgres and to Kysely but not to the rule.
//
// `no-string-built-sql.js` and `tenant-setting-only-in-with-tenant.js` each
// carry their own copy of this, older than this file and reviewed as part of
// SEC-TEN-07 and ADR-005 §4. They are left as they are on purpose: they are
// the two rules a mistake in this helper would weaken, and unifying them is
// its own change with its own proofs, not a passenger on A3c-2.

/** Stands for a value spliced into a string, so no two pieces read as one word. */
const VALUE = '\u0000';

/**
 * A value with its TypeScript wrappers taken off, so `'agent' as const` and
 * `('x' satisfies string)` read as the string they are. A rule that stopped at
 * the wrapper would miss the spelling a strict codebase actually uses.
 */
export function withoutWrappers(node) {
  let current = node;
  while (
    current !== undefined &&
    current !== null &&
    (current.type === 'TSAsExpression' ||
      current.type === 'TSSatisfiesExpression' ||
      current.type === 'TSNonNullExpression' ||
      current.type === 'TSInstantiationExpression')
  ) {
    current = current.expression;
  }
  return current;
}

/** The text of a literal or a template with no values in it, or null for anything else. */
export function textOf(node) {
  const value = withoutWrappers(node);
  if (value === undefined || value === null) return null;
  if (value.type === 'Literal') return typeof value.value === 'string' ? value.value : null;
  if (value.type === 'TemplateLiteral' && value.expressions.length === 0) {
    return value.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join('');
  }
  return null;
}

/**
 * A character a name is made of. A name is looked for with one of these on
 * neither side, so `'agents.agents as a'` carries `agents.agents` while
 * `'agents.agents_old'` and `'my_agents.agents'` are other names.
 */
const NAME_CHARACTER = /[A-Za-z0-9_.]/;

/** True when `text` carries `name` as a name of its own, not as part of a longer one. */
export function carries(text, name) {
  let at = text.indexOf(name);
  while (at !== -1) {
    const before = at === 0 ? '' : text[at - 1];
    const after = text[at + name.length] ?? '';
    if (!NAME_CHARACTER.test(before) && !NAME_CHARACTER.test(after)) return true;
    at = text.indexOf(name, at + 1);
  }
  return false;
}

/**
 * The text a string expression says, with every value replaced by a marker:
 * a literal, a template (values marked), or a chain of `+`s of those. So
 * `'agents.' + 'agents'` reads as `agents.agents`, while `'agents.' + name`
 * reads as `agents.` then a marker, and can't be mistaken for the whole name.
 */
export function joinedText(node) {
  const value = withoutWrappers(node);
  if (value === undefined || value === null) return VALUE;
  if (value.type === 'Literal') return typeof value.value === 'string' ? value.value : VALUE;
  if (value.type === 'TemplateLiteral') {
    const pieces = value.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw);
    return pieces.join(VALUE);
  }
  if (value.type === 'BinaryExpression' && value.operator === '+') {
    return joinedText(value.left) + joinedText(value.right);
  }
  return VALUE;
}

/** True for a `+` chain, whose text is judged once, from the top of the chain. */
export const isConcatenation = (node) =>
  node !== undefined && node !== null && node.type === 'BinaryExpression' && node.operator === '+';

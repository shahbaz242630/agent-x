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

/** The text of a literal or a template with no values in it, or null for anything else. */
export function textOf(node) {
  if (node === undefined || node === null) return null;
  if (node.type === 'Literal') return typeof node.value === 'string' ? node.value : null;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join('');
  }
  return null;
}

/**
 * The text a string expression says, with every value replaced by a marker:
 * a literal, a template (values marked), or a chain of `+`s of those. So
 * `'agents.' + 'agents'` reads as `agents.agents`, while `'agents.' + name`
 * reads as `agents.` then a marker, and can't be mistaken for the whole name.
 */
export function joinedText(node) {
  if (node === undefined || node === null) return VALUE;
  if (node.type === 'Literal') return typeof node.value === 'string' ? node.value : VALUE;
  if (node.type === 'TemplateLiteral') {
    const pieces = node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw);
    return pieces.join(VALUE);
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return joinedText(node.left) + joinedText(node.right);
  }
  return VALUE;
}

/** True for a `+` chain, whose text is judged once, from the top of the chain. */
export const isConcatenation = (node) =>
  node !== undefined && node !== null && node.type === 'BinaryExpression' && node.operator === '+';

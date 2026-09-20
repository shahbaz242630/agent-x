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
 * A TypeScript wrapper around a value: `as`, `satisfies`, `!`, an explicit
 * type argument list, or an angle-bracket assertion. One list, read by both
 * directions below, so a rule can't know about a wrapper going down and not
 * coming back up.
 */
const isWrapper = (node) =>
  node !== undefined &&
  node !== null &&
  (node.type === 'TSAsExpression' ||
    node.type === 'TSSatisfiesExpression' ||
    node.type === 'TSNonNullExpression' ||
    node.type === 'TSInstantiationExpression' ||
    node.type === 'TSTypeAssertion');

/**
 * A value with its TypeScript wrappers taken off, so `'agent' as const` and
 * `('x' satisfies string)` read as the string they are. A rule that stopped at
 * the wrapper would miss the spelling a strict codebase actually uses.
 */
export function withoutWrappers(node) {
  let current = node;
  while (isWrapper(current)) current = current.expression;
  return current;
}

/**
 * The node this one sits inside once its wrappers are climbed: the other way
 * round, for a rule asking what a string is being *used as*.
 */
export function outermost(node) {
  let current = node;
  while (isWrapper(current.parent) && current.parent.expression === current) current = current.parent;
  return current;
}

/** True for Kysely's `sql` tag, written `sql` or `something.sql`. */
export function isSqlTag(tag) {
  if (tag === undefined || tag === null) return false;
  if (tag.type === 'Identifier') return tag.name === 'sql';
  return tag.type === 'MemberExpression' && !tag.computed && tag.property.type === 'Identifier'
    ? tag.property.name === 'sql'
    : false;
}

/**
 * The fixed text a `const` holds, for a name written once and used in a query
 * later (`const SQL = '…'; db.executeSql(SQL)`). One level, and only for a
 * plain single-definition `const`: more than that is a value, not a name
 * anyone can read off the page. no-string-built-sql.js resolves a const the
 * same way for the same reason.
 */
export function constText(context, identifier) {
  let scope = context.sourceCode.getScope(identifier);
  while (scope) {
    const variable = scope.set.get(identifier.name);
    if (variable) {
      const [definition] = variable.defs;
      const declaration = definition?.parent;
      const isConst = definition?.type === 'Variable' && declaration?.kind === 'const' && variable.defs.length === 1;
      return isConst && definition.node.id.type === 'Identifier' ? definition.node.init : null;
    }
    scope = scope.upper;
  }
  return null;
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

// SEC-TEN-07: SQL is never built from strings. Values reach the database only
// as bound parameters, through Kysely's query builder or its sql`...` tag.
//
// Two checks:
// 1. Text that is sent as a query (to query(), raw(), executeSql(), unsafe(),
//    including Kysely's CompiledQuery.raw) must be fixed text: a string
//    literal, a template with no values, a sql`...` query, or a const holding
//    one of those. Anything assembled at run time (with +, +=, concat(),
//    join() or a helper) is refused, whatever it contains.
// 2. Anywhere else, a template string or a + chain that mixes values into the
//    start of a SQL statement is refused. The pieces are joined first, with
//    each value replaced by a marker, because a selector only ever sees one
//    piece at a time.

const QUERY_METHODS = new Set(['query', 'raw', 'executeSql', 'unsafe']);

/** Stands for an interpolated value in the joined text. */
const VALUE = '\u0000';
const V = '\\u0000';
const NAME = `(?:[\\w."]+|${V})`;
const CLAUSE = '(?:where|join|left|right|inner|full|cross|group|order|limit|returning|using|on)\\b';
/** What may follow a table name: the end, a value, or the next clause (after an optional alias). */
const AFTER_TABLE = `(?:\\s*(?:$|${V}|;|\\))|\\s+(?:(?:as\\s+)?\\w+\\s+)?${CLAUSE})`;
/** Between SELECT and FROM: anything but the end of a sentence, so prose isn't mistaken for SQL. */
const SELECT_LIST = '(?:(?![.!?]\\s)[\\s\\S])*?';
const SQL_STATEMENT = new RegExp(
  [
    `\\bselect\\s${SELECT_LIST}\\bfrom\\s+${NAME}${AFTER_TABLE}`,
    `\\binsert\\s+into\\s+${NAME}\\s*(?:\\(|${V}|\\b(?:values|select|default)\\b)`,
    `\\bupdate\\s+${NAME}(?:\\s+(?:as\\s+)?\\w+)?\\s+set\\s+${NAME}\\s*=`,
    `\\bdelete\\s+from\\s+${NAME}${AFTER_TABLE}`,
  ].join('|'),
  'i',
);

const isPlus = (node) => node.type === 'BinaryExpression' && node.operator === '+';
const isStringLiteral = (node) => node.type === 'Literal' && typeof node.value === 'string';

/** True for Kysely's sql tag, written `sql` or `something.sql`. */
function isSqlTag(tag) {
  if (tag.type === 'Identifier') return tag.name === 'sql';
  return tag.type === 'MemberExpression' && !tag.computed && tag.property.name === 'sql';
}

function templateText(node) {
  return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join(VALUE);
}

/** The text of a `+` chain, and whether any part of it is a value rather than fixed text. */
function chainText(node) {
  if (isPlus(node)) {
    const left = chainText(node.left);
    const right = chainText(node.right);
    return { text: left.text + right.text, hasValue: left.hasValue || right.hasValue };
  }
  if (isStringLiteral(node)) return { text: node.value, hasValue: false };
  if (node.type === 'TemplateLiteral') return { text: templateText(node), hasValue: node.expressions.length > 0 };
  return { text: VALUE, hasValue: true };
}

/** The const initialiser an identifier refers to, if it is a plain `const name = …`. */
function constInitializer(context, identifier) {
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

/** Fixed text: a literal, a template without values, a sql`...` query, or a const holding one. */
function isFixedQueryText(context, node, depth = 0) {
  if (isStringLiteral(node)) return true;
  if (node.type === 'TemplateLiteral') return node.expressions.length === 0;
  if (node.type === 'TaggedTemplateExpression') return isSqlTag(node.tag);
  if (node.type === 'Identifier' && depth < 5) {
    const init = constInitializer(context, node);
    return init !== null && init !== undefined && isFixedQueryText(context, init, depth + 1);
  }
  return false;
}

/** @type {import('eslint').Rule.RuleModule} */
export default {
  meta: {
    type: 'problem',
    docs: { description: 'Forbid SQL built from strings (SEC-TEN-07)' },
    schema: [],
    messages: {
      template: 'SEC-TEN-07: SQL built with a template string. Use the query builder or the sql`...` tag.',
      concatenation: 'SEC-TEN-07: SQL built by string concatenation. Use the query builder or the sql`...` tag.',
      unsafeHelper: 'SEC-TEN-07: sql.{{name}} splices unchecked text into SQL. Use sql`...` with ${} parameters.',
      queryArgument:
        'SEC-TEN-07: {{name}}() must get fixed SQL text (a literal, a sql`...` query, or a const holding one), with values passed as parameters.',
    },
  },
  create(context) {
    return {
      TemplateLiteral(node) {
        if (node.expressions.length === 0) return;
        if (node.parent.type === 'TaggedTemplateExpression' && isSqlTag(node.parent.tag)) return;
        if (isPlus(node.parent)) return; // judged as part of its + chain
        if (SQL_STATEMENT.test(templateText(node))) context.report({ node, messageId: 'template' });
      },
      BinaryExpression(node) {
        if (!isPlus(node) || isPlus(node.parent)) return; // judge each chain once, from its top
        const { text, hasValue } = chainText(node);
        if (hasValue && SQL_STATEMENT.test(text)) context.report({ node, messageId: 'concatenation' });
      },
      CallExpression(node) {
        const { callee } = node;
        if (callee.type !== 'MemberExpression' || callee.computed || callee.property.type !== 'Identifier') return;
        const name = callee.property.name;

        if (callee.object.type === 'Identifier' && callee.object.name === 'sql' && (name === 'raw' || name === 'lit')) {
          context.report({ node, messageId: 'unsafeHelper', data: { name } });
          return;
        }
        const [first] = node.arguments;
        if (!QUERY_METHODS.has(name) || first === undefined) return;
        if (!isFixedQueryText(context, first)) context.report({ node, messageId: 'queryArgument', data: { name } });
      },
    };
  },
};

// ADR-012 §2, ADR-014 §8, A3c: an authority table is reached through its own
// description, and every read a decision rests on goes through verifiedState.
// This rule holds three things in product code, each anchored to the place
// where the mistake actually happens.
//
// **A table's name may not be written into a query.** `selectFrom`,
// `insertInto`, `updateTable`, `deleteFrom`, a join, a `with`, or SQL text
// given to `query`/`raw` or the `sql` tag: naming an authority table there
// reads or writes the row without finding its latest signed event, without
// checking its seal and without the row's lock. Kysely takes a table as a
// string, so refusing the string in a query is what pushes every access
// through the module's own `SignedStateTable` -- and that constant is only
// accepted by verifiedState, record and changeStatus (a sibling rule keeps the
// raw steps in the audit module).
//
// The name is looked for inside the query's text, with a name character on
// neither side, so Kysely's alias form (`'agents.agents as a'`), a name built
// with `+`, and a name inside SQL text are all caught, while a longer name
// that merely starts with it (`agents.agents_old`) is another table.
//
// **A query is the anchor, and it has to be.** The name itself belongs in
// plenty of places: a Kysely schema interface keys its tables by name
// (`{ 'audit.events': EventsTable }`, as the audit module does today), a type
// can be a literal of it, and an error or a log line may well name the table
// someone couldn't read. None of those reaches a row, and a rule that refused
// them would refuse the module its own schema type -- with nothing the author
// could do to comply.
//
// **An event's subject type may not be written into a subject.** Events about
// an authority object are its state changes only (ADR-014 §8): `record` writes
// them, sealed. A module recording an event of its own would put an event in
// the log that carries no seal. Only a subject's own type is judged
// (`subject: { type: '…' }`): a subject type is a plain word like `agent`,
// which is also an actor type, a union member and a switch case all over the
// code, and none of those records anything.
//
// **A table that declares itself must be on the registry**
// (tooling/authority-tables.ts) and must record its rows as the registry says,
// or the CI checks and the lint rules would be judging a different table from
// the one the app runs on: no signed-state columns checked, no key rules, no
// app-role rights, no status guard, and a subject type nobody watches. The
// registry is the list eslint.config.js passes in, imported from the same file
// the CI checks read, so the two can't drift. A description whose table isn't
// written there as a string is refused too: a name assembled elsewhere is a
// name no check can follow.
//
// A declaration counts only when its type came from @agentx/platform/db,
// under whatever name this file imports it as (plain or namespaced); a local
// `type SignedStateTable = …` would otherwise let any file speak for itself.
// Declarations are judged once the file has been read, since an import may be
// written below what it types.
//
// **What this rule is, and isn't.** It is a guard rail: it catches the honest
// mistake, at the moment it is written. It is not the wall. The wall is the
// signed state itself -- a field changed by anything but `record` fails
// `verifiedState` and raises the SEV-1 integrity alarm -- and the CI checks on
// the table. The row, not the code, is what the system actually trusts.
//
// **Where its reach ends** (four review rounds found each of these, and this
// is the line we stopped at, on purpose):
// - a query sink nobody listed: the list above is names, and a helper of our
//   own that takes a table name is not on it;
// - a name assembled beyond one `const` or one `+` chain: read from config,
//   built in a loop, or passed in as an argument;
// - a table reached through a variable holding the module's description, since
//   the description is what the signed-state calls take anyway;
// - anything in a file the rule doesn't run on (the exemptions in
//   eslint.config.js, which are a short and reviewed list).
// Each of those still meets the signed state: the row's fields must equal its
// latest signed event, and a change made any other way is denied and raises
// the alarm. That is the order of the defences, and it is deliberate -- a
// lint rule that chased every spelling would still not be a wall, and would
// cost a false failure on the day someone needed to ship.
import { carries, constText, isSqlTag, joinedText, outermost, textOf, withoutWrappers } from './strings.js';

/** The type a module's table description is declared as, and where it must come from. */
const DECLARED_AS = 'SignedStateTable';
const DECLARED_IN = '@agentx/platform/db';

/**
 * Kysely's ways of naming a table, and the ways SQL text is sent. Any method
 * whose name ends in `Join` counts as well, so a join shape Kysely adds (the
 * lateral ones, an apply) is caught without anyone having to remember it.
 *
 * **This list is where the rule's reach ends, and it is a list.** A sink
 * nobody wrote down here -- a wrapper of our own, a helper that takes a table
 * name -- reaches a row unreported. That is the guard rail's limit, written
 * out rather than implied.
 */
const QUERY_METHODS = new Set([
  'selectFrom',
  'insertInto',
  'updateTable',
  'deleteFrom',
  'replaceInto',
  'mergeInto',
  'using',
  'with',
  'withRecursive',
  'table',
  'createTable',
  'alterTable',
  'dropTable',
  'createIndex',
  'dropIndex',
  'query',
  'raw',
  'executeSql',
  'unsafe',
]);

/**
 * A name that carries `Join`, or ends in `Apply`, counts too: that is every
 * join shape Kysely has (`innerJoin`, `innerJoinLateral`, `crossApply`) and
 * every one it adds. Case matters, so an array's `join` is not a query.
 */
const isQueryMethod = (name) =>
  name !== null && (QUERY_METHODS.has(name) || name.includes('Join') || /Apply$/.test(name));

/** An event's subject: the property whose object's own `type` names the object recorded. */
const SUBJECT = 'subject';
const TYPE = 'type';
const TABLE = 'table';

/** The name a call is made by, for a member call (`db.selectFrom`) or a plain one. */
function calledName(node) {
  const { callee } = node;
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
    return callee.property.name;
  }
  return null;
}

/** The property this node is the value of, by name, or null. */
function propertyOf(node, name) {
  const parent = outermost(node).parent;
  if (parent === undefined || parent === null || parent.type !== 'Property') return null;
  if (parent.computed || outermost(parent.value) !== outermost(node)) return null;
  const key = parent.key.type === 'Identifier' ? parent.key.name : textOf(parent.key);
  return key === name ? parent : null;
}

/** True when this string is an event subject's own type: `subject: { type: '…' }`. */
function namesASubjectType(node) {
  const type = propertyOf(node, TYPE);
  if (type === null) return false;
  const holder = type.parent;
  if (holder === undefined || holder === null || holder.type !== 'ObjectExpression') return false;
  return propertyOf(holder, SUBJECT) !== null;
}

/** Every object a declaration's value holds: the object itself, or the objects in an array of them. */
function objectsIn(node) {
  const value = withoutWrappers(node);
  if (value === undefined || value === null) return [];
  if (value.type === 'ObjectExpression') return [value];
  if (value.type === 'ArrayExpression') {
    return value.elements.flatMap((element) => (element === null ? [] : objectsIn(element)));
  }
  return [];
}

/** The `table` and `subject` properties of a description, each with the node that holds it. */
function describedBy(node) {
  const found = {};
  for (const property of node.properties) {
    if (property.type !== 'Property' || property.computed) continue;
    const key = property.key.type === 'Identifier' ? property.key.name : textOf(property.key);
    if (key === TABLE || key === SUBJECT) found[key] = property.value;
  }
  return found;
}

/** @type {import('eslint').Rule.RuleModule} */
export default {
  meta: {
    type: 'problem',
    docs: { description: 'Authority tables are reached only through their signed state (ADR-012 §2)' },
    schema: [
      {
        type: 'object',
        properties: {
          tables: {
            type: 'array',
            items: {
              type: 'object',
              properties: { table: { type: 'string' }, subject: { type: 'string' } },
              required: ['table', 'subject'],
              additionalProperties: false,
            },
          },
        },
        required: ['tables'],
        additionalProperties: false,
      },
    ],
    defaultOptions: [{ tables: [] }],
    messages: {
      table:
        'ADR-012 §2: {{name}} is an authority table, and this is a query on it. Reach its rows through the audit module instead: verifiedState to decide, record or changeStatus to change. The name belongs in the SignedStateTable that declares the table, and nowhere else in a query.',
      subject:
        "ADR-014 §8: {{name}} is an authority table's subject type, and events about such an object are its state changes only, which record writes and seals. Record your own events against another subject.",
      unregistered:
        "A3c: the authority table {{name}} is not on the registry (tooling/authority-tables.ts), so nothing checks it: not its signed-state columns, its keys, the app role's rights, or its status guard. Add it there in the same change as its migration.",
      unwritten:
        "A3c: write this table's name here as a string, so the registry (tooling/authority-tables.ts) can be checked against it. A name assembled elsewhere is a name no check can follow.",
      subjectDiffers:
        'A3c: this table records its rows as {{found}}, but the registry (tooling/authority-tables.ts) says {{wanted}}. The registry is what the CI checks and the lint rules judge, so the two must say the same thing.',
    },
  },
  create(context) {
    const tables = context.options[0]?.tables ?? [];
    const names = tables.map((entry) => entry.table);
    const subjectOf = new Map(tables.map((entry) => [entry.table, entry.subject]));
    const subjects = new Set(tables.map((entry) => entry.subject));
    /** The names this file imports the declaration type as, and the namespaces it imports the module as. */
    const typeNames = new Set();
    const namespaces = new Set();
    /** Declarations found while reading, judged at the end: an import may be written below what it types. */
    const declarations = [];
    /** The functions being walked, so a `return` knows whose it is. */
    const functions = [];
    /**
     * Almost no file in the repository names the declaration type, and one
     * that doesn't can hold no description: the collecting is skipped there.
     * The query and subject checks still run everywhere, which is the point of
     * them.
     */
    const mayDeclare = context.sourceCode.getText().includes(DECLARED_AS);

    /** True if the type node mentions the declaration type, through any wrapper a declaration may use. */
    const mentions = (node) => {
      if (node === undefined || node === null) return false;
      switch (node.type) {
        case 'TSTypeAnnotation':
        case 'TSTypeOperator': {
          return mentions(node.typeAnnotation);
        }
        case 'TSArrayType': {
          return mentions(node.elementType);
        }
        case 'TSTupleType': {
          return node.elementTypes.some((one) => mentions(one));
        }
        // Either way round: an intersection says "this is one and more", a
        // union "this or something else". Both are a description the registry
        // must know about, and a union is the cheapest thing to hide behind
        // (`SignedStateTable | undefined`) if it isn't read.
        case 'TSIntersectionType':
        case 'TSUnionType': {
          return node.types.some((one) => mentions(one));
        }
        case 'TSTypeReference': {
          const { typeName } = node;
          if (typeName.type === 'Identifier') return typeNames.has(typeName.name);
          return (
            typeName.type === 'TSQualifiedName' &&
            typeName.left.type === 'Identifier' &&
            namespaces.has(typeName.left.name) &&
            typeName.right.type === 'Identifier' &&
            typeName.right.name === DECLARED_AS
          );
        }
        default: {
          return false;
        }
      }
    };

    /**
     * What a query was given, as text: the argument itself, the strings in an
     * array of tables, or the text a `const` holds. Wrappers are climbed on
     * the way, so `'agents.agents' as const` reads as the name it is.
     */
    const textsGivenTo = (argument) => {
      const value = withoutWrappers(argument);
      if (value === undefined || value === null) return [];
      if (value.type === 'ArrayExpression') {
        return value.elements.flatMap((element) => (element === null ? [] : textsGivenTo(element)));
      }
      if (value.type === 'Identifier') {
        const held = constText(context, value);
        return held === null ? [] : [[argument, joinedText(held)]];
      }
      return [[argument, joinedText(value)]];
    };

    /** A query on an authority table, wherever the name came from. */
    const judgeQuery = (node, argument) => {
      for (const [where, text] of textsGivenTo(argument)) {
        const named = names.find((name) => carries(text, name));
        if (named !== undefined) {
          context.report({ node: where, messageId: 'table', data: { name: named } });
          return;
        }
      }
    };

    /** An event's own subject type, which only record may write. */
    const judgeSubject = (node) => {
      const whole = textOf(node);
      if (whole !== null && subjects.has(whole) && namesASubjectType(node)) {
        context.report({ node, messageId: 'subject', data: { name: whole } });
      }
    };

    /** A description of a table: its name must be written here, registered, and recorded as the registry says. */
    const judge = (object) => {
      const { table, subject } = describedBy(object);
      if (table === undefined) return;
      const name = textOf(table);
      if (name === null) {
        context.report({ node: table, messageId: 'unwritten' });
        return;
      }
      if (!subjectOf.has(name)) {
        context.report({ node: table, messageId: 'unregistered', data: { name } });
        return;
      }
      const recorded = subject === undefined ? null : textOf(subject);
      if (subject !== undefined && recorded === null) {
        context.report({ node: subject, messageId: 'unwritten' });
        return;
      }
      const wanted = subjectOf.get(name);
      if (recorded !== null && recorded !== wanted) {
        context.report({
          node: subject,
          messageId: 'subjectDiffers',
          data: { found: recorded, wanted },
        });
      }
    };

    const declares = (type, value) => {
      if (!mayDeclare || type === undefined || type === null || value === undefined || value === null) return;
      declarations.push([type, value]);
    };

    return {
      ImportDeclaration(node) {
        if (node.source.value !== DECLARED_IN) return;
        for (const specifier of node.specifiers) {
          if (specifier.type === 'ImportNamespaceSpecifier') namespaces.add(specifier.local.name);
          if (specifier.type !== 'ImportSpecifier') continue;
          const imported =
            specifier.imported.type === 'Identifier' ? specifier.imported.name : textOf(specifier.imported);
          if (imported === DECLARED_AS) typeNames.add(specifier.local.name);
        }
      },
      VariableDeclarator(node) {
        if (node.id.type === 'Identifier') declares(node.id.typeAnnotation, node.init);
      },
      PropertyDefinition(node) {
        declares(node.typeAnnotation, node.value);
      },
      TSSatisfiesExpression(node) {
        declares(node.typeAnnotation, node.expression);
      },
      TSAsExpression(node) {
        declares(node.typeAnnotation, node.expression);
      },
      TSTypeAssertion(node) {
        declares(node.typeAnnotation, node.expression);
      },
      // A description a function gives back, whose type is the function's. The
      // stack is what a `return` inside it reads, rather than walking every
      // ancestor of every return in the repository.
      'ArrowFunctionExpression, FunctionDeclaration, FunctionExpression'(node) {
        functions.push(node);
        if (node.returnType === undefined || node.returnType === null) return;
        if (node.body.type !== 'BlockStatement') declares(node.returnType, node.body);
      },
      'ArrowFunctionExpression, FunctionDeclaration, FunctionExpression:exit'() {
        functions.pop();
      },
      ReturnStatement(node) {
        if (node.argument === null || node.argument === undefined) return;
        const holder = functions.at(-1);
        if (holder !== undefined) declares(holder.returnType, node.argument);
      },
      CallExpression(node) {
        if (!isQueryMethod(calledName(node))) return;
        for (const argument of node.arguments) judgeQuery(node, argument);
      },
      TaggedTemplateExpression(node) {
        if (!isSqlTag(node.tag)) return;
        judgeQuery(node, node.quasi);
      },
      Literal: judgeSubject,
      'Program:exit'() {
        // A description with both an annotation and a `satisfies` is found
        // twice; it is one description, and one report.
        const judged = new Set();
        for (const [type, value] of declarations) {
          if (!mentions(type)) continue;
          for (const object of objectsIn(value)) {
            if (judged.has(object)) continue;
            judged.add(object);
            judge(object);
          }
        }
      },
    };
  },
};

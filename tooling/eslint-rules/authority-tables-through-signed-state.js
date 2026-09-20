// ADR-012 §2, ADR-014 §8, A3c: an authority table is reached through its own
// description, and every read a decision rests on goes through verifiedState.
// This rule holds three things in product code.
//
// **A table's name belongs where the table is declared.** The module that owns
// an authority table writes its name once, in the `SignedStateTable` it hands
// to the audit module. Anywhere else, the name in a string is a query built
// around the signed state: `db.selectFrom('agents.agents')` reads the row
// without finding its latest signed event, without checking its seal and
// without the row's lock. Kysely takes a table as a string, so refusing the
// string is what pushes every access through the constant -- and the constant
// is only accepted by verifiedState, record and changeStatus (a sibling rule
// keeps the raw steps in the audit module). The name is looked for inside the
// string, not compared with it, so Kysely's alias form
// (`'agents.agents as a'`) and a name built with `+` are caught too, while a
// longer name that merely starts with it (`agents.agents_old`) is not this
// table.
//
// **An event's subject type belongs there too.** Events about an authority
// object are its state changes only (ADR-014 §8): `record` writes them,
// sealed. A module recording an event of its own against that subject type
// would put an event in the log that carries no seal. Only a subject's own
// type is judged (`subject: { type: '…' }`): a subject type is a plain word
// like `agent`, which is also an actor type, a union member and a switch case
// all over the code, and none of those reaches a row.
//
// **A table that declares itself must be on the registry**
// (tooling/authority-tables.ts), or CI checks nothing about it: no
// signed-state columns, no key rules, no app-role rights, no status guard. The
// registry is the list eslint.config.js passes in, imported from the same file
// the CI checks read, so the two can't drift.
//
// **What this rule is, and isn't.** It is a guard rail: it catches the honest
// mistake of reaching past the signed state, at the moment it is written. It
// is not the wall. The wall is the signed state itself -- a field changed by
// anything but `record` fails `verifiedState` and raises the SEV-1 integrity
// alarm -- and the CI checks on the table. Someone determined can still build
// a name the syntax can't show (from config, or a value read at run time), and
// this rule will not see it. That is why the row, not the code, is what the
// system actually trusts.
//
// A declaration counts only when its type came from @agentx/platform/db: a
// local `type SignedStateTable = …` would otherwise let any file exempt
// itself, and grant itself the names, in three lines.
import { isConcatenation, joinedText, textOf } from './strings.js';

/** The type a module's table description is declared as, and where it must come from. */
const DECLARED_AS = 'SignedStateTable';
const DECLARED_IN = '@agentx/platform/db';

/**
 * A character a name is made of. The name is looked for with one of these on
 * neither side, so `'agents.agents as a'` carries the table and
 * `'agents.agents_old'` or `'my_agents.agents'` are other tables, not this one.
 */
const NAME_CHARACTER = /[A-Za-z0-9_.]/;

/** True when `text` carries `name` as a name of its own, not as part of a longer one. */
function carries(text, name) {
  let at = text.indexOf(name);
  while (at !== -1) {
    const before = at === 0 ? '' : text[at - 1];
    const after = text[at + name.length] ?? '';
    if (!NAME_CHARACTER.test(before) && !NAME_CHARACTER.test(after)) return true;
    at = text.indexOf(name, at + 1);
  }
  return false;
}

/** An event's subject: the property whose object's own `type` names the object recorded. */
const SUBJECT = 'subject';
const TYPE = 'type';

/** True if the type node mentions the declaration type, at the top or inside an intersection, union or array. */
function mentions(node, name) {
  if (node === undefined || node === null) return false;
  if (node.type === 'TSTypeReference') return node.typeName.type === 'Identifier' && node.typeName.name === name;
  if (node.type === 'TSIntersectionType' || node.type === 'TSUnionType') {
    return node.types.some((one) => mentions(one, name));
  }
  if (node.type === 'TSArrayType') return mentions(node.elementType, name);
  if (node.type === 'TSTypeAnnotation') return mentions(node.typeAnnotation, name);
  return false;
}

/** The `table` and `subject` strings of an object literal, when it is written as one. */
function describedBy(node) {
  if (node === undefined || node === null || node.type !== 'ObjectExpression') return {};
  const found = {};
  for (const property of node.properties) {
    if (property.type !== 'Property' || property.computed) continue;
    const key = property.key.type === 'Identifier' ? property.key.name : textOf(property.key);
    if (key === 'table' || key === SUBJECT) {
      const value = textOf(property.value);
      if (value !== null) found[key] = value;
    }
  }
  return found;
}

/** The property this node is the value of, by name, or null. */
function propertyOf(node, name) {
  const parent = node.parent;
  if (parent === undefined || parent === null || parent.type !== 'Property' || parent.value !== node) return null;
  if (parent.computed) return null;
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
        'ADR-012 §2: {{name}} is an authority table. Its name belongs in the SignedStateTable that declares it; reach its rows through the audit module (verifiedState to decide, record or changeStatus to change), never through a query of your own.',
      subject:
        "ADR-014 §8: {{name}} is an authority table's subject type, and events about such an object are its state changes only, which record writes and seals. Record your own events against another subject.",
      unregistered:
        "A3c: the authority table {{name}} is not on the registry (tooling/authority-tables.ts), so CI checks nothing about it: not its signed-state columns, its keys, the app role's rights, or its status guard. Add it there in the same change as its migration.",
    },
  },
  create(context) {
    const tables = context.options[0]?.tables ?? [];
    const names = new Set(tables.map((entry) => entry.table));
    const subjects = new Set(tables.map((entry) => entry.subject));
    /** The local name of the declaration type, once it is imported from the platform. */
    let declarationType = null;
    /** Where a description was written: the names inside it are its own. */
    const descriptions = [];
    /** Every string that carries a registered name, judged once the file has been read. */
    const written = [];

    const inADescription = (node) =>
      descriptions.some(([start, end]) => node.range[0] >= start && node.range[1] <= end);

    /** A description of a table: its own names belong here, and the table must be registered. */
    const declares = (type, value) => {
      if (declarationType === null || !mentions(type, declarationType)) return;
      if (value === undefined || value === null) return;
      descriptions.push([value.range[0], value.range[1]]);
      const { table } = describedBy(value);
      if (table !== undefined && !names.has(table)) {
        context.report({ node: value, messageId: 'unregistered', data: { name: table } });
      }
    };

    const note = (node) => {
      if (isConcatenation(node.parent)) return; // judged once, from the top of the chain
      const text = joinedText(node);
      const table = [...names].find((name) => carries(text, name));
      if (table !== undefined) {
        written.push([node, 'table', table]);
        return;
      }
      const whole = textOf(node);
      if (whole !== null && subjects.has(whole) && namesASubjectType(node)) {
        written.push([node, 'subject', whole]);
      }
    };

    return {
      // The type the platform gives, under whatever name this file imports it as.
      ImportDeclaration(node) {
        if (node.source.value !== DECLARED_IN) return;
        for (const specifier of node.specifiers) {
          if (
            specifier.type === 'ImportSpecifier' &&
            specifier.imported.type === 'Identifier' &&
            specifier.imported.name === DECLARED_AS
          ) {
            declarationType = specifier.local.name;
          }
        }
      },
      VariableDeclarator(node) {
        declares(node.id.type === 'Identifier' ? node.id.typeAnnotation : null, node.init);
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
      Literal: note,
      TemplateLiteral: note,
      BinaryExpression: note,
      'Program:exit'() {
        for (const [node, messageId, name] of written) {
          if (!inADescription(node)) context.report({ node, messageId, data: { name } });
        }
      },
    };
  },
};

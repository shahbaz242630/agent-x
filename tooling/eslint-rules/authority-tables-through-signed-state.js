// ADR-012 §2, ADR-014 §8, A3c: an authority table is reached only through its
// own description, and every read a decision rests on goes through
// verifiedState. This rule holds the two halves of that in product code.
//
// **A table's name belongs where the table is declared.** The module that owns
// an authority table writes its name once, in the `SignedStateTable` it hands
// to the audit module. Anywhere else, the name in a string is a query built
// around the signed state: `db.selectFrom('agents.agents')` reads the row
// without finding its latest signed event, without checking its seal, and
// without the row's lock. Since Kysely takes a table as a string, refusing the
// string is what forces every access through the constant -- and the constant
// is only accepted by verifiedState, record and changeStatus (the steps
// themselves are kept in the audit module by its sibling rule).
//
// **A subject type belongs there too.** Events about an authority object are
// its state changes only (ADR-014 §8): `record` writes them, sealed. A module
// recording an event of its own against that subject type would put an event
// in the log that carries no seal, which the next read of the object reports
// as tampering -- or, with a seal marker stripped, hides a change.
//
// **And a table that declares itself must be on the registry**
// (tooling/authority-tables.ts), or CI checks nothing about it: no
// signed-state columns, no key rules, no app-role rights, no status guard. A
// module could otherwise build an authority table that skips every wall by
// simply not telling anyone.
//
// The registry is the list eslint.config.js passes in, imported from the same
// file the CI checks read, so the two can't drift.

/** The type a module's table description is declared as; `SignedStateTable & StatusTable<…>` counts too. */
const DECLARED_AS = 'SignedStateTable';

/** The string value of a literal or a template with no values, or null. */
function textOf(node) {
  if (node === undefined || node === null) return null;
  if (node.type === 'Literal') return typeof node.value === 'string' ? node.value : null;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join('');
  }
  return null;
}

/** True if the type node mentions SignedStateTable, at the top or in an intersection or union. */
function mentionsSignedStateTable(node) {
  if (node === undefined || node === null) return false;
  if (node.type === 'TSTypeReference') {
    return node.typeName.type === 'Identifier' && node.typeName.name === DECLARED_AS;
  }
  if (node.type === 'TSIntersectionType' || node.type === 'TSUnionType') {
    return node.types.some((one) => mentionsSignedStateTable(one));
  }
  if (node.type === 'TSTypeAnnotation') return mentionsSignedStateTable(node.typeAnnotation);
  return false;
}

/** The `table` and `subject` strings of an object literal, when it is written as one. */
function describedBy(node) {
  if (node === undefined || node === null || node.type !== 'ObjectExpression') return {};
  const found = {};
  for (const property of node.properties) {
    if (property.type !== 'Property' || property.computed) continue;
    const name = property.key.type === 'Identifier' ? property.key.name : textOf(property.key);
    if (name === 'table' || name === 'subject') {
      const value = textOf(property.value);
      if (value !== null) found[name] = value;
    }
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
    const [{ tables }] = context.options;
    const byTable = new Map(tables.map((entry) => [entry.table, entry]));
    const bySubject = new Map(tables.map((entry) => [entry.subject, entry]));
    /** The names this file declares, which may be written here. */
    const declared = new Set();
    /** Every place a registered name was written, judged once the file has been read. */
    const written = [];

    /** A declaration of a table description: its own names are allowed here, and it must be registered. */
    const declares = (type, value) => {
      if (!mentionsSignedStateTable(type)) return;
      const { table, subject } = describedBy(value);
      if (table !== undefined) declared.add(table);
      if (subject !== undefined) declared.add(subject);
      if (table !== undefined && !byTable.has(table)) {
        context.report({ node: value, messageId: 'unregistered', data: { name: table } });
      }
    };

    const note = (node) => {
      const text = textOf(node);
      if (text === null) return;
      if (byTable.has(text)) written.push([node, 'table', text]);
      else if (bySubject.has(text)) written.push([node, 'subject', text]);
    };

    return {
      VariableDeclarator(node) {
        declares(node.id.type === 'Identifier' ? node.id.typeAnnotation : null, node.init);
      },
      TSSatisfiesExpression(node) {
        declares(node.typeAnnotation, node.expression);
      },
      TSAsExpression(node) {
        declares(node.typeAnnotation, node.expression);
      },
      Literal: note,
      TemplateLiteral: note,
      'Program:exit'() {
        for (const [node, messageId, name] of written) {
          if (!declared.has(name)) context.report({ node, messageId, data: { name } });
        }
      },
    };
  },
};

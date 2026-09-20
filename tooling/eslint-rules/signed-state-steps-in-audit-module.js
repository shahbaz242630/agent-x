// ADR-012 §2, A3c: the steps that read, write and point a signed row, and the
// step that moves a status, belong to the audit module. Every other module
// reaches an authority row only through the audit module's signed states:
//
//   verifiedState(tx, TABLE, key, lock)   to decide anything on the row
//   record(tx, TABLE, key, from, set, …)  to create it or change a field
//   changeStatus(tx, TABLE, key, event, …) to move its status
//
// Those three find the object's latest signed event in the log, check the row
// against its seal, and seal every change as it is recorded. The raw steps
// (`readSignedRow`, `writeSignedRow`, `pointSignedRow`) and the bare status
// change (`createStatusChanger`) do none of that: a module using them directly
// would write an authority field, or move a status, with nothing to prove it
// afterwards -- which is exactly the tamper the signed state exists to catch.
//
// So this rule refuses their names outright in product code. Where they are
// written (@agentx/platform/db) and where they are used (the audit module's
// infrastructure) the rule is turned off in eslint.config.js, which is also
// the list of the places allowed to hold them.
import { textOf } from './strings.js';

const STEPS = new Set(['readSignedRow', 'writeSignedRow', 'pointSignedRow', 'createStatusChanger']);

/** The module the steps come from: re-exporting it whole would pass them on wholesale. */
const PLATFORM_DB = '@agentx/platform/db';

/**
 * The name a node says: an identifier, or a string wherever a name may be
 * written as one (a computed key, and the module export names ES2022 allows in
 * an import or an export).
 */
const named = (node) =>
  node === undefined || node === null ? null : node.type === 'Identifier' ? node.name : textOf(node);

/** @type {import('eslint').Rule.RuleModule} */
export default {
  meta: {
    type: 'problem',
    docs: { description: 'Only the audit module uses the signed-row steps (ADR-012 §2)' },
    schema: [],
    messages: {
      step: 'ADR-012 §2: {{name}} writes an authority row without signing the change. Go through the audit module: verifiedState to decide, record to create or change a field, changeStatus to move a status.',
      wholesale:
        'ADR-012 §2: re-exporting {{module}} whole passes the signed-row steps on to everything that imports this module. Export the names you mean, and leave the steps to the audit module.',
    },
  },
  create(context) {
    const check = (node, name) => {
      if (name !== null && STEPS.has(name)) context.report({ node, messageId: 'step', data: { name } });
    };
    return {
      // import { writeSignedRow } from '@agentx/platform/db', and the string
      // spelling of the same thing: import { 'writeSignedRow' as write } …
      ImportSpecifier(node) {
        check(node, named(node.imported));
      },
      // export { writeSignedRow } / export { mine as writeSignedRow }, either
      // side of the rename and either spelling. Reported once.
      ExportSpecifier(node) {
        const both = [named(node.local), named(node.exported)].find((name) => name !== null && STEPS.has(name));
        if (both !== undefined) check(node, both);
      },
      // export * from '@agentx/platform/db', which passes all four on at once
      ExportAllDeclaration(node) {
        if (node.source.value === PLATFORM_DB) {
          context.report({ node, messageId: 'wholesale', data: { module: PLATFORM_DB } });
        }
      },
      // db.writeSignedRow(...), db['writeSignedRow'](...) and the same in
      // backticks, after import * as db
      MemberExpression(node) {
        check(node, named(node.property));
      },
      // const { writeSignedRow } = db, and const { ['writeSignedRow']: write } = db
      Property(node) {
        if (node.parent.type !== 'ObjectPattern') return;
        check(node, named(node.key));
      },
    };
  },
};

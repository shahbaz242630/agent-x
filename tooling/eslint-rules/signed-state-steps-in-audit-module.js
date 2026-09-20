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
const STEPS = new Set(['readSignedRow', 'writeSignedRow', 'pointSignedRow', 'createStatusChanger']);

/** The module the steps come from: re-exporting it whole would pass them on wholesale. */
const PLATFORM_DB = '@agentx/platform/db';

/** The string a literal says, for a step reached as `db['writeSignedRow']`. */
const textOf = (node) => (node.type === 'Literal' && typeof node.value === 'string' ? node.value : null);

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
      if (STEPS.has(name)) context.report({ node, messageId: 'step', data: { name } });
    };
    return {
      // import { writeSignedRow } from '@agentx/platform/db'
      ImportSpecifier(node) {
        if (node.imported.type === 'Identifier') check(node, node.imported.name);
      },
      // export { writeSignedRow } / export { mine as writeSignedRow }
      ExportSpecifier(node) {
        if (node.local.type === 'Identifier') check(node, node.local.name);
        if (node.exported.type === 'Identifier') check(node, node.exported.name);
      },
      // export * from '@agentx/platform/db', which passes all four on at once
      ExportAllDeclaration(node) {
        if (node.source.value === PLATFORM_DB) {
          context.report({ node, messageId: 'wholesale', data: { module: PLATFORM_DB } });
        }
      },
      // db.writeSignedRow(...) and db['writeSignedRow'](...), after import * as db
      MemberExpression(node) {
        if (node.computed) {
          const named = textOf(node.property);
          if (named !== null) check(node, named);
          return;
        }
        if (node.property.type === 'Identifier') check(node, node.property.name);
      },
      // const { writeSignedRow } = db
      Property(node) {
        if (node.parent.type !== 'ObjectPattern' || node.computed) return;
        if (node.key.type === 'Identifier') check(node, node.key.name);
        else {
          const named = textOf(node.key);
          if (named !== null) check(node, named);
        }
      },
    };
  },
};

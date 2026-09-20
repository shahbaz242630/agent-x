// Gate proof for the authority-state rules (A3c-2; ADR-012 §2, ADR-014 §8):
// the signed-row steps belong to the audit module, and an authority table that
// declares itself must be on the registry. Each snippet is linted with the
// real eslint.config.js as if it sat at its path, so the path-scoped exemption
// for the audit module is the real one.
//
// The rule that refuses a registered table's own name and subject type
// elsewhere can't be proven here while the registry is empty (it is, until
// slice B1): that half is proven on the rule's own options in
// tooling/eslint-rules/authority-tables-through-signed-state.test.ts.
import { API, AUDIT, CORE, type LintCase, PLATFORM, proveLintRules } from './lint-harness.ts';

const STEPS_RULE = 'agentx/signed-state-steps-in-audit-module';
const TABLES_RULE = 'agentx/authority-tables-through-signed-state';

/**
 * A table description as a module writes one. The type is declared in the
 * snippet rather than imported, since the rule reads the name it is declared
 * as; in product code that name comes from @agentx/platform/db.
 */
const DECLARATION = `type SignedStateTable = {
  readonly table: string;
  readonly subject: string;
  readonly fields: readonly { readonly column: string; readonly type: string }[];
};
export const AGENTS: SignedStateTable = {
  table: 'agents.agents',
  subject: 'agent',
  fields: [{ column: 'status', type: 'text' }],
};
`;

const REJECTED: LintCase[] = [
  {
    name: 'a module importing a signed-row step',
    filePath: `${CORE}/import-step.ts`,
    code: "import { writeSignedRow } from '@agentx/platform/db';\n\nexport const step = writeSignedRow;\n",
    rule: STEPS_RULE,
    says: 'writeSignedRow writes an authority row without signing the change',
  },
  {
    name: 'a signed-row step reached through a namespace',
    filePath: `${API}/namespace-step.ts`,
    code:
      'declare const db: { pointSignedRow: (row: string) => void };\n\n' +
      'export const point = (row: string): void => {\n  db.pointSignedRow(row);\n};\n',
    rule: STEPS_RULE,
    says: 'pointSignedRow',
  },
  {
    name: 'a module passing a signed-row step on',
    filePath: `${PLATFORM}/re-export-step.ts`,
    code: "export { readSignedRow } from '@agentx/platform/db';\n",
    rule: STEPS_RULE,
    says: 'readSignedRow',
  },
  {
    name: 'the bare status change outside the audit module',
    filePath: `${CORE}/bare-status-change.ts`,
    code:
      'declare const platform: { createStatusChanger: (options: { logger: unknown }) => unknown };\n\n' +
      'export const changer = (logger: unknown): unknown => platform.createStatusChanger({ logger });\n',
    rule: STEPS_RULE,
    says: 'createStatusChanger',
  },
  {
    name: 'an authority table that is not on the registry',
    filePath: `${CORE}/unregistered-table.ts`,
    code: DECLARATION,
    rule: TABLES_RULE,
    says: 'is not on the registry (tooling/authority-tables.ts)',
  },
];

const ALLOWED: LintCase[] = [
  {
    name: 'the audit module holding the signed-row steps',
    filePath: `${AUDIT}/holds-the-steps.ts`,
    code:
      "import { pointSignedRow, readSignedRow, writeSignedRow } from '@agentx/platform/db';\n\n" +
      'export const steps = { readSignedRow, writeSignedRow, pointSignedRow };\n',
    rule: STEPS_RULE,
  },
  {
    name: 'a module going through the audit module instead',
    filePath: `${CORE}/through-signed-state.ts`,
    code:
      'declare const signedStates: { verifiedState: (key: string) => string; changeStatus: (key: string) => void };\n\n' +
      'export const decide = (key: string): string => signedStates.verifiedState(key);\n',
    rule: STEPS_RULE,
  },
  {
    name: 'a table name that belongs to no authority table',
    filePath: `${CORE}/another-table.ts`,
    code: "export const table = 'audit.events';\nexport const subject = 'request';\n",
    rule: TABLES_RULE,
  },
];

proveLintRules(REJECTED, ALLOWED);

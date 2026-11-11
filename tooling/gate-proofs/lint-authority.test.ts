// Gate proof for the signed-row steps rule (A3c-2; ADR-012 §2): the steps
// that write or point a signed row, and the step that moves a status, belong
// to the audit module. Each snippet is linted with the real eslint.config.js
// as if it sat at its path, so the exemption for the audit module is the real
// one — and so are the ways round it that a review found: a star re-export,
// computed access, destructuring off a namespace, and a rename on the way out.
//
// What the authority-table rule does with a registry is proven in
// lint-authority-registry.test.ts, on a registry of its own. Its one rule that
// bites whatever the registry holds — a table that declares itself and isn't
// on it — is proven here.
import {
  API,
  AUDIT,
  CORE,
  describes,
  type LintCase,
  OPERATOR,
  PLATFORM,
  PLATFORM_DB,
  proveLintRules,
} from './lint-harness.ts';

const STEPS_RULE = 'agentx/signed-state-steps-in-audit-module';
const TABLES_RULE = 'agentx/authority-tables-through-signed-state';
const IMPORTS_RULE = 'no-restricted-imports';
/** What the state repair's fence says (PL-29 follow-up, eslint.config.js). */
const STATE_REPAIR = "the operator's repair alone (apps/operator) uses them";
/** What the start's own fence says (PM3, eslint.config.js). */
const START_RECORD = "only the API's boot (apps/api/src/boot.ts) notes the start it recorded";
/** Code that notes a start, as only the API's boot may. */
const NOTES_A_START =
  "import { recordedStartWith } from '@agentx/platform/config';\n\nexport const note = recordedStartWith;\n";

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
    name: 'a signed-row step reached by a name in brackets',
    filePath: `${API}/computed-step.ts`,
    code:
      "declare const db: Record<'writeSignedRow', (row: string) => void>;\n\n" +
      "export const write = (row: string): void => {\n  db['writeSignedRow'](row);\n};\n",
    rule: STEPS_RULE,
    says: 'writeSignedRow',
  },
  {
    name: 'a signed-row step imported under the string spelling of its name',
    filePath: `${CORE}/string-named-import.ts`,
    code: ["import { 'readSignedRow' as read } from '@agentx/platform/db';", '', 'export const step = read;', ''].join(
      '\n',
    ),
    rule: STEPS_RULE,
    says: 'readSignedRow',
  },
  {
    name: 'a signed-row step reached by a name in backticks',
    filePath: `${API}/backtick-step.ts`,
    code: [
      "declare const db: Record<'writeSignedRow', (row: string) => void>;",
      '',
      'export const write = (row: string): void => {',
      '  db[`writeSignedRow`](row);',
      '};',
      '',
    ].join('\n'),
    rule: STEPS_RULE,
    says: 'writeSignedRow',
  },
  {
    name: 'a signed-row step taken out by a computed destructuring key',
    filePath: `${CORE}/computed-destructured-step.ts`,
    code: [
      'declare const db: { readSignedRow: (row: string) => string };',
      '',
      "const { ['readSignedRow']: read } = db;",
      'export const step = read;',
      '',
    ].join('\n'),
    rule: STEPS_RULE,
    says: 'readSignedRow',
  },
  {
    name: 'a signed-row step taken out of a namespace by destructuring',
    filePath: `${CORE}/destructured-step.ts`,
    code:
      'declare const db: { readSignedRow: (row: string) => string };\n\n' +
      'const { readSignedRow } = db;\nexport const read = readSignedRow;\n',
    rule: STEPS_RULE,
    says: 'readSignedRow',
  },
  {
    name: 'a module passing a signed-row step on',
    filePath: `${PLATFORM}/re-export-step.ts`,
    code: "export { readSignedRow } from '@agentx/platform/db';\n",
    rule: STEPS_RULE,
    says: 'readSignedRow',
    once: true,
  },
  {
    name: 'a signed-row step passed on under another name',
    filePath: `${CORE}/renamed-step.ts`,
    code: 'const mine = (row: string): void => {\n  void row;\n};\n\nexport { mine as writeSignedRow };\n',
    rule: STEPS_RULE,
    says: 'writeSignedRow',
  },
  {
    name: "a module re-exporting the platform's database module whole",
    filePath: `${CORE}/star-export.ts`,
    code: "export * from '@agentx/platform/db';\n",
    rule: STEPS_RULE,
    says: 'passes the signed-row steps on to everything that imports this module',
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
    name: "a module importing the state repair's steps from the audit module",
    filePath: `${API}/state-repair-step.ts`,
    code: "import { guardsOff } from '@agentx/core/modules/audit';\n\nexport const step = guardsOff;\n",
    rule: IMPORTS_RULE,
    says: STATE_REPAIR,
  },
  {
    name: "a core module importing the state repair's steps by a path to the audit module",
    filePath: `${CORE}/state-repair-relative.ts`,
    code:
      "import { guardsOff, judgeSignedRow, withRepairStates, writeStateRow } from '../../audit/index.ts';\n\n" +
      'export const steps = { guardsOff, judgeSignedRow, withRepairStates, writeStateRow };\n',
    rule: IMPORTS_RULE,
    says: STATE_REPAIR,
  },
  {
    name: "a core module importing the state repair's file itself",
    filePath: `${CORE}/state-repair-file.ts`,
    code: "import { guardsOff } from '../../audit/infrastructure/state-repair.ts';\n\nexport const step = guardsOff;\n",
    rule: IMPORTS_RULE,
    says: STATE_REPAIR,
  },
  {
    name: 'SEC-OPS-07 a module other than the boot noting the start it recorded, which the live adapter trusts',
    filePath: `${API}/notes-a-start.ts`,
    code: NOTES_A_START,
    rule: IMPORTS_RULE,
    says: START_RECORD,
  },
  {
    name: 'an authority table that is not on the registry',
    filePath: `${CORE}/unregistered-table.ts`,
    // A name no registry will ever hold, so this stays a proof of the rule
    // rather than of today's registry (slice B1 registers the real ones).
    code: describes('gate_proof.made_up', 'made_up'),
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
    name: "the platform's own database module, where the steps are written",
    filePath: `${PLATFORM_DB}/writes-the-steps.ts`,
    // Something the rule bites on elsewhere: a plain declaration would pass
    // with the rule fully switched on, and prove nothing about the exemption.
    code: [
      'declare const inner: { writeSignedRow: (row: string) => string };',
      '',
      'export const writeSignedRow = (row: string): string => inner.writeSignedRow(row);',
      '',
    ].join('\n'),
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
    name: "the operator's repair importing the state repair's steps",
    filePath: `${OPERATOR}/state-repair.ts`,
    code: "import { guardsOff } from '@agentx/core/modules/audit';\n\nexport const step = guardsOff;\n",
    rule: IMPORTS_RULE,
  },
  {
    name: "SEC-OPS-07 the API's boot noting the start it recorded",
    filePath: 'apps/api/src/boot.ts',
    code: NOTES_A_START,
    rule: IMPORTS_RULE,
  },
  {
    name: 'a core module importing what else the audit module offers by a path to it',
    filePath: `${CORE}/audit-relative.ts`,
    code: "import { withSignedStates } from '../../audit/index.ts';\n\nexport const work = withSignedStates;\n",
    rule: IMPORTS_RULE,
  },
  {
    name: 'a module re-exporting another module whole',
    filePath: `${CORE}/star-export-elsewhere.ts`,
    code: "export * from '@agentx/platform/observability';\n",
    rule: STEPS_RULE,
  },
];

proveLintRules(REJECTED, ALLOWED);

// Gate proof for the authority-table rule with a registry (A3c-2; ADR-012 §2,
// ADR-014 §8). The real registry (tooling/authority-tables.ts) is empty until
// slice B1, so these snippets are linted with the real eslint.config.js and
// the rule given a registry of two tables: everything else about the
// configuration — where the rule applies, and where it is turned off — is the
// real thing. What the rule does with the real, empty registry is in
// lint-authority.test.ts.
import { CORE, type LintCase, proveLintRules } from './lint-harness.ts';

const RULE = 'agentx/authority-tables-through-signed-state';

/** Two authority tables, as slice B1 will add them. */
const TABLES = [
  { table: 'agents.agents', subject: 'agent' },
  { table: 'orgs.organisations', subject: 'organisation' },
];

/**
 * The type a module's description is declared as, written out in the snippet:
 * the rule reads the name it is declared as, and in product code that name
 * comes from @agentx/platform/db.
 */
const TYPE = `type SignedStateTable = {
  readonly table: string;
  readonly subject: string;
  readonly fields: readonly { readonly column: string; readonly type: string }[];
};
`;

const declaration = (table: string, subject: string): string =>
  `${TYPE}export const TABLE: SignedStateTable = {
  table: '${table}',
  subject: '${subject}',
  fields: [{ column: 'status', type: 'text' }],
};
`;

const REJECTED: LintCase[] = [
  {
    name: 'a query of its own on an authority table',
    filePath: `${CORE}/own-query.ts`,
    code:
      'declare const db: { selectFrom: (table: string) => unknown };\n\n' +
      "export const rows = db.selectFrom('agents.agents');\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'the table name written in a template',
    filePath: `${CORE}/template-name.ts`,
    code: 'export const table = `agents.agents`;\n',
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: "an event of its own against an authority object's subject type",
    filePath: `${CORE}/own-event.ts`,
    code: "export const event = { subject: { type: 'agent', id: '1' }, action: 'agent.used' };\n",
    rule: RULE,
    says: "is an authority table's subject type",
  },
  {
    name: 'a declaring file naming another table as well as its own',
    filePath: `${CORE}/names-another.ts`,
    code: `${declaration('agents.agents', 'agent')}export const other = 'orgs.organisations';\n`,
    rule: RULE,
    says: 'orgs.organisations is an authority table',
  },
  {
    name: 'a table that declares itself and is not on the registry',
    filePath: `${CORE}/off-the-registry.ts`,
    code: declaration('keys.agent_keys', 'agent_key'),
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'the same, declared with satisfies',
    filePath: `${CORE}/off-the-registry-satisfies.ts`,
    code: `${TYPE}export const TABLE = {
  table: 'keys.agent_keys',
  subject: 'agent_key',
  fields: [{ column: 'status', type: 'text' }],
} satisfies SignedStateTable;
`,
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'the same, declared with as',
    filePath: `${CORE}/off-the-registry-as.ts`,
    code: `${TYPE}export const TABLE = {
  table: 'keys.agent_keys',
  subject: 'agent_key',
  fields: [{ column: 'status', type: 'text' }],
} as SignedStateTable;
`,
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'the same, declared as an intersection with its status table',
    filePath: `${CORE}/off-the-registry-intersection.ts`,
    code: `${TYPE}type StatusTable = { readonly table: string; readonly rules: { readonly name: string } };
export const TABLE: SignedStateTable & StatusTable = {
  table: 'keys.agent_keys',
  subject: 'agent_key',
  fields: [{ column: 'status', type: 'text' }],
  rules: { name: 'agent_key' },
};
`,
    rule: RULE,
    says: 'is not on the registry',
  },
];

const ALLOWED: LintCase[] = [
  {
    name: 'the file that declares the table, naming its own table and subject',
    filePath: `${CORE}/declares-its-own.ts`,
    code: `${declaration('agents.agents', 'agent')}export const named = ['agents.agents', 'agent'];\n`,
    rule: RULE,
  },
  {
    name: 'a declaration with satisfies, naming its own table',
    filePath: `${CORE}/declares-with-satisfies.ts`,
    code: `${TYPE}export const TABLE = {
  table: 'orgs.organisations',
  subject: 'organisation',
  fields: [{ column: 'status', type: 'text' }],
} satisfies SignedStateTable;
export const named = 'orgs.organisations';
`,
    rule: RULE,
  },
  {
    name: 'a table and a subject of no authority',
    filePath: `${CORE}/other-names.ts`,
    code: "export const table = 'audit.events';\nexport const subject = 'request';\n",
    rule: RULE,
  },
  {
    name: 'a property named after a subject type, which names no string',
    filePath: `${CORE}/property-name.ts`,
    code: 'export const counts = { agent: 1, organisation: 2 };\n',
    rule: RULE,
  },
];

proveLintRules(REJECTED, ALLOWED, { [RULE]: ['error', { tables: TABLES }] });

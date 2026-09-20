// Gate proof for the authority-table rule with a registry (A3c-2; ADR-012 §2,
// ADR-014 §8). The real registry (tooling/authority-tables.ts) is empty until
// slice B1, so these snippets are given a registry of two tables — and only
// these snippets, so the real configuration still decides everywhere else,
// the paths it turns the rule off for included.
//
// The cases are what three review rounds probed: the ways round the rule
// (Kysely's alias form, a name built with `+`, a name in SQL text, a local
// type standing in for the platform's, a description wrapped in `as const
// satisfies`, a namespaced type, an import written below what it types), and
// the ways it was too eager — a table name in a schema interface, in a type,
// or in a log line reaches no row, and a plain word like `agent` is an actor
// type and a switch case all over the code.
import { CORE, describes, type LintCase, proveLintRules, TESTING } from './lint-harness.ts';

const RULE = 'agentx/authority-tables-through-signed-state';

/** Two authority tables, as slice B1 will add them. */
const TABLES = [
  { table: 'agents.agents', subject: 'agent' },
  { table: 'orgs.organisations', subject: 'organisation' },
];

/** A name no registry will ever hold, for the cases about declaring one. */
const MADE_UP = 'gate_proof.made_up';

const query = (code: string): string => `declare const db: { selectFrom: (table: string) => unknown };\n\n${code}`;

const REJECTED: LintCase[] = [
  {
    name: 'a query of its own on an authority table',
    filePath: `${CORE}/own-query.ts`,
    code: query("export const rows = db.selectFrom('agents.agents');\n"),
    rule: RULE,
    says: 'agents.agents is an authority table, and this is a query on it',
    withOptions: true,
  },
  {
    name: "the same query written with Kysely's alias form",
    filePath: `${CORE}/aliased-query.ts`,
    code: query("export const rows = db.selectFrom('agents.agents as a');\n"),
    rule: RULE,
    says: 'agents.agents is an authority table',
    withOptions: true,
  },
  {
    name: 'a join on an authority table',
    filePath: `${CORE}/joined-query.ts`,
    code:
      'declare const db: { innerJoin: (table: string, left: string, right: string) => unknown };\n\n' +
      "export const rows = db.innerJoin('orgs.organisations', 'a.org_id', 'o.id');\n",
    rule: RULE,
    says: 'orgs.organisations is an authority table',
    withOptions: true,
  },
  {
    name: 'the name built with a plus inside a query',
    filePath: `${CORE}/built-name.ts`,
    code: query("export const rows = db.selectFrom('agents.' + 'agents');\n"),
    rule: RULE,
    says: 'agents.agents is an authority table',
    withOptions: true,
  },
  {
    name: 'the name in SQL text on the sql tag',
    filePath: `${CORE}/sql-text.ts`,
    code:
      'declare const sql: (text: TemplateStringsArray, ...values: unknown[]) => unknown;\n\n' +
      'export const rows = sql`select status from agents.agents where id = 1`;\n',
    rule: RULE,
    says: 'agents.agents is an authority table',
    withOptions: true,
  },
  {
    name: 'a file that declares a table, querying it anyway',
    filePath: `${CORE}/declares-and-queries.ts`,
    code: `${describes('agents.agents', 'agent')}\n${query("export const rows = db.selectFrom('agents.agents');\n")}`,
    rule: RULE,
    says: 'agents.agents is an authority table',
    withOptions: true,
  },
  {
    name: 'a query nested inside the description itself',
    filePath: `${CORE}/query-inside-description.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      'declare const db: { selectFrom: (table: string) => unknown };\n\n' +
      'export const TABLE: SignedStateTable & { rows: unknown } = {\n' +
      "  table: 'agents.agents',\n  subject: 'agent',\n  fields: [],\n" +
      "  rows: db.selectFrom('agents.agents'),\n};\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
    withOptions: true,
  },
  {
    name: "an event of its own against an authority object's subject",
    filePath: `${CORE}/own-event.ts`,
    code: "export const event = { actor: { type: 'user', id: '1' }, subject: { type: 'agent', id: '2' }, action: 'x' };\n",
    rule: RULE,
    says: "is an authority table's subject type",
    withOptions: true,
  },
  {
    name: 'the same subject type written as a constant',
    filePath: `${CORE}/own-event-as-const.ts`,
    code: "export const event = { subject: { type: 'agent' as const, id: '2' }, action: 'x' };\n",
    rule: RULE,
    says: "is an authority table's subject type",
    withOptions: true,
  },
  {
    name: 'a table declared off the registry',
    filePath: `${CORE}/off-the-registry.ts`,
    code: describes(MADE_UP, 'made_up'),
    rule: RULE,
    says: 'is not on the registry',
    withOptions: true,
  },
  {
    name: 'the same, wrapped in as const satisfies',
    filePath: `${CORE}/off-the-registry-as-const.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const TABLE = { table: '${MADE_UP}', subject: 'made_up', fields: [] } as const satisfies SignedStateTable;\n`,
    rule: RULE,
    says: 'is not on the registry',
    withOptions: true,
  },
  {
    name: 'the same, in a readonly array of descriptions',
    filePath: `${CORE}/off-the-registry-array.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const TABLES: readonly SignedStateTable[] = [{ table: '${MADE_UP}', subject: 'made_up', fields: [] }];\n`,
    rule: RULE,
    says: 'is not on the registry',
    withOptions: true,
  },
  {
    name: 'the same, with the type named through a namespace',
    filePath: `${CORE}/off-the-registry-namespace.ts`,
    code:
      "import type * as platform from '@agentx/platform/db';\n\n" +
      `export const TABLE: platform.SignedStateTable = { table: '${MADE_UP}', subject: 'made_up', fields: [] };\n`,
    rule: RULE,
    says: 'is not on the registry',
    withOptions: true,
  },
  {
    name: 'the same, given back by a function',
    filePath: `${CORE}/off-the-registry-returned.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const describe = (): SignedStateTable => ({ table: '${MADE_UP}', subject: 'made_up', fields: [] });\n`,
    rule: RULE,
    says: 'is not on the registry',
    withOptions: true,
  },
  {
    name: 'a description whose table is named through a constant',
    filePath: `${CORE}/name-through-a-constant.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `const NAME = '${MADE_UP}';\n` +
      'export const TABLE: SignedStateTable = { table: NAME, subject: '.concat("'made_up', fields: [] };\n"),
    rule: RULE,
    says: "write this table's name here as a string",
    withOptions: true,
  },
  {
    name: 'a description that records its rows as something the registry does not say',
    filePath: `${CORE}/subject-differs.ts`,
    code: describes('agents.agents', 'agent_row'),
    rule: RULE,
    says: 'this table records its rows as agent_row, but the registry',
    withOptions: true,
  },
  {
    name: 'a description read through a local type of the same name',
    filePath: `${CORE}/local-type.ts`,
    code:
      'type SignedStateTable = { readonly table: string; readonly subject: string };\n\n' +
      `export const TABLE: SignedStateTable = { table: '${MADE_UP}', subject: 'made_up' };\n` +
      query("export const rows = db.selectFrom('agents.agents');\n"),
    rule: RULE,
    says: 'agents.agents is an authority table',
    withOptions: true,
  },
];

const ALLOWED: LintCase[] = [
  {
    name: 'the description itself, on the registry and recording what it says',
    filePath: `${CORE}/declares-its-own.ts`,
    code: describes('agents.agents', 'agent'),
    rule: RULE,
    withOptions: true,
  },
  {
    name: 'the same description written with satisfies, and its import below it',
    filePath: `${CORE}/declares-with-satisfies.ts`,
    code:
      'export const TABLE = {\n' +
      "  table: 'orgs.organisations',\n" +
      "  subject: 'organisation',\n" +
      "  fields: [{ column: 'status', type: 'text' }],\n" +
      '} satisfies SignedStateTable;\n\n' +
      "import type { SignedStateTable } from '@agentx/platform/db';\n",
    rule: RULE,
    withOptions: true,
  },
  {
    name: 'a description as an intersection with its status table',
    filePath: `${CORE}/declares-with-status.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      'type StatusTable = { readonly rules: { readonly name: string } };\n\n' +
      'export const TABLE: SignedStateTable & StatusTable = {\n' +
      "  table: 'agents.agents',\n  subject: 'agent',\n  fields: [],\n  rules: { name: 'agent' },\n};\n",
    rule: RULE,
    withOptions: true,
  },
  {
    name: 'a Kysely schema interface, which keys its tables by name',
    filePath: `${CORE}/schema-interface.ts`,
    code:
      'export interface AgentTables {\n' +
      "  'agents.agents': { org_id: string; status: string };\n" +
      "  'orgs.organisations': { org_id: string; status: string };\n" +
      '}\n',
    rule: RULE,
    withOptions: true,
  },
  {
    name: 'a table name in a type and in a message someone will read',
    filePath: `${CORE}/name-in-a-type.ts`,
    code:
      "export type AgentsTable = 'agents.agents';\n\n" +
      'declare const log: (line: string) => void;\n\n' +
      "export const complain = (): void => {\n  log('could not read agents.agents');\n};\n",
    rule: RULE,
    withOptions: true,
  },
  {
    name: 'a subject type as a union member, an actor and a switch case',
    filePath: `${CORE}/plain-words.ts`,
    code:
      "export type ActorType = 'user' | 'agent' | 'system';\n\n" +
      "export const actor = { type: 'agent', id: '1' };\n\n" +
      'export const named = (kind: ActorType): string => {\n' +
      '  switch (kind) {\n' +
      "    case 'agent':\n      return 'an agent';\n" +
      "    default:\n      return 'someone';\n" +
      '  }\n' +
      '};\n',
    rule: RULE,
    withOptions: true,
  },
  {
    name: 'a longer name that merely starts with an authority table’s',
    filePath: `${CORE}/longer-name.ts`,
    code: query(
      "export const archive = db.selectFrom('agents.agents_old');\nexport const other = db.selectFrom('my_agents.agents');\n",
    ),
    rule: RULE,
    withOptions: true,
  },
  {
    name: 'a query on a table of no authority',
    filePath: `${CORE}/other-names.ts`,
    code: query("export const rows = db.selectFrom('audit.events');\n"),
    rule: RULE,
    withOptions: true,
  },
  {
    name: 'the test harness, which the real configuration exempts',
    // No options here: this case is judged by the real configuration, which is
    // what makes it a proof of the exemption rather than of the override.
    filePath: `${TESTING}/harness-fixture.ts`,
    code: query("export const rows = db.selectFrom('agents.agents');\n"),
    rule: RULE,
  },
];

proveLintRules(REJECTED, ALLOWED, { [RULE]: ['error', { tables: TABLES }] });

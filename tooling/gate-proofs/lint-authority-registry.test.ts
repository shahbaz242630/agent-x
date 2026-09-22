// Gate proof for the authority-table rule with a registry (A3c-2; ADR-012 §2,
// ADR-014 §8). These snippets are given a registry of two tables of their own,
// so no case depends on which tables the product lists today
// (tooling/authority-tables.ts) — and only these snippets, so the real
// configuration still decides everywhere else, the paths it turns the rule off
// for included.
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

/** Two authority tables of the snippets' own. */
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
  },
  {
    name: "the same query written with Kysely's alias form",
    filePath: `${CORE}/aliased-query.ts`,
    code: query("export const rows = db.selectFrom('agents.agents as a');\n"),
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'a query whose table is written as a constant',
    filePath: `${CORE}/as-const-query.ts`,
    code: query("export const rows = db.selectFrom('agents.agents' as const);\n"),
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: "a query given a list of tables, Kysely's array form",
    filePath: `${CORE}/array-query.ts`,
    code:
      'declare const db: { selectFrom: (tables: readonly string[]) => unknown };\n\n' +
      "export const rows = db.selectFrom(['agents.agents as a', 'audit.events']);\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'a lateral join, a shape nobody listed by hand',
    filePath: `${CORE}/lateral-join.ts`,
    code:
      'declare const db: { innerJoinLateral: (table: string, left: string, right: string) => unknown };\n\n' +
      "export const rows = db.innerJoinLateral('agents.agents', 'a', 'b');\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'a schema change on an authority table',
    filePath: `${CORE}/schema-change.ts`,
    code:
      'declare const schema: { dropTable: (table: string) => unknown };\n\n' +
      "export const gone = schema.dropTable('agents.agents');\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'SQL text held in a constant and sent later',
    filePath: `${CORE}/const-sql.ts`,
    code:
      'declare const db: { executeSql: (text: string) => unknown };\n\n' +
      "const SQL = 'select status from agents.agents where id = 1';\n\n" +
      'export const rows = db.executeSql(SQL);\n',
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'a join on an authority table',
    filePath: `${CORE}/joined-query.ts`,
    code:
      'declare const db: { innerJoin: (table: string, left: string, right: string) => unknown };\n\n' +
      "export const rows = db.innerJoin('orgs.organisations', 'a.org_id', 'o.id');\n",
    rule: RULE,
    says: 'orgs.organisations is an authority table',
  },
  {
    name: 'the name built with a plus inside a query',
    filePath: `${CORE}/built-name.ts`,
    code: query("export const rows = db.selectFrom('agents.' + 'agents');\n"),
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'the name in SQL text on the sql tag',
    filePath: `${CORE}/sql-text.ts`,
    code:
      'declare const sql: (text: TemplateStringsArray, ...values: unknown[]) => unknown;\n\n' +
      'export const rows = sql`select status from agents.agents where id = 1`;\n',
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'a file that declares a table, querying it anyway',
    filePath: `${CORE}/declares-and-queries.ts`,
    code: `${describes('agents.agents', 'agent')}\n${query("export const rows = db.selectFrom('agents.agents');\n")}`,
    rule: RULE,
    says: 'agents.agents is an authority table',
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
  },
  {
    name: "an event of its own against an authority object's subject",
    filePath: `${CORE}/own-event.ts`,
    code: "export const event = { actor: { type: 'user', id: '1' }, subject: { type: 'agent', id: '2' }, action: 'x' };\n",
    rule: RULE,
    says: "is an authority table's subject type",
  },
  {
    name: 'the same subject type written as a constant',
    filePath: `${CORE}/own-event-as-const.ts`,
    code: "export const event = { subject: { type: 'agent' as const, id: '2' }, action: 'x' };\n",
    rule: RULE,
    says: "is an authority table's subject type",
  },
  {
    name: 'a table declared off the registry',
    filePath: `${CORE}/off-the-registry.ts`,
    code: describes(MADE_UP, 'made_up'),
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'the same, wrapped in as const satisfies',
    filePath: `${CORE}/off-the-registry-as-const.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const TABLE = { table: '${MADE_UP}', subject: 'made_up', fields: [] } as const satisfies SignedStateTable;\n`,
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'the same, in a readonly array of descriptions',
    filePath: `${CORE}/off-the-registry-array.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const TABLES: readonly SignedStateTable[] = [{ table: '${MADE_UP}', subject: 'made_up', fields: [] }];\n`,
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'the same, with the type named through a namespace',
    filePath: `${CORE}/off-the-registry-namespace.ts`,
    code:
      "import type * as platform from '@agentx/platform/db';\n\n" +
      `export const TABLE: platform.SignedStateTable = { table: '${MADE_UP}', subject: 'made_up', fields: [] };\n`,
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'the same, given back by a function',
    filePath: `${CORE}/off-the-registry-returned.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const describe = (): SignedStateTable => ({ table: '${MADE_UP}', subject: 'made_up', fields: [] });\n`,
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'a description typed as the table or nothing',
    filePath: `${CORE}/off-the-registry-union.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const TABLE: SignedStateTable | undefined = { table: '${MADE_UP}', subject: 'made_up', fields: [] };\n`,
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'a description declared off the registry with an angle-bracket assertion',
    filePath: `${CORE}/asserted-table.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const TABLE = <SignedStateTable>{ table: '${MADE_UP}', subject: 'made_up', fields: [] };\n`,
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'a description declared off the registry as a class property',
    filePath: `${CORE}/class-table.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      'export class Module {\n' +
      `  static readonly TABLE: SignedStateTable = { table: '${MADE_UP}', subject: 'made_up', fields: [] };\n` +
      '}\n',
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'a description annotated and satisfied at once, reported once',
    filePath: `${CORE}/twice-typed.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      `export const TABLE: SignedStateTable = { table: '${MADE_UP}', subject: 'made_up', fields: [] } satisfies SignedStateTable;\n`,
    rule: RULE,
    says: 'is not on the registry',
    once: true,
  },
  {
    name: 'a description whose subject is named through a constant',
    filePath: `${CORE}/subject-through-a-constant.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      "const RECORDED = 'agent';\n" +
      "export const TABLE: SignedStateTable = { table: 'agents.agents', subject: RECORDED, fields: [] };\n",
    rule: RULE,
    says: "write this table's name here as a string",
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
  },
  {
    name: 'a description that records its rows as something the registry does not say',
    filePath: `${CORE}/subject-differs.ts`,
    code: describes('agents.agents', 'agent_row'),
    rule: RULE,
    says: 'this table records its rows as agent_row, but the registry',
  },
];

const ALLOWED: LintCase[] = [
  {
    name: 'the description itself, on the registry and recording what it says',
    filePath: `${CORE}/declares-its-own.ts`,
    code: describes('agents.agents', 'agent'),
    rule: RULE,
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
  },
  {
    name: 'a table name in a type and in a message someone will read',
    filePath: `${CORE}/name-in-a-type.ts`,
    code:
      "export type AgentsTable = 'agents.agents';\n\n" +
      'declare const log: (line: string) => void;\n\n' +
      "export const complain = (): void => {\n  log('could not read agents.agents');\n};\n",
    rule: RULE,
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
  },
  {
    name: 'a value standing between two pieces that would otherwise read as the name',
    // The pieces are joined with a marker, so `agents.` and `agents` either
    // side of a value are two names, not one. Joined bare they would read as
    // the table and this snippet would be refused.
    filePath: `${CORE}/value-between-pieces.ts`,
    code: [
      'declare const db: { executeSql: (text: string) => unknown };',
      'declare const other: string;',
      '',
      'export const rows = db.executeSql(`select from agents.${other}agents`);',
      '',
    ].join('\n'),
    rule: RULE,
  },
  {
    name: 'a longer name that merely starts with an authority table’s',
    filePath: `${CORE}/longer-name.ts`,
    code: query(
      "export const archive = db.selectFrom('agents.agents_old');\nexport const other = db.selectFrom('my_agents.agents');\n",
    ),
    rule: RULE,
  },
  {
    name: 'a local type of the same name, which declares nothing',
    // Nothing else in the snippet: if a local type counted as a declaration
    // the table would be judged against the registry and reported, so silence
    // here is the proof.
    filePath: `${CORE}/local-type.ts`,
    code:
      'type SignedStateTable = { readonly table: string; readonly subject: string };\n\n' +
      `export const TABLE: SignedStateTable = { table: '${MADE_UP}', subject: 'made_up' };\n`,
    rule: RULE,
  },
  {
    name: 'a query on a table of no authority',
    filePath: `${CORE}/other-names.ts`,
    code: query("export const rows = db.selectFrom('audit.events');\n"),
    rule: RULE,
  },
  {
    name: 'the test harness, which the real configuration exempts',
    // Judged by the real configuration alone, on a table the real registry
    // lists (B1a), so only the exemption keeps the rule quiet here.
    filePath: `${TESTING}/harness-fixture.ts`,
    realConfig: true,
    code: query("export const rows = db.selectFrom('organizations.organizations');\n"),
    rule: RULE,
  },
];

proveLintRules(REJECTED, ALLOWED, { [RULE]: ['error', { tables: TABLES }] });

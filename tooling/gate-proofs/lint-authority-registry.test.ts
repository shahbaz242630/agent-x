// Gate proof for the authority-table rule with a registry (A3c-2; ADR-012 §2,
// ADR-014 §8). The real registry (tooling/authority-tables.ts) is empty until
// slice B1, so the rule is given a registry of two tables — for these folders
// only, so the real configuration still decides everywhere else, the paths it
// turns the rule off for included.
//
// The cases are the ways a review found round the first version of the rule:
// Kysely's alias form, a name built with `+` or a template, a local type alias
// standing in for the platform's, and a file that declares a table helping
// itself to a query. And the ways it was too eager: a subject type is a plain
// word, which is also an actor type, a union member and a switch case all over
// the code.
import { CORE, describes, type LintCase, proveLintRules, TESTING } from './lint-harness.ts';

const RULE = 'agentx/authority-tables-through-signed-state';

/** Two authority tables, as slice B1 will add them. */
const TABLES = [
  { table: 'agents.agents', subject: 'agent' },
  { table: 'orgs.organisations', subject: 'organisation' },
];

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
    name: "the same query written with Kysely's alias form",
    filePath: `${CORE}/aliased-query.ts`,
    code:
      'declare const db: { selectFrom: (table: string) => unknown };\n\n' +
      "export const rows = db.selectFrom('agents.agents as a');\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'the name built with a plus',
    filePath: `${CORE}/built-name.ts`,
    code: "export const table = 'agents.' + 'agents';\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'the name in a template that also carries a value',
    filePath: `${CORE}/template-name.ts`,
    code: 'declare const suffix: string;\n\nexport const text = `select from agents.agents ${suffix}`;\n',
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: "an event of its own against an authority object's subject",
    filePath: `${CORE}/own-event.ts`,
    code: "export const event = { actor: { type: 'user', id: '1' }, subject: { type: 'agent', id: '2' }, action: 'agent.used' };\n",
    rule: RULE,
    says: "is an authority table's subject type",
  },
  {
    name: 'a file that declares a table, querying it anyway',
    filePath: `${CORE}/declares-and-queries.ts`,
    code:
      `${describes('agents.agents', 'agent')}\ndeclare const db: { selectFrom: (table: string) => unknown };\n\n` +
      "export const rows = db.selectFrom('agents.agents');\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'a local type alias standing in for the platform’s',
    filePath: `${CORE}/local-type.ts`,
    code:
      'type SignedStateTable = { readonly table: string; readonly subject: string };\n\n' +
      "export const TABLE: SignedStateTable = { table: 'agents.agents', subject: 'agent' };\n",
    rule: RULE,
    says: 'agents.agents is an authority table',
  },
  {
    name: 'a table declared off the registry with an angle-bracket assertion',
    filePath: `${CORE}/asserted-table.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      "export const TABLE = <SignedStateTable>{ table: 'gate_proof.made_up', subject: 'made_up', fields: [] };\n",
    rule: RULE,
    says: 'is not on the registry',
  },
  {
    name: 'a table declared off the registry as a class property',
    filePath: `${CORE}/class-table.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      'export class Module {\n' +
      "  static readonly TABLE: SignedStateTable = { table: 'gate_proof.made_up', subject: 'made_up', fields: [] };\n" +
      '}\n',
    rule: RULE,
    says: 'is not on the registry',
  },
];

const ALLOWED: LintCase[] = [
  {
    name: 'the description itself, which is where the names belong',
    filePath: `${CORE}/declares-its-own.ts`,
    code: describes('agents.agents', 'agent'),
    rule: RULE,
  },
  {
    name: 'the same description written with satisfies',
    filePath: `${CORE}/declares-with-satisfies.ts`,
    code:
      "import type { SignedStateTable } from '@agentx/platform/db';\n\n" +
      'export const TABLE = {\n' +
      "  table: 'orgs.organisations',\n" +
      "  subject: 'organisation',\n" +
      "  fields: [{ column: 'status', type: 'text' }],\n" +
      '} satisfies SignedStateTable;\n',
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
    name: 'a longer name that merely starts with an authority table’s',
    filePath: `${CORE}/longer-name.ts`,
    code: "export const archive = 'agents.agents_old';\nexport const other = 'my_agents.agents';\n",
    rule: RULE,
  },
  {
    name: 'a table and a subject of no authority',
    filePath: `${CORE}/other-names.ts`,
    code: "export const table = 'audit.events';\nexport const subject = 'request';\n",
    rule: RULE,
  },
  {
    name: 'the test harness, which the real configuration exempts',
    // Proves the override didn't switch the rule back on where the real
    // configuration turns it off: this path is outside the override's folders.
    filePath: `${TESTING}/harness-fixture.ts`,
    code:
      'declare const db: { selectFrom: (table: string) => unknown };\n\n' +
      "export const rows = db.selectFrom('agents.agents');\n",
    rule: RULE,
  },
];

proveLintRules(REJECTED, ALLOWED, { files: [CORE], rules: { [RULE]: ['error', { tables: TABLES }] } });

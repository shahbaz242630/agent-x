// Gate proof for the code rules (Rule Book §5, §8; SEC-WEB-03, SEC-TEN-07;
// ADR-006): each snippet breaks one rule and the real eslint.config.js must
// report it; each "allowed" snippet must pass that rule. The config, network,
// TLS and reason-code rules are proven in lint-platform.test.ts.
import { CONSOLE, CORE, type LintCase, PLATFORM, proveLintRules } from './lint-harness.ts';

const SQL_RULE = 'agentx/no-string-built-sql';

const REJECTED: LintCase[] = [
  // Rule Book §5: strict, honest TypeScript.
  {
    name: 'any',
    filePath: `${CORE}/any.ts`,
    code: 'export const value: any = 1;\n',
    rule: '@typescript-eslint/no-explicit-any',
  },
  {
    name: '@ts-ignore',
    filePath: `${CORE}/ts-ignore.ts`,
    code: '// @ts-ignore\nexport const value = 1;\n',
    rule: '@typescript-eslint/ban-ts-comment',
  },
  {
    name: 'a promise nobody awaits',
    filePath: `${CORE}/floating.ts`,
    code: 'async function save(): Promise<void> {\n  await Promise.resolve();\n}\nexport function run(): void {\n  save();\n}\n',
    rule: '@typescript-eslint/no-floating-promises',
  },
  {
    name: 'a switch that misses a case',
    filePath: `${CORE}/switch.ts`,
    code:
      "type Colour = 'red' | 'blue';\nexport function hex(colour: Colour): string {\n  switch (colour) {\n" +
      "    case 'red':\n      return '#f00';\n  }\n  return '';\n}\n",
    rule: '@typescript-eslint/switch-exhaustiveness-check',
  },
  {
    name: 'loose equality',
    filePath: `${CORE}/equality.ts`,
    code: 'export const same = (a: unknown, b: unknown): boolean => a == b;\n',
    rule: 'eqeqeq',
  },
  {
    name: 'the Function constructor',
    filePath: `${PLATFORM}/function.ts`,
    code: "export const make = new Function('return 1');\n",
    rule: 'no-new-func',
  },

  // Rule Book §5: every eslint-disable has a reason, and no directive is left unused.
  {
    name: 'an eslint-disable without a reason',
    filePath: `${PLATFORM}/disable.ts`,
    code: "// eslint-disable-next-line no-console\nconsole.info('started');\n",
    rule: '@eslint-community/eslint-comments/require-description',
  },
  {
    name: 'an eslint-disable that disables nothing',
    filePath: `${PLATFORM}/unused-disable.ts`,
    code: '// eslint-disable-next-line no-console -- nothing to hide here\nexport const value = 1;\n',
    rule: null,
    says: 'Unused eslint-disable directive',
  },
  {
    name: 'an inline config that changes nothing',
    filePath: `${PLATFORM}/unused-inline.ts`,
    code: '/* eslint eqeqeq: ["error", "always"] */\nexport const same = (a: number, b: number): boolean => a === b;\n',
    rule: null,
    says: 'Unused inline config',
  },

  // Rule Book §8 and randomness.
  {
    name: 'console in product code',
    filePath: `${PLATFORM}/console.ts`,
    code: "console.info('started');\n",
    rule: 'no-console',
  },
  {
    name: 'Math.random',
    filePath: `${PLATFORM}/random.ts`,
    code: 'export const roll = Math.random();\n',
    rule: 'no-restricted-properties',
    says: 'Math.random',
  },

  // ADR-006 §3: business time comes from the Clock.
  ...[
    ['Date.now()', 'export const at = Date.now();\n'],
    ['new Date()', 'export const at = new Date();\n'],
    ['Date() called without new', 'export const at = Date();\n'],
    ['globalThis.Date', 'export const at = new globalThis.Date();\n'],
  ].map(([what, code]) => ({
    name: `${String(what)} in core`,
    filePath: `${CORE}/clock-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: 'no-restricted-syntax',
    says: 'ADR-006',
  })),

  // SEC-WEB-03: no raw HTML.
  ...[
    ['innerHTML', 'export function show(el: { innerHTML: string }, html: string): void {\n  el.innerHTML = html;\n}\n'],
    ['outerHTML', 'export function show(el: { outerHTML: string }, html: string): void {\n  el.outerHTML = html;\n}\n'],
    ['srcdoc', 'export function frame(el: { srcdoc: string }, html: string): void {\n  el.srcdoc = html;\n}\n'],
    [
      'insertAdjacentHTML',
      'export function add(el: { insertAdjacentHTML(at: string, html: string): void }, html: string): void {\n' +
        "  el.insertAdjacentHTML('beforeend', html);\n}\n",
    ],
    [
      'document.write',
      'declare const document: { write(html: string): void };\nexport function w(html: string): void {\n  document.write(html);\n}\n',
    ],
    [
      'document.writeln',
      'declare const document: { writeln(html: string): void };\nexport function w(html: string): void {\n  document.writeln(html);\n}\n',
    ],
  ].map(([what, code]) => ({
    name: String(what),
    filePath: `${CONSOLE}/${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: 'no-restricted-syntax',
    says: 'SEC-WEB-03',
  })),
  {
    name: 'the React raw-HTML prop',
    filePath: `${CONSOLE}/view.tsx`,
    code: 'export const View = (props: { html: string }) => <div dangerouslySetInnerHTML={{ __html: props.html }} />;\n',
    rule: 'no-restricted-syntax',
    says: 'SEC-WEB-03',
  },

  // SEC-TEN-07: no SQL built from strings.
  ...[
    [
      'SQL in a template string',
      'export const q = (id: string): string => `SELECT * FROM suppliers WHERE id = ${id}`;\n',
    ],
    [
      'SQL with an interpolated column list',
      'export const q = (cols: string, id: string): string => `SELECT ${cols} FROM suppliers WHERE id = ${id}`;\n',
    ],
    [
      'UPDATE with an interpolated table',
      'export const q = (table: string, name: string): string => `UPDATE ${table} SET name = ${name}`;\n',
    ],
    [
      'SQL built by concatenation',
      "export const q = (id: string): string => 'DELETE FROM suppliers WHERE id = ' + id;\n",
    ],
    [
      'SQL split across concatenated literals',
      "export const q = (id: string): string => 'SELECT * ' + 'FROM suppliers WHERE id = ' + id;\n",
    ],
    [
      'sql.raw',
      'declare const sql: { raw(text: string): unknown };\nexport const q = (text: string): unknown => sql.raw(text);\n',
    ],
    [
      'sql.lit',
      'declare const sql: { lit(value: unknown): unknown };\nexport const q = (v: string): unknown => sql.lit(v);\n',
    ],
    [
      'query() given a template string with values',
      'declare const client: { query(text: string): Promise<unknown> };\n' +
        'export const q = (limit: number): Promise<unknown> => client.query(`SELECT 1 LIMIT ${limit}`);\n',
    ],
    [
      'query() given a concatenated string',
      'declare const client: { query(text: string): Promise<unknown> };\n' +
        "export const q = (limit: number): Promise<unknown> => client.query('SELECT 1 LIMIT ' + String(limit));\n",
    ],
    [
      'executeSql() given a template string with values',
      'declare const boss: { executeSql(text: string): Promise<unknown> };\n' +
        'export const run = (table: string): Promise<unknown> => boss.executeSql(`VACUUM ${table}`);\n',
    ],
    [
      'unsafe() given a concatenated string',
      'declare const db: { unsafe(text: string): Promise<unknown> };\n' +
        "export const run = (table: string): Promise<unknown> => db.unsafe('VACUUM ' + table);\n",
    ],
    [
      'raw() given a template string with values',
      'declare const knex: { raw(text: string): unknown };\nexport const q = (col: string): unknown => knex.raw(`${col} DESC`);\n',
    ],
    [
      'SQL in a template with a tag other than sql',
      'declare function dedent(text: TemplateStringsArray, ...values: unknown[]): string;\n' +
        'export const q = (id: string): string => dedent`SELECT * FROM suppliers WHERE id = ${id}`;\n',
    ],
    [
      'SQL in String.raw',
      'export const q = (id: string): string => String.raw`SELECT * FROM suppliers WHERE id = ${id}`;\n',
    ],
    [
      'query() given text built up with +=',
      'declare const client: { query(text: string): Promise<unknown> };\n' +
        'export function find(id: string): Promise<unknown> {\n' +
        "  let text = 'SELECT * FROM suppliers WHERE 1 = 1';\n" +
        "  text += ' AND id = ' + id;\n  return client.query(text);\n}\n",
    ],
    [
      'query() given text joined with concat()',
      'declare const client: { query(text: string): Promise<unknown> };\n' +
        "export const q = (id: string): Promise<unknown> => client.query('SELECT * FROM suppliers WHERE id = '.concat(id));\n",
    ],
    [
      'query() given text joined from an array',
      'declare const client: { query(text: string): Promise<unknown> };\n' +
        "export const q = (id: string): Promise<unknown> => client.query(['SELECT * FROM suppliers WHERE id =', id].join(' '));\n",
    ],
    [
      "Kysely's CompiledQuery.raw given text from outside",
      'declare const CompiledQuery: { raw(text: string, values: unknown[]): unknown };\n' +
        'export const q = (text: string, values: unknown[]): unknown => CompiledQuery.raw(text, values);\n',
    ],
  ].map(([what, code]) => ({
    name: String(what),
    filePath: `${CORE}/sql-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: SQL_RULE,
    says: 'SEC-TEN-07',
  })),
];

const ALLOWED: LintCase[] = [
  {
    name: "Kysely's sql tag, which binds values as parameters",
    filePath: `${CORE}/sql-tag.ts`,
    code:
      'declare function sql(text: TemplateStringsArray, ...values: unknown[]): unknown;\n' +
      'export const q = (id: string): unknown => sql`SELECT * FROM suppliers WHERE id = ${id}`;\n',
    rule: SQL_RULE,
  },
  {
    name: 'a fixed SQL string with no values in it',
    filePath: `${CORE}/sql-fixed.ts`,
    code: "export const q = 'SELECT 1 FROM suppliers';\n",
    rule: SQL_RULE,
  },
  {
    name: 'query() given a const holding fixed SQL, with values as parameters',
    filePath: `${CORE}/sql-const.ts`,
    code:
      'declare const client: { query(text: string, values: unknown[]): Promise<unknown> };\n' +
      "const FIND = 'SELECT * FROM suppliers WHERE id = $1';\n" +
      'export const find = (id: string): Promise<unknown> => client.query(FIND, [id]);\n',
    rule: SQL_RULE,
  },
  ...[
    [
      'ordinary text that mentions deleting',
      'export const note = (n: number): string => `Deleted ${n} drafts from the list`;\n',
    ],
    [
      'a prompt to select from a list',
      'export const note = (name: string): string => `Select a supplier from the list: ${name}`;\n',
    ],
    [
      'a prompt to select one of several',
      'export const note = (n: number): string => `Please select one option from ${n} choices`;\n',
    ],
    [
      'a sentence about updating a setting',
      "export const note = (f: string, v: string): string => 'Update ' + f + ' set to ' + v;\n",
    ],
    ['a question about deleting', 'export const note = (list: string): string => `Delete from ${list}?`;\n'],
    [
      'a two-sentence message',
      'export const note = (bank: string): string => `Please select a plan.\\nPayment from ${bank}`;\n',
    ],
  ].map(([what, code]) => ({
    name: String(what),
    filePath: `${CORE}/prose-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: SQL_RULE,
  })),
  {
    name: 'a Date built from a known value in core',
    filePath: `${CORE}/from-value.ts`,
    code: 'export const at = (epochMs: number): Date => new Date(epochMs);\n',
    rule: 'no-restricted-syntax',
    says: 'ADR-006',
  },
  {
    name: 'Date.now() outside core',
    filePath: `${PLATFORM}/timing.ts`,
    code: 'export const startedAt = Date.now();\n',
    rule: 'no-restricted-syntax',
    says: 'ADR-006',
  },
  {
    name: 'console in a repository script',
    filePath: 'scripts/gate-proof.mjs',
    code: "console.log('ok');\n",
    rule: 'no-console',
  },
];

proveLintRules(REJECTED, ALLOWED);

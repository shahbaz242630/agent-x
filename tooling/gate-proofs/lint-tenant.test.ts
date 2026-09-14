// Gate proof for the tenant-setting rule (ADR-005 §4, SEC-TEN-06): product code
// never names the `app.org_id` setting outside withTenant's file, never calls
// set_config, and never SETs a custom (two-part) setting, so nothing can set
// the tenant for a whole session. Tests and the test harness may: they read the
// setting back, and build tenant tables with the policy.
import { API, CORE, type LintCase, PLATFORM, proveLintRules, TESTING } from './lint-harness.ts';

const RULE = 'agentx/tenant-setting-only-in-with-tenant';

const cases = (entries: readonly (readonly [string, string, string, string])[]): LintCase[] =>
  entries.map(([what, folder, code, says]) => ({
    name: what,
    filePath: `${folder}/tenant-${what.replace(/\W/g, '')}.ts`,
    code,
    rule: RULE,
    says,
  }));

const REJECTED: LintCase[] = cases([
  ['a session-level SET of the tenant', PLATFORM, "export const pin = 'set app.org_id = 1';\n", 'naming app.org_id'],
  [
    'set_config with the tenant in a tagged query',
    API,
    'declare const sql: (text: TemplateStringsArray, ...values: unknown[]) => unknown;\n' +
      "export const pin = (orgId: string): unknown => sql`select set_config('app.org_id', ${orgId}, false)`;\n",
    'naming app.org_id',
  ],
  [
    'the setting in a template string',
    PLATFORM,
    "export const pin = (id: string): string => `set app.org_id = '${id}'`;\n",
    'naming app.org_id',
  ],
  ['the setting in capitals, in core', CORE, "export const name = 'APP.ORG_ID';\n", 'naming app.org_id'],
  [
    'the setting as a bound value',
    API,
    "export const pin = ['select set_config($1, $2, false)', ['app.org_id', 'x']] as const;\n",
    'naming app.org_id',
  ],
  // Found by the adversarial review: the name built from pieces, so it never appears whole.
  [
    'set_config with the name built from pieces',
    PLATFORM,
    "export const pin = \"select pg_catalog.set_config('app.' || 'org_id', $1, false)\";\n",
    'set_config',
  ],
  [
    'set_config for any other setting',
    API,
    "export const pin = \"select set_config('search_path', '', false)\";\n",
    'set_config',
  ],
  ['a SET SESSION of a custom setting', PLATFORM, "export const pin = 'SET SESSION agentx.mode = 1';\n", 'set_config'],
  ['a SET of a quoted custom setting', CORE, 'export const pin = \'set "app".other = 1\';\n', 'set_config'],
]);

const ALLOWED: LintCase[] = [
  ...cases([
    ['an UPDATE with SET', PLATFORM, "export const q = 'update t set name = $1 where id = $2';\n", ''],
    ['a SET LOCAL of a built-in setting', PLATFORM, "export const q = 'set local statement_timeout = 1000';\n", ''],
    ['a RESET', PLATFORM, "export const q = 'reset all';\n", ''],
    [
      'names that only look alike',
      PLATFORM,
      "export const names = ['org_id', 'app_org_id', 'app.org', 'application.org_id_x'];\n",
      '',
    ],
    ['prose with the word set', API, "export const note = 'Set up the account, then set the limits.';\n", ''],
  ]).map(({ says: _, ...rest }) => rest),
  {
    name: 'withTenant’s own file',
    filePath: 'packages/platform/src/db/tenant.ts',
    code: 'export const setting = "select pg_catalog.set_config(\'app.org_id\', $1, true)";\n',
    rule: RULE,
  },
  {
    name: 'a test that reads the setting back',
    filePath: `${PLATFORM}/tenant-reads.test.ts`,
    code: "export const read = \"select set_config('app.' || 'org_id', $1, false), current_setting('app.org_id', true)\";\n",
    rule: RULE,
  },
  {
    name: 'the test harness building a tenant table',
    filePath: `${TESTING}/probe.ts`,
    code: "export const policy = \"using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)\";\n",
    rule: RULE,
  },
];

proveLintRules(REJECTED, ALLOWED);

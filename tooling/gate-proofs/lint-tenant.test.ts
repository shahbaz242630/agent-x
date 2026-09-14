// Gate proof for the tenant-setting rule (ADR-005 §4, SEC-TEN-06): product code
// never names the `app.org_id` setting outside withTenant's file, so nothing
// can set the tenant for a whole session. Tests and the test harness may name
// it: they read it back, and build tenant tables with the policy.
import { API, CORE, type LintCase, PLATFORM, proveLintRules, TESTING } from './lint-harness.ts';

const RULE = 'agentx/tenant-setting-only-in-with-tenant';

const REJECTED: LintCase[] = [
  ['a session-level SET of the tenant', PLATFORM, "export const pin = 'set app.org_id = 1';\n"],
  [
    'set_config with the tenant in a tagged query',
    API,
    'declare const sql: (text: TemplateStringsArray, ...values: unknown[]) => unknown;\n' +
      "export const pin = (orgId: string): unknown => sql`select set_config('app.org_id', ${orgId}, false)`;\n",
  ],
  [
    'the setting in a template string',
    PLATFORM,
    "export const pin = (id: string): string => `set app.org_id = '${id}'`;\n",
  ],
  ['the setting in capitals, in core', CORE, "export const name = 'APP.ORG_ID';\n"],
  [
    'the setting as a bound value',
    API,
    "export const pin = ['select set_config($1, $2, false)', ['app.org_id', 'x']] as const;\n",
  ],
].map(([what, folder, code]) => ({
  name: String(what),
  filePath: `${String(folder)}/tenant-${String(what).replace(/\W/g, '')}.ts`,
  code: String(code),
  rule: RULE,
}));

const ALLOWED: LintCase[] = [
  {
    name: 'withTenant’s own file',
    filePath: 'packages/platform/src/db/tenant.ts',
    code: "export const setting = 'app.org_id';\n",
    rule: RULE,
  },
  {
    name: 'a test that reads the setting back',
    filePath: `${PLATFORM}/tenant-reads.test.ts`,
    code: 'export const read = "select current_setting(\'app.org_id\', true)";\n',
    rule: RULE,
  },
  {
    name: 'the test harness building a tenant table',
    filePath: `${TESTING}/probe.ts`,
    code: "export const policy = \"using (org_id = nullif(current_setting('app.org_id', true), '')::uuid)\";\n",
    rule: RULE,
  },
  {
    name: 'names that only look alike',
    filePath: `${PLATFORM}/tenant-lookalikes.ts`,
    code: "export const names = ['org_id', 'app_org_id', 'app.org', 'application.org_id_x'];\n",
    rule: RULE,
  },
];

proveLintRules(REJECTED, ALLOWED);

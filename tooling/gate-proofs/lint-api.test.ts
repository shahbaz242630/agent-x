// Gate proof for the API contract's lint rule (SEC-WEB-06, SEC-DATA-04): how
// the API checks input, writes answers, and answers errors and unknown
// addresses is set once, in server.ts and contract.ts. A not-found handler or
// a reply serializer set anywhere else isn't a route, so the contract's check
// at start can't see it. Each snippet breaks the rule and the real
// eslint.config.js must report it; each "allowed" snippet must pass it.
import { API, type LintCase, proveLintRules } from './lint-harness.ts';

const SETTERS = [
  'setErrorHandler',
  'setNotFoundHandler',
  'setValidatorCompiler',
  'setSerializerCompiler',
  'setReplySerializer',
  'serializer',
  'addContentTypeParser',
  'removeContentTypeParser',
  'removeAllContentTypeParsers',
] as const;

/** A plugin that calls one setter, typed just enough to compile on its own. */
const calls = (setter: string): string =>
  `export function plugin(app: { ${setter}(handler: () => void): void }): void {\n  app.${setter}(() => undefined);\n}\n`;

const REJECTED: LintCase[] = [
  ...SETTERS.map((setter) => ({
    name: `${setter} in an API module`,
    filePath: `${API}/${setter}.ts`,
    code: calls(setter),
    rule: 'no-restricted-properties',
    says: 'SEC-WEB-06',
  })),
  // Beside the two files that may, so an exemption wider than those two fails here.
  ...['apps/api/src/health.ts', 'apps/api/src/server.test.ts', 'apps/api/src/contract.test.ts'].map((filePath) => ({
    name: `setNotFoundHandler in ${filePath}`,
    filePath,
    code: calls('setNotFoundHandler'),
    rule: 'no-restricted-properties',
    says: 'SEC-WEB-06',
    realConfig: true,
  })),
  {
    name: "Math.random in the API, whose block repeats the product's list",
    filePath: `${API}/random.ts`,
    code: 'export const roll = Math.random();\n',
    rule: 'no-restricted-properties',
    says: 'Math.random',
  },
  {
    name: "process.env in the API, whose block repeats the product's list",
    filePath: `${API}/env.ts`,
    code: 'export const level = process.env.LOG_LEVEL;\n',
    rule: 'no-restricted-properties',
    says: 'loadConfig',
  },
];

/** A plugin that calls every setter. */
const callsAll = [
  `export function plugin(app: Record<${SETTERS.map((setter) => `'${setter}'`).join(' | ')}, (handler: () => void) => void>): void {`,
  ...SETTERS.map((setter) => `  app.${setter}(() => undefined);`),
  '}',
  '',
].join('\n');

const ALLOWED: LintCase[] = ['apps/api/src/server.ts', 'apps/api/src/contract.ts'].map((filePath) => ({
  name: `every setter in ${filePath}`,
  filePath,
  code: callsAll,
  rule: 'no-restricted-properties',
  realConfig: true,
}));

proveLintRules(REJECTED, ALLOWED);

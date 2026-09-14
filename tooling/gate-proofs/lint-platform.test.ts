// Gate proof for the platform rules (Rule Book §4, §5; SEC-WEB-05, SEC-PTR-07,
// SEC-EVD-06): settings are read only through the checked config; outbound
// requests go only through the allowlisted client; TLS certificate checks stay
// on; and a reason code can't be forced past the registry. Each snippet breaks
// one rule and the real eslint.config.js must report it; each "allowed"
// snippet must pass that rule. The logging rules are in lint-output.test.ts.
import { API, CONFIG, CONSOLE, CORE, type LintCase, OUTBOUND, PLATFORM, proveLintRules } from './lint-harness.ts';

const REJECTED: LintCase[] = [
  {
    name: 'Math.random in the config module, whose block repeats the list',
    filePath: `${CONFIG}/random.ts`,
    code: 'export const roll = Math.random();\n',
    rule: 'no-restricted-properties',
    says: 'Math.random',
  },

  // Rule Book §4, §5: settings are read only through the checked config.
  ...[
    ['process.env outside the config module', PLATFORM, 'export const level = process.env.LOG_LEVEL;\n'],
    ['process.env in core', CORE, 'export const level = process.env.LOG_LEVEL;\n'],
    ['process.env destructured', PLATFORM, 'const { env } = process;\nexport const level = env.LOG_LEVEL;\n'],
    [
      'process.env written, e.g. to turn TLS checks off',
      API,
      "export function relax(): void {\n  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n}\n",
    ],
  ].map(([what, folder, code]) => ({
    name: String(what),
    filePath: `${String(folder)}/env-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: 'no-restricted-properties',
    says: 'loadConfig',
  })),
  ...[
    ['process.env through globalThis', API, "globalThis.process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"],
    ['process.env through global', PLATFORM, 'export const level = global.process.env.LOG_LEVEL;\n'],
  ].map(([what, folder, code]) => ({
    name: String(what),
    filePath: `${String(folder)}/env-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: 'no-restricted-syntax',
    says: 'loadConfig',
  })),
  ...[
    ['env imported from node:process', "import { env } from 'node:process';\nexport const level = env.LOG_LEVEL;\n"],
    ['env imported from process', "import { env } from 'process';\nexport const level = env.LOG_LEVEL;\n"],
    ['node:process imported by name', "import proc from 'node:process';\nexport const level = proc.env.LOG_LEVEL;\n"],
    [
      'node:process imported whole',
      "import * as proc from 'node:process';\nexport const level = proc.env.LOG_LEVEL;\n",
    ],
  ].map(([what, code]) => ({
    name: String(what),
    filePath: `${PLATFORM}/env-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: 'no-restricted-imports',
    says: 'loadConfig',
  })),

  // SEC-WEB-05: outbound requests go through the allowlisted client.
  ...[
    ['fetch in platform code', PLATFORM, 'export const get = (url: string): Promise<Response> => fetch(url);\n'],
    ['fetch in core', CORE, 'export const get = (url: string): Promise<Response> => fetch(url);\n'],
    ['fetch in an app', API, 'export const get = (url: string): Promise<Response> => fetch(url);\n'],
    ['fetch in a test file', PLATFORM, 'export const get = (url: string): Promise<Response> => fetch(url);\n', '.test'],
    ['globalThis.fetch', PLATFORM, 'export const get = (url: string): Promise<Response> => globalThis.fetch(url);\n'],
    ['global.fetch', PLATFORM, 'export const get = (url: string): Promise<Response> => global.fetch(url);\n'],
    ['a WebSocket', API, 'export const open = (url: string): WebSocket => new WebSocket(url);\n'],
  ].map(([what, folder, code, suffix]) => ({
    name: String(what),
    filePath: `${String(folder)}/net-${String(what).replace(/\W/g, '')}${suffix ?? ''}.ts`,
    code: String(code),
    rule: 'no-restricted-globals',
    says: 'SEC-WEB-05',
  })),
  ...[
    ['fetch destructured from globalThis', 'const { fetch: send } = globalThis;\nexport const get = send;\n'],
    ['WebSocket destructured from global', 'const { WebSocket: Socket } = global;\nexport const open = Socket;\n'],
  ].map(([what, code]) => ({
    name: String(what),
    filePath: `${PLATFORM}/net-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: 'no-restricted-syntax',
    says: 'SEC-WEB-05',
  })),

  // SEC-PTR-07: TLS certificate checks stay on.
  ...[
    ['rejectUnauthorized: false', PLATFORM, 'export const options = { rejectUnauthorized: false };\n'],
    ['rejectUnauthorized: false in core', CORE, 'export const options = { rejectUnauthorized: false };\n'],
    [
      'rejectUnauthorized set from a variable',
      PLATFORM,
      'export const options = (strict: boolean) => ({ rejectUnauthorized: strict });\n',
    ],
    ['rejectUnauthorized as a quoted key', PLATFORM, "export const options = { 'rejectUnauthorized': false };\n"],
    [
      'rejectUnauthorized assigned',
      PLATFORM,
      'export function relax(agent: { options: { rejectUnauthorized?: boolean } }): void {\n' +
        '  agent.options.rejectUnauthorized = false;\n}\n',
    ],
    [
      'rejectUnauthorized assigned by a quoted key',
      PLATFORM,
      "export function relax(options: Record<string, unknown>): void {\n  options['rejectUnauthorized'] = false;\n}\n",
    ],
    ['rejectUnauthorized as a class field', PLATFORM, 'export class Options {\n  rejectUnauthorized = false;\n}\n'],
    [
      'a custom checkServerIdentity',
      PLATFORM,
      'export const options = { checkServerIdentity: (): undefined => undefined };\n',
    ],
    [
      'checkServerIdentity as a quoted key',
      PLATFORM,
      "export const options = { 'checkServerIdentity': (): undefined => undefined };\n",
    ],
    [
      'checkServerIdentity assigned',
      PLATFORM,
      'export function relax(options: { checkServerIdentity?: () => undefined }): void {\n' +
        '  options.checkServerIdentity = () => undefined;\n}\n',
    ],
    [
      'checkServerIdentity assigned by a quoted key',
      PLATFORM,
      'export function relax(options: Record<string, unknown>): void {\n' +
        "  options['checkServerIdentity'] = () => undefined;\n}\n",
    ],
    [
      'checkServerIdentity as a class field',
      PLATFORM,
      'export class Options {\n  checkServerIdentity = (): undefined => undefined;\n}\n',
    ],
  ].map(([what, folder, code]) => ({
    name: String(what),
    filePath: `${String(folder)}/tls-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: 'no-restricted-syntax',
    says: 'SEC-PTR-07',
  })),

  // SEC-EVD-06: a reason code can't be forced past the registry.
  ...[
    ['as ReasonCode', CORE, "const raw: string = 'MADE_UP';\nexport const code = raw as ReasonCode;\n"],
    [
      'as ReasonCode in platform code',
      PLATFORM,
      "const raw: string = 'MADE_UP';\nexport const code = raw as ReasonCode;\n",
    ],
    ['as unknown as ReasonCode', CORE, 'export const code = 1 as unknown as ReasonCode;\n'],
    ['as ReasonCode[] (a list)', CORE, 'const raw: string[] = [];\nexport const codes = raw as ReasonCode[];\n'],
    [
      'as readonly ReasonCode[]',
      CORE,
      'const raw: string[] = [];\nexport const codes = raw as readonly ReasonCode[];\n',
    ],
    ['<ReasonCode>', CORE, "const raw: string = 'MADE_UP';\nexport const code = <ReasonCode>raw;\n"],
    [
      'as keyof typeof REASON_CODES',
      CORE,
      "const REASON_CODES = { ORG_FROZEN: 'Frozen.' } as const;\n" +
        "const raw: string = 'MADE_UP';\nexport const code = raw as keyof typeof REASON_CODES;\n",
    ],
  ].map(([what, folder, code]) => ({
    name: `a reason code forced with ${String(what)}`,
    filePath: `${String(folder)}/reason-${String(what).replace(/\W/g, '')}.ts`,
    code: `export type ReasonCode = 'ORG_FROZEN';\n${String(code)}`,
    rule: 'no-restricted-syntax',
    says: 'SEC-EVD-06',
  })),
];

const ALLOWED: LintCase[] = [
  {
    name: 'process.env in the config module',
    filePath: `${CONFIG}/read.ts`,
    code: 'export const read = (): NodeJS.ProcessEnv => process.env;\n',
    rule: 'no-restricted-properties',
  },
  {
    name: 'env imported in the config module',
    filePath: `${CONFIG}/import.ts`,
    code: "import { env } from 'node:process';\nexport const read = (): NodeJS.ProcessEnv => env;\n",
    rule: 'no-restricted-imports',
  },
  {
    name: 'fetch in the outbound client',
    filePath: `${OUTBOUND}/send.ts`,
    code: 'export const send = (url: URL): Promise<Response> => fetch(url);\n',
    rule: 'no-restricted-globals',
  },
  {
    name: 'fetch in the console, which calls its own origin',
    filePath: `${CONSOLE}/api.ts`,
    code: "export const load = (): Promise<Response> => fetch('/v1/requests');\n",
    rule: 'no-restricted-globals',
  },
  {
    name: 'a Response built from a value (no network)',
    filePath: `${PLATFORM}/response.ts`,
    code: "export const ok = (): Response => new Response('ok');\n",
    rule: 'no-restricted-globals',
  },
  {
    name: 'globalThis used for something other than the network or the environment',
    filePath: `${PLATFORM}/global-this.ts`,
    code: 'const { structuredClone: copy } = globalThis;\nexport const clone = <T>(value: T): T => copy(value);\n',
    rule: 'no-restricted-syntax',
  },
  ...[
    ['rejectUnauthorized: true', 'export const options = { rejectUnauthorized: true };\n'],
    [
      'rejectUnauthorized read',
      'export const strict = (options: { rejectUnauthorized?: boolean }): boolean => options.rejectUnauthorized !== false;\n',
    ],
    [
      'rejectUnauthorized destructured',
      'export const strict = ({ rejectUnauthorized }: { rejectUnauthorized?: boolean }): boolean =>\n' +
        '  rejectUnauthorized !== false;\n',
    ],
  ].map(([what, code]) => ({
    name: String(what),
    filePath: `${PLATFORM}/tls-${String(what).replace(/\W/g, '')}.ts`,
    code: String(code),
    rule: 'no-restricted-syntax',
    says: 'SEC-PTR-07',
  })),
  ...[
    ['annotated with ReasonCode', "export const code: ReasonCode = 'ORG_FROZEN';\n"],
    ['checked with satisfies ReasonCode', "export const code = 'ORG_FROZEN' satisfies ReasonCode;\n"],
    [
      'checked with satisfies inside an as const list',
      "export const codes = [{ code: 'ORG_FROZEN' satisfies ReasonCode }] as const;\n",
    ],
    [
      'used as a parameter type inside an as const object',
      'export const labels = { show: (code: ReasonCode): string => code } as const;\n',
    ],
    ['used as the key of a Record', 'export const counts = {} as Partial<Record<ReasonCode, number>>;\n'],
  ].map(([what, code]) => ({
    name: `a reason code ${String(what)}`,
    filePath: `${CORE}/reason-${String(what).replace(/\W/g, '')}.ts`,
    code: `type ReasonCode = 'ORG_FROZEN';\n${String(code)}`,
    rule: 'no-restricted-syntax',
    says: 'SEC-EVD-06',
  })),
];

proveLintRules(REJECTED, ALLOWED);

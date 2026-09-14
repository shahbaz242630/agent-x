// Gate proof for the logging rules (Rule Book §8, ADR-013, SEC-DATA-03): logs
// leave only through the redacting logger, so product code can't write to
// stdout or stderr another way; pino writes only to stdout; nothing listens on
// diagnostics channels; and modules are loaded only by a fixed name, so the
// boundary check sees every one. Each snippet breaks one rule and the real
// eslint.config.js must report it; each "allowed" snippet must pass that rule.
import { API, CONFIG, CORE, type LintCase, PLATFORM, proveLintRules } from './lint-harness.ts';

const file = (folder: string, what: string): string => `${folder}/out-${what.replace(/\W/g, '')}.ts`;

const REJECTED: LintCase[] = [
  ...[
    ['process.stdout in platform code', PLATFORM, "export const say = (): boolean => process.stdout.write('x');\n"],
    ['process.stderr in core', CORE, "export const say = (): boolean => process.stderr.write('x');\n"],
    ['process.stdout destructured', API, 'const { stdout } = process;\nexport const out = stdout;\n'],
    ['process.stdout in the config module', CONFIG, "export const say = (): boolean => process.stdout.write('x');\n"],
    [
      'process._rawDebug',
      PLATFORM,
      "export const say = (): unknown => Reflect.apply(process._rawDebug, process, ['x']);\n",
    ],
    ['process.report', PLATFORM, 'export const report = (): unknown => process.report.getReport();\n'],
    [
      'process.report in the config module',
      CONFIG,
      'export const report = (): unknown => process.report.getReport();\n',
    ],
  ].map(([what, folder, code]) => ({
    name: String(what),
    filePath: file(String(folder), String(what)),
    code: String(code),
    rule: 'no-restricted-properties',
    says: 'ADR-013',
  })),
  ...[
    [
      'process.stdout through globalThis',
      API,
      "export const say = (): boolean => globalThis.process.stdout.write('x');\n",
    ],
    [
      'process.stderr through global',
      PLATFORM,
      "export const say = (): boolean => global.process.stderr.write('x');\n",
    ],
    ['console through globalThis', PLATFORM, "export const say = (): void => {\n  globalThis.console.log('x');\n};\n"],
    [
      'writeSync to descriptor 1',
      PLATFORM,
      "import fs from 'node:fs';\nexport const say = (): number => fs.writeSync(1, 'x');\n",
    ],
    [
      'writeSync to descriptor 2, imported by name',
      CORE,
      "import { writeSync } from 'node:fs';\nexport const say = (): number => writeSync(2, 'x');\n",
    ],
    [
      'a write stream on descriptor 2',
      API,
      "import { createWriteStream } from 'node:fs';\nexport const out = createWriteStream('', { fd: 2 });\n",
    ],
    [
      'a write to /dev/stdout',
      PLATFORM,
      "import { writeFileSync } from 'node:fs';\nexport const say = (): void => {\n  writeFileSync('/dev/stdout', 'x');\n};\n",
    ],
  ].map(([what, folder, code]) => ({
    name: String(what),
    filePath: file(String(folder), String(what)),
    code: String(code),
    rule: 'no-restricted-syntax',
    says: 'ADR-013',
  })),
  ...[
    [
      'a pino transport',
      "import pino from 'pino';\nexport const log = pino({ transport: { target: 'pino-socket' } });\n",
    ],
    ['pino.transport', "import pino from 'pino';\nexport const out = pino.transport({ target: 'pino-socket' });\n"],
    ['pino.multistream', "import pino from 'pino';\nexport const out = pino.multistream([]);\n"],
  ].map(([what, code]) => ({
    name: String(what),
    filePath: file(PLATFORM, String(what)),
    code: String(code),
    rule: 'no-restricted-syntax',
    says: 'pino writes only to stdout',
  })),
  {
    name: 'an import by a computed name',
    filePath: file(PLATFORM, 'an import by a computed name'),
    code: 'export const load = async (name: string): Promise<unknown> => import(`@vendor/${name}`);\n',
    rule: 'no-restricted-syntax',
    says: 'fixed name',
  },
  ...[
    [
      'console imported from node:console',
      PLATFORM,
      "import console from 'node:console';\nexport const say = (): void => {\n  console.info('x');\n};\n",
      'ADR-013',
    ],
    [
      'console imported in the config module',
      CONFIG,
      "import { Console } from 'console';\nexport const make = Console;\n",
      'ADR-013',
    ],
    [
      'stdout imported from node:process in the config module',
      CONFIG,
      "import { stdout } from 'node:process';\nexport const out = stdout;\n",
      'ADR-013',
    ],
    [
      'stderr imported from process in the config module',
      CONFIG,
      "import { stderr } from 'process';\nexport const out = stderr;\n",
      'ADR-013',
    ],
    [
      'the diagnostics channel imported',
      PLATFORM,
      "import { channel } from 'node:diagnostics_channel';\nexport const lines = channel('pino_asJson');\n",
      'diagnostics channels',
    ],
    [
      'createRequire imported',
      API,
      "import { createRequire } from 'node:module';\nexport const load = createRequire(import.meta.url);\n",
      'fixed name',
    ],
  ].map(([what, folder, code, says]) => ({
    name: String(what),
    filePath: file(String(folder), String(what)),
    code: String(code),
    rule: 'no-restricted-imports',
    says: String(says),
  })),
];

const ALLOWED: LintCase[] = [
  {
    name: 'the process used for something other than its output streams',
    filePath: file(PLATFORM, 'exit code'),
    code: 'export function fail(): void {\n  process.exitCode = 1;\n}\n',
    rule: 'no-restricted-properties',
    says: 'ADR-013',
  },
  {
    name: 'a write to a file descriptor held in a variable',
    filePath: file(PLATFORM, 'descriptor in a variable'),
    code: "import { writeSync } from 'node:fs';\nexport const save = (fd: number): number => writeSync(fd, 'x');\n",
    rule: 'no-restricted-syntax',
    says: 'ADR-013',
  },
  {
    name: 'pino writing to descriptor 1 through its destination',
    filePath: file(PLATFORM, 'pino destination'),
    code: "import pino from 'pino';\nexport const out = pino.destination({ dest: 1, sync: true });\n",
    rule: 'no-restricted-syntax',
    says: 'ADR-013',
  },
  {
    name: 'an import by a fixed name',
    filePath: file(PLATFORM, 'fixed import'),
    code: "export const load = async (): Promise<unknown> => import('node:crypto');\n",
    rule: 'no-restricted-syntax',
    says: 'fixed name',
  },
  {
    name: 'node:module used for something other than createRequire',
    filePath: file(PLATFORM, 'builtin modules'),
    code: "import { builtinModules } from 'node:module';\nexport const names = builtinModules;\n",
    rule: 'no-restricted-imports',
    says: 'fixed name',
  },
];

proveLintRules(REJECTED, ALLOWED);

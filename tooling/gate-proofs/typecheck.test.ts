// Gate proof for the strict TypeScript settings (Rule Book §5): each snippet
// breaks one compiler setting from tsconfig.base.json, and the compiler, run
// with the root tsconfig.json, must report exactly that setting's error.
import path from 'node:path';

import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

const ROOT = process.cwd();
const DIR = 'packages/core/src/gate-proof';

/** Snippet file(s) → the one error code the setting must produce in the first file. */
const CASES: { setting: string; files: Record<string, string>; code: number | null }[] = [
  {
    setting: 'noUncheckedIndexedAccess',
    files: { 'indexed.ts': 'const amounts: number[] = [1];\nexport const first: number = amounts[0];\n' },
    code: 2322,
  },
  {
    setting: 'exactOptionalPropertyTypes',
    files: {
      'optional.ts':
        'interface Options {\n  label?: string;\n}\nexport const options: Options = { label: undefined };\n',
    },
    code: 2375,
  },
  {
    setting: 'strict (noImplicitAny)',
    files: { 'implicit-any.ts': 'export function echo(value) {\n  return value;\n}\n' },
    code: 7006,
  },
  {
    setting: 'strict (strictNullChecks)',
    files: { 'null.ts': 'export const name: string = null;\n' },
    code: 2322,
  },
  {
    setting: 'strict (useUnknownInCatchVariables)',
    files: {
      'catch.ts':
        "export function read(): string {\n  try {\n    return '';\n  } catch (error) {\n    return error.message;\n  }\n}\n",
    },
    code: 18046,
  },
  {
    setting: 'noImplicitOverride',
    files: {
      'override.ts': 'class Base {\n  run(): void {}\n}\nexport class Child extends Base {\n  run(): void {}\n}\n',
    },
    code: 4114,
  },
  {
    setting: 'noImplicitReturns',
    files: {
      'returns.ts': 'export function pick(flag: boolean): number | undefined {\n  if (flag) {\n    return 1;\n  }\n}\n',
    },
    code: 7030,
  },
  {
    setting: 'noFallthroughCasesInSwitch',
    files: {
      'fallthrough.ts':
        'export function band(level: number): string {\n  let band = "";\n  switch (level) {\n' +
        '    case 1:\n      band = "low";\n    case 2:\n      band = "high";\n      break;\n  }\n  return band;\n}\n',
    },
    code: 7029,
  },
  {
    setting: 'allowUnreachableCode: false',
    files: { 'unreachable.ts': 'export function total(): number {\n  return 1;\n  total();\n}\n' },
    code: 7027,
  },
  {
    setting: 'allowUnusedLabels: false',
    files: { 'label.ts': 'export function spin(): void {\n  unused: for (;;) {\n    break;\n  }\n}\n' },
    code: 7028,
  },
  {
    setting: 'erasableSyntaxOnly (no enums)',
    files: { 'enum.ts': 'export enum Colour {\n  Red,\n}\n' },
    code: 1294,
  },
  {
    setting: 'verbatimModuleSyntax (type imports are marked)',
    files: {
      'uses-shape.ts': "import { Shape } from './shape.ts';\nexport const square: Shape = { sides: 4 };\n",
      'shape.ts': 'export interface Shape {\n  sides: number;\n}\n',
    },
    code: 1484,
  },
  {
    setting: 'none: well-typed code compiles cleanly',
    files: { 'clean.ts': 'export const double = (value: number): number => value * 2;\n' },
    code: null,
  },
];

const toKey = (fileName: string): string => path.resolve(fileName).replaceAll('\\', '/');
const virtualPath = (name: string): string => toKey(path.join(ROOT, DIR, name));

let codesByFile: Map<string, number[]>;

beforeAll(() => {
  const parsed = ts.getParsedCommandLineOfConfigFile(path.join(ROOT, 'tsconfig.json'), undefined, {
    ...ts.sys,
    onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
      throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'));
    },
  });
  if (!parsed) throw new Error('tsconfig.json could not be read');

  const virtual = new Map(
    CASES.flatMap(({ files }) => Object.entries(files)).map(([name, text]) => [virtualPath(name), text]),
  );
  const host = ts.createCompilerHost(parsed.options);
  const readFromDisk = host.getSourceFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreate) => {
    const text = virtual.get(toKey(fileName));
    return text === undefined
      ? readFromDisk(fileName, languageVersion, onError, shouldCreate)
      : ts.createSourceFile(fileName, text, languageVersion);
  };
  const fileExistsOnDisk = host.fileExists.bind(host);
  host.fileExists = (fileName) => virtual.has(toKey(fileName)) || fileExistsOnDisk(fileName);
  const readFromDiskText = host.readFile.bind(host);
  host.readFile = (fileName) => virtual.get(toKey(fileName)) ?? readFromDiskText(fileName);
  // Module resolution checks the snippets' folder exists before looking inside it.
  const virtualDir = toKey(path.join(ROOT, DIR));
  const directoryExistsOnDisk = host.directoryExists?.bind(host);
  host.directoryExists = (directory) =>
    toKey(directory) === virtualDir || (directoryExistsOnDisk?.(directory) ?? ts.sys.directoryExists(directory));

  const program = ts.createProgram([...virtual.keys()], parsed.options, host);
  codesByFile = new Map();
  for (const diagnostic of ts.getPreEmitDiagnostics(program)) {
    const key = diagnostic.file ? toKey(diagnostic.file.fileName) : '(global)';
    codesByFile.set(key, [...(codesByFile.get(key) ?? []), diagnostic.code]);
  }
});

describe('typecheck: every strict setting rejects its broken snippet', () => {
  it('reports nothing outside the snippets', () => {
    const outside = [...codesByFile.keys()].filter((key) => !key.includes(`/${DIR}/`));
    expect(outside).toEqual([]);
  });

  it.each(CASES.map((testCase) => [testCase.setting, testCase] as const))('%s', (_setting, { files, code }) => {
    const [firstFile] = Object.keys(files);
    expect(codesByFile.get(virtualPath(firstFile ?? '')) ?? []).toEqual(code === null ? [] : [code]);
  });
});

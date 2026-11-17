// The type check in parts (S201): one tsc program for the whole repository grew past Node's 4 GB heap on CI's
// runner, so `pnpm typecheck` runs one program per part, each with room to grow (tsconfig.check-*.json). The whole
// program, tsconfig.json, stays as editors read it. This holds the parts to it: together they check every file it
// checks, each in one part alone, so no file is ever silently dropped from the type check.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

/** The test database's vitest context (inject): every part with tests against Postgres takes it beside its own. */
const SHARED = path.resolve('tooling/test-db/global-setup.ts');

/** The root files a tsconfig names, as tsc reads it. */
function rootFiles(config: string): string[] {
  const parsed = ts.getParsedCommandLineOfConfigFile(
    path.resolve(config),
    {},
    {
      ...ts.sys,
      onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
        throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'));
      },
    },
  );
  if (parsed === undefined) throw new Error(`${config} could not be read`);
  return parsed.fileNames.map((file) => path.resolve(file));
}

const PARTS = readdirSync('.')
  .filter((name) => /^tsconfig\.check-[a-z-]+\.json$/.test(name))
  .sort();

describe('the type check in parts covers the whole program, each file once', () => {
  it('runs every part, then the console, in the typecheck script', () => {
    const scripts = (JSON.parse(readFileSync('package.json', 'utf8')) as { scripts: Record<string, string> }).scripts;
    expect(PARTS.length).toBeGreaterThan(1);
    const run = scripts.typecheck?.split(' && ') ?? [];
    expect([...run].sort()).toEqual(
      [...PARTS.map((part) => `tsc --project ${part}`), 'tsc --project apps/console/tsconfig.json'].sort(),
    );
  });

  it('checks every file of tsconfig.json in exactly one part, and nothing it doesn’t', () => {
    const whole = new Set(rootFiles('tsconfig.json'));
    const seen = new Map<string, string[]>();
    for (const part of PARTS) {
      for (const file of rootFiles(part)) seen.set(file, [...(seen.get(file) ?? []), part]);
    }
    expect([...whole].filter((file) => !seen.has(file))).toEqual([]);
    expect([...seen.keys()].filter((file) => !whole.has(file))).toEqual([]);
    const twice = [...seen].filter(([file, parts]) => parts.length > 1 && file !== SHARED);
    expect(twice).toEqual([]);
  });
});

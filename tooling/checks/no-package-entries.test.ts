// Some CI jobs run our scripts on the runner's own Node with nothing installed
// (the release to staging, image signing and pruning, the DAST scan): they can
// sign or reach Azure, so they take no same-day package. A script there that
// reaches a package, even through a file it imports, crashes the job: S176's
// release failed so when deploy.ts came to load the database package through
// tooling/load/throwaway.ts. This walks every such script's imports and holds
// them to Node's own modules and our files.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

interface Step {
  run?: string;
}
interface Workflow {
  jobs: Record<string, { steps?: Step[] }>;
}

const WORKFLOWS = '.github/workflows';
const SCRIPT = /\bnode\s+([\w./-]+\.(?:ts|mjs|js))\b/g;
/**
 * Imports that load a module when run (`import type` and `export type` are
 * erased first): static ones, a bare `import '…'`, and `import('…')` of a literal.
 */
const LOADING_IMPORT =
  /^\s*(?:import|export)\s+(?!type\b)[^'"]*?\bfrom\s+['"]([^'"]+)['"]|^\s*import\s+['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/gm;

/**
 * Scripts run by `node` before any package is installed in their job, as
 * `workflow job`: a step after `pnpm install` has packages, one before it doesn't.
 */
function scriptsRunWithoutPackages(): Map<string, string> {
  const scripts = new Map<string, string>();
  for (const file of readdirSync(WORKFLOWS).filter((name) => name.endsWith('.yml'))) {
    const workflow = parse(readFileSync(path.join(WORKFLOWS, file), 'utf8')) as Workflow;
    for (const [job, { steps = [] }] of Object.entries(workflow.jobs)) {
      for (const { run = '' } of steps) {
        if (/\bpnpm\s+install\b/.test(run)) break;
        for (const match of run.matchAll(SCRIPT)) scripts.set(match[1] ?? '', `${file} ${job}`);
      }
    }
  }
  return scripts;
}

/** Every package the file reaches through the imports that load, with the file importing it. */
function packagesReached(entry: string): string[] {
  const seen = new Set<string>();
  const reached: string[] = [];
  const walk = (file: string): void => {
    if (seen.has(file)) return;
    seen.add(file);
    if (!existsSync(file)) {
      reached.push(`${file} (missing)`);
      return;
    }
    for (const match of readFileSync(file, 'utf8').matchAll(LOADING_IMPORT)) {
      const specifier = match[1] ?? match[2] ?? match[3] ?? '';
      if (specifier.startsWith('.')) walk(path.join(path.dirname(file), specifier).replaceAll('\\', '/'));
      else if (!specifier.startsWith('node:')) reached.push(`${specifier} (from ${file})`);
    }
  };
  walk(entry);
  return reached;
}

describe('scripts CI runs with no packages installed', () => {
  const scripts = scriptsRunWithoutPackages();

  it('finds the release and the other such jobs', () => {
    expect([...scripts.keys()]).toEqual(
      expect.arrayContaining([
        'deploy/azure/release.ts',
        'deploy/image/verify.ts',
        'tooling/dast/scan.ts',
        'tooling/places/pin.ts',
      ]),
    );
  });

  it.each([...scripts])('%s (%s) reaches no package', (script) => {
    expect(packagesReached(script)).toEqual([]);
  });

  it('would catch a package reached through another file', () => {
    expect(packagesReached('tooling/load/throwaway-sentinel.ts')).toContain(
      'kysely (from packages/platform/src/db/database.ts)',
    );
  });
});

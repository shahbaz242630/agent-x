// CI-05: the verify gate stays wired up. Each check runs with exactly the
// command reviewed here, CI runs every check with nothing allowed to fail or be
// skipped, the local `pnpm verify` runs the same commands, and the boundary
// check covers every workspace folder that exists. Changing any of this means
// changing this test, in a reviewed PR.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

/** Each check and the exact command it runs. */
const CHECKS = {
  'format:check': 'prettier --check .',
  lint: 'eslint --max-warnings 0 .',
  typecheck: 'tsc --project tsconfig.json',
  boundaries: `depcruise ${['apps', 'packages'].filter((folder) => existsSync(folder)).join(' ')}`,
  knip: 'knip',
  'test:coverage': 'vitest run --coverage',
} as const;

type Step = Record<string, unknown> & { run?: string };
type Job = Record<string, unknown> & { name?: string; steps?: Step[] };

const scripts = (JSON.parse(readFileSync('package.json', 'utf8')) as { scripts: Record<string, string> }).scripts;
const verifyJob = (parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as { jobs: Record<string, Job> }).jobs
  .verify;

/** The only other root scripts: conveniences that CI never runs. */
const OTHER_SCRIPTS = { format: 'prettier --write .', test: 'vitest run', verify: Object.values(CHECKS).join(' && ') };

/** Scripts pnpm runs by itself during an install. */
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack'];

describe('CI-05 verify gate', () => {
  it.each(Object.entries(CHECKS))('runs %s as reviewed', (check, command) => {
    expect(scripts[check]).toBe(command);
  });

  it('has no root script beyond the reviewed ones', () => {
    expect(scripts).toEqual({ ...CHECKS, ...OTHER_SCRIPTS });
  });

  it('gives no workspace package a script that runs on install', () => {
    const packageFolders = readdirSync('packages', { withFileTypes: true }).filter((entry) => entry.isDirectory());
    const installScripts = packageFolders.flatMap((folder) => {
      const manifest = path.join('packages', folder.name, 'package.json');
      if (!existsSync(manifest)) return [];
      const packageScripts = (JSON.parse(readFileSync(manifest, 'utf8')) as { scripts?: Record<string, string> })
        .scripts;
      return Object.keys(packageScripts ?? {})
        .filter((name) => INSTALL_SCRIPTS.includes(name))
        .map((name) => `${manifest}: ${name}`);
    });
    expect(installScripts).toEqual([]);
  });

  it('runs every check in the CI "Verify" job', () => {
    expect(verifyJob?.name).toBe('Verify');
    const runs = (verifyJob?.steps ?? []).map((step) => step.run);
    expect(runs).toEqual(expect.arrayContaining(Object.keys(CHECKS).map((check) => `pnpm ${check}`)));
  });

  it('lets no Verify step, or the job, be skipped or allowed to fail', () => {
    const escapes = [verifyJob ?? {}, ...(verifyJob?.steps ?? [])].filter(
      (entry) => 'if' in entry || 'continue-on-error' in entry,
    );
    expect(escapes).toEqual([]);
  });
});

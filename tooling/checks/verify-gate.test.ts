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
const ciJobs = (parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as { jobs: Record<string, Job> }).jobs;
const verifyJob = ciJobs.verify;
const endToEndJob = ciJobs['end-to-end'];

/** The end-to-end suite (ADR-010 §7), run by its own CI job against the compose stack. */
const END_TO_END = { e2e: 'vitest run --config vitest.e2e.config.ts' } as const;

/** The only other root scripts: conveniences that CI never runs. */
const OTHER_SCRIPTS = { format: 'prettier --write .', test: 'vitest run', verify: Object.values(CHECKS).join(' && ') };

/** Scripts pnpm runs by itself during an install. */
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack'];

describe('CI-05 verify gate', () => {
  it.each(Object.entries(CHECKS))('runs %s as reviewed', (check, command) => {
    expect(scripts[check]).toBe(command);
  });

  it('has no root script beyond the reviewed ones', () => {
    expect(scripts).toEqual({ ...CHECKS, ...END_TO_END, ...OTHER_SCRIPTS });
  });

  it('runs the end-to-end suite, as reviewed, in the CI "End to end" job, which nothing may skip', () => {
    expect(scripts.e2e).toBe(END_TO_END.e2e);
    expect(endToEndJob?.name).toBe('End to end');
    expect((endToEndJob?.steps ?? []).map((step) => step.run)).toContain('pnpm e2e');
    const escapes = [endToEndJob ?? {}, ...(endToEndJob?.steps ?? [])]
      .filter((entry) => 'if' in entry || 'continue-on-error' in entry)
      .map((entry) => ('name' in entry ? String(entry.name) : 'job'));
    // Only the two clean-up steps may run on failure; nothing may be allowed to fail.
    expect(escapes).toEqual(['Stack logs (only when something failed)', 'Stop the stack']);
  });

  it('gives no workspace package or app a script that runs on install', () => {
    const folders = ['apps', 'packages']
      .filter((parent) => existsSync(parent))
      .flatMap((parent) =>
        readdirSync(parent, { withFileTypes: true })
          .filter((entry) => entry.isDirectory())
          .map((entry) => path.join(parent, entry.name)),
      );
    expect(folders).toEqual(expect.arrayContaining([path.join('apps', 'api'), path.join('packages', 'platform')]));
    const installScripts = folders.flatMap((folder) => {
      const manifest = path.join(folder, 'package.json');
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

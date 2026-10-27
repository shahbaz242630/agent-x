// CI-05: the verify gate stays wired up. Each check runs with exactly the
// command reviewed here, CI runs every check with nothing allowed to fail or be
// skipped, the local `pnpm verify` runs the same commands, and the boundary
// check covers every workspace folder that exists. Changing any of this means
// changing this test, in a reviewed PR.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import config from '../../vitest.config.ts';
import { POSTGRES_IMAGES } from '../test-db/postgres-images.ts';

/** Each check and the exact command it runs. */
const CHECKS = {
  'format:check': 'prettier --check .',
  // ESLint once with the repository's rules and SonarJS's, failing on every finding but SonarJS's not yet blocking (#222);
  // with a 6 GB heap: the whole repository in one process passed Node's 4 GB default on CI's runner (S141, #453).
  lint: 'node --max-old-space-size=6144 tooling/quality/lint.ts',
  // The server's code against Node alone, then the console's against the browser's (Phase 6 6A1: DOM and JSX).
  typecheck: 'tsc --project tsconfig.json && tsc --project apps/console/tsconfig.json',
  boundaries: `depcruise ${['apps', 'packages'].filter((folder) => existsSync(folder)).join(' ')}`,
  knip: 'knip',
  'test:coverage': 'vitest run --coverage',
} as const;

type Step = Record<string, unknown> & { run?: string };
type Job = Record<string, unknown> & { name?: string; steps?: Step[] };

const scripts = (JSON.parse(readFileSync('package.json', 'utf8')) as { scripts: Record<string, string> }).scripts;
const workflow = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as {
  env?: Record<string, string>;
  jobs: Record<string, Job>;
};
const ciJobs = workflow.jobs;

/** The part step's command, exactly: the projects, both reporters and the blob's own file. */
const PART_RUN =
  'pnpm test:coverage ${PROJECTS} --reporter=default --reporter=blob --outputFile.blob=".vitest-reports/blob-${VITEST_PART}.json"';
const verifyJob = ciJobs.verify;
/** The suite's parts at once (Phase 3 debt), whose reports Verify merges. */
const partsJob = ciJobs['verify-tests'];
const endToEndJob = ciJobs['end-to-end'];

/** The end-to-end suite (ADR-010 §7), run by its own CI job against the compose stack. */
const END_TO_END = { e2e: 'vitest run --config vitest.e2e.config.ts' } as const;

/**
 * The only other root scripts: conveniences that CI never runs, the one-time
 * git hooks set-up (Security-Handoff §7), the one-time install of the pinned
 * Bicep compiler, which Verify also runs before its tests (tooling/bicep), and
 * the one-time install of the pinned cosign on a machine that deploys, which
 * CI's release job alone also runs (tooling/cosign).
 */
const OTHER_SCRIPTS = {
  format: 'prettier --write .',
  test: 'vitest run',
  verify: Object.values(CHECKS).join(' && '),
  hooks: 'node tooling/git-hooks/install.ts',
  tools: 'node tooling/bicep/install.ts',
  'tools:cosign': 'node tooling/cosign/install.ts',
  // The copied-code check (#222): Verify runs it, failing past the threshold in .jscpd.json.
  duplicates: 'jscpd',
  // The load test of the money paths (Phase 4 D2), run by hand: it needs Docker and takes minutes.
  load: 'node tooling/load/run.ts',
};

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

  it('runs every check in the CI "Verify" job, the tests in its parts, merged there with every limit', () => {
    expect(verifyJob?.name).toBe('Verify');
    const runs = (verifyJob?.steps ?? []).map((step) => step.run);
    const { 'test:coverage': _tests, ...statics } = CHECKS;
    expect(runs).toEqual(expect.arrayContaining(Object.keys(statics).map((check) => `pnpm ${check}`)));
    expect(runs).toContain('pnpm vitest --merge-reports --coverage');
    const partRuns = (partsJob?.steps ?? []).map((step) => step.run ?? '');
    expect(partRuns.filter((run) => run.startsWith('pnpm test:coverage '))).toEqual([PART_RUN]);
    // Together the parts run every project the config makes, each once: one added is in a part or this fails.
    const projects = ((partsJob?.strategy as { matrix?: { include?: { projects: string }[] } }).matrix?.include ?? [])
      .flatMap(({ projects: flags }) => flags.split(' ').filter((flag) => flag !== '--project'))
      .sort();
    expect(projects).toEqual(['unit', 'console', 'repo-checks', ...Object.keys(POSTGRES_IMAGES)].sort());
    const configured = (config.test?.projects ?? []).map((project) =>
      typeof project === 'object' && 'test' in project ? project.test.name : undefined,
    );
    expect(configured.toSorted()).toEqual(projects);
  });

  it('checks every coverage limit on the merge: VITEST_PART reaches the parts alone', () => {
    // Read as written: this test itself runs in a part, where the limits are off.
    expect(readFileSync('vitest.config.ts', 'utf8')).toContain(
      'thresholds: process.env.VITEST_PART === undefined ? coverageThresholds : {},',
    );
    expect(workflow.env?.VITEST_PART).toBeUndefined();
    expect((verifyJob?.env as Record<string, string> | undefined)?.VITEST_PART).toBeUndefined();
    expect((partsJob?.env as Record<string, string> | undefined)?.VITEST_PART).toBe('${{ matrix.part }}');
  });

  it('lets no Verify step, or a part, be skipped or allowed to fail; Verify runs past a failed part and fails', () => {
    const escapes = [...(verifyJob?.steps ?? []), partsJob ?? {}, ...(partsJob?.steps ?? [])].filter(
      (entry) => 'if' in entry || 'continue-on-error' in entry,
    );
    expect(escapes).toEqual([]);
    expect(verifyJob?.needs).toEqual(['verify-tests']);
    expect(verifyJob?.if).toBe('${{ always() }}');
    expect('continue-on-error' in (verifyJob ?? {})).toBe(false);
    expect(verifyJob?.steps?.[0]).toMatchObject({ name: 'Every test part passed', run: 'test "${PARTS}" = success' });
    expect((verifyJob?.env as Record<string, string> | undefined)?.PARTS).toBe('${{ needs.verify-tests.result }}');
    expect((partsJob?.strategy as { 'fail-fast'?: boolean })['fail-fast']).toBe(false);
  });
});

// Gate proof for the coverage floors (Rule Book §6): Vitest runs the fixture
// project with the real thresholds, and must fail the run for a file below the
// standard floors (lines, statements, branches, functions) and for a
// money-critical file below 95% of branches, while a standard file at 90% of
// branches passes.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { MONEY_CRITICAL_GLOB } from '../coverage-thresholds.ts';

const FIXTURE = 'tooling/gate-proofs/fixtures/coverage-floors';
const VITEST = path.join('node_modules', 'vitest', 'vitest.mjs');

const reportsDirectory = mkdtempSync(path.join(tmpdir(), 'agentx-coverage-proof-'));
let run: { status: number | null; output: string };

beforeAll(() => {
  // Without GITHUB_*, the nested run can't write its own report into the CI job summary.
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GITHUB_')));
  const result = spawnSync(
    process.execPath,
    [
      VITEST,
      'run',
      '--coverage',
      '--reporter=default',
      '--root',
      FIXTURE,
      `--coverage.reportsDirectory=${reportsDirectory}`,
    ],
    { encoding: 'utf8', timeout: 90_000, env: { ...env, NO_COLOR: '1', FORCE_COLOR: '0' } },
  );
  if (result.error) throw result.error;
  run = { status: result.status, output: `${result.stdout}\n${result.stderr}` };
});

afterAll(() => {
  rmSync(reportsDirectory, { recursive: true, force: true });
});

const errorsFor = (file: string): string[] =>
  run.output.split('\n').filter((line) => line.startsWith('ERROR: Coverage') && line.endsWith(`${FIXTURE}/${file}`));

describe('coverage: files below their floor fail the run', () => {
  it('exits with a failure, although every fixture test passes', () => {
    expect(run.output).toContain('Tests  4 passed');
    expect(run.status).toBe(1);
  });

  it('fails a standard file below 90% of lines and statements and 85% of branches', () => {
    expect(errorsFor('src/half/half.ts')).toEqual([
      expect.stringContaining('lines (50%) does not meet global threshold (90%)'),
      expect.stringContaining('statements (66.66%) does not meet global threshold (90%)'),
      expect.stringContaining('branches (50%) does not meet global threshold (85%)'),
    ]);
  });

  it('fails a standard file below 90% of functions', () => {
    expect(errorsFor('src/unused-function/pair.ts')).toContainEqual(
      expect.stringContaining('functions (50%) does not meet global threshold (90%)'),
    );
  });

  it('fails a money-critical file at 90% of branches', () => {
    expect(errorsFor('packages/core/src/modules/policies/grade.ts')).toEqual([
      expect.stringContaining(`branches (90%) does not meet "${MONEY_CRITICAL_GLOB}" threshold (95%)`),
    ]);
  });

  it('passes the same file at 90% of branches outside the money-critical modules', () => {
    expect(errorsFor('src/standard/grade.ts')).toEqual([]);
  });
});

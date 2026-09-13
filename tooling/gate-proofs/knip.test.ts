// Gate proof for the dead-code check (Rule Book §5): knip, run with the
// repository's own knip.json on a small workspace shaped like ours, must
// report the fixture's unused file, unused export and unused dependency.
import { spawnSync } from 'node:child_process';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

const FIXTURE = 'tooling/gate-proofs/fixtures/knip';
const KNIP = path.join('node_modules', 'knip', 'bin', 'knip.js');

interface KnipIssue {
  file: string;
  files: { name: string }[];
  exports: { name: string }[];
  dependencies: { name: string }[];
}

let status: number | null;
let issues: KnipIssue[];

beforeAll(() => {
  const result = spawnSync(
    process.execPath,
    [
      KNIP,
      '--directory',
      FIXTURE,
      '--config',
      path.resolve('knip.json'),
      '--reporter',
      'json',
      '--no-progress',
      '--no-config-hints',
    ],
    { encoding: 'utf8', timeout: 90_000 },
  );
  if (result.error) throw result.error;
  status = result.status;
  issues = (JSON.parse(result.stdout) as { issues: KnipIssue[] }).issues;
});

const found = (kind: 'files' | 'exports' | 'dependencies'): string[] =>
  issues.flatMap((issue) => issue[kind].map((item) => `${issue.file}: ${item.name}`)).sort();

describe('knip: dead code fails the build', () => {
  it('exits with a failure', () => {
    expect(status).toBe(1);
  });

  it('reports the file nothing imports', () => {
    expect(found('files')).toEqual(['packages/demo/src/orphan.ts: packages/demo/src/orphan.ts']);
  });

  it('reports the export nothing uses', () => {
    expect(found('exports')).toEqual(['packages/demo/src/helpers.ts: neverImported']);
  });

  it('reports the dependency nothing imports', () => {
    expect(found('dependencies')).toEqual(['packages/demo/package.json: left-pad']);
  });
});

// What the deploy tools read from git (G4-3), against a throwaway repository
// made here. This machine's git settings (signing, hooks) are kept out of it:
// they are for our own repository, not a fixture.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { realCheckout, realHistory } from './git.ts';
import { decide, HAND_DEPLOYED, runningIn, type Workload, WORKLOADS } from './release.ts';

const MISSING = 'd'.repeat(40);

let dir: string;
let repository: string;
let git: (...args: readonly string[]) => string;
/** The fixture's commits, in the order they were made. */
const made = { first: '', tool: '', bicep: '', renamed: '', deleted: '', unusual: '' };

/** A file written, added and committed: the new commit. */
function commitFile(file: string, content = `${file}\n`): string {
  mkdirSync(path.dirname(path.join(repository, file)), { recursive: true });
  writeFileSync(path.join(repository, file), content);
  git('add', '--all');
  git('commit', '--quiet', '--message', file);
  return git('rev-parse', 'HEAD');
}

beforeAll(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'agentx-git-'));
  const empty = path.join(dir, 'no-config');
  writeFileSync(empty, '');
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: empty,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Fixture',
    GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
    GIT_COMMITTER_NAME: 'Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
  };
  repository = path.join(dir, 'repository');
  mkdirSync(repository);
  git = (...args) => {
    const done = spawnSync('git', args, { cwd: repository, env, encoding: 'utf8', windowsHide: true });
    if (done.status !== 0) throw new Error(`git ${args.join(' ')}: ${done.stderr}`);
    return done.stdout.trim();
  };
  git('init', '--quiet');
  made.first = commitFile('README.md');
  made.tool = commitFile('deploy/azure/release.ts');
  made.bicep = commitFile('deploy/azure/apps.bicep');
  git('mv', 'deploy/azure/apps.bicep', 'elsewhere-apps.bicep');
  git('commit', '--quiet', '--message', 'moved out of deploy/azure');
  made.renamed = git('rev-parse', 'HEAD');
  git('rm', '--quiet', 'deploy/azure/release.ts');
  git('commit', '--quiet', '--message', 'deleted');
  made.deleted = git('rev-parse', 'HEAD');
  made.unusual = commitFile('deploy/azure/modules/ré.bicep');
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('the history', () => {
  it('knows which commits are in which history, and a commit it does not have is in none', () => {
    const history = realHistory(repository);
    expect(history.isAncestor(made.first, made.unusual)).toBe(true);
    expect(history.isAncestor(made.bicep, made.bicep)).toBe(true);
    expect(history.isAncestor(made.bicep, made.first)).toBe(false);
    expect(history.isAncestor(MISSING, made.bicep)).toBe(false);
  });

  it('is an error, never an answer, when git cannot say', () => {
    // A commit to compare with that it doesn't have.
    expect(() => realHistory(repository).isAncestor(made.first, MISSING)).toThrow(
      `git couldn't compare ${made.first} and ${MISSING}`,
    );
    // A folder that isn't a repository.
    expect(() => realHistory(dir).isAncestor(made.first, made.bicep)).toThrow(`git couldn't look for ${made.first}`);
    expect(() => realHistory(dir).changedFiles(made.first, made.bicep)).toThrow(
      `git couldn't list the changes from ${made.first} to ${made.bicep}`,
    );
  });

  it('lists every file that changed: a renamed one under both names, a deleted one, an unusual name as it is', () => {
    const history = realHistory(repository);
    expect(history.changedFiles(made.first, made.bicep)).toEqual([
      'deploy/azure/apps.bicep',
      'deploy/azure/release.ts',
    ]);
    expect(history.changedFiles(made.bicep, made.bicep)).toEqual([]);
    expect(history.changedFiles(made.bicep, made.renamed)).toEqual(['deploy/azure/apps.bicep', 'elsewhere-apps.bicep']);
    expect(history.changedFiles(made.renamed, made.deleted)).toEqual(['deploy/azure/release.ts']);
    expect(history.changedFiles(made.deleted, made.unusual)).toEqual(['deploy/azure/modules/ré.bicep']);
  });
});

describe('a release, read from a real history', () => {
  const at = (release: string) => (workload: Workload) =>
    runningIn(workload, [
      {
        name: WORKLOADS[workload].container,
        image: `ghcr.io/shahbaz242630/agent-x@sha256:${'1'.repeat(64)}`,
        command: ['node'],
        args: [],
        env: [{ name: 'AGENTX_RELEASE', value: release }],
        resources: { cpu: 0.5, memory: '1Gi' },
        volumeMounts: [],
      },
    ]);
  const from = (release: string, target: string) =>
    decide(
      new Map([
        ['migrate', at(release)('migrate')],
        ['api', at(release)('api')],
      ]),
      target,
      `ghcr.io/shahbaz242630/agent-x@sha256:${'2'.repeat(64)}`,
      realHistory(repository),
    );
  const azure = HAND_DEPLOYED[0]?.why ?? '';

  it('goes ahead when only a tool changed, and stops for the Bicep, however it left', () => {
    expect(from(made.first, made.tool).kind).toBe('release');
    expect(from(made.first, made.bicep)).toEqual({
      kind: 'by-hand',
      reasons: [`deploy/azure/apps.bicep changed since ${made.first}: ${azure}`],
    });
    // Moved out of deploy/azure, it still left deploy/azure.
    expect(from(made.bicep, made.renamed)).toEqual({
      kind: 'by-hand',
      reasons: [`deploy/azure/apps.bicep changed since ${made.bicep}: ${azure}`],
    });
    // A deleted tool is still only a tool; an unusually named module is still Bicep.
    expect(from(made.renamed, made.deleted).kind).toBe('release');
    expect(from(made.deleted, made.unusual)).toEqual({
      kind: 'by-hand',
      reasons: [`deploy/azure/modules/ré.bicep changed since ${made.deleted}: ${azure}`],
    });
  });
});

describe('the checkout', () => {
  it('is the commit the folder is at, clean only when nothing differs from it', () => {
    expect(realCheckout(repository)).toEqual({ head: made.unusual, clean: true });
    // An added file, then a changed one.
    writeFileSync(path.join(repository, 'untracked.txt'), 'x');
    expect(realCheckout(repository)).toEqual({ head: made.unusual, clean: false });
    rmSync(path.join(repository, 'untracked.txt'));
    writeFileSync(path.join(repository, 'README.md'), 'changed\n');
    expect(realCheckout(repository)).toEqual({ head: made.unusual, clean: false });
    git('checkout', '--quiet', '--', 'README.md');
    expect(realCheckout(repository).clean).toBe(true);
  });

  it('is an error in a folder that is not a repository, or where git cannot even start', () => {
    expect(() => realCheckout(dir)).toThrow("git couldn't say which commit this folder is at");
    // A folder that doesn't exist: git isn't started at all.
    const nowhere = path.join(dir, 'nowhere');
    expect(() => realCheckout(nowhere)).toThrow("git couldn't be run:");
    expect(() => realHistory(nowhere).isAncestor(made.first, made.bicep)).toThrow("git couldn't be run:");
  });
});

// What the deploy tools read from git (G4-3), against a throwaway repository
// made here. This machine's git settings (signing, hooks) are kept out of it:
// they are for our own repository, not a fixture.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { atCommit, realCheckout, realHistory } from './git.ts';
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
    // A commit to compare with that it doesn't have, or a name that isn't one, on either side: no ancestry, never a
    // crash (AZ2c: a revision or run Azure keeps may name anything).
    const history = realHistory(repository);
    for (const odd of [MISSING, 'x\n::error::y', '--all', 'HEAD~99', '']) {
      expect(history.isAncestor(made.first, odd), odd).toBe(false);
      expect(history.isAncestor(odd, made.first), odd).toBe(false);
    }
    expect(history.isAncestor(made.first, made.first)).toBe(true);
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

describe('files at a commit (decision 49: the coming list staging runs)', () => {
  it("reads a file's text as the commit had it, and none where it had none", () => {
    const history = realHistory(repository);
    expect(history.fileAt(made.first, 'README.md')).toBe('README.md\n');
    expect(history.fileAt(made.first, 'deploy/azure/release.ts')).toBeUndefined();
    expect(history.fileAt(made.deleted, 'deploy/azure/release.ts')).toBeUndefined();
    expect(history.fileAt(made.tool, 'deploy/azure/release.ts')).toBe('deploy/azure/release.ts\n');
  });

  it('lists the files directly in a folder', () => {
    expect(realHistory(repository).filesIn(made.bicep, 'deploy/azure')).toEqual(['apps.bicep', 'release.ts']);
  });

  it('is an error for a commit this clone lacks, or a folder the commit lacks: never taken as nothing there', () => {
    expect(() => realHistory(repository).fileAt(MISSING, 'README.md')).toThrow(`git couldn't find ${MISSING}`);
    expect(() => realHistory(repository).filesIn(made.first, 'deploy/azure')).toThrow("git couldn't list deploy/azure");
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

describe('a folder as it is at a commit (AZ2c: the watch reads a build’s own apps.bicep)', () => {
  it('holds that commit’s files alone, in a worktree removed after, whatever the reader does', () => {
    expect(atCommit(made.bicep, 'deploy/azure', (at) => readdirSync(at).sort(), repository)).toEqual([
      'apps.bicep',
      'release.ts',
    ]);
    expect(atCommit(made.tool, 'deploy/azure', (at) => readdirSync(at), repository)).toEqual(['release.ts']);
    expect(() =>
      atCommit(
        made.bicep,
        'deploy/azure',
        () => {
          throw new Error('the reader failed');
        },
        repository,
      ),
    ).toThrow('the reader failed');
    expect(() => atCommit(MISSING, 'deploy/azure', () => 'read', repository)).toThrow(
      `git couldn't make a worktree at ${MISSING}`,
    );
    expect(() => atCommit(made.first, 'deploy/azure', () => 'read', repository)).toThrow(
      `git couldn't check out deploy/azure at ${made.first}`,
    );
    // Every worktree made is gone: only the repository's own is left.
    expect(git('worktree', 'list', '--porcelain').match(/^worktree /gm)).toHaveLength(1);
  });
});

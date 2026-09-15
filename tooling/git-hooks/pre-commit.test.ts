import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import { addedLines, type Git, preCommit, stagedProblems, unformatted } from './pre-commit.ts';

const LF = String.fromCharCode(10);
const lines = (...text: string[]): string => text.join(LF);
/** A GitHub-shaped token, assembled so this file holds none. */
const token = (): string => ['gh', 'p_', 'A1b2'.repeat(9)].join('');

describe('reading the lines a commit adds', () => {
  it('numbers each added line as in the staged file, across files and hunks', () => {
    const diff = lines(
      'diff --git a/src/a.ts b/src/a.ts',
      'index 1111111..2222222 100644',
      '--- a/src/a.ts',
      '+++ b/src/a.ts',
      '@@ -3,0 +4,2 @@ export const x = 1;',
      '+const four = 4;',
      '+const five = 5;',
      '@@ -10 +12 @@',
      '-old',
      '+new',
      'diff --git a/docs/new.md b/docs/new.md',
      'new file mode 100644',
      'index 0000000..3333333',
      '--- /dev/null',
      '+++ b/docs/new.md',
      '@@ -0,0 +1 @@',
      '+# Title',
      '',
    );
    expect(addedLines(diff)).toEqual([
      { file: 'src/a.ts', line: 4, text: 'const four = 4;' },
      { file: 'src/a.ts', line: 5, text: 'const five = 5;' },
      { file: 'src/a.ts', line: 12, text: 'new' },
      { file: 'docs/new.md', line: 1, text: '# Title' },
    ]);
  });

  it('keeps an added line that starts with "++" as content, not a header', () => {
    const diff = lines(
      'diff --git a/a.md b/a.md',
      '--- a/a.md',
      '+++ b/a.md',
      '@@ -1,0 +2,2 @@',
      '+++ not a header',
      '+diff --git not a header either',
    );
    expect(addedLines(diff)).toEqual([
      { file: 'a.md', line: 2, text: '++ not a header' },
      { file: 'a.md', line: 3, text: 'diff --git not a header either' },
    ]);
  });

  it('counts context lines, skips binary files and reads a quoted path', () => {
    const diff = lines(
      'diff --git a/image.png b/image.png',
      'Binary files /dev/null and b/image.png differ',
      'diff --git "a/odd name.ts" "b/odd name.ts"',
      '--- "a/odd name.ts"',
      '+++ "b/odd name.ts"',
      '@@ -1,2 +1,3 @@',
      ' kept',
      '+added',
      String.fromCharCode(92) + ' No newline at end of file',
    );
    expect(addedLines(diff)).toEqual([{ file: 'odd name.ts', line: 2, text: 'added' }]);
  });
});

describe('the problems in what is staged', () => {
  it('reports forbidden paths and bad added lines, but not lines that were only removed', () => {
    const diff = lines(
      'diff --git a/src/a.ts b/src/a.ts',
      '--- a/src/a.ts',
      '+++ b/src/a.ts',
      '@@ -1 +1 @@',
      `-const old = '${token()}';`,
      `+const value = '${token()}';`,
    );
    expect(
      stagedProblems(['src/a.ts', '.env'], diff).map((problem) => [problem.rule, problem.file, problem.line]),
    ).toEqual([
      ['forbidden-file', '.env', undefined],
      ['provider-token', 'src/a.ts', 1],
    ]);
  });
});

describe('formatting, on the staged content', () => {
  it('lists the files Prettier would change, and skips ignored and unknown files', async () => {
    const staged: Record<string, string> = {
      'tooling/good.ts': `export const a = 1;${LF}`,
      'tooling/bad.ts': `export const a=1${LF}`,
      'coverage/report.ts': `export const a=1${LF}`,
      'assets/logo.png': 'not text',
    };
    expect(await unformatted(Object.keys(staged), (file) => staged[file] ?? '')).toEqual(['tooling/bad.ts']);
  });
});

describe('the hook', () => {
  /** A git that answers the hook's three questions from a staged set. */
  const fakeGit = (staged: Record<string, string>, diff: string): Git => {
    return (args) => {
      if (args.includes('--name-only'))
        return `${Object.keys(staged).join(String.fromCharCode(0))}${String.fromCharCode(0)}`;
      if (args[0] === 'show') return staged[(args[1] ?? '').slice(1)] ?? '';
      return diff;
    };
  };

  it('lets a clean commit through silently', async () => {
    const said: string[] = [];
    const git = fakeGit({ 'tooling/a.ts': `export const a = 1;${LF}` }, '');
    expect(await preCommit(git, (line) => said.push(line))).toBe(0);
    expect(said).toEqual([]);
  });

  it('lets an empty commit through', async () => {
    expect(
      await preCommit(
        () => '',
        () => undefined,
      ),
    ).toBe(0);
  });

  it('refuses, naming each problem and never the secret', async () => {
    const secret = token();
    const diff = lines(
      'diff --git a/tooling/a.ts b/tooling/a.ts',
      '--- a/tooling/a.ts',
      '+++ b/tooling/a.ts',
      '@@ -0,0 +1 @@',
      `+export const a = '${secret}';`,
    );
    const said: string[] = [];
    const git = fakeGit({ 'tooling/a.ts': `export const a='${secret}'${LF}` }, diff);
    expect(await preCommit(git, (line) => said.push(line))).toBe(1);
    expect(said).toEqual([
      'Commit refused by the pre-commit hook (tooling/git-hooks):',
      '  tooling/a.ts:1 [provider-token] looks like a GitHub token',
      '  tooling/a.ts [format] not formatted: run corepack pnpm format, then stage it again',
      'Fix these and commit again. CI checks the same rules; never skip them with --no-verify.',
    ]);
    expect(said.join(LF)).not.toContain(secret);
  });
});

describe('the hook in a real repository', () => {
  const repo = mkdtempSync(path.join(tmpdir(), 'agentx-hook-'));
  const hook = fileURLToPath(new URL('./pre-commit.ts', import.meta.url));
  afterAll(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  const git = (...args: string[]): void => {
    const run = spawnSync('git', args, { cwd: repo, encoding: 'utf8' });
    if (run.status !== 0) throw new Error(run.stderr);
  };
  const runHook = (): { status: number | null; stderr: string } => {
    const run = spawnSync(process.execPath, [hook], { cwd: repo, encoding: 'utf8' });
    return { status: run.status, stderr: run.stderr };
  };

  it('passes clean staged files, and refuses a staged env file and an invisible character', () => {
    git('init', '--quiet');
    mkdirSync(path.join(repo, 'src'));
    writeFileSync(path.join(repo, 'src', 'a.ts'), `export const a = 1;${LF}`);
    git('add', 'src/a.ts');
    expect(runHook()).toEqual({ status: 0, stderr: '' });

    writeFileSync(path.join(repo, '.env'), `NAME=value${LF}`);
    writeFileSync(path.join(repo, 'src', 'b.ts'), `export const b = 1;${String.fromCharCode(0x200b)}${LF}`);
    git('add', '.env', 'src/b.ts');
    const refused = runHook();
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain('.env [forbidden-file]');
    expect(refused.stderr).toContain('src/b.ts:1 [invisible-character] invisible character U+200B');
  });
});

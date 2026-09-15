// The pre-commit hook (.githooks/pre-commit, installed by `corepack pnpm hooks`):
// refuses a commit whose staged changes break a rule in rules.ts, or whose
// staged files Prettier would change. It reads what is staged, not the working
// tree, needs Node and the installed packages only (no Docker), and never
// prints a matched secret. CI checks the same rules over every tracked file.
import { spawnSync } from 'node:child_process';

import { describeProblem, lineProblems, pathProblems, type Problem } from './rules.ts';

export interface AddedLine {
  readonly file: string;
  /** 1-based, in the staged file. */
  readonly line: number;
  readonly text: string;
}

const HUNK = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/g;

/** The file a `+++ b/path` header names; git quotes unusual paths, which are kept as written. */
function headerPath(header: string): string {
  const name = header.slice('+++ '.length);
  const unquoted = name.startsWith('"') && name.endsWith('"') ? name.slice(1, -1) : name;
  return unquoted.startsWith('b/') ? unquoted.slice(2) : unquoted;
}

/**
 * The added lines of `git diff --cached --unified=0`, numbered as in the
 * staged file. Headers are read only between `diff --git` and the first hunk,
 * so an added line that itself starts with "++" is still content.
 */
export function addedLines(diff: string): AddedLine[] {
  const added: AddedLine[] = [];
  let file: string | undefined;
  let inHeader = false;
  let next = 0;
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('diff --git ')) {
      inHeader = true;
      file = undefined;
      continue;
    }
    const hunk = [...raw.matchAll(HUNK)][0];
    if (hunk !== undefined) {
      inHeader = false;
      next = Number(hunk[1]);
      continue;
    }
    if (inHeader) {
      if (raw.startsWith('+++ ')) file = raw === '+++ /dev/null' ? undefined : headerPath(raw);
      continue;
    }
    if (file === undefined) continue;
    if (raw.startsWith('+')) {
      added.push({ file, line: next, text: raw.slice(1) });
      next += 1;
    } else if (raw.startsWith(' ')) {
      next += 1;
    }
  }
  return added;
}

/** Every rule broken by the staged paths and the lines they add. */
export function stagedProblems(files: readonly string[], diff: string): Problem[] {
  return [
    ...files.flatMap(pathProblems),
    ...addedLines(diff).flatMap(({ file, line, text }) => lineProblems(file, line, text)),
  ];
}

/** The staged files Prettier would change, checked on their staged content. */
export async function unformatted(files: readonly string[], staged: (file: string) => string): Promise<string[]> {
  const prettier = await import('prettier');
  const changed: string[] = [];
  for (const file of files) {
    // Prettier gives no parser to a file it ignores or can't format.
    const info = await prettier.getFileInfo(file, { ignorePath: ['.gitignore', '.prettierignore'] });
    if (info.inferredParser === null) continue;
    const options = (await prettier.resolveConfig(file)) ?? {};
    if (!(await prettier.check(staged(file), { ...options, filepath: file }))) changed.push(file);
  }
  return changed;
}

export type Git = (args: readonly string[]) => string;

/** Runs git with an argument list and no shell; paths are printed as they are. */
export const runGit: Git = (args) => {
  const run = spawnSync('git', ['-c', 'core.quotePath=false', ...args], {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    windowsHide: true,
  });
  if (run.error !== undefined || run.status !== 0) {
    throw new Error(`git ${args[0] ?? ''} failed: ${run.error?.message ?? run.stderr.trim()}`);
  }
  return run.stdout;
};

/** The hook: returns the exit code, printing what to fix. */
export async function preCommit(git: Git = runGit, log: (line: string) => void = console.error): Promise<number> {
  const files = git(['diff', '--cached', '--name-only', '-z', '--diff-filter=ACM', '--no-renames'])
    .split(String.fromCharCode(0))
    .filter((file) => file !== '');
  if (files.length === 0) return 0;

  const diff = git([
    'diff',
    '--cached',
    '--unified=0',
    '--no-color',
    '--no-ext-diff',
    '--diff-filter=ACM',
    '--no-renames',
  ]);
  const problems = stagedProblems(files, diff);
  const notFormatted = await unformatted(files, (file) => git(['show', `:${file}`]));

  if (problems.length === 0 && notFormatted.length === 0) return 0;
  log('Commit refused by the pre-commit hook (tooling/git-hooks):');
  for (const problem of problems) log(`  ${describeProblem(problem)}`);
  for (const file of notFormatted)
    log(`  ${file} [format] not formatted: run corepack pnpm format, then stage it again`);
  log('Fix these and commit again. CI checks the same rules; never skip them with --no-verify.');
  return 1;
}

if (import.meta.main) process.exitCode = await preCommit();

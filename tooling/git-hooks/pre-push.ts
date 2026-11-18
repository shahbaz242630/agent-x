// The pre-push hook (.githooks/pre-push, installed by `corepack pnpm hooks`):
// scans the commits being pushed with gitleaks, the pinned binary run as CI
// runs it, then type-checks and lints. A flagged commit costs a fresh PR once
// it reaches GitHub (S4, S10), so this is where to catch it. The type check
// and lint read the working tree; CI checks the commit itself. The lint reads
// only the files the branch changes (S200: the whole repository took ~45 min
// and ~6 GB on the partner's laptop), the whole when the lint's own setup
// changed or git can't say what changed; CI still lints the whole. The whole
// runs in parts, one process each (S201: one run passed V8's 6 GB cap).
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { readFileSync } from 'node:fs';

import type { LintPart } from '../quality/lint-parts.ts';
import { lintPart, wholeParts } from '../quality/lint-whole.ts';

import { ensureGitleaks } from './gitleaks.ts';
import { runGit } from './pre-commit.ts';

export interface PushedRef {
  readonly localRef: string;
  readonly localSha: string;
  readonly remoteRef: string;
  readonly remoteSha: string;
}

const NO_COMMIT = /^0+$/;

/** Git's stdin for the hook: one `<local ref> <local sha> <remote ref> <remote sha>` line per ref. */
export function parseRefs(stdin: string): PushedRef[] {
  return stdin
    .split('\n')
    .map((line) => line.trim().split(/\s+/))
    .filter((fields) => fields.length === 4)
    .map(([localRef = '', localSha = '', remoteRef = '', remoteSha = '']) => ({
      localRef,
      localSha,
      remoteRef,
      remoteSha,
    }));
}

/**
 * The `git log` arguments naming the commits each push adds: those after the
 * remote's commit, or those on no branch of that remote yet, for a new branch
 * or when this clone lacks the remote's commit (the branch moved on GitHub
 * and wasn't fetched). A deleted ref adds nothing.
 */
export function logRanges(refs: readonly PushedRef[], remote: string, known: (sha: string) => boolean): string[] {
  return refs
    .filter((ref) => !NO_COMMIT.test(ref.localSha))
    .map((ref) =>
      NO_COMMIT.test(ref.remoteSha) || !known(ref.remoteSha)
        ? `${ref.localSha} --not --remotes=${remote}`
        : `${ref.remoteSha}..${ref.localSha}`,
    );
}

/** Whether this clone has the commit. */
export const knownCommit = (sha: string): boolean =>
  spawnSync('git', ['cat-file', '-e', `${sha}^{commit}`], { windowsHide: true }).status === 0;

/**
 * How many commits a range names; throws when git can't read it. gitleaks
 * reports an unreadable range as "0 commits scanned" and exits 0, so the hook
 * counts first and refuses rather than pass a push it never scanned.
 */
export const commitCount = (range: string): number =>
  Number(runGit(['rev-list', '--count', ...range.split(' ')]).trim());

/** gitleaks over a range of commits, with the repository's rules, redacting whatever it finds. */
export const gitleaksArgs = (range: string): string[] => [
  'git',
  '--no-banner',
  '--redact',
  '--config',
  '.gitleaks.toml',
  '--log-opts',
  range,
  '.',
];

/** The type check through Corepack; on Windows Corepack is a .cmd shim, which only a shell runs (fixed text). */
function typecheckScript(): SpawnSyncReturns<Buffer> {
  return process.platform === 'win32'
    ? spawnSync('corepack pnpm typecheck', { shell: true, stdio: 'inherit', windowsHide: true })
    : spawnSync('corepack', ['pnpm', 'typecheck'], { stdio: 'inherit' });
}

/** Paths whose change can alter what the lint finds anywhere: the whole is linted then. */
const WHOLE_LINT = [
  /^eslint(\.[a-z]+)?\.config\.js$/,
  /^tooling\/quality\//,
  /(^|\/)package\.json$/,
  /^pnpm-lock\.yaml$/,
  /(^|\/)tsconfig[^/]*\.json$/,
];

const LINTED = /\.(?:[cm]?[jt]s|[jt]sx)$/;

/**
 * What the lint reads: 'all' when git couldn't say what changed or the lint's
 * own setup changed; otherwise the changed files it lints (none skips it).
 */
export function lintTargets(changed: readonly string[] | undefined): readonly string[] | 'all' {
  if (changed === undefined) return 'all';
  if (changed.some((path) => WHOLE_LINT.some((pattern) => pattern.test(path)))) return 'all';
  return changed.filter((path) => LINTED.test(path));
}

/**
 * The files changed since the branch left the default branch: committed,
 * staged, unstaged and untracked (the lint reads the working tree), deleted
 * ones left out. Undefined when git can't find where the branch left it.
 */
export function changedFiles(base = 'origin/main'): readonly string[] | undefined {
  try {
    const from = runGit(['merge-base', 'HEAD', base]).trim();
    const lines = (text: string) => text.split('\n').filter((line) => line !== '');
    const tracked = lines(runGit(['diff', '--name-only', '--diff-filter=d', from]));
    const untracked = lines(runGit(['ls-files', '--others', '--exclude-standard']));
    return [...new Set([...tracked, ...untracked])].sort();
  } catch {
    return undefined;
  }
}

export interface Steps {
  readonly known: (sha: string) => boolean;
  readonly commits: (range: string) => number;
  readonly gitleaks: (range: string) => Promise<number>;
  readonly typecheck: () => number;
  readonly changed: () => readonly string[] | undefined;
  readonly parts: () => Promise<readonly LintPart[]>;
  readonly lint: (paths: readonly string[]) => number;
}

const realSteps: Steps = {
  known: knownCommit,
  commits: commitCount,
  gitleaks: async (range) => {
    const binary = await ensureGitleaks();
    return spawnSync(binary, gitleaksArgs(range), { stdio: 'inherit', windowsHide: true }).status ?? 1;
  },
  typecheck: () => typecheckScript().status ?? 1,
  changed: () => changedFiles(),
  // The same parts and runs as `pnpm lint` on CI (lint-whole.ts).
  parts: wholeParts,
  lint: (paths) => lintPart(paths),
};

/** The hook: returns the exit code. Stops at the first failing step. */
export async function prePush(
  stdin: string,
  remote: string,
  steps: Steps = realSteps,
  log: (line: string) => void = console.error,
): Promise<number> {
  const ranges = logRanges(parseRefs(stdin), remote, steps.known);
  if (ranges.length === 0) return 0;

  const refuse = (what: string): number => {
    log(`Push refused by the pre-push hook: ${what}. CI would refuse it too; never skip this with --no-verify.`);
    return 1;
  };
  for (const range of ranges) {
    let count: number;
    try {
      count = steps.commits(range);
    } catch (error) {
      return refuse(`git can't read the commits being pushed (${(error as Error).message}); fetch, then push again`);
    }
    if (count === 0) continue;
    let status: number;
    try {
      status = await steps.gitleaks(range);
    } catch (error) {
      return refuse(`gitleaks could not run (${(error as Error).message}); run corepack pnpm hooks`);
    }
    if (status !== 0) return refuse('gitleaks found something in the commits being pushed');
  }
  if (steps.typecheck() !== 0) return refuse('the type check failed');
  const targets = lintTargets(steps.changed());
  if (targets === 'all') return await lintWhole(steps, log, refuse);
  if (targets.length === 0) {
    log('No changed files to lint; CI lints the whole repository.');
    return 0;
  }
  log(`Linting the ${targets.length} changed file(s); CI lints the whole repository.`);
  return steps.lint(targets) === 0 ? 0 : refuse('lint failed');
}

/** The whole repository's lint, one part at a time, stopping at the first that fails. */
async function lintWhole(steps: Steps, log: (line: string) => void, refuse: (what: string) => number): Promise<number> {
  let parts: readonly LintPart[];
  try {
    parts = await steps.parts();
  } catch (error) {
    return refuse(`the files to lint could not be listed (${(error as Error).message})`);
  }
  log(
    `Linting the whole repository in ${parts.length} parts (the lint setup changed, or git could not say what changed).`,
  );
  for (const [index, part] of parts.entries()) {
    log(`Linting part ${index + 1} of ${parts.length}: ${part.label}...`);
    if (steps.lint(part.paths) !== 0) return refuse(`lint failed in part ${index + 1} (${part.label})`);
  }
  return 0;
}

if (import.meta.main) {
  // Git passes the remote's name (or URL) first, and the refs on stdin.
  process.exitCode = await prePush(readFileSync(0, 'utf8'), process.argv[2] ?? 'origin');
}

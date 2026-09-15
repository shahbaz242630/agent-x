// The pre-push hook (.githooks/pre-push, installed by `corepack pnpm hooks`):
// scans the commits being pushed with gitleaks, the pinned binary run as CI
// runs it, then type-checks and lints. A flagged commit costs a fresh PR once
// it reaches GitHub (S4, S10), so this is where to catch it. The type check
// and lint read the working tree; CI checks the commit itself.
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { readFileSync } from 'node:fs';

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

/** A package script through Corepack; on Windows Corepack is a .cmd shim, which only a shell runs (fixed text). */
function packageScript(name: 'typecheck' | 'lint'): SpawnSyncReturns<Buffer> {
  return process.platform === 'win32'
    ? spawnSync(`corepack pnpm ${name}`, { shell: true, stdio: 'inherit', windowsHide: true })
    : spawnSync('corepack', ['pnpm', name], { stdio: 'inherit' });
}

export interface Steps {
  readonly known: (sha: string) => boolean;
  readonly commits: (range: string) => number;
  readonly gitleaks: (range: string) => Promise<number>;
  readonly script: (name: 'typecheck' | 'lint') => number;
}

const realSteps: Steps = {
  known: knownCommit,
  commits: commitCount,
  gitleaks: async (range) => {
    const binary = await ensureGitleaks();
    return spawnSync(binary, gitleaksArgs(range), { stdio: 'inherit', windowsHide: true }).status ?? 1;
  },
  script: (name) => packageScript(name).status ?? 1,
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
  if (steps.script('typecheck') !== 0) return refuse('the type check failed');
  if (steps.script('lint') !== 0) return refuse('lint failed');
  return 0;
}

if (import.meta.main) {
  // Git passes the remote's name (or URL) first, and the refs on stdin.
  process.exitCode = await prePush(readFileSync(0, 'utf8'), process.argv[2] ?? 'origin');
}

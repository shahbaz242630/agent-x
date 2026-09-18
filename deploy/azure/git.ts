// What the deploy tools read from git (0e G4-3): the history a release is
// judged against (release.ts), and the checkout a hand deploy is sent from
// (deploy.ts). git runs with its arguments as a list, never through a shell,
// in this repository unless told otherwise. Anything git can't answer is an
// error, never taken as an answer.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** Reading the repository's history, which the release job must check out whole. */
export interface History {
  /** Whether `ancestor` is `commit` or in its history; false for a commit this clone doesn't have. */
  isAncestor(ancestor: string, commit: string): boolean;
  /** The files that differ between the two commits, a renamed one under both its names. */
  changedFiles(from: string, to: string): readonly string[];
}

/** The folder a hand deploy is sent from: the commit it is at, and whether anything differs from it. */
export interface Checkout {
  readonly head: string;
  readonly clean: boolean;
}

/** The repository this file is in: git runs there, whatever the shell's folder. */
const REPOSITORY = fileURLToPath(new URL('../../', import.meta.url));

/** git's own separator for a list of paths it hasn't quoted (`-z`). */
const NUL = String.fromCharCode(0);

interface Ran {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function git(repository: string, args: readonly string[]): Ran {
  const done = spawnSync('git', args, { cwd: repository, encoding: 'utf8', windowsHide: true });
  if (done.error !== undefined) throw new Error(`git couldn't be run: ${done.error.message}`);
  return { status: done.status, stdout: done.stdout, stderr: done.stderr.trim() };
}

export function realHistory(repository = REPOSITORY): History {
  return {
    isAncestor: (ancestor, commit) => {
      // 1 is "no such commit here"; 128 (not a repository, say) is an error, not an answer.
      const known = git(repository, ['rev-parse', '--verify', '--quiet', `${ancestor}^{commit}`]);
      if (known.status === 1) return false;
      if (known.status !== 0) throw new Error(`git couldn't look for ${ancestor}:\n${known.stderr}`);
      const done = git(repository, ['merge-base', '--is-ancestor', ancestor, commit]);
      if (done.status === 0 || done.status === 1) return done.status === 0;
      throw new Error(`git couldn't compare ${ancestor} and ${commit}:\n${done.stderr}`);
    },
    changedFiles: (from, to) => {
      // -z: every path as it is, never quoted (git quotes an unusual one, which would hide its folder).
      const done = git(repository, ['diff', '--name-only', '-z', '--no-renames', '--no-color', from, to]);
      if (done.status !== 0) throw new Error(`git couldn't list the changes from ${from} to ${to}:\n${done.stderr}`);
      return done.stdout.split(NUL).filter((file) => file !== '');
    },
  };
}

/** The commit the repository is at, and whether its files are exactly that commit's (nothing changed or added). */
export function realCheckout(repository = REPOSITORY): Checkout {
  const head = git(repository, ['rev-parse', '--verify', 'HEAD']);
  if (head.status !== 0) throw new Error(`git couldn't say which commit this folder is at:\n${head.stderr}`);
  const status = git(repository, ['status', '--porcelain', '-z']);
  if (status.status !== 0) throw new Error(`git couldn't say whether this folder has changes:\n${status.stderr}`);
  return { head: head.stdout.trim(), clean: status.stdout === '' };
}

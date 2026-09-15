// Sets up the git hooks for this clone, once: `corepack pnpm hooks`.
// - git runs the hooks in .githooks (core.hooksPath, this clone only; no husky,
//   no install-time script)
// - the pinned gitleaks is installed into .tools/ for the pre-push hook
// Running it again changes nothing.
import { ensureGitleaks } from './gitleaks.ts';
import { type Git, runGit } from './pre-commit.ts';

export const HOOKS_PATH = '.githooks';

export async function install(
  git: Git = runGit,
  ensure: () => Promise<string> = ensureGitleaks,
  log: (line: string) => void = console.log,
): Promise<void> {
  git(['config', '--local', 'core.hooksPath', HOOKS_PATH]);
  log(`Git hooks: git now runs ${HOOKS_PATH}/pre-commit and ${HOOKS_PATH}/pre-push in this clone.`);
  log(`gitleaks: ${await ensure()}`);
}

if (import.meta.main) await install();

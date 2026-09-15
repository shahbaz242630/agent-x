// Sets up the git hooks for this clone, once: `corepack pnpm hooks`.
// - copies .githooks/pre-commit and .githooks/pre-push into the clone's own
//   hooks folder (.git/hooks), which no branch can change. core.hooksPath is
//   never pointed at the tracked folder, and is unset if an earlier install
//   did: otherwise checking out a branch would run whatever hooks it carries
//   (post-checkout and the rest), before any review
// - installs the pinned gitleaks into .tools/ for the pre-push hook
// No husky and no install-time script. Running it again changes nothing.
// The two hooks still run the checked-out tooling/git-hooks code on a commit
// or push, so review a contributor's branch on GitHub or in a separate clone,
// never by checking it out here (Security-Handoff §7).
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync } from 'node:fs';
import path from 'node:path';

import { ensureGitleaks } from './gitleaks.ts';
import { type Git, runGit } from './pre-commit.ts';

export const HOOKS = ['pre-commit', 'pre-push'] as const;
const SOURCE = '.githooks';

export interface InstallSteps {
  readonly git: Git;
  /** Removes core.hooksPath from this clone's config; nothing to remove is fine. */
  readonly unsetHooksPath: () => void;
  readonly copy: (from: string, to: string) => void;
  readonly ensure: () => Promise<string>;
}

const realSteps: InstallSteps = {
  git: runGit,
  unsetHooksPath: () => {
    const run = spawnSync('git', ['config', '--local', '--unset-all', 'core.hooksPath'], { windowsHide: true });
    // 5: the setting wasn't there.
    if (run.error !== undefined || (run.status !== 0 && run.status !== 5)) {
      throw new Error(`Could not unset core.hooksPath (git exited ${String(run.status)}).`);
    }
  },
  copy: (from, to) => {
    copyFileSync(from, to);
    chmodSync(to, 0o755);
  },
  ensure: ensureGitleaks,
};

export async function install(
  steps: InstallSteps = realSteps,
  log: (line: string) => void = console.log,
): Promise<void> {
  steps.unsetHooksPath();
  // Asked after the unset: git answers with core.hooksPath while it is set.
  const hooksDir = steps.git(['rev-parse', '--git-path', 'hooks']).trim();
  for (const hook of HOOKS) steps.copy(path.join(SOURCE, hook), path.join(hooksDir, hook));
  log(`Git hooks: ${HOOKS.join(' and ')} copied into ${hooksDir}.`);
  log(`gitleaks: ${await steps.ensure()}`);
}

if (import.meta.main) await install();

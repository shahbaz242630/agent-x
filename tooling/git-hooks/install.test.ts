import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { HOOKS, install, type InstallSteps } from './install.ts';

/** Steps that record what the install did, in order. */
function recording(hooksDir: string): InstallSteps & { done: string[] } {
  const done: string[] = [];
  return {
    done,
    unsetHooksPath: () => done.push('unset core.hooksPath'),
    git: (args) => {
      done.push(`git ${args.join(' ')}`);
      return `${hooksDir}\n`;
    },
    copy: (from, to) => done.push(`copy ${from} -> ${to}`),
    ensure: () => {
      done.push('gitleaks');
      return Promise.resolve('/tools/gitleaks');
    },
  };
}

describe('setting the hooks up', () => {
  it("copies the two hooks into the clone's own hooks folder, after unsetting any hooks path, then installs gitleaks", async () => {
    const steps = recording('.git/hooks');
    const said: string[] = [];
    await install(steps, (line) => said.push(line));
    expect(steps.done).toEqual([
      'unset core.hooksPath',
      'git rev-parse --git-path hooks',
      `copy ${path.join('.githooks', 'pre-commit')} -> ${path.join('.git/hooks', 'pre-commit')}`,
      `copy ${path.join('.githooks', 'pre-push')} -> ${path.join('.git/hooks', 'pre-push')}`,
      'gitleaks',
    ]);
    expect(said).toEqual(['Git hooks: pre-commit and pre-push copied into .git/hooks.', 'gitleaks: /tools/gitleaks']);
  });

  it('installs exactly the two hooks the repository ships', () => {
    expect(HOOKS).toEqual(['pre-commit', 'pre-push']);
  });
});

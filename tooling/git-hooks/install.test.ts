import { describe, expect, it } from 'vitest';

import { HOOKS_PATH, install } from './install.ts';

describe('setting the hooks up', () => {
  it("points this clone's git at .githooks and installs gitleaks", async () => {
    const calls: string[][] = [];
    const said: string[] = [];
    await install(
      (args) => {
        calls.push([...args]);
        return '';
      },
      () => Promise.resolve('/tools/gitleaks'),
      (line) => said.push(line),
    );
    expect(calls).toEqual([['config', '--local', 'core.hooksPath', HOOKS_PATH]]);
    expect(said).toEqual([
      'Git hooks: git now runs .githooks/pre-commit and .githooks/pre-push in this clone.',
      'gitleaks: /tools/gitleaks',
    ]);
  });
});

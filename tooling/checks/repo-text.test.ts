// The pre-commit rules (tooling/git-hooks/rules.ts) over every tracked file,
// so a commit that skipped the hook still can't bring in a secret, a key or
// env file, the internal documents, scanner bait or an invisible character.
// Security-Handoff §7: hooks can be skipped, so CI is the real gate. Also
// checks the hooks themselves are wired as installed.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { describeProblem, pathProblems, textProblems } from '../git-hooks/rules.ts';

const NUL = String.fromCharCode(0);

const tracked = execFileSync('git', ['-c', 'core.quotePath=false', 'ls-files', '-z'], {
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
})
  .split(NUL)
  .filter((file) => file !== '');

/** A file is text unless its first 8000 bytes hold a NUL, git's own test. */
const isText = (bytes: Buffer): boolean => !bytes.subarray(0, 8000).includes(0);

describe('Security-Handoff §7: what the pre-commit hook refuses, CI refuses too', () => {
  it('finds the tracked files (so the checks below are not vacuous)', () => {
    expect(tracked.length).toBeGreaterThan(300);
    expect(tracked).toContain('tooling/git-hooks/rules.ts');
  });

  it('tracks no forbidden file', () => {
    expect(tracked.flatMap(pathProblems).map(describeProblem)).toEqual([]);
  });

  it('holds no secret, scanner bait, bad placeholder or invisible character in any text file', () => {
    const problems = tracked.flatMap((file) => {
      const bytes = readFileSync(file);
      return isText(bytes) ? textProblems(file, bytes.toString('utf8')) : [];
    });
    expect(problems.map(describeProblem)).toEqual([]);
  });

  it('keeps each hook an executable shell script that runs its Node hook', () => {
    const modes = execFileSync('git', ['ls-files', '--stage', '.githooks'], { encoding: 'utf8' })
      .trim()
      .split(String.fromCharCode(10))
      .map((line) => {
        const [mode = '', , , file = ''] = line.split(/\s+/);
        return `${file} ${mode}`;
      });
    expect(modes).toEqual(['.githooks/pre-commit 100755', '.githooks/pre-push 100755']);
    for (const [hook, command] of [
      ['pre-commit', 'exec node tooling/git-hooks/pre-commit.ts'],
      ['pre-push', 'exec node tooling/git-hooks/pre-push.ts "$@"'],
    ] as const) {
      const lines = readFileSync(`.githooks/${hook}`, 'utf8').trimEnd().split(String.fromCharCode(10));
      expect(lines[0]).toBe('#!/bin/sh');
      expect(lines.at(-1)).toBe(command);
    }
  });

  it('the text check reads a binary file as binary', () => {
    expect(isText(Buffer.from('plain text'))).toBe(true);
    expect(isText(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]))).toBe(false);
  });
});

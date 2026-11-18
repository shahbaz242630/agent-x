// The whole lint in parts (tooling/quality/lint-parts.ts): the parts are
// worked out from the files, split when too big, and together lint exactly
// what one whole run lints, no file dropped or linted twice.
import { existsSync } from 'node:fs';

import { beforeAll, describe, expect, it } from 'vitest';

import { runGit } from '../git-hooks/pre-commit.ts';
import { wholeParts } from './lint-whole.ts';
import { lintWith } from './lint.ts';
import { areaOf, type LintPart, lintParts, MAX_PART_FILES, workspaceGlobs } from './lint-parts.ts';

const GLOBS = ['apps/*', 'packages/*'];

describe('the area a file belongs to', () => {
  it.each([
    ['eslint.config.js', ''],
    ['apps/api/src/server.ts', 'apps/api'],
    ['packages/core/src/a.ts', 'packages/core'],
    ['tooling/quality/lint.ts', 'tooling'],
    ['apps/top.ts', 'apps'],
  ])('%s is in %j', (file, area) => {
    expect(areaOf(file, GLOBS)).toBe(area);
  });

  it('reads the workspace globs from pnpm-workspace.yaml', () => {
    expect(workspaceGlobs()).toEqual(GLOBS);
  });
});

describe('the parts', () => {
  it('is one part an area, the root files named one by one, first', () => {
    expect(lintParts(['b.js', 'a.ts', 'tooling/x.ts', 'apps/api/src/y.ts', 'apps/console/z.ts'], GLOBS)).toEqual([
      { label: 'the root files', paths: ['b.js', 'a.ts'] },
      { label: 'apps/api', paths: ['apps/api'] },
      { label: 'apps/console', paths: ['apps/console'] },
      { label: 'tooling', paths: ['tooling'] },
    ]);
  });

  it('splits a too-big area by what sits inside it, through a lone directory, in name order', () => {
    const files = ['apps/api/src/a/1.ts', 'apps/api/src/a/2.ts', 'apps/api/src/b.ts', 'apps/api/src/c/3.ts'];
    expect(lintParts(files, GLOBS, 3)).toEqual([
      { label: 'apps/api/src (a–b)', paths: ['apps/api/src/a', 'apps/api/src/b.ts'] },
      { label: 'apps/api/src (c)', paths: ['apps/api/src/c'] },
    ]);
  });

  it('splits an entry that is itself too big, keeping the order', () => {
    const files = ['t/a.ts', 't/m/1.ts', 't/m/2.ts', 't/m/n/3.ts', 't/z.ts'];
    expect(lintParts(files, GLOBS, 2)).toEqual([
      { label: 't (a)', paths: ['t/a.ts'] },
      { label: 't/m (1–2)', paths: ['t/m/1.ts', 't/m/2.ts'] },
      { label: 't/m (n)', paths: ['t/m/n'] },
      { label: 't (z)', paths: ['t/z.ts'] },
    ]);
  });
});

/** What a path names among the files: itself, or the files under it. */
const under = (path: string, files: readonly string[]) =>
  files.filter((file) => file === path || file.startsWith(`${path}/`));

/** Where the parts differ from the whole: files left out, files linted twice, and paths naming no file to lint. */
function compare(parts: readonly LintPart[], whole: readonly string[]) {
  const seen = parts.flatMap((part) => part.paths.flatMap((path) => under(path, whole)));
  return {
    missing: whole.filter((file) => !seen.includes(file)),
    twice: seen.filter((file, index) => seen.indexOf(file) !== index),
    empty: parts.flatMap((part) => part.paths.filter((path) => under(path, whole).length === 0)),
  };
}

describe('the parts against the whole repository (repo check)', () => {
  const whole: string[] = [];
  let parts: readonly LintPart[] = [];

  beforeAll(async () => {
    const eslint = lintWith();
    const listed = runGit(['ls-files', '--cached', '--others', '--exclude-standard', '--deduplicate'])
      .split(String.fromCharCode(10))
      .filter((file) => file !== '' && existsSync(file));
    // What one whole run lints: every file there that ESLint neither ignores
    // nor lacks a config for (isPathIgnored says true for both).
    for (const file of listed) if (!(await eslint.isPathIgnored(file))) whole.push(file);
    parts = await wholeParts();
  });

  it('lints every file the whole run lints, each once, and names no path without one', () => {
    expect(whole.length).toBeGreaterThan(1000);
    expect(compare(parts, whole)).toEqual({ missing: [], twice: [], empty: [] });
  });

  it('notices a dropped part (positive control)', () => {
    const dropped = parts.filter((_, index) => index !== 1);
    expect(compare(dropped, whole).missing.length).toBeGreaterThan(0);
  });

  it('notices a part naming only ignored files, which ESLint stops on (positive control)', () => {
    const fixtures = { label: 'fixtures', paths: ['tooling/gate-proofs/fixtures'] };
    expect(compare([...parts, fixtures], whole).empty).toEqual(['tooling/gate-proofs/fixtures']);
  });

  it('keeps every part within the size it was measured at', () => {
    const sizes = parts.map((part) => part.paths.flatMap((path) => under(path, whole)).length);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(MAX_PART_FILES);
  });
});

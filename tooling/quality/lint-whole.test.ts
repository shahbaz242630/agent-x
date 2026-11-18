// `pnpm lint` in parts (S201): the parts in turn, stopping at the first that
// fails, and the reported-only SonarJS counts summed across them.
import { describe, expect, it } from 'vitest';

import { firstFailing, summedReport } from './lint-whole.ts';

const PARTS = [
  { label: 'apps/api (a–m)', paths: ['apps/api/src/a.ts'] },
  { label: 'apps/console', paths: ['apps/console'] },
  { label: 'tooling', paths: ['tooling'] },
];

describe('the whole lint, one part at a time', () => {
  it('lints every part in order when all pass, saying which it is on', () => {
    const linted: (readonly string[])[] = [];
    const lines: string[] = [];
    expect(
      firstFailing(
        PARTS,
        (paths) => {
          linted.push(paths);
          return 0;
        },
        (line) => lines.push(line),
      ),
    ).toBeUndefined();
    expect(linted).toEqual(PARTS.map(({ paths }) => paths));
    expect(lines).toEqual([
      'Linting part 1 of 3: apps/api (a–m)...',
      'Linting part 2 of 3: apps/console...',
      'Linting part 3 of 3: tooling...',
    ]);
  });

  it('stops at the first part that fails, naming it', () => {
    const linted: (readonly string[])[] = [];
    const failed = firstFailing(
      PARTS,
      (paths) => {
        linted.push(paths);
        return paths[0] === 'apps/console' ? 1 : 0;
      },
      () => undefined,
    );
    expect(failed).toBe(2);
    expect(linted).toHaveLength(2);
  });
});

describe('the reported-only counts across parts', () => {
  it('sums each rule across the parts, the most first, then by name', () => {
    const written = [
      JSON.stringify([
        ['sonarjs/no-extra-arguments', 4],
        ['sonarjs/use-type-alias', 1],
      ]),
      JSON.stringify([]),
      JSON.stringify([
        ['sonarjs/pseudo-random', 2],
        ['sonarjs/use-type-alias', 1],
      ]),
      '',
    ].join('\n');
    expect(summedReport(written)).toEqual([
      ['sonarjs/no-extra-arguments', 4],
      ['sonarjs/pseudo-random', 2],
      ['sonarjs/use-type-alias', 2],
    ]);
    expect(summedReport('')).toEqual([]);
  });
});

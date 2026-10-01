// `pnpm lint`'s split (tooling/quality/lint.ts): the repository's own rules
// and parse errors always fail the run; a SonarJS rule only once it blocks.
import { describe, expect, it } from 'vitest';

import { reportByRule, reportedOnly } from './lint.ts';

describe('what `pnpm lint` only reports', () => {
  it('reports a SonarJS finding whose rule is not yet blocking', () => {
    expect(reportedOnly({ ruleId: 'sonarjs/cognitive-complexity' }, new Set())).toBe(true);
  });

  it('fails on a SonarJS finding once its rule blocks', () => {
    expect(reportedOnly({ ruleId: 'sonarjs/cognitive-complexity' }, new Set(['sonarjs/cognitive-complexity']))).toBe(
      false,
    );
  });

  it.each([
    ['one of the repository’s own rules', '@typescript-eslint/no-floating-promises'],
    ['a rule merely named like SonarJS', 'agentx/sonarjs-lookalike'],
    ['a parse error or an unused disable directive', null],
  ])('always fails on %s', (_what, ruleId) => {
    expect(reportedOnly({ ruleId }, new Set())).toBe(false);
  });

  it('counts the reported findings by rule, the most first, ties by name', () => {
    expect(
      reportByRule([
        { ruleId: 'sonarjs/b' },
        { ruleId: 'sonarjs/a' },
        { ruleId: 'sonarjs/c' },
        { ruleId: 'sonarjs/c' },
        { ruleId: null },
      ]),
    ).toEqual([
      ['sonarjs/c', 2],
      ['sonarjs/a', 1],
      ['sonarjs/b', 1],
    ]);
  });
});

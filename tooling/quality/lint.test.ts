// `pnpm lint`'s split (tooling/quality/lint.ts): the repository's own rules
// and parse errors always fail the run; a SonarJS rule only once it blocks.
import { describe, expect, it } from 'vitest';

import { lintWith, reportByRule, reportedOnly, split } from './lint.ts';

describe('`pnpm lint` end to end, with the real config (#222’s review)', () => {
  const lint = async (code: string) =>
    split(await lintWith().lintText(code, { filePath: 'tooling/quality/example.js' }));

  it('fails on one of the repository’s own rules, as `eslint --max-warnings 0` did', async () => {
    const run = await lint('export const same = (a, b) => a == b;\n');

    expect(run.fails).toBe(true);
    expect(run.failing.flatMap((result) => result.messages.map((message) => message.ruleId))).toEqual(['eqeqeq']);
  });

  it('fails on a disable directive that disables nothing', async () => {
    const run = await lint('// eslint-disable-next-line no-console -- not needed\nexport const one = 1;\n');

    expect(run.fails).toBe(true);
  });

  it('only reports a SonarJS finding, counting it, with no fixable count left over', async () => {
    const run = await lint('export const nested = (c) => `a${`b${String(c)}`}`;\n');

    expect(run.fails).toBe(false);
    expect(run.reported).toEqual([['sonarjs/no-nested-template-literals', 1]]);
    expect(run.failing).toMatchObject([{ errorCount: 0, warningCount: 0, fixableErrorCount: 0 }]);
  });
});

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

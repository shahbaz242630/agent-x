// `pnpm lint`'s split (tooling/quality/lint.ts): the repository's own rules
// and parse errors always fail the run; a SonarJS rule only once it blocks.
import { describe, expect, it } from 'vitest';

import { BLOCKING, lintWith, reportByRule, reportedOnly, split } from './lint.ts';

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
    // A rule still reported only: once it blocks, pick another that isn't in BLOCKING.
    const run = await lint(
      'export const f = (n) => {\n  switch (n) {\n    case 1:\n      return 1;\n    default:\n      return 0;\n  }\n};\n',
    );

    expect(BLOCKING.has('sonarjs/no-small-switch')).toBe(false);
    expect(run.fails).toBe(false);
    expect(run.reported).toEqual([['sonarjs/no-small-switch', 1]]);
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

describe('each blocking SonarJS rule fails `pnpm lint` on a broken snippet', () => {
  // A rule that needs types is linted as this TypeScript file's text, which the project knows.
  const ruleIdsOf = async (code: string, typed: boolean) => {
    const filePath = typed ? 'tooling/quality/lint.test.ts' : 'tooling/quality/example.js';
    const run = split(await lintWith().lintText(code, { filePath }));
    return {
      fails: run.fails,
      rules: run.failing.flatMap((result) => result.messages.map((message) => message.ruleId)),
    };
  };
  // Six ifs, each inside the last: 1 + 2 + … + 6 = 21, past the 15 allowed.
  let deepest = 'return n;';
  for (let level = 6; level > 0; level -= 1) deepest = `if (n > ${String(level)}) {\n${deepest}\n}`;
  const twice = (name: string) =>
    `export function ${name}(list) {\n  const kept = list.filter(Boolean);\n  const count = kept.length;\n  return count * 2;\n}\n`;
  // Four tests of one shape, differing only in their literals: the shape the first report found.
  const alike = [
    "import { describe, it } from 'vitest';",
    'declare const newRow: () => Promise<string>;',
    'declare const tamper: (statement: string, id: string) => Promise<void>;',
    'declare const deniedWith: (id: string, sign: string) => Promise<void>;',
    "describe('tampering', () => {",
    ...[
      ['a status flipped', "update t set status = 'x'", 'seal'],
      ['a role raised', "update t set role = 'admin'", 'seal'],
      ['a pointer cleared', 'update t set p = null', 'pointer'],
      ['a name changed', "update t set name = 'y'", 'seal'],
    ].map(
      ([title, statement, sign]) =>
        `  it('${String(title)}', async () => {\n    const id = await newRow();\n    await tamper("${String(statement)}", id);\n\n    await deniedWith(id, '${String(sign)}');\n  });\n`,
    ),
    '});',
    '',
  ].join('\n');

  it.each([
    ['sonarjs/class-name', 'export class not_a_class_name {}\n'],
    ['sonarjs/cognitive-complexity', `export const f = (n) => {\n${deepest}\nreturn 0;\n};\n`],
    ['sonarjs/no-nested-functions', 'export const a = () => () => () => () => () => () => () => 1;\n'],
    [
      'sonarjs/updated-loop-counter',
      'export const sum = (n) => {\n  let total = 0;\n  for (let i = 0; i < n; i += 1) {\n    total += i;\n    i = total;\n  }\n  return total;\n};\n',
    ],
    ['sonarjs/no-identical-functions', twice('first') + twice('second')],
    ['sonarjs/no-inverted-boolean-check', 'export const notMore = (a, b) => !(a > b);\n'],
    // The shapes the first report found: a sort inside a call, a count bumped inside one.
    [
      'sonarjs/no-misleading-array-reverse',
      'const list: number[] = [3, 1, 2];\nexport const sortedTo = (use: (sorted: number[]) => void) => {\n  use(list.sort());\n};\n',
      true,
    ],
    ['sonarjs/no-nested-assignment', 'let count = 0;\nexport const next = (use) => use((count += 1));\n'],
    ['sonarjs/anchor-precedence', 'export const leadingOrAnywhere = /^a|b/;\n'],
    ['sonarjs/existing-groups', "export const replaced = (text: string): string => text.replace('a', '$0');\n", true],
    [
      'sonarjs/misplaced-loop-counter',
      'export const f = (n) => {\n  let i = 0;\n  for (let j = 0; i < n; j += 1) {\n    i += 2;\n  }\n  return i;\n};\n',
    ],
    ['sonarjs/no-nested-template-literals', 'export const say = (a, b) => `x${`y${a}`}${b}`;\n'],
    ['sonarjs/parameterized-tests', alike, true],
    [
      'sonarjs/prefer-specific-assertions',
      "import { expect, it } from 'vitest';\nit('counts', () => {\n  expect([1, 2].length).toBe(2);\n});\n",
      true,
    ],
  ])('%s', async (rule, code, typed = false) => {
    const { fails, rules } = await ruleIdsOf(code, typed);

    expect(BLOCKING.has(rule)).toBe(true);
    expect(fails).toBe(true);
    expect(rules).toContain(rule);
  });

  // The scrubber's old pattern: quadratic on a line of many `?`.
  const backtracks = "export const cut = (text) => text.replace(/[?#].*$/s, '');\n";

  it('sonarjs/super-linear-regex, in product code, where a stranger’s input reaches it', async () => {
    const run = split(await lintWith().lintText(backtracks, { filePath: 'packages/platform/src/example.js' }));

    expect(BLOCKING.has('sonarjs/super-linear-regex')).toBe(true);
    expect(run.fails).toBe(true);
    expect(run.failing.flatMap((result) => result.messages.map((message) => message.ruleId))).toContain(
      'sonarjs/super-linear-regex',
    );
  });

  it('but not in tooling, which reads only our own files (OWN_INPUT_ONLY)', async () => {
    const run = split(await lintWith().lintText(backtracks, { filePath: 'tooling/quality/example.js' }));

    expect(run.fails).toBe(false);
    expect(run.reported).toEqual([]);
  });
});

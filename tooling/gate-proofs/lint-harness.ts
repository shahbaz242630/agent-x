// Shared by the lint gate proofs. Each snippet is linted with the real
// eslint.config.js as if it sat at its path, so path-scoped rules apply as they
// would there. A rejected snippet must be reported by its rule; an allowed one
// must not be. Every snippet needs its own type-checked program, which takes up
// to a second on a busy machine, so the proofs are split across files that
// Vitest runs in parallel.
import { ESLint, type Linter } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

export interface LintCase {
  name: string;
  filePath: string;
  code: string;
  /** The rule that must report; null for ESLint's own reports (unused directives and inline configs). */
  rule: string | null;
  /** Text the message must contain, to tell apart checks that share a rule. */
  says?: string;
  /**
   * True for a snippet that needs the options `proveLintRules` was given: they
   * reach this file and no other, so a case meant to be judged by the real
   * configuration (an exemption, say) can't be given them by accident.
   */
  withOptions?: boolean;
}

/** Folders the snippets pretend to sit in. None exists on disk. */
export const CORE = 'packages/core/src/modules/gate-proof/domain';
export const PLATFORM = 'packages/platform/src/gate-proof';
export const CONFIG = 'packages/platform/src/config/gate-proof';
export const OUTBOUND = 'packages/platform/src/outbound/gate-proof';
export const API = 'apps/api/src/gate-proof';
export const CONSOLE = 'apps/console/src/gate-proof';
export const TESTING = 'packages/testing/src/gate-proof';
/** Inside the audit module, the one product module allowed to hold the signed-row steps (A3c). */
export const AUDIT = 'packages/core/src/modules/audit/gate-proof';
/** Inside the platform's database module, where the signed-row steps are written (A3c). */
export const PLATFORM_DB = 'packages/platform/src/db/gate-proof';

/**
 * A module's table description, for the A3c-2 proofs. The type is imported
 * from the platform, as product code imports it: the rule counts a declaration
 * only when the type came from there, so a local type alias of the same name
 * can't exempt a file.
 */
export const describes = (table: string, subject: string): string =>
  `import type { SignedStateTable } from '@agentx/platform/db';

export const TABLE: SignedStateTable = {
  table: '${table}',
  subject: '${subject}',
  fields: [{ column: 'status', type: 'text' }],
};
`;

/**
 * Lints every snippet with the real eslint.config.js and checks each verdict.
 *
 * `options` gives one rule other options, for a rule whose behaviour depends
 * on them (A3c's authority tables, whose registry is empty until slice B1).
 * They reach **only the snippets that ask for them** (`withOptions` on the
 * case), because a rule written into a block that matches everything applies
 * everywhere: it would switch the rule back on for the very paths the real
 * configuration turns it off for, and a proof of an exemption would then pass
 * while proving nothing. The folders are taken from those cases, so no caller
 * can get that wrong.
 */
export function proveLintRules(
  rejected: readonly LintCase[],
  allowed: readonly LintCase[],
  options: Linter.RulesRecord = {},
): void {
  const withOptions = [...rejected, ...allowed]
    .filter((testCase) => testCase.withOptions === true)
    .map((testCase) => testCase.filePath);
  const eslint = new ESLint({
    // The snippets are not on disk, so the TypeScript project service opens them
    // in a default project built from the root tsconfig.json.
    overrideConfig: [
      {
        files: ['**/*.{ts,tsx}'],
        languageOptions: {
          parserOptions: {
            projectService: {
              allowDefaultProject: [
                CORE,
                PLATFORM,
                CONFIG,
                OUTBOUND,
                API,
                CONSOLE,
                TESTING,
                AUDIT,
                PLATFORM_DB,
              ].flatMap((folder) => [`${folder}/*.ts`, `${folder}/*.tsx`]),
              defaultProject: 'tsconfig.json',
              // The limit guards editor performance; here every snippet uses the default project.
              maximumDefaultProjectFileMatchCount_THIS_WILL_SLOW_DOWN_LINTING: 100,
            },
          },
        },
      },
      // Last, so the options win for the snippets that asked for them and
      // nowhere else.
      ...(withOptions.length === 0 ? [] : [{ files: withOptions, rules: options }]),
    ],
  });

  const results = new Map<string, Linter.LintMessage[]>();

  beforeAll(async () => {
    for (const { name, filePath, code } of [...rejected, ...allowed]) {
      const [result] = await eslint.lintText(code, { filePath });
      results.set(name, result?.messages ?? []);
    }
  });

  const reports = (testCase: LintCase): boolean =>
    (results.get(testCase.name) ?? []).some(
      (message) =>
        message.ruleId === testCase.rule && (testCase.says === undefined || message.message.includes(testCase.says)),
    );
  const fatal = (testCase: LintCase): Linter.LintMessage[] =>
    (results.get(testCase.name) ?? []).filter((message) => message.fatal === true);

  describe('lint: every rule rejects its broken snippet', () => {
    it('gives every snippet its own file and name', () => {
      const cases = [...rejected, ...allowed];
      expect(new Set(cases.map((testCase) => testCase.filePath)).size).toBe(cases.length);
      expect(new Set(cases.map((testCase) => testCase.name)).size).toBe(cases.length);
    });

    it.each(rejected.map((testCase) => [testCase.name, testCase] as const))('%s', (_name, testCase) => {
      expect(fatal(testCase)).toEqual([]);
      expect(reports(testCase)).toBe(true);
    });
  });

  describe('lint: the rules leave safe code alone', () => {
    it.each(allowed.map((testCase) => [testCase.name, testCase] as const))('%s', (_name, testCase) => {
      expect(fatal(testCase)).toEqual([]);
      expect(reports(testCase)).toBe(false);
    });
  });
}

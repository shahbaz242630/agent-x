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
}

/** Folders the snippets pretend to sit in. None exists on disk. */
export const CORE = 'packages/core/src/modules/gate-proof/domain';
export const PLATFORM = 'packages/platform/src/gate-proof';
export const CONFIG = 'packages/platform/src/config/gate-proof';
export const OUTBOUND = 'packages/platform/src/outbound/gate-proof';
export const API = 'apps/api/src/gate-proof';
export const CONSOLE = 'apps/console/src/gate-proof';
export const TESTING = 'packages/testing/src/gate-proof';

export function proveLintRules(rejected: readonly LintCase[], allowed: readonly LintCase[]): void {
  const eslint = new ESLint({
    // The snippets are not on disk, so the TypeScript project service opens them
    // in a default project built from the root tsconfig.json.
    overrideConfig: {
      files: ['**/*.{ts,tsx}'],
      languageOptions: {
        parserOptions: {
          projectService: {
            allowDefaultProject: [CORE, PLATFORM, CONFIG, OUTBOUND, API, CONSOLE, TESTING].flatMap((folder) => [
              `${folder}/*.ts`,
              `${folder}/*.tsx`,
            ]),
            defaultProject: 'tsconfig.json',
            // The limit guards editor performance; here every snippet uses the default project.
            maximumDefaultProjectFileMatchCount_THIS_WILL_SLOW_DOWN_LINTING: 100,
          },
        },
      },
    },
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

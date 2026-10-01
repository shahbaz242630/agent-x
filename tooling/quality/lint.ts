// `pnpm lint` (Rule Book §5): ESLint once over the repository, with
// eslint.quality.config.js. Every finding of the repository's own rules
// fails the run, as `eslint --max-warnings 0` did. A SonarJS finding fails it
// only once its rule is in BLOCKING; until then it is reported, counted by
// rule, so the garbage-code findings can be cleaned one rule at a time and
// each rule then made to block (partner, S69).
import { ESLint } from 'eslint';

/** The SonarJS rules whose findings are cleaned, so they block like any other. */
export const BLOCKING: ReadonlySet<string> = new Set<string>([
  'sonarjs/anchor-precedence',
  'sonarjs/class-name',
  'sonarjs/existing-groups',
  'sonarjs/misplaced-loop-counter',
  'sonarjs/no-identical-functions',
  'sonarjs/no-inverted-boolean-check',
  'sonarjs/no-misleading-array-reverse',
  'sonarjs/no-nested-assignment',
  'sonarjs/no-nested-template-literals',
  'sonarjs/parameterized-tests',
  'sonarjs/prefer-specific-assertions',
]);

/** One finding, as ESLint gives it. */
interface Finding {
  readonly ruleId: string | null;
}

/** Whether a finding is only reported: a SonarJS rule not yet blocking. Anything else (a parse error included) fails the run. */
export const reportedOnly = (finding: Finding, blocking: ReadonlySet<string> = BLOCKING): boolean =>
  finding.ruleId !== null && finding.ruleId.startsWith('sonarjs/') && !blocking.has(finding.ruleId);

/** The reported findings, counted by rule, the most first. */
export function reportByRule(findings: readonly Finding[]): readonly (readonly [string, number])[] {
  const counts = new Map<string, number>();
  for (const { ruleId } of findings) {
    if (ruleId !== null) counts.set(ruleId, (counts.get(ruleId) ?? 0) + 1);
  }
  return [...counts].sort(([a, m], [b, n]) => n - m || (a < b ? -1 : 1));
}

/** The config `pnpm lint` runs: the repository's own rules and SonarJS's. */
export const lintWith = () => new ESLint({ overrideConfigFile: 'eslint.quality.config.js' });

/**
 * ESLint's results split: those that fail the run (every finding but the
 * reported-only ones, each result's counts made from what it keeps, as the
 * formatter reads them), and the reported ones counted by rule.
 */
export function split(results: readonly ESLint.LintResult[]) {
  const failing = results.map((result) => {
    const messages = result.messages.filter((message) => !reportedOnly(message));
    const errors = messages.filter((message) => message.severity === 2);
    const warnings = messages.filter((message) => message.severity !== 2);
    return {
      ...result,
      messages,
      errorCount: errors.length,
      warningCount: warnings.length,
      fixableErrorCount: errors.filter((message) => message.fix !== undefined).length,
      fixableWarningCount: warnings.filter((message) => message.fix !== undefined).length,
    };
  });
  const reported = reportByRule(
    results.flatMap((result) => result.messages.filter((message) => reportedOnly(message))),
  );
  return { failing, reported, fails: failing.some((result) => result.messages.length > 0) };
}

async function main(): Promise<number> {
  const eslint = lintWith();
  const { failing, reported, fails } = split(await eslint.lintFiles(['.']));
  if (reported.length > 0) {
    console.log('Garbage-code report (SonarJS, not yet blocking):');
    for (const [rule, count] of reported) console.log(`${String(count).padStart(6)}  ${rule}`);
  }
  const formatted = await (await eslint.loadFormatter('stylish')).format(failing);
  if (formatted !== '') console.log(formatted);
  return fails ? 1 : 0;
}

if (import.meta.main) process.exitCode = await main();

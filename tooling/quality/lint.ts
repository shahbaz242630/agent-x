// `pnpm lint` (Rule Book §5): ESLint once over the repository, with
// eslint.quality.config.js. Every finding of the repository's own rules
// fails the run, as `eslint --max-warnings 0` did. A SonarJS finding fails it
// only once its rule is in BLOCKING; until then it is reported, counted by
// rule, so the garbage-code findings can be cleaned one rule at a time and
// each rule then made to block (partner, S69).
import { ESLint } from 'eslint';

/** The SonarJS rules whose findings are cleaned, so they block like any other. */
export const BLOCKING: ReadonlySet<string> = new Set<string>([]);

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

async function main(): Promise<number> {
  const eslint = new ESLint({ overrideConfigFile: 'eslint.quality.config.js' });
  const results = await eslint.lintFiles(['.']);
  const failing = results.map((result) => ({
    ...result,
    messages: result.messages.filter((message) => !reportedOnly(message)),
  }));
  // Counts kept with the messages, as the formatter reads them.
  for (const result of failing) {
    result.errorCount = result.messages.filter((message) => message.severity === 2).length;
    result.warningCount = result.messages.length - result.errorCount;
  }
  const reported = reportByRule(
    results.flatMap((result) => result.messages.filter((message) => reportedOnly(message))),
  );
  if (reported.length > 0) {
    console.log('Garbage-code report (SonarJS, not yet blocking):');
    for (const [rule, count] of reported) console.log(`${String(count).padStart(6)}  ${rule}`);
  }
  const formatted = await (await eslint.loadFormatter('stylish')).format(failing);
  if (formatted !== '') console.log(formatted);
  return failing.some((result) => result.messages.length > 0) ? 1 : 0;
}

if (import.meta.main) process.exitCode = await main();

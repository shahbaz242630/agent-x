// A load run's report (D2, PL-38), numbers only: kept in tooling/load/reports
// so runs can be compared version to version. A laptop's numbers show the
// answers stay right under load and how one version compares with another;
// PL-38 closes only on the same run against a production-sized Azure stack.
import type { LogSummary } from './logs.ts';
import { STAGING_API_CPUS } from './plan.ts';

/** One phase as k6 sums it up (money-paths.k6.js, handleSummary). */
export interface PhaseResult {
  readonly phase: number;
  readonly requests: number;
  readonly created: number;
  readonly serverErrors: number;
  readonly rateLimited: number;
  readonly checksFailed: number;
  /** Requests k6 never sent, having no free VU: the load fell short of the plan. */
  readonly dropped: number;
  readonly asksMs: { readonly p50: number; readonly p95: number; readonly p99: number; readonly max: number };
  /** Each threshold, as `metric rule`, and whether it held. */
  readonly thresholds: Readonly<Record<string, boolean>>;
}

export interface RunResult {
  /** When it ran, as an ISO time. */
  readonly at: string;
  /** The commit it ran. */
  readonly commit: string;
  /** The CPUs the API was given: staging's half unless the run said otherwise. */
  readonly apiCpus: number;
  readonly phases: readonly PhaseResult[];
  readonly logs: LogSummary;
  readonly databaseChecksPassed: boolean;
  /** Every check that failed, in plain words: none on a clean run. */
  readonly failures: readonly string[];
}

const ms = (value: number) => value.toFixed(1);

/** What k6's numbers say went wrong, in plain words. */
export function phaseFailures(phase: PhaseResult): string[] {
  const failed = Object.entries(phase.thresholds)
    .filter(([, held]) => !held)
    .map(([rule]) => `Phase ${String(phase.phase)}: k6's threshold ${rule} did not hold.`);
  return phase.created === 0 ? [...failed, `Phase ${String(phase.phase)}: no request was made.`] : failed;
}

export function renderReport(run: RunResult): string {
  const { decisions } = run.logs;
  const checked = run.logs.holdingsChecks.reduce((sum, { requests }) => sum + requests, 0);
  const size =
    run.apiCpus === STAGING_API_CPUS
      ? "sized as staging's (half a CPU, 1 GiB, ten connections)"
      : `given ${String(run.apiCpus)} CPU(s) (staging has half), 1 GiB and ten connections as staging`;
  const lines = [
    `# Load test, ${run.at.slice(0, 10)} (local, API ${String(run.apiCpus)} CPU)`,
    '',
    run.failures.length === 0 ? '**Passed.**' : `**Failed: ${String(run.failures.length)} check(s).**`,
    '',
    `Commit \`${run.commit}\`, run at ${run.at}, on a laptop: the compose stack's database and API only, the API`,
    `${size}, k6 straight to it. As on staging today, the hand-off is`,
    'paused: its timer re-checks the approved requests each run, and that work is in these numbers. Laptop numbers compare versions;',
    'they do not close PL-38, which closes on the same run on Azure, production-sized, before live.',
    '',
    '## Requests (k6)',
    '',
    '| Phase | Requests | New | Not sent | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
    ...run.phases.map(
      (p) =>
        `| ${String(p.phase)} | ${String(p.requests)} | ${String(p.created)} | ${String(p.dropped)} | ${ms(p.asksMs.p50)} | ${ms(p.asksMs.p95)} | ` +
        `${ms(p.asksMs.p99)} | ${ms(p.asksMs.max)} | ${String(p.serverErrors)} | ${String(p.rateLimited)} | ${String(p.checksFailed)} |`,
    ),
    '',
    'Target: a request p95 under 500 ms, with every planned request sent.',
    '',
    '## Decisions (the API’s log)',
    '',
    '| Decisions | p50 ms | p95 ms | p99 ms | Max ms |',
    '| --- | --- | --- | --- | --- |',
    `| ${String(decisions.count)} | ${String(decisions.p50)} | ${String(decisions.p95)} | ${String(decisions.p99)} | ${String(decisions.max)} |`,
    '',
    'Target: a decision p95 under 150 ms, timed over its whole transaction (lock waits, retries, the reservation, signing).',
    '',
    '## Checks',
    '',
    `- The database after the run: ${run.databaseChecksPassed ? 'passed' : 'failed'} (each request once, every month within its limit, holdings exactly matching decisions, one open claim an order, no integrity hold).`,
    `- The holdings check at the restart: ${String(run.logs.holdingsChecks.length)} run(s) over ${String(checked)} request(s).`,
    `- Warnings or errors logged: ${String(Object.values(run.logs.problems).reduce((sum, n) => sum + n, 0))}; lines suppressed: ${String(run.logs.suppressed)}.`,
  ];
  if (run.failures.length > 0) lines.push('', '## What failed', '', ...run.failures.map((failure) => `- ${failure}`));
  return `${lines.join('\n')}\n`;
}

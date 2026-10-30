// A load run's report (D2, PL-38), numbers only: kept in tooling/load/reports
// so runs can be compared version to version. A laptop's numbers show the
// answers stay right under load and how one version compares with another;
// PL-38 closes only on the same run against a production-sized Azure stack
// (D2c), whose report says so.
import type { LogSummary, Percentiles } from './logs.ts';
import { type LoadSite, STAGING_API_CPUS } from './plan.ts';

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
  /** Phase 2's spike, timed apart from the steady traffic (money-paths.k6.js); null in phase 1. */
  readonly spikeMs: { readonly p50: number; readonly p95: number; readonly max: number } | null;
  /** Each threshold, as `metric rule`, and whether it held. */
  readonly thresholds: Readonly<Record<string, boolean>>;
}

/** The statements the app's role ran while one phase ran: the API's for its requests, and its timers'. */
export interface PhaseStatements {
  readonly phase: number;
  readonly statements: number;
}

export interface RunResult {
  /** When it ran, as an ISO time. */
  readonly at: string;
  /** The commit it ran. */
  readonly commit: string;
  /** The laptop's compose stack, or staging on Azure sized up for the run. */
  readonly site: LoadSite;
  /** The CPUs the API was given: staging's half unless the run said otherwise. */
  readonly apiCpus: number;
  /** On Azure (load.ts): the database server's size as Azure gave it (`Standard_D2ads_v5 (GeneralPurpose)`). */
  readonly database?: string;
  /** The wiring run's short k6 (load.ts run --smoke): it proves the run is wired and measures nothing. */
  readonly smoke?: boolean;
  readonly phases: readonly PhaseResult[];
  /** On the laptop (`--delay-ms`): whole ms added to every packet the database sent, as Azure's network adds them. */
  readonly delayMs?: number;
  /** On the laptop: the app's round trips over each phase (pg_stat_statements, less statements sent in another's trip). */
  readonly statements?: readonly PhaseStatements[];
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

/** Where a laptop run ran, and why its numbers don't close PL-38. */
function onTheLaptop(run: RunResult): string[] {
  const size =
    run.apiCpus === STAGING_API_CPUS
      ? "sized as staging's (half a CPU, 1 GiB, ten connections)"
      : `given ${String(run.apiCpus)} CPU(s) (staging has half), 1 GiB and ten connections as staging`;
  const delayed =
    run.delayMs === undefined || run.delayMs === 0
      ? ''
      : ` ${String(run.delayMs)} ms was added to every packet the database sent, as Azure's network adds it.`;
  return [
    `Commit \`${run.commit}\`, run at ${run.at}, on a laptop: the compose stack's database and API only, the API`,
    `${size}, k6 straight to it.${delayed} As on staging today, the hand-off is`,
    'paused: its timer re-checks the approved requests each run, and that work is in these numbers. Laptop numbers compare versions;',
    'they do not close PL-38, which closes on the same run on Azure, production-sized, before live.',
  ];
}

/** Where an Azure run ran: the run PL-38 closes on. */
function onAzure(run: RunResult): string[] {
  const lines = [
    `Commit \`${run.commit}\`, run at ${run.at}, on staging in Azure UAE North: the API`,
    `given ${String(run.apiCpus)} CPU(s) and ten connections, the database ${run.database ?? 'of a size not read'}, k6 in a job inside`,
    "staging's own network, through the API's internal address. The hand-off is paused, as on staging today: its timer",
    're-checks the approved requests each run, and that work is in these numbers.',
  ];
  return run.smoke === true
    ? [
        ...lines,
        '**The wiring run (--smoke): 20 seconds of k6 at 5 a second. It proves every step is wired; its numbers measure nothing.**',
      ]
    : [...lines, 'Sized up for the run, this is the run PL-38 closes on (D2c).'];
}

/** The database trips each request cost, phase by phase: the number 4D2d brings down. */
function tripsLine(run: RunResult): string[] {
  const each = (run.statements ?? []).flatMap(({ phase, statements }) => {
    const requests = run.phases.find((p) => p.phase === phase)?.requests ?? 0;
    return requests === 0 ? [] : [`phase ${String(phase)} ${(statements / requests).toFixed(1)}`];
  });
  return each.length === 0
    ? []
    : [
        `Database trips a request (the app's round trips over the phase, its timers' included: its statements by pg_stat_statements, less those sent in another's trip): ${each.join(', ')}.`,
      ];
}

const decisionRow = (traffic: string, { count, p50, p95, p99, max }: Percentiles) =>
  `| ${traffic} | ${String(count)} | ${String(p50)} | ${String(p95)} | ${String(p99)} | ${String(max)} |`;

export function renderReport(run: RunResult): string {
  const { decisions, spikeDecisions } = run.logs;
  const spiked = run.phases.flatMap(({ phase, spikeMs }) => (spikeMs === null ? [] : [{ phase, spikeMs }]));
  const checked = run.logs.holdingsChecks.reduce((sum, { requests }) => sum + requests, 0);
  const lines = [
    `# Load test, ${run.at.slice(0, 10)} (${run.site}${run.smoke === true ? ', smoke' : ''}, API ${String(run.apiCpus)} CPU)`,
    '',
    run.failures.length === 0 ? '**Passed.**' : `**Failed: ${String(run.failures.length)} check(s).**`,
    '',
    ...(run.site === 'local' ? onTheLaptop(run) : onAzure(run)),
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
    'Target: a request p95 under 500 ms, with every planned request sent: the steady traffic, not the spike.',
    ...tripsLine(run),
    ...spiked.map(
      ({ phase, spikeMs }) =>
        `Phase ${String(phase)}'s spike, 50 requests at once from the capped agent, queued on its month's lock by design: ` +
        `p50 ${ms(spikeMs.p50)} ms, p95 ${ms(spikeMs.p95)} ms, max ${ms(spikeMs.max)} ms.`,
    ),
    '',
    '## Decisions (the API’s log)',
    '',
    '| Traffic | Decisions | p50 ms | p95 ms | p99 ms | Max ms |',
    '| --- | --- | --- | --- | --- | --- |',
    decisionRow('Steady', decisions),
    ...(spikeDecisions.count === 0 ? [] : [decisionRow('The spike', spikeDecisions)]),
    '',
    'Target: a steady decision p95 under 150 ms, timed over its whole transaction (lock waits, retries, the reservation, signing).',
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

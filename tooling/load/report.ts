// A load run's report (D2, PL-38), numbers only: kept in tooling/load/reports
// so runs can be compared version to version. A laptop's numbers show the
// answers stay right under load and how one version compares with another;
// PL-38 closes only on the same run against a production-sized Azure stack
// (D2c), whose report says so.
import type { DecisionParts, LogSummary, NeighbourKind, Percentiles } from './logs.ts';
import { type LoadSite, NEIGHBOURS_PHASE, POLICY_P95_MS, STAGING_API_CPUS } from './plan.ts';

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
  /** Phase 5's: each kind of organisation's requests, as k6 saw them. */
  readonly neighbours?: Readonly<Record<NeighbourKind, NeighbourRequests>>;
  /** Phase 5's: when it ran, which lines of the API's log are its trouble's. */
  readonly startedAt?: string;
  readonly endedAt?: string;
}

/** One kind of organisation's requests in phase 5, as k6 saw them. */
interface NeighbourRequests {
  readonly requests: number;
  readonly serverErrors: number;
  readonly rateLimited: number;
  readonly p95Ms: number;
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

/** The phases of the crowds, reported apart from the steady traffic's. */
const CROWD_PHASES: readonly {
  readonly phase: number;
  readonly setup: string;
  readonly of: 'crowdOwnDecisions' | 'crowdSharedDecisions';
}[] = [
  { phase: 3, setup: 'Each agent with its own three suppliers', of: 'crowdOwnDecisions' },
  { phase: 4, setup: 'All agents sharing three suppliers', of: 'crowdSharedDecisions' },
];

/** Where a laptop run ran, and why its numbers don't close PL-38. */
function onTheLaptop(run: RunResult): string[] {
  const size =
    run.apiCpus === STAGING_API_CPUS
      ? "sized as staging's (half a CPU, 1 GiB), with the load run's twenty connections"
      : `given ${String(run.apiCpus)} CPU(s) (staging has half), 1 GiB and the load run's twenty connections`;
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
    `given ${String(run.apiCpus)} CPU(s) and twenty connections, the database ${run.database ?? 'of a size not read'}, k6 in a job inside`,
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

/** Each crowd that missed the decision target, in plain words, whether or not its phase ran to the end. */
const crowdMisses = (run: RunResult): string[] =>
  CROWD_PHASES.flatMap(({ setup, of }) =>
    run.logs[of].p95 >= POLICY_P95_MS ? [`${setup}: a decision's p95 was ${String(run.logs[of].p95)} ms.`] : [],
  );

/** Each crowd with no phase summary or no decisions: never read as having met the target. */
const crowdsUnmeasured = (run: RunResult): string[] =>
  CROWD_PHASES.flatMap(({ phase, setup, of }) =>
    run.logs[of].count > 0 && run.phases.some((p) => p.phase === phase) ? [] : [`${setup}: not measured.`],
  );

/** The crowds' numbers, apart: a miss of the decision target is named here, and doesn't yet fail the run (the partner's call). */
function crowdSection(run: RunResult): string[] {
  const rows = CROWD_PHASES.flatMap(({ phase, setup, of }) => {
    const p = run.phases.find((candidate) => candidate.phase === phase);
    if (p === undefined) return [];
    const parts = run.logs[of];
    const { count, p50, p95, p99, max } = parts;
    return [
      `| ${setup} | ${String(p.requests)} | ${String(p.dropped)} | ${ms(p.asksMs.p95)} | ${String(count)} | ${String(p50)} | ${String(p95)} | ` +
        `${String(p99)} | ${String(max)} | ${String(p.serverErrors)} | ${String(p.rateLimited)} | ${String(p.checksFailed)} | ${partsCells(parts)} |`,
    ];
  });
  const misses = crowdMisses(run);
  const unmeasured = crowdsUnmeasured(run);
  const verdict = [
    ...(misses.length === 0 ? [] : [`**Decision target missed (${String(POLICY_P95_MS)} ms).** ${misses.join(' ')}`]),
    ...unmeasured,
  ];
  return rows.length === 0 && misses.length === 0
    ? []
    : [
        '',
        `## Many agents in one organisation (apart from the numbers above; the same ${String(POLICY_P95_MS)} ms decision target, not yet failing a run)`,
        '',
        'Ten agents of one organisation, 25 requests a second between them, picked at random, with the same duplicates and replays. They share its chain head, and in the second row each supplier’s lock too.',
        '',
        `| Setup | Requests | Not sent | Request p95 ms | Decisions | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed | ${PARTS_HEADINGS} |`,
        '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
        ...rows,
        '',
        verdict.length === 0
          ? `Decision target met in each: p95 under ${String(POLICY_P95_MS)} ms.`
          : verdict.join(' '),
      ];
}

/** Phase 5's calm organisations, if they missed the decision target beside the others' trouble: in plain words. */
function neighbourMiss(run: RunResult): string[] {
  const { p95, count } = run.logs.neighbours.calm;
  const ran = run.phases.some(({ phase }) => phase === NEIGHBOURS_PHASE);
  if (ran && count === 0) return ['Calm organisations beside the others: not measured.'];
  return p95 >= POLICY_P95_MS
    ? [
        `Calm organisations beside a busy and a stuck one: a decision's p95 was ${String(p95)} ms, against the ${String(POLICY_P95_MS)} ms target.`,
      ]
    : [];
}

const partsCells = ({ connectionWaitP95, turnWaitP95, tripsP50, supplierLockP95, headLockP95 }: DecisionParts) =>
  [connectionWaitP95, turnWaitP95, tripsP50, supplierLockP95, headLockP95].map(String).join(' | ');

const PARTS_HEADINGS =
  "Connection wait p95 ms | Own agent wait p95 ms | Trips p50 | Supplier's lock trip p95 ms | Chain head trip p95 ms";

/** One organisation's trouble beside others (PL-63): the same target, each kind apart, beside the quiet phases. */
function neighbourSection(run: RunResult): string[] {
  const requests = run.phases.find(({ phase }) => phase === NEIGHBOURS_PHASE)?.neighbours;
  if (requests === undefined) return [];
  const { neighbours, decisions, steadyParts, neighbourProblems } = run.logs;
  const row = (name: string, kind: NeighbourKind) => {
    const r = requests[kind];
    const d = neighbours[kind];
    return (
      `| ${name} | ${String(r.requests)} | ${ms(r.p95Ms)} | ${String(r.serverErrors)} | ${String(r.rateLimited)} | ${String(d.count)} | ` +
      `${String(d.p50)} | ${String(d.p95)} | ${String(d.p99)} | ${partsCells(d)} |`
    );
  };
  const miss = neighbourMiss(run);
  const problems = Object.entries(neighbourProblems).map(([event, count]) => `${event} ${String(count)}`);
  return [
    '',
    `## One organisation's trouble beside others (the same ${String(POLICY_P95_MS)} ms decision target, not yet failing a run)`,
    '',
    'Ten calm organisations, sending what the steady traffic sends, beside a busy organisation (25 requests a second on three shared suppliers) and a stuck one (5 a second, two of its three suppliers held locked for the phase). The calm ones should read as the quiet phases do.',
    '',
    `| Traffic | Requests | Request p95 ms | 5xx | 429 | Decisions | p50 ms | p95 ms | p99 ms | ${PARTS_HEADINGS} |`,
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
    `| Quiet (phases 1 and 2) | | | | | ${String(decisions.count)} | ${String(decisions.p50)} | ${String(decisions.p95)} | ${String(decisions.p99)} | ${partsCells(steadyParts)} |`,
    row('Calm, beside the others', 'calm'),
    row('Busy organisation', 'busy'),
    row('Stuck organisation', 'stuck'),
    '',
    miss.length === 0
      ? `Decision target met by the calm organisations: p95 under ${String(POLICY_P95_MS)} ms.`
      : `**${miss.join(' ')}**`,
    `Warnings or errors while it ran: ${problems.length === 0 ? 'none' : problems.join(', ')}.`,
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
    // Never only "Passed" above a miss further down (partner's heads-up, S164).
    ...(crowdMisses(run).length === 0
      ? []
      : [
          '',
          `**But many agents in one organisation missed the ${String(POLICY_P95_MS)} ms decision target: see below.**`,
        ]),
    ...(neighbourMiss(run).length === 0
      ? []
      : ['', `**But one organisation's trouble reached others. ${neighbourMiss(run).join(' ')} See below.**`]),
    '',
    ...(run.site === 'local' ? onTheLaptop(run) : onAzure(run)),
    '',
    '## Requests (k6)',
    '',
    '| Phase | Requests | New | Not sent | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
    ...run.phases
      .filter(({ phase }) => phase <= 2)
      .map(
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
    `Allowed at once: ${String(run.logs.allowed)} of the ${String(decisions.count)} steady decisions; the rest wait for a person, or are denied. Hand-offs are paused, so what follows an allowed request isn't timed.`,
    ...crowdSection(run),
    ...neighbourSection(run),
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

// What the API's log says about a load run (D2, PL-38): how long each
// decision took (`spend_request.decided`'s `durationMs`, D2a), the holdings
// checks that ran (at the restart between the phases, under load), and every
// line that should not be there: any warning or error (a retried
// transaction, `db.transaction_retried`, among them), a line the volume
// guard suppressed, or one that isn't the logger's JSON.

export interface Percentiles {
  readonly count: number;
  readonly p50: number;
  readonly p95: number;
  readonly p99: number;
  readonly max: number;
}

export interface LogSummary {
  /** Each warning or error event, by name, with how many times it came. */
  readonly problems: Readonly<Record<string, number>>;
  /** Lines the volume guard dropped: the run's own lines must all be there. */
  readonly suppressed: number;
  /** Lines that aren't the logger's JSON (a crash's stack, say). */
  readonly unreadable: number;
  readonly holdingsChecks: readonly {
    readonly requests: number;
    readonly mismatched: number;
    readonly tampered: number;
  }[];
  /** The steady traffic's decisions: the ones the decision target is for. */
  readonly decisions: Percentiles;
  /** Phase 2's spike's: 50 at once on one agent's month, queued on its lock by design, so apart. */
  readonly spikeDecisions: Percentiles;
  /** Phase 3's crowd's, ten agents of one organisation with suppliers of their own: apart, with no target yet. */
  readonly crowdOwnDecisions: Percentiles;
  /** Phase 4's crowd's, ten agents of one organisation sharing three suppliers: apart, with no target yet. */
  readonly crowdSharedDecisions: Percentiles;
  /** How many of the steady traffic's decisions allowed the request at once: about half, as it means to. */
  readonly allowed: number;
}

interface Line {
  readonly level?: string;
  readonly event?: string;
  readonly durationMs?: number;
  readonly decision?: string;
  readonly orgId?: string;
  readonly requests?: number;
  readonly mismatched?: number;
  readonly tampered?: number;
}

/** The nearest-rank percentile of values sorted ascending: 0 when there are none. */
export function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)] ?? 0;
}

export function percentilesOf(values: readonly number[]): Percentiles {
  const sorted = [...values].sort((a, b) => a - b);
  return {
    count: sorted.length,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    max: sorted.at(-1) ?? 0,
  };
}

const readLine = (text: string): Line | undefined => {
  try {
    const parsed = JSON.parse(text) as Line | null;
    return typeof parsed === 'object' && parsed !== null ? parsed : undefined;
  } catch {
    return undefined;
  }
};

/** A holdings check's line, as what it checked; a check stopped at its share of pages says what it checked so far. */
const isHoldingsCheck = ({ event }: Line) => event === 'holdings_check.passed' || event === 'holdings_check.paused';
const isProblem = ({ level }: Line) => level === 'warn' || level === 'error' || level === 'fatal';

/** The organisations whose decisions are timed apart from the steady traffic's. */
export interface ApartOrgs {
  /** The capped agent's. */
  readonly spike?: ReadonlySet<string>;
  /** Phase 3's crowd's. */
  readonly crowdOwn?: ReadonlySet<string>;
  /** Phase 4's crowd's. */
  readonly crowdShared?: ReadonlySet<string>;
}

/** The organisations of the agents of one kind, from a run's seed or a job's printed lines. */
const orgsOfKind = (agents: readonly { readonly kind?: unknown; readonly orgId?: unknown }[], kind: string) =>
  new Set(agents.flatMap((agent) => (agent.kind === kind && typeof agent.orgId === 'string' ? [agent.orgId] : [])));

/** Which of a run's organisations are timed apart, by their agents' kinds. */
export const apartOrgsOf = (agents: readonly { readonly kind?: unknown; readonly orgId?: unknown }[]): ApartOrgs => ({
  spike: orgsOfKind(agents, 'capped'),
  crowdOwn: orgsOfKind(agents, 'crowd-own'),
  crowdShared: orgsOfKind(agents, 'crowd-shared'),
});

/** Below this share allowed, the steady traffic isn't the mix it means to be (S164: the split check made it 0.4%). */
const LEAST_ALLOWED_SHARE = 0.3;

/** Too few decisions say nothing about the mix: the wiring run's. */
const LEAST_DECISIONS_FOR_THE_MIX = 100;

/** The API's log, as `docker compose logs --no-log-prefix` prints it, summed up. */
export function summariseLogs(text: string, apart: ApartOrgs = {}): LogSummary {
  const raws = text.split(/\r?\n/).filter((raw) => raw.trim() !== '');
  const lines = raws.map(readLine).filter((line) => line !== undefined);
  const problems: Record<string, number> = {};
  for (const { event = '(no event)' } of lines.filter(isProblem)) problems[event] = (problems[event] ?? 0) + 1;
  const decided = lines.filter((line) => line.event === 'spend_request.decided' && line.durationMs !== undefined);
  const timesIn = (orgs: ReadonlySet<string> | undefined) =>
    decided.filter(({ orgId = '' }) => orgs?.has(orgId) === true).map(({ durationMs = 0 }) => durationMs);
  const steady = decided.filter(
    ({ orgId = '' }) =>
      apart.spike?.has(orgId) !== true && apart.crowdOwn?.has(orgId) !== true && apart.crowdShared?.has(orgId) !== true,
  );
  return {
    problems,
    suppressed: lines.filter(({ event }) => event === 'log.suppressed').length,
    unreadable: raws.length - lines.length,
    holdingsChecks: lines.filter(isHoldingsCheck).map(({ requests = 0, mismatched = -1, tampered = -1 }) => ({
      requests,
      mismatched,
      tampered,
    })),
    decisions: percentilesOf(steady.map(({ durationMs = 0 }) => durationMs)),
    spikeDecisions: percentilesOf(timesIn(apart.spike)),
    crowdOwnDecisions: percentilesOf(timesIn(apart.crowdOwn)),
    crowdSharedDecisions: percentilesOf(timesIn(apart.crowdShared)),
    allowed: steady.filter(({ decision }) => decision === 'ALLOW').length,
  };
}

/**
 * What the log shows went wrong, in plain words: none when the run was
 * clean. `decided` is how many decisions the run made, which the log must
 * account for one line each.
 */
export function logFailures(summary: LogSummary, decided: number, policyP95Ms: number): string[] {
  const failures = Object.entries(summary.problems).map(
    ([event, count]) => `The API logged ${event} ${String(count)} time(s); a load run must log no warning or error.`,
  );
  if (summary.suppressed > 0) failures.push('The API suppressed log lines, so the run’s numbers are incomplete.');
  if (summary.unreadable > 0) {
    failures.push(`${String(summary.unreadable)} line(s) of the API’s output were not its JSON log: read the log.`);
  }
  // The check at the restart between the phases, under load: the first start's had no requests to check.
  if (!summary.holdingsChecks.some(({ requests }) => requests > 0)) {
    failures.push('The holdings check did not check any request: it did not run at the restart between the phases.');
  }
  if (summary.holdingsChecks.some(({ mismatched, tampered }) => mismatched !== 0 || tampered !== 0)) {
    failures.push('A holdings check found a request whose money held did not match its decision.');
  }
  const lines =
    summary.decisions.count +
    summary.spikeDecisions.count +
    summary.crowdOwnDecisions.count +
    summary.crowdSharedDecisions.count;
  if (lines !== decided) {
    failures.push(`The log has ${String(lines)} decision line(s) for ${String(decided)} decision(s).`);
  }
  const { count } = summary.decisions;
  if (count >= LEAST_DECISIONS_FOR_THE_MIX && summary.allowed / count < LEAST_ALLOWED_SHARE) {
    failures.push(
      `Only ${String(summary.allowed)} of ${String(count)} steady decisions allowed the request at once: the run should allow about half, or it measures one path only.`,
    );
  }
  if (summary.decisions.p95 >= policyP95Ms) {
    failures.push(
      `A decision's p95 was ${String(summary.decisions.p95)} ms, at or past the ${String(policyP95Ms)} ms target.`,
    );
  }
  return failures;
}

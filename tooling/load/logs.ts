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
}

interface Line {
  readonly level?: string;
  readonly event?: string;
  readonly durationMs?: number;
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

/**
 * The API's log, as `docker compose logs --no-log-prefix` prints it, summed
 * up; a decision in one of `spikeOrgs` (the capped agent's organisation) is
 * the spike's.
 */
export function summariseLogs(text: string, spikeOrgs: ReadonlySet<string> = new Set()): LogSummary {
  const problems: Record<string, number> = {};
  const holdingsChecks: { requests: number; mismatched: number; tampered: number }[] = [];
  const durations: number[] = [];
  const spiked: number[] = [];
  let suppressed = 0;
  let unreadable = 0;
  for (const raw of text.split(/\r?\n/)) {
    if (raw.trim() === '') continue;
    const line = readLine(raw);
    if (line === undefined) {
      unreadable += 1;
      continue;
    }
    const event = line.event ?? '(no event)';
    if (line.level === 'warn' || line.level === 'error' || line.level === 'fatal') {
      problems[event] = (problems[event] ?? 0) + 1;
    }
    if (event === 'log.suppressed') suppressed += 1;
    // A check stopped at its share of pages says what it checked so far; it goes on at the next run.
    if (event === 'holdings_check.passed' || event === 'holdings_check.paused') {
      holdingsChecks.push({
        requests: line.requests ?? 0,
        mismatched: line.mismatched ?? -1,
        tampered: line.tampered ?? -1,
      });
    }
    if (event === 'spend_request.decided' && typeof line.durationMs === 'number') {
      (spikeOrgs.has(line.orgId ?? '') ? spiked : durations).push(line.durationMs);
    }
  }
  return {
    problems,
    suppressed,
    unreadable,
    holdingsChecks,
    decisions: percentilesOf(durations),
    spikeDecisions: percentilesOf(spiked),
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
  const lines = summary.decisions.count + summary.spikeDecisions.count;
  if (lines !== decided) {
    failures.push(`The log has ${String(lines)} decision line(s) for ${String(decided)} decision(s).`);
  }
  if (summary.decisions.p95 >= policyP95Ms) {
    failures.push(
      `A decision's p95 was ${String(summary.decisions.p95)} ms, at or past the ${String(policyP95Ms)} ms target.`,
    );
  }
  return failures;
}

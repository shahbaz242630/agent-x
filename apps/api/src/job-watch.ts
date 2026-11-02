// A job that has stopped, seen from inside (4D2e D, PL-33 part, PL-34). Each job
// has its runs' starts and ends recorded. Each minute a pulse looks at them:
// - a run going past its job's limit logs `job.stalled` once;
// - where the jobs are, `jobs.pulse` says the process is alive and looking, which
//   the outside's dead-man rule reads (no pulse for too long: nothing is running).
// A job that says it skipped its run three times in a row logs `job.skipping_runs`
// once a streak: a warning a run alone gave went unseen for 10+ days (S122).
//
// It can't fire asleep. A process that wakes after a freeze has every clock ahead
// and its runs seemingly hours old: a pulse arriving late forgives what it finds.
// Staging scales to zero, where a wake is a new process with nothing yet recorded.
import type { Logger } from '@agentx/platform/observability';

/** How often the pulse looks. */
export const PULSE_EVERY_MS = 60_000;

/** A pulse this late means the process was frozen or asleep, not that its jobs were slow. */
const ASLEEP_AFTER_MS = 2 * PULSE_EVERY_MS;

/** How many skipped runs in a row are worth saying. */
const SKIPS_TO_SAY = 3;

/** A job's work: what a timer runs. A run that says 'skipped' did nothing it was there to do. */
export interface Work {
  run(signal?: AbortSignal): Promise<unknown>;
}

/** Work with its runs recorded, and the job's name. */
export interface WatchedWork {
  readonly name: string;
  run(signal?: AbortSignal): Promise<void>;
}

interface JobState {
  readonly stalledAfterMs: number;
  /** When the run in flight began; undefined between runs. */
  since: number | undefined;
  /** Whether this run's stall has been said. */
  said: boolean;
  skips: number;
}

export interface JobWatch {
  /** Its own job's name: it is scheduled as a job, unwatched. */
  readonly name: 'pulse';
  /** The work with its runs recorded under this name. */
  watching(name: string, work: Work, stalledAfterMs: number): WatchedWork;
  /** One pulse. Never throws. */
  run(): Promise<void>;
}

export function createJobWatch({
  logger,
  now,
  pulsing,
}: {
  readonly logger: Logger;
  readonly now: () => number;
  /** Whether this process runs the `jobs` side now: a `web` copy, or a follower, would hide those jobs having stopped. */
  readonly pulsing: () => boolean;
}): JobWatch {
  const jobs = new Map<string, JobState>();
  let lastPulse = now();

  const forgive = (at: number): void => {
    for (const state of jobs.values()) {
      if (state.since !== undefined) state.since = at;
    }
  };

  const sayStalled = (at: number): number => {
    let running = 0;
    for (const [job, state] of jobs) {
      if (state.since === undefined) continue;
      running += 1;
      const runningMs = at - state.since;
      if (runningMs > state.stalledAfterMs && !state.said) {
        state.said = true;
        logger.error('job.stalled', { job, runningMs, limitMs: state.stalledAfterMs });
      }
    }
    return running;
  };

  return {
    name: 'pulse',
    watching(name, work, stalledAfterMs) {
      const state: JobState = { stalledAfterMs, since: undefined, said: false, skips: 0 };
      jobs.set(name, state);
      return {
        name,
        async run(signal) {
          state.since = now();
          state.said = false;
          try {
            const result = await work.run(signal);
            state.skips = result === 'skipped' ? state.skips + 1 : 0;
            if (state.skips === SKIPS_TO_SAY) logger.error('job.skipping_runs', { job: name, runs: state.skips });
          } finally {
            state.since = undefined;
          }
        },
      };
    },
    run() {
      const at = now();
      if (at - lastPulse > ASLEEP_AFTER_MS) forgive(at);
      lastPulse = at;
      const running = sayStalled(at);
      if (pulsing()) logger.info('jobs.pulse', { jobs: jobs.size, running });
      return Promise.resolve();
    },
  };
}

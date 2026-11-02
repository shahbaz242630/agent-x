// 4D2e D (PL-33 part, PL-34): a job that has stopped, seen from inside.
import { LogCapture, testLogger } from '@agentx/testing';
import { beforeEach, describe, expect, it } from 'vitest';

import { createJobWatch, PULSE_EVERY_MS } from './job-watch.ts';

const MINUTE = 60_000;
const LIMIT = 10 * MINUTE;

let at = 0;
let capture: LogCapture;

beforeEach(() => {
  at = 1_000_000;
  capture = new LogCapture();
});

const watchOf = (pulsing = true) => createJobWatch({ logger: testLogger(capture), now: () => at, pulsing });

/** A run that ends when told to. */
function hanging() {
  const { promise, resolve } = Promise.withResolvers<undefined>();
  return {
    work: { run: () => promise },
    end: () => {
      resolve(undefined);
    },
  };
}

const said = (event: string) => capture.lines().filter((line) => line.event === event);

/** Pulses a minute apart, as the timer gives them, for this long. */
async function pulseFor(watch: { run(): Promise<void> }, ms: number): Promise<void> {
  for (let passed = 0; passed < ms; passed += PULSE_EVERY_MS) {
    at += PULSE_EVERY_MS;
    await watch.run();
  }
}

describe('a run past its job limit', () => {
  it('logs job.stalled once, naming the job, and not before the limit', async () => {
    const watch = watchOf();
    const { work, end } = hanging();
    const run = watch.watching('handoff', work, LIMIT).run();

    await pulseFor(watch, LIMIT);
    expect(said('job.stalled')).toEqual([]);

    await pulseFor(watch, 3 * MINUTE);
    expect(said('job.stalled')).toEqual([
      expect.objectContaining({ level: 'error', job: 'handoff', runningMs: LIMIT + MINUTE, limitMs: LIMIT }),
    ]);
    end();
    await run;
  });

  it('says nothing of a run that ended within it, or between runs', async () => {
    const watch = watchOf();
    const job = watch.watching('sweep', { run: () => Promise.resolve() }, LIMIT);
    await job.run();
    await pulseFor(watch, LIMIT * 2);
    expect(said('job.stalled')).toEqual([]);
  });

  it('holds each job to its own limit', async () => {
    const watch = watchOf();
    const [short, long] = [hanging(), hanging()];
    const runs = [
      watch.watching('short', short.work, MINUTE).run(),
      watch.watching('long', long.work, 100 * MINUTE).run(),
    ];
    await pulseFor(watch, 5 * MINUTE);
    expect(said('job.stalled').map((line) => line.job)).toEqual(['short']);
    short.end();
    long.end();
    await Promise.all(runs);
  });

  it('says it again of a later run that stalls too', async () => {
    const watch = watchOf();
    const first = hanging();
    const job = watch.watching('handoff', { run: (): Promise<unknown> => current.work.run() }, LIMIT);
    let current = first;
    const firstRun = job.run();
    await pulseFor(watch, LIMIT + 2 * MINUTE);
    first.end();
    await firstRun;

    current = hanging();
    const secondRun = job.run();
    await pulseFor(watch, LIMIT + 2 * MINUTE);
    expect(said('job.stalled')).toHaveLength(2);
    current.end();
    await secondRun;
  });

  it('records a run that throws as ended', async () => {
    const watch = watchOf();
    const job = watch.watching('handoff', { run: () => Promise.reject(new Error('broke')) }, LIMIT);
    await expect(job.run()).rejects.toThrow('broke');
    await pulseFor(watch, LIMIT * 2);
    expect(said('job.stalled')).toEqual([]);
  });
});

describe('it cannot fire asleep (a wake must raise nothing)', () => {
  it('forgives a run a frozen process finds hours old, on the first pulse after and those following', async () => {
    const watch = watchOf();
    const { work, end } = hanging();
    const run = watch.watching('anchor_check', work, LIMIT).run();
    await pulseFor(watch, 2 * MINUTE);

    at += 3 * 60 * MINUTE;
    await watch.run();
    await pulseFor(watch, LIMIT);
    expect(said('job.stalled')).toEqual([]);
    end();
    await run;
  });

  it('counts the limit again from the wake, so a run truly stuck past it is still said', async () => {
    const watch = watchOf();
    const { work, end } = hanging();
    const run = watch.watching('anchor_check', work, LIMIT).run();
    at += 3 * 60 * MINUTE;
    await watch.run();
    await pulseFor(watch, LIMIT + 2 * MINUTE);
    expect(said('job.stalled')).toHaveLength(1);
    end();
    await run;
  });

  it('a pulse a little late is no sleep: a run past its limit is still said', async () => {
    const watch = watchOf();
    const { work, end } = hanging();
    const run = watch.watching('handoff', work, MINUTE).run();
    at += 2 * PULSE_EVERY_MS;
    await watch.run();
    expect(said('job.stalled')).toHaveLength(1);
    end();
    await run;
  });

  it('a new process, as a scale-to-zero wake is, has nothing recorded to say', async () => {
    const watch = watchOf();
    await watch.run();
    expect(said('job.stalled')).toEqual([]);
    expect(said('jobs.pulse')).toHaveLength(1);
  });
});

describe('jobs.pulse', () => {
  it('says how many jobs there are and how many are running, each pulse', async () => {
    const watch = watchOf();
    const { work, end } = hanging();
    const run = watch.watching('one', work, LIMIT).run();
    watch.watching('two', { run: () => Promise.resolve() }, LIMIT);
    await watch.run();
    await watch.run();
    expect(said('jobs.pulse')).toEqual([
      expect.objectContaining({ level: 'info', jobs: 2, running: 1 }),
      expect.objectContaining({ level: 'info', jobs: 2, running: 1 }),
    ]);
    end();
    await run;
  });

  it('stays silent where the process has none of the `jobs` side, but still sees a stall', async () => {
    const watch = watchOf(false);
    const { work, end } = hanging();
    const run = watch.watching('recorder', work, MINUTE).run();
    await pulseFor(watch, 3 * MINUTE);
    expect(said('jobs.pulse')).toEqual([]);
    expect(said('job.stalled')).toHaveLength(1);
    end();
    await run;
  });
});

describe('job.skipping_runs (PL-34)', () => {
  const runs = (outcomes: readonly unknown[]) => {
    const left = [...outcomes];
    return { run: () => Promise.resolve(left.shift()) };
  };

  it('logs at the third skipped run in a row, once a streak', async () => {
    const watch = watchOf();
    const job = watch.watching('idp_events', runs(Array.from({ length: 7 }, () => 'skipped')), LIMIT);
    await job.run();
    await job.run();
    expect(said('job.skipping_runs')).toEqual([]);
    await job.run();
    expect(said('job.skipping_runs')).toEqual([
      expect.objectContaining({ level: 'error', job: 'idp_events', runs: 3 }),
    ]);
    for (let more = 0; more < 4; more += 1) await job.run();
    expect(said('job.skipping_runs')).toHaveLength(1);
  });

  it('a run that ran starts the count again', async () => {
    const watch = watchOf();
    const job = watch.watching(
      'notification',
      runs(['skipped', 'skipped', 'ran', 'skipped', 'skipped', undefined, 'skipped']),
      LIMIT,
    );
    for (let run = 0; run < 7; run += 1) await job.run();
    expect(said('job.skipping_runs')).toEqual([]);
  });

  it('a new streak is said again', async () => {
    const watch = watchOf();
    const job = watch.watching(
      'factor_resets',
      runs(['skipped', 'skipped', 'skipped', 'ran', 'skipped', 'skipped', 'skipped']),
      LIMIT,
    );
    for (let run = 0; run < 7; run += 1) await job.run();
    expect(said('job.skipping_runs')).toHaveLength(2);
  });
});

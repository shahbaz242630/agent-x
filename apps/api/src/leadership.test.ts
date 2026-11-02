// 4D2e D: one copy of the jobs at a time, the process's side of the lease. Two
// processes share one stand-in row with a term on a clock the test moves;
// job-lease.db.test.ts proves the row itself on a real Postgres, and
// main.db.test.ts two whole processes.
import { LogCapture, testLogger } from '@agentx/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createLeadership,
  LEASE_RETRY_AFTER_MS,
  LEASE_TRY_WITHIN_MS,
  type Leadership,
  type LeaseStore,
  LEASE_RENEW_EVERY_MS,
  LEASE_TERM_MS,
} from './background.ts';

import { createJobWatch } from './job-watch.ts';

/** The database's row, on the same clock: takes as the UPDATE's WHERE does. */
function rowAt(now: () => number) {
  const row = { holder: undefined as string | undefined, until: Number.NEGATIVE_INFINITY, beats: 0 };
  const storeFor = (me: string): LeaseStore => ({
    take: (beating) => {
      if (row.holder !== me && row.until >= now()) return Promise.resolve(false);
      row.holder = me;
      row.until = now() + LEASE_TERM_MS;
      if (beating) row.beats += 1;
      return Promise.resolve(true);
    },
    release: () => {
      if (row.holder === me) {
        row.holder = undefined;
        row.until = Number.NEGATIVE_INFINITY;
      }
      return Promise.resolve();
    },
  });
  return { row, storeFor };
}

const SECOND = 1000;
/** Three anchor intervals, as it is run. */
const NOT_LEADING_MS = 15 * 60 * SECOND;
const now = () => Date.now();

let capture: LogCapture;
const started: Leadership[] = [];

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
  capture = new LogCapture();
});

afterEach(async () => {
  await Promise.all(started.splice(0).map((one) => one.stop()));
  vi.useRealTimers();
});

const leadershipOf = (store: LeaseStore, beating = () => false) => {
  const one = createLeadership({ store, logger: testLogger(capture), now, notLeadingAfterMs: NOT_LEADING_MS });
  started.push(one);
  return { one, begun: one.start(beating) };
};

const said = (event: string) => capture.lines().filter((line) => line.event === event);

/** Work that runs until its signal is aborted, and says what it saw. */
function untilAborted(name = 'job') {
  const runs: AbortSignal[] = [];
  return {
    runs,
    work: {
      name,
      run: (signal?: AbortSignal) =>
        new Promise<void>((resolve) => {
          if (signal === undefined) throw new Error('a job always has a signal here');
          runs.push(signal);
          signal.addEventListener('abort', () => {
            resolve();
          });
        }),
    },
  };
}

describe('two processes never both lead', () => {
  it('holds at every moment through a holder going quiet and another taking over', async () => {
    const { storeFor } = rowAt(now);
    const quiet = storeFor('a');
    let answering = true;
    const a = leadershipOf({
      take: (beating) => (answering ? quiet.take(beating) : Promise.reject(new Error('connection lost'))),
      release: () => quiet.release(),
    });
    await a.begun;
    const b = leadershipOf(storeFor('b'));
    await b.begun;
    expect([a.one.leading(), b.one.leading()]).toEqual([true, false]);

    answering = false;
    const seen = new Set<string>();
    for (let passed = 0; passed < 3 * LEASE_TERM_MS; passed += SECOND) {
      await vi.advanceTimersByTimeAsync(SECOND);
      expect(a.one.leading() && b.one.leading()).toBe(false);
      seen.add(`${String(a.one.leading())},${String(b.one.leading())}`);
    }
    expect(b.one.leading()).toBe(true);
    expect(seen).toContain('true,false');
    expect(seen).toContain('false,true');
    expect(said('jobs.lease_renew_failed').length).toBeGreaterThan(0);
  });

  it('a holder that comes back after another took over gets nothing, and stays out', async () => {
    const { storeFor } = rowAt(now);
    const quiet = storeFor('a');
    let answering = true;
    const a = leadershipOf({
      take: (beating) => (answering ? quiet.take(beating) : Promise.reject(new Error('connection lost'))),
      release: () => quiet.release(),
    });
    await a.begun;
    const b = leadershipOf(storeFor('b'));
    answering = false;
    await vi.advanceTimersByTimeAsync(2 * LEASE_TERM_MS);
    answering = true;
    await vi.advanceTimersByTimeAsync(5 * LEASE_RENEW_EVERY_MS);
    expect([a.one.leading(), b.one.leading()]).toEqual([false, true]);
  });

  it('it lets go by its own clock from when the renewal was sent, before the database would hand over', async () => {
    const { row, storeFor } = rowAt(now);
    const quiet = storeFor('a');
    let answering = true;
    const a = leadershipOf({
      take: (beating) => (answering ? quiet.take(beating) : Promise.reject(new Error('connection lost'))),
      release: () => quiet.release(),
    });
    await a.begun;
    answering = false;
    const until = row.until;
    await vi.advanceTimersByTimeAsync(LEASE_TERM_MS - 1);
    expect(a.one.leading()).toBe(true);
    await vi.advanceTimersByTimeAsync(1);
    expect(a.one.leading()).toBe(false);
    expect(Date.now()).toBeLessThanOrEqual(until);
  });

  it('reads as not leading past its term even if the timer has not fired, as a process just thawed', async () => {
    let at = 0;
    const one = createLeadership({
      store: { take: () => Promise.resolve(true), release: () => Promise.resolve() },
      logger: testLogger(capture),
      notLeadingAfterMs: NOT_LEADING_MS,
      now: () => at,
    });
    started.push(one);
    await one.start(() => false);
    at = LEASE_TERM_MS + 1;
    expect(one.leading()).toBe(false);
  });
});

describe('a lost lease aborts runs', () => {
  it('through the signal, as soon as a renewal is refused, and warns', async () => {
    const { row, storeFor } = rowAt(now);
    const { one, begun } = leadershipOf(storeFor('a'));
    await begun;
    const { runs, work } = untilAborted();
    const run = one.onlyWhileLeading(work).run(new AbortController().signal);
    await vi.advanceTimersByTimeAsync(0);
    expect(runs[0]?.aborted).toBe(false);

    row.holder = 'b';
    row.until = Date.now() + LEASE_TERM_MS;
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS);
    expect(runs[0]?.aborted).toBe(true);
    await run;
    expect(said('jobs.lease_lost')).toEqual([expect.objectContaining({ level: 'warn' })]);
    expect(one.leading()).toBe(false);
  });

  it('through the signal, when renewals fail past the term', async () => {
    const { one, begun } = leadershipOf({
      take: vi.fn<LeaseStore['take']>().mockResolvedValueOnce(true).mockRejectedValue(new Error('connection lost')),
      release: () => Promise.resolve(),
    });
    await begun;
    const { runs, work } = untilAborted();
    const run = one.onlyWhileLeading(work).run();
    await vi.advanceTimersByTimeAsync(LEASE_TERM_MS - 1);
    expect(runs[0]?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(runs[0]?.aborted).toBe(true);
    await run;
  });

  it('a stop of the process still aborts a run in its own right', async () => {
    const { storeFor } = rowAt(now);
    const { one, begun } = leadershipOf(storeFor('a'));
    await begun;
    const { runs, work } = untilAborted();
    const stopping = new AbortController();
    const run = one.onlyWhileLeading(work).run(stopping.signal);
    await vi.advanceTimersByTimeAsync(0);
    stopping.abort();
    await run;
    expect(runs[0]?.aborted).toBe(true);
    expect(one.leading()).toBe(true);
  });

  it('takes the lease back when it can, and the next run goes ahead', async () => {
    const take = vi
      .fn<LeaseStore['take']>()
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false)
      .mockResolvedValue(true);
    const { one, begun } = leadershipOf({ take, release: () => Promise.resolve() });
    await begun;
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS);
    expect(one.leading()).toBe(false);
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS);
    expect(one.leading()).toBe(true);
    expect(said('jobs.lease_taken')).toHaveLength(2);
  });
});

describe('a follower waits, and expiry hands over', () => {
  it('holds its runs back, without counting as running them, until the lease ends, then runs them at once', async () => {
    const { storeFor } = rowAt(now);
    const crashed = storeFor('a');
    const a = leadershipOf({ take: (beating) => crashed.take(beating), release: () => Promise.resolve() });
    await a.begun;
    await a.one.stop();
    started.length = 0;

    const b = leadershipOf(storeFor('b'));
    await b.begun;
    expect(b.one.leading()).toBe(false);
    const { runs, work } = untilAborted();
    const stopping = new AbortController();
    const run = b.one.onlyWhileLeading(work).run(stopping.signal);
    await vi.advanceTimersByTimeAsync(LEASE_TERM_MS - 2 * SECOND);
    expect(runs).toEqual([]);

    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS + 2 * SECOND);
    expect(b.one.leading()).toBe(true);
    expect(runs).toHaveLength(1);
    stopping.abort();
    await run;
  });

  it('a run waiting for the lease is no run stalled: the job list puts the gate outside the watch', async () => {
    const { one, begun } = leadershipOf({ take: () => Promise.resolve(false), release: () => Promise.resolve() });
    await begun;
    let at = 0;
    const watch = createJobWatch({ logger: testLogger(capture), now: () => at, pulsing: () => one.leading() });
    const stopping = new AbortController();
    const run = one
      .onlyWhileLeading(watch.watching('handoff', { run: () => Promise.resolve() }, 60_000))
      .run(stopping.signal);
    for (let minute = 0; minute < 10; minute += 1) {
      at += 60_000;
      await watch.run();
    }
    expect(said('job.stalled')).toEqual([]);
    // Nor does a follower say the pulse the dead-man rule reads.
    expect(said('jobs.pulse')).toEqual([]);
    stopping.abort();
    await run;
  });

  it('a stop of the process ends a run still waiting, with nothing run', async () => {
    const { one, begun } = leadershipOf({ take: () => Promise.resolve(false), release: () => Promise.resolve() });
    await begun;
    const { runs, work } = untilAborted();
    const stopping = new AbortController();
    const run = one.onlyWhileLeading(work).run(stopping.signal);
    stopping.abort();
    await run;
    expect(runs).toEqual([]);

    const already = one.onlyWhileLeading(work).run(stopping.signal);
    await already;
    expect(runs).toEqual([]);
  });

  it('keeps the job name, for the list', () => {
    const { one } = leadershipOf({ take: () => Promise.resolve(false), release: () => Promise.resolve() });
    expect(one.onlyWhileLeading({ name: 'handoff', run: () => Promise.resolve() }).name).toBe('handoff');
  });
});

describe('the holder releases on stop', () => {
  it('so the next takes it at its next try, not a whole term later', async () => {
    const { row, storeFor } = rowAt(now);
    const a = leadershipOf(storeFor('a'));
    await a.begun;
    const b = leadershipOf(storeFor('b'));
    await b.begun;
    await a.one.stop();
    expect(row.holder).toBeUndefined();
    expect(a.one.leading()).toBe(false);
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS);
    expect(b.one.leading()).toBe(true);
  });

  it('renews no more once stopped, even with a renewal in flight as it stops', async () => {
    const answers: ((held: boolean) => void)[] = [];
    const take = vi.fn(() => new Promise<boolean>((resolve) => answers.push(resolve)));
    const release = vi.fn(() => Promise.resolve());
    const one = createLeadership({
      store: { take, release },
      logger: testLogger(capture),
      now,
      notLeadingAfterMs: NOT_LEADING_MS,
    });
    const begun = one.start(() => false);
    const stopping = one.stop();
    answers[0]?.(true);
    await begun;
    await stopping;
    expect(release).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5 * LEASE_RENEW_EVERY_MS);
    expect(take).toHaveBeenCalledTimes(1);
    expect(one.leading()).toBe(false);
  });

  it('a release that fails warns and never throws: the term ends it anyway', async () => {
    const { one, begun } = leadershipOf({
      take: () => Promise.resolve(true),
      release: () => Promise.reject(new Error('connection lost')),
    });
    await begun;
    await expect(one.stop()).resolves.toBeUndefined();
    expect(said('jobs.lease_release_failed')).toEqual([expect.objectContaining({ level: 'warn' })]);
    expect(said('jobs.lease_lost')).toEqual([]);
  });
});

describe('the heartbeat', () => {
  it('moves only with a renewal, and only while the jobs beat', async () => {
    const { row, storeFor } = rowAt(now);
    let beating = true;
    const { begun } = leadershipOf(storeFor('a'), () => beating);
    await begun;
    expect(row.beats).toBe(1);
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS);
    expect(row.beats).toBe(2);
    beating = false;
    await vi.advanceTimersByTimeAsync(2 * LEASE_RENEW_EVERY_MS);
    expect(row.beats).toBe(2);
  });
});

describe('a try that goes unanswered has a deadline', () => {
  const never = () => new Promise<boolean>(() => undefined);

  it('the first take: start ends within it, so the process goes on, following', async () => {
    const { one, begun } = leadershipOf({ take: never, release: () => Promise.resolve() });
    let ended = false;
    void begun.then(() => {
      ended = true;
    });
    await vi.advanceTimersByTimeAsync(LEASE_TRY_WITHIN_MS - 1);
    expect(ended).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(ended).toBe(true);
    expect(one.leading()).toBe(false);
    expect(said('jobs.lease_renew_failed')).toHaveLength(1);
  });

  it('a renewal: it counts as failed, the next try still comes, and the lease is kept if that one is answered', async () => {
    const take = vi
      .fn<LeaseStore['take']>()
      .mockResolvedValueOnce(true)
      .mockImplementationOnce(never)
      .mockResolvedValue(true);
    const { one, begun } = leadershipOf({ take, release: () => Promise.resolve() });
    await begun;
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS + LEASE_TRY_WITHIN_MS);
    expect(said('jobs.lease_renew_failed')).toHaveLength(1);
    expect(take).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(LEASE_RETRY_AFTER_MS);
    expect(take).toHaveBeenCalledTimes(3);
    expect(one.leading()).toBe(true);
    expect(said('jobs.lease_lost')).toEqual([]);
  });

  it('every renewal unanswered: it let go at the term, from the last answered try, not a try later', async () => {
    const take = vi.fn<LeaseStore['take']>().mockResolvedValueOnce(true).mockImplementation(never);
    const { one, begun } = leadershipOf({ take, release: () => Promise.resolve() });
    await begun;
    await vi.advanceTimersByTimeAsync(LEASE_TERM_MS - 1);
    expect(one.leading()).toBe(true);
    await vi.advanceTimersByTimeAsync(1);
    expect(one.leading()).toBe(false);
    expect(said('jobs.lease_lost')).toHaveLength(1);
    // T+20 hung to T+30, then a try each 15 s: more than the two a plain 20 s renewal would have had.
    expect(take.mock.calls.length).toBeGreaterThanOrEqual(4);
  });

  it('a stop with a take unanswered ends at once, and still gives the lease up', async () => {
    const release = vi.fn(() => Promise.resolve());
    const { one } = leadershipOf({ take: never, release });
    await vi.advanceTimersByTimeAsync(SECOND);
    await one.stop();
    expect(release).toHaveBeenCalledTimes(1);
    expect(said('jobs.lease_renew_failed')).toEqual([]);
  });

  it('a release unanswered: the stop ends within the deadline, with a warning', async () => {
    const { one, begun } = leadershipOf({
      take: () => Promise.resolve(true),
      release: () => new Promise(() => undefined),
    });
    await begun;
    let ended = false;
    const stopping = one.stop().then(() => {
      ended = true;
    });
    await vi.advanceTimersByTimeAsync(LEASE_TRY_WITHIN_MS - 1);
    expect(ended).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await stopping;
    expect(said('jobs.lease_release_failed')).toHaveLength(1);
    // Stopped here: the same hung release would hold up afterEach's stop, on a clock no one moves.
    started.length = 0;
  });
});

describe('a process long without the lease says so', () => {
  const refusing = { take: () => Promise.resolve(false), release: () => Promise.resolve() };

  it('says a refusal once a stretch, and the error at the limit, once, then again past the same again', async () => {
    const { begun } = leadershipOf(refusing);
    await begun;
    expect(said('jobs.lease_held_elsewhere')).toEqual([expect.objectContaining({ level: 'info' })]);

    await vi.advanceTimersByTimeAsync(NOT_LEADING_MS - 2 * LEASE_RENEW_EVERY_MS);
    expect(said('jobs.not_leading')).toEqual([]);
    await vi.advanceTimersByTimeAsync(2 * LEASE_RENEW_EVERY_MS);
    expect(said('jobs.not_leading')).toEqual([expect.objectContaining({ level: 'error', forMs: NOT_LEADING_MS })]);
    await vi.advanceTimersByTimeAsync(NOT_LEADING_MS - LEASE_RENEW_EVERY_MS);
    expect(said('jobs.not_leading')).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS);
    expect(said('jobs.not_leading')).toHaveLength(2);
    expect(said('jobs.lease_held_elsewhere')).toHaveLength(1);
  });

  it('a database that never answers is the same error', async () => {
    const { begun } = leadershipOf({ take: () => new Promise(() => undefined), release: () => Promise.resolve() });
    await vi.advanceTimersByTimeAsync(NOT_LEADING_MS + LEASE_RENEW_EVERY_MS);
    await begun;
    expect(said('jobs.not_leading')).toHaveLength(1);
  });

  it('never while leading, however long', async () => {
    const { storeFor } = rowAt(now);
    const { begun } = leadershipOf(storeFor('a'));
    await begun;
    await vi.advanceTimersByTimeAsync(3 * NOT_LEADING_MS);
    expect(said('jobs.not_leading')).toEqual([]);
  });

  it('a lease taken again starts the count and the refusal line again', async () => {
    let held = false;
    const { begun } = leadershipOf({ take: () => Promise.resolve(held), release: () => Promise.resolve() });
    await begun;
    await vi.advanceTimersByTimeAsync(NOT_LEADING_MS);
    expect(said('jobs.not_leading')).toHaveLength(1);
    held = true;
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS);
    held = false;
    await vi.advanceTimersByTimeAsync(NOT_LEADING_MS - LEASE_RENEW_EVERY_MS);
    expect(said('jobs.not_leading')).toHaveLength(1);
    expect(said('jobs.lease_held_elsewhere')).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(2 * LEASE_RENEW_EVERY_MS);
    expect(said('jobs.not_leading')).toHaveLength(2);
  });

  it('a process frozen past the limit says nothing at its wake: it counts from there', async () => {
    let at = 0;
    const one = createLeadership({
      store: refusing,
      logger: testLogger(capture),
      notLeadingAfterMs: NOT_LEADING_MS,
      now: () => at,
    });
    started.push(one);
    await one.start(() => false);
    at += 2 * NOT_LEADING_MS;
    await vi.advanceTimersByTimeAsync(LEASE_RENEW_EVERY_MS);
    expect(said('jobs.not_leading')).toEqual([]);
  });
});

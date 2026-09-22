import { afterEach, describe, expect, it, vi } from 'vitest';

import { Barrier, BarrierBroken, failures, race, successes, within } from './race.ts';

afterEach(() => {
  vi.useRealTimers();
});

const WHY =
  'A party may be waiting for a lock that one at the barrier holds, or for a pooled connection that one at the barrier has';

/** What a promise has done so far, read without waiting for it. */
function track(promise: Promise<unknown>): { state: () => 'pending' | 'resolved' | 'rejected'; reason: () => unknown } {
  let state: 'pending' | 'resolved' | 'rejected' = 'pending';
  let reason: unknown;
  void promise.then(
    () => {
      state = 'resolved';
    },
    (error: unknown) => {
      state = 'rejected';
      reason = error;
    },
  );
  return { state: () => state, reason: () => reason };
}

describe('Barrier', () => {
  it('holds every party until the last arrives, then releases them together', async () => {
    vi.useFakeTimers();
    const barrier = new Barrier(3, 1000);
    const first = track(barrier.arrive());
    const second = track(barrier.arrive());
    await vi.advanceTimersByTimeAsync(999);
    expect([first.state(), second.state()]).toEqual(['pending', 'pending']);
    await barrier.arrive();
    await vi.advanceTimersByTimeAsync(0);
    expect([first.state(), second.state()]).toEqual(['resolved', 'resolved']);
    // Released: the timer that would have broken it is gone.
    expect(vi.getTimerCount()).toBe(0);
  });

  it('lets a single party straight through', async () => {
    await expect(new Barrier(1, 1000).arrive()).resolves.toBeUndefined();
  });

  it('times out, naming how many arrived, and refuses later arrivals the same way', async () => {
    vi.useFakeTimers();
    const barrier = new Barrier(3, 1000);
    const first = track(barrier.arrive());
    await vi.advanceTimersByTimeAsync(400);
    const second = track(barrier.arrive());
    await vi.advanceTimersByTimeAsync(599);
    expect(first.state()).toBe('pending');
    await vi.advanceTimersByTimeAsync(1);
    expect([first.state(), second.state()]).toEqual(['rejected', 'rejected']);
    expect(first.reason()).toBeInstanceOf(BarrierBroken);
    expect((first.reason() as Error).message).toBe(
      `The barrier timed out after 1000 ms with 2 of 3 parties arrived. ${WHY}`,
    );
    expect(second.reason()).toBe(first.reason());
    await expect(barrier.arrive()).rejects.toBe(first.reason());
  });

  it('starts the wait at the first arrival, not when it is made', async () => {
    vi.useFakeTimers();
    const barrier = new Barrier(2, 1000);
    await vi.advanceTimersByTimeAsync(5000);
    const first = track(barrier.arrive());
    await vi.advanceTimersByTimeAsync(999);
    expect(first.state()).toBe('pending');
    await barrier.arrive();
    await vi.advanceTimersByTimeAsync(0);
    expect(first.state()).toBe('resolved');
  });

  it('refuses more arrivals than parties', async () => {
    const barrier = new Barrier(2, 1000);
    await Promise.all([barrier.arrive(), barrier.arrive()]);
    await expect(barrier.arrive()).rejects.toThrow('More than 2 parties arrived at the barrier');
  });

  it('rejects the waiting parties and later arrivals with the reason it was broken with', async () => {
    vi.useFakeTimers();
    const barrier = new Barrier(3, 1000);
    const waiting = barrier.arrive();
    const reason = new Error('stopped');
    barrier.break(reason);
    expect(vi.getTimerCount()).toBe(0);
    await expect(waiting).rejects.toBe(reason);
    await expect(barrier.arrive()).rejects.toBe(reason);
    // Only the first reason counts.
    barrier.break(new Error('stopped again'));
    await expect(barrier.arrive()).rejects.toBe(reason);
  });

  it('ignores a break once it has released', async () => {
    const barrier = new Barrier(2, 1000);
    await Promise.all([barrier.arrive(), barrier.arrive()]);
    barrier.break(new Error('too late'));
    await expect(barrier.arrive()).rejects.toThrow('More than 2 parties');
  });

  it.each([0, -1, 1.5, Number.NaN])('refuses %s parties', (parties) => {
    expect(() => new Barrier(parties, 1000)).toThrow(RangeError);
  });

  it.each([0, -1, 0.5, Number.POSITIVE_INFINITY])('refuses a timeout of %s ms', (timeoutMs) => {
    expect(() => new Barrier(2, timeoutMs)).toThrow(RangeError);
  });
});

describe('within', () => {
  it('gives back what the work gives back, and what it throws', async () => {
    await expect(within(1_000, Promise.resolve('done'), 'the work')).resolves.toBe('done');
    await expect(within(1_000, Promise.reject(new Error('refused')), 'the work')).rejects.toThrow('refused');
  });

  it('rejects, naming the work, once the time has passed', async () => {
    await expect(within(20, new Promise(() => undefined), 'the stuck work')).rejects.toThrow(
      'Waited 20 ms for the stuck work',
    );
  });
});

describe('race', () => {
  it('starts every party before any of them finishes', async () => {
    const events: string[] = [];
    await race(3, async (party) => {
      events.push(`start ${party}`);
      await Promise.resolve();
      events.push(`end ${party}`);
    });
    expect(events.slice(0, 3)).toEqual(['start 0', 'start 1', 'start 2']);
  });

  it('gives the outcomes in party order, failures included', async () => {
    const outcomes = await race(3, async (party) => {
      await new Promise((resolve) => setTimeout(resolve, (3 - party) * 5));
      if (party === 1) throw new Error('party 1 lost');
      return `party ${party}`;
    });
    expect(outcomes).toEqual([
      { status: 'fulfilled', value: 'party 0' },
      { status: 'rejected', reason: new Error('party 1 lost') },
      { status: 'fulfilled', value: 'party 2' },
    ]);
  });

  it('lines the parties up: none goes past the barrier until all have reached it', async () => {
    const events: string[] = [];
    await race(3, async (party, sync) => {
      await new Promise((resolve) => setTimeout(resolve, party * 20));
      events.push(`before ${party}`);
      await sync();
      events.push(`after ${party}`);
    });
    expect(events.slice(0, 3).sort()).toEqual(['before 0', 'before 1', 'before 2']);
    expect(events.slice(3).sort()).toEqual(['after 0', 'after 1', 'after 2']);
  });

  it('breaks the barrier at once when a party fails before reaching it, with that failure as the cause', async () => {
    const failure = new Error('could not start');
    const outcomes = await race(2, async (party, sync) => {
      if (party === 1) throw failure;
      await sync();
    });
    const [waiting] = outcomes;
    expect(waiting?.status).toBe('rejected');
    const reason = (waiting as PromiseRejectedResult).reason as BarrierBroken;
    expect(reason).toBeInstanceOf(BarrierBroken);
    expect(reason.message).toBe('Party 1 failed before reaching the barrier');
    expect(reason.cause).toBe(failure);
  });

  it('breaks the barrier when a party finishes without reaching it', async () => {
    const outcomes = await race(2, async (party, sync) => {
      if (party === 0) await sync();
      return party;
    });
    expect(outcomes[0]).toEqual({
      status: 'rejected',
      reason: new BarrierBroken('Party 1 finished without reaching the barrier'),
    });
    expect(outcomes[1]).toEqual({ status: 'fulfilled', value: 1 });
  });

  it('refuses a party that reaches the barrier twice', async () => {
    const outcomes = await race(2, async (_, sync) => {
      await sync();
      await sync();
    });
    expect(outcomes.map((outcome) => outcome.status)).toEqual(['rejected', 'rejected']);
    expect((outcomes[0] as PromiseRejectedResult).reason).toEqual(
      new BarrierBroken('Party 0 reached the barrier twice'),
    );
  });

  it.each([
    ['10 seconds by default', undefined, 10_000],
    ['the time given', 50, 50],
  ])('times out after %s', async (_, timeoutMs, expected) => {
    vi.useFakeTimers();
    let unstick = (): void => undefined;
    const stuck = new Promise<void>((resolve) => {
      unstick = resolve;
    });
    let first: unknown = 'waiting';
    const running = race(
      2,
      async (party, sync) => {
        if (party === 1) {
          await stuck;
          return;
        }
        await sync().then(
          () => {
            first = 'released';
          },
          (error: unknown) => {
            first = error;
          },
        );
      },
      timeoutMs === undefined ? {} : { timeoutMs },
    );
    await vi.advanceTimersByTimeAsync(expected - 1);
    expect(first).toBe('waiting');
    await vi.advanceTimersByTimeAsync(1);
    expect(first).toEqual(
      new BarrierBroken(`The barrier timed out after ${expected} ms with 1 of 2 parties arrived. ${WHY}`),
    );
    unstick();
    await running;
  });

  it('sorts the outcomes into the values of the runs that succeeded and the errors of those that failed', async () => {
    const outcomes = await race(4, (party) =>
      party % 2 === 0 ? Promise.resolve(party) : Promise.reject(new Error(`party ${party}`)),
    );
    expect(successes(outcomes)).toEqual([0, 2]);
    expect(failures(outcomes)).toEqual([new Error('party 1'), new Error('party 3')]);
  });

  it.each([1, 0, 2.5])('refuses %s parties', async (parties) => {
    await expect(race(parties, () => Promise.resolve())).rejects.toThrow(
      new RangeError(`A race needs a whole number of parties, at least 2; got ${parties}`),
    );
  });
});

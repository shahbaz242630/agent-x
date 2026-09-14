// FX-RACE (Security Test Catalogue; ADR-006 §6): runs several pieces of work
// at the same time, so limits, locks and idempotency are tested under real
// contention rather than one request after another. Where a test needs the
// parties lined up exactly, each waits at a shared barrier until all have
// reached it, and then they go on together.
//
// Where the barrier goes decides what the race proves. Put it after what the
// parties must all have done (read a total, take a first lock) and before what
// must not have happened yet (write the total back, take the second lock). A
// party that waits at the barrier while holding a lock another party needs to
// get there would wait for ever, so the barrier times out, says why, and
// releases every party; their transactions then roll back.
//
// Code under test that can't call the barrier (a service running its own
// transactions) is lined up in the database instead: the test holds the lock
// every party takes first, waits until all of them queue behind it
// (waitUntilQueued, in db/lock-wait.ts), then lets go.

/** How long the harness waits for parties to line up or queue, unless a test says otherwise. */
export const DEFAULT_WAIT_MS = 10_000;

/** The barrier can't line the parties up: it timed out, or a party ended without reaching it. */
export class BarrierBroken extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'BarrierBroken';
  }
}

interface Waiting {
  readonly resolve: () => void;
  readonly reject: (reason: Error) => void;
}

/** Holds each party that arrives until all `parties` have, then releases them together. */
export class Barrier {
  readonly parties: number;
  readonly #timeoutMs: number;
  readonly #waiting: Waiting[] = [];
  #arrived = 0;
  #broken: Error | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;

  /** The wait starts with the first arrival; after `timeoutMs` without the last one, the barrier breaks. */
  constructor(parties: number, timeoutMs: number) {
    if (!Number.isSafeInteger(parties) || parties < 1) {
      throw new RangeError(`A barrier needs a whole number of parties, at least 1; got ${parties}`);
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
      throw new RangeError(`A barrier needs a timeout of a whole number of milliseconds, at least 1; got ${timeoutMs}`);
    }
    this.parties = parties;
    this.#timeoutMs = timeoutMs;
  }

  /** Resolves once every party has arrived. Rejects with BarrierBroken if the barrier breaks first. */
  arrive(): Promise<void> {
    if (this.#broken !== undefined) return Promise.reject(this.#broken);
    if (this.#arrived === this.parties) {
      return Promise.reject(new BarrierBroken(`More than ${this.parties} parties arrived at the barrier`));
    }
    this.#arrived += 1;
    if (this.#arrived === this.parties) {
      clearTimeout(this.#timer);
      for (const waiting of this.#waiting.splice(0)) waiting.resolve();
      return Promise.resolve();
    }
    this.#timer ??= setTimeout(() => {
      this.break(
        new BarrierBroken(
          `The barrier timed out after ${this.#timeoutMs} ms with ${this.#arrived} of ${this.parties} parties arrived. A party may be waiting for a lock that one at the barrier holds, or for a pooled connection that one at the barrier has`,
        ),
      );
    }, this.#timeoutMs);
    return new Promise((resolve, reject) => {
      this.#waiting.push({ resolve, reject });
    });
  }

  /** Rejects every waiting party, and every later arrival, with `reason`. Does nothing once the barrier has released or broken. */
  break(reason: Error): void {
    if (this.#broken !== undefined || this.#arrived === this.parties) return;
    this.#broken = reason;
    clearTimeout(this.#timer);
    for (const waiting of this.#waiting.splice(0)) waiting.reject(reason);
  }
}

export interface RaceOptions {
  /** How long a party waits at the barrier for the others. Default 10 seconds. */
  readonly timeoutMs?: number;
}

/**
 * Starts `parties` runs of `work` at once, and settles when every one has.
 * Each run gets its number (0 upward) and `sync`, which waits at the shared
 * barrier. If any run calls `sync`, every run must, once. A run that ends
 * without reaching the barrier breaks it, so the others don't wait for the
 * timeout. The timeout covers only the wait at the barrier: a run that hangs
 * anywhere else holds the race up until the test's own timeout. The outcomes
 * come back in run order, as Promise.allSettled gives them: a race is
 * expected to have losers.
 */
export async function race<T>(
  parties: number,
  work: (party: number, sync: () => Promise<void>) => Promise<T>,
  options: RaceOptions = {},
): Promise<PromiseSettledResult<T>[]> {
  if (!Number.isSafeInteger(parties) || parties < 2) {
    throw new RangeError(`A race needs a whole number of parties, at least 2; got ${parties}`);
  }
  const barrier = new Barrier(parties, options.timeoutMs ?? DEFAULT_WAIT_MS);
  // Array.from calls each run in turn, in this tick, so every run has started before any continues past its first await.
  const runs = Array.from({ length: parties }, async (_, party) => {
    // An object, not a let: sync changes it, which the compiler can't see from here.
    const run = { arrived: false };
    const sync = (): Promise<void> => {
      if (run.arrived) return Promise.reject(new BarrierBroken(`Party ${party} reached the barrier twice`));
      run.arrived = true;
      return barrier.arrive();
    };
    try {
      return await work(party, sync);
    } catch (error) {
      if (!run.arrived) {
        barrier.break(new BarrierBroken(`Party ${party} failed before reaching the barrier`, { cause: error }));
      }
      throw error;
    } finally {
      if (!run.arrived) barrier.break(new BarrierBroken(`Party ${party} finished without reaching the barrier`));
    }
  });
  return Promise.allSettled(runs);
}

/** The values of the runs that succeeded, in run order. */
export function successes<T>(outcomes: readonly PromiseSettledResult<T>[]): T[] {
  return outcomes.flatMap((outcome) => (outcome.status === 'fulfilled' ? [outcome.value] : []));
}

/** The errors of the runs that failed, in run order. */
export function failures(outcomes: readonly PromiseSettledResult<unknown>[]): unknown[] {
  return outcomes.flatMap((outcome): unknown[] => (outcome.status === 'rejected' ? [outcome.reason as unknown] : []));
}

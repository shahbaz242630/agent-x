/**
 * A clock that moves only when a test moves it (Rule Book §6: fixed clocks).
 * Each call to `now()` returns a new Date, so a caller can't change the
 * clock's time by mutating the value it was given. It fits core's `Clock`
 * (checked in its test); it doesn't import it, since core's own tests use
 * this package.
 */
export class FixedClock {
  #epochMs: number;

  constructor(start: Date) {
    this.#epochMs = toValidEpochMs(start);
  }

  now(): Date {
    return new Date(this.#epochMs);
  }

  /** Moves time forward. Business time never runs backwards, so negative steps are refused. */
  advanceBy(ms: number): void {
    if (!Number.isSafeInteger(ms) || ms < 0) {
      throw new RangeError(`advanceBy needs a whole, non-negative number of milliseconds; got ${ms}`);
    }
    this.#epochMs = toValidEpochMs(new Date(this.#epochMs + ms));
  }
}

function toValidEpochMs(date: Date): number {
  const epochMs = date.getTime();
  if (Number.isNaN(epochMs)) {
    throw new RangeError('FixedClock needs a valid date');
  }
  return epochMs;
}

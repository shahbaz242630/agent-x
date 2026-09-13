/**
 * The source of business time (ADR-006 §3). Business code reads the time only
 * through a Clock, so tests can fix it; the database's `now()` is kept for
 * "recorded at" audit fields.
 */
export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

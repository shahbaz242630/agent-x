/**
 * The source of business time (ADR-006 §3). Business code reads the time only
 * through a Clock, so tests can fix it; the database's clock is kept for
 * "recorded at" audit fields.
 */
export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

/** An hour and a day, in milliseconds: the units business periods are counted in. */
export const HOUR_MS = 3_600_000;
export const DAY_MS = 86_400_000;

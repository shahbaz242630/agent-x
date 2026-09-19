/** The last UUID group has 12 hex digits. */
const MAX_SEQUENCE = 0xffff_ffff_ffff;

/**
 * Deterministic IDs for tests: valid, ordered UUIDv7 strings with a counter in
 * the last group (`00000000-0000-7000-8000-000000000001`, then `…002`), so a
 * test can write the expected IDs by hand. `startAfter` gives two generators
 * separate ranges. It fits core's `IdGenerator` (checked in its test); it
 * doesn't import it, since core's own tests use this package.
 */
export class SequentialIds {
  #sequence: number;

  constructor(startAfter = 0) {
    if (!Number.isSafeInteger(startAfter) || startAfter < 0 || startAfter > MAX_SEQUENCE) {
      throw new RangeError(`startAfter must be a whole number from 0 to ${MAX_SEQUENCE}; got ${startAfter}`);
    }
    this.#sequence = startAfter;
  }

  next(): string {
    if (this.#sequence >= MAX_SEQUENCE) {
      throw new RangeError('SequentialIds has no IDs left');
    }
    this.#sequence += 1;
    return `00000000-0000-7000-8000-${this.#sequence.toString(16).padStart(12, '0')}`;
  }
}

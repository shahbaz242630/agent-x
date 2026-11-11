// The sweep's floor held by the adapter itself (S185), not only by the setting's
// schema: a retention below the least, or not a whole number of days, is refused
// before anything is built, so no sweep can delete a fresh partner message.
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { FixedClock, SequentialIds } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createProviderEvents, LEAST_RETENTION_DAYS } from './provider-events.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const build = (retentionDays: number) =>
  createProviderEvents({ keys, ids: new SequentialIds(1), clock: new FixedClock(new Date(0)), retentionDays });

describe('provider events retention', () => {
  it(`keeps messages at least ${String(LEAST_RETENTION_DAYS)} whole days`, () => {
    expect(() => build(LEAST_RETENTION_DAYS)).not.toThrow();
    for (const days of [LEAST_RETENTION_DAYS - 1, 0, -1, 30.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => build(days)).toThrow(RangeError);
    }
  });
});

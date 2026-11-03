import { describe, expect, it } from 'vitest';

import { growthBetween, readGrowthEnd } from './table-growth.ts';

const SIZES = {
  tables: { 't.a': { rows: 8192, indexes: 16_384, longValues: 0 } },
  indexes: { 't.a_pkey': { table: 't.a', bytes: 16_384, scans: 3 } },
};
const reading = (sizes: unknown = SIZES) => ({ event: 'load.table_sizes', stage: 'x', sizes });

describe('the growth between a run’s two ends (4D2e F12)', () => {
  it('takes their sizes', () => {
    expect(growthBetween(reading(), reading())).toEqual({ before: SIZES, after: SIZES });
  });

  it('says which end could not be read, and why', () => {
    expect(growthBetween({ problem: 'its sizes could not be read: refused' }, reading())).toEqual({
      problem: 'The before reading: its sizes could not be read: refused',
    });
    expect(growthBetween(reading(), { problem: 'no' })).toEqual({ problem: 'The after reading: no' });
  });

  it('says an end that printed nothing, or nothing it can use, said nothing', () => {
    expect(growthBetween(undefined, reading())).toEqual({ problem: 'The before reading said nothing' });
    expect(growthBetween(reading(), undefined)).toEqual({ problem: 'The after reading said nothing' });
    const unusable = [
      null,
      {},
      { tables: {} },
      { tables: { 't.a': { rows: 'big', indexes: 0, longValues: 0 } }, indexes: {} },
      { tables: { 't.a': null }, indexes: {} },
      { tables: {}, indexes: { 't.i': { table: 't.a', bytes: 1 } } },
      { tables: {}, indexes: { 't.i': { table: 7, bytes: 1, scans: 0 } } },
    ];
    for (const sizes of unusable) {
      expect(growthBetween(reading(sizes), reading())).toEqual({ problem: 'The before reading said nothing' });
    }
  });

  it('says a read that failed, and why, rather than stop the run', async () => {
    const failing = (thrown: unknown) =>
      ({
        getExecutor: () => {
          throw thrown;
        },
      }) as unknown as Parameters<typeof readGrowthEnd>[0];
    expect(await readGrowthEnd(failing(new Error('refused')), 'after')).toEqual({
      stage: 'after',
      problem: "its tables' sizes couldn't be read: refused",
    });
    expect(await readGrowthEnd(failing('gone'), 'before')).toEqual({
      stage: 'before',
      problem: "its tables' sizes couldn't be read: gone",
    });
  });
});

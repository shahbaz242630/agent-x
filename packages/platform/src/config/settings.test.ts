import { describe, expect, it } from 'vitest';

import { allOk, type Checked, failures } from './settings.ts';

const ok = (value: unknown): Checked<unknown> => ({ ok: true, value });
const failed = (problem: string): Checked<unknown> => ({ ok: false, problem });

describe('the settings loaders share how a group of checks is judged', () => {
  it('allOk is true only when every check passed', () => {
    expect(allOk({ a: ok(1), b: ok('x') })).toBe(true);
    expect(allOk({ a: ok(1), b: failed('b: is required') })).toBe(false);
    expect(allOk({ a: failed('a: is required') })).toBe(false);
    expect(allOk({})).toBe(true);
  });

  it('failures lists every problem, in the order the checks were made', () => {
    expect(failures([ok(1), failed('second: bad'), ok(3), failed('fourth: bad')])).toEqual([
      'second: bad',
      'fourth: bad',
    ]);
    expect(failures([ok(1)])).toEqual([]);
  });
});

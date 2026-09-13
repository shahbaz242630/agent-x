import { expect, it } from 'vitest';
import { half } from './half.ts';
it('covers one of the two branches', () => {
  expect(half(true)).toBe(1);
});

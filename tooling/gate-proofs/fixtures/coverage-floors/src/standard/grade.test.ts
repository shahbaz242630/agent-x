import { expect, it } from 'vitest';
import { grade } from './grade.ts';
it('covers nine of the ten branches', () => {
  expect(grade(true, true, true, true, true)).toBe(5);
  expect(grade(false, false, false, false, true)).toBe(1);
});

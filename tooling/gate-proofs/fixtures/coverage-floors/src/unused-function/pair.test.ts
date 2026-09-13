import { expect, it } from 'vitest';
import { used } from './pair.ts';
it('calls one of the two functions', () => {
  expect(used()).toBe(1);
});

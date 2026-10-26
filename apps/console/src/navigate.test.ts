import { describe, expect, it } from 'vitest';

import { goTo } from './navigate.ts';

describe('sending the browser on (6A1)', () => {
  it('goes to the address given', () => {
    goTo('#signed-out');
    expect(window.location.hash).toBe('#signed-out');
  });
});

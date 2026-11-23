import { describe, expect, it } from 'vitest';

import { cameBackLate, withoutSignInLate } from './sign-in-late.tsx';

describe('E6-P1 the late sign-in mark', () => {
  it('drops it alone: to the bare path when nothing else was asked, the rest kept otherwise', () => {
    expect(withoutSignInLate('/', '?signInLate=1')).toBe('/');
    expect(withoutSignInLate('/more', '?signInLate=1&tab=x')).toBe('/more?tab=x');
  });

  it('keeps an address without it exactly as written', () => {
    expect(withoutSignInLate('/payments', '?q=a%20b')).toBe('/payments?q=a%20b');
    expect(withoutSignInLate('/payments', '')).toBe('/payments');
  });

  it('reads the mark whatever its value, and nothing else as it', () => {
    expect(cameBackLate('?signInLate=1')).toBe(true);
    expect(cameBackLate('?signInLate=')).toBe(true);
    expect(cameBackLate('?signedInLate=1')).toBe(false);
    expect(cameBackLate('')).toBe(false);
  });
});

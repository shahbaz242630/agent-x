// 6D2: a pass-through held for Try again is held for its own person, in their
// own organisation, for its own supplier: no one else's form ever shows it.
import { afterEach, describe, expect, it } from 'vitest';

import { dropAllTries, heldTry, holdTry } from './held-tries.ts';

const WHOSE = { user: 'User-1', organization: 'org-1', supplier: 'supplier-1' };
const TRIED = {
  key: 'key-1',
  body: { name: 'Gulf Traders LLC', iban: 'AE070331234567890123456', pendingRequests: 'pause' },
  told: 'no',
} as const;

afterEach(() => {
  dropAllTries();
});

describe('a held try', () => {
  it('is found for the same person, in any case of their ID, until dropped', () => {
    holdTry(WHOSE, TRIED);
    expect(heldTry({ ...WHOSE, user: 'user-1' })).toEqual(TRIED);
    holdTry(WHOSE, null);
    expect(heldTry(WHOSE)).toBeUndefined();
  });

  it.each([
    ['another person', { user: 'user-2' }],
    ['another organisation', { organization: 'org-2' }],
    ['another supplier', { supplier: 'supplier-2' }],
  ])('is never found for %s', (_what, change) => {
    holdTry(WHOSE, TRIED);
    expect(heldTry({ ...WHOSE, ...change })).toBeUndefined();
  });
});

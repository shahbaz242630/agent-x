// 6D2: a pass-through held for Try again is held for its own person, in their
// own organisation, for its own supplier: no one else's form ever shows it.
import { afterEach, describe, expect, it } from 'vitest';

import { dropAllTries, heldDraft, heldTry, holdDraft, holdTry } from './held-tries.ts';

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

// 6D3a: a mandate's draft sent with no answer is held the same way, for a new
// mandate apart from each mandate's new version, and dropped with every try.
const DRAFT_WHOSE = { user: 'User-1', organization: 'org-1', mandate: null };
const DRAFT = { key: 'key-2', body: { purpose: 'Office supplies', perOrderLimitMinor: 250_000 } } as const;

describe('a held mandate draft', () => {
  it('is found for the same person, in any case of their ID, until dropped', () => {
    holdDraft(DRAFT_WHOSE, DRAFT);
    expect(heldDraft({ ...DRAFT_WHOSE, user: 'user-1' })).toEqual(DRAFT);
    holdDraft(DRAFT_WHOSE, null);
    expect(heldDraft(DRAFT_WHOSE)).toBeUndefined();
  });

  it.each([
    ['another person', { user: 'user-2' }],
    ['another organisation', { organization: 'org-2' }],
    ['a mandate’s new version', { mandate: 'mandate-1' }],
  ])('is never found for %s', (_what, change) => {
    holdDraft(DRAFT_WHOSE, DRAFT);
    expect(heldDraft({ ...DRAFT_WHOSE, ...change })).toBeUndefined();
  });

  it('is dropped with every try on sign-out, and when the page is left', () => {
    holdDraft(DRAFT_WHOSE, DRAFT);
    holdTry(WHOSE, TRIED);
    dropAllTries();
    expect(heldDraft(DRAFT_WHOSE)).toBeUndefined();
    expect(heldTry(WHOSE)).toBeUndefined();

    holdDraft(DRAFT_WHOSE, DRAFT);
    globalThis.dispatchEvent(new Event('pagehide'));
    expect(heldDraft(DRAFT_WHOSE)).toBeUndefined();
  });
});

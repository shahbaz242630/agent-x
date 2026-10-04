import { describe, expect, it } from 'vitest';

import { movedAsRead } from './use-case-work.ts';

describe('movedAsRead', () => {
  it('lets a move the read allowed through', () => {
    expect(() => {
      movedAsRead({ outcome: 'changed' }, "an agent read as ACTIVE didn't suspend");
    }).not.toThrow();
  });

  it.each(['not_allowed', 'missing', 'stale'])(
    'throws, never answers, a move refused as %s: something past the app is at work',
    (outcome) => {
      expect(() => {
        movedAsRead({ outcome }, "an agent read as ACTIVE didn't suspend");
      }).toThrow(new Error(`an agent read as ACTIVE didn't suspend: ${outcome}`));
    },
  );
});

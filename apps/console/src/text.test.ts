import { describe, expect, it } from 'vitest';

import { t } from './text.ts';

describe('the console’s words (6A1)', () => {
  it('reads a word by its key, filling in what it names, and leaves a name it isn’t given', () => {
    expect(t('nav.approvals')).toBe('Approvals');
    expect(t('more.session', { time: '26 Oct 2026, 21:00', idle: '26 Oct 2026, 10:00' })).toBe(
      "Signed in until 26 Oct 2026, 21:00 at the latest. If you're away, you're signed out at 26 Oct 2026, 10:00; using Agent X moves that on.",
    );
    expect(t('more.session', { time: '26 Oct 2026, 21:00' })).toContain('signed out at {idle};');
  });
});

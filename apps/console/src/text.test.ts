import { describe, expect, it } from 'vitest';

import { t } from './text.ts';

describe('the console’s words (6A1)', () => {
  it('reads a word by its key, filling in what it names, and leaves a name it isn’t given', () => {
    expect(t('nav.approvals')).toBe('Approvals');
    expect(t('more.session', { time: '26 Oct 2026, 21:00' })).toBe('Signed in until 26 Oct 2026, 21:00');
    expect(t('more.session')).toBe('Signed in until {time}');
  });
});

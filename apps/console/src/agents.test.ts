// 6D1: an agent's name is checked by the API's rules (isAgentName,
// visible-name.ts) before anything is sent, and a confirm's answer is read
// for a new key only where it gives one.
import { describe, expect, it } from 'vitest';

import { isAgentName, isLive } from './agents.ts';
import { keyIn } from './pages/key-once.tsx';

describe('isAgentName', () => {
  it.each([
    ['a plain name', 'Payables bot', true],
    ['one character', '7', true],
    ['100 characters', 'a'.repeat(100), true],
    ['100 characters counted as code points, not UTF-16 units', '😀'.repeat(99) + 'a', true],
    ['a joiner inside a word, left to the API', 'نامه\u200Cها', true],
    ['nothing', '', false],
    ['101 characters', 'a'.repeat(101), false],
    ['a space at the start', ' bot', false],
    ['a space at the end', 'bot ', false],
    ['no letter or digit', '!!!', false],
    ['a control character', 'bot\u0007', false],
    ['a format character that reorders text', 'bot\u202Eabc', false],
    ['braille, which shows as a space', 'bot\u2800', false],
    ['a combining mark first', '\u0301bot', false],
    ['five marks piled on one letter', 'x' + '\u0334'.repeat(5), false],
  ])('%s', (_what, name, fine) => {
    expect(isAgentName(name)).toBe(fine);
  });
});

describe('isLive', () => {
  const key = { id: 'k', scopes: [], expiresAt: '2026-11-16T00:00:00.000Z' } as const;
  it('is live only while active and before its expiry', () => {
    const before = Date.parse('2026-11-15T00:00:00.000Z');
    expect(isLive({ ...key, status: 'ACTIVE' }, before)).toBe(true);
    expect(isLive({ ...key, status: 'REVOKED' }, before)).toBe(false);
    expect(isLive({ ...key, status: 'ACTIVE' }, Date.parse('2026-11-16T00:00:00.000Z'))).toBe(false);
  });
});

describe('keyIn', () => {
  it.each([
    ['an answer with a key', { key: 'axk_1_s' }, { key: 'axk_1_s' }],
    ['a retry, its key null', { key: null }, { key: null }],
    ['an answer whose key is not text', { key: 7 }, { key: null }],
    ['an answer with no key (a revoke)', { agent: {} }, undefined],
    ['no answer body', null, undefined],
    ['an answer that is not an object', 'done', undefined],
  ])('reads %s', (_what, answer, read) => {
    expect(keyIn(answer)).toEqual(read);
  });
});

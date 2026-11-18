// 6E3b (SEC-OAUTH-11): where the consent page may send the browser back to: only a web address, from its start.
import { describe, expect, it } from 'vitest';

import { isWebAddress } from './connections.ts';

describe('SEC-OAUTH-11 isWebAddress', () => {
  it.each(['https://chatgpt.com/cb?code=c', 'http://127.0.0.1:53682/callback', 'HTTP://a', 'Https://claude.ai/x'])(
    'takes %j: a web address, its scheme in any case as URLs allow',
    (address) => {
      expect(isWebAddress(address)).toBe(true);
    },
  );

  it.each([
    'javascript:alert(1)',
    "javascript:fetch('https://evil.example')//",
    ' https://x',
    'data:text/html,https://x',
    '//evil.example',
    'https:evil.example',
    '',
    null,
    undefined,
    42,
  ])('refuses %j', (address) => {
    expect(isWebAddress(address)).toBe(false);
  });
});

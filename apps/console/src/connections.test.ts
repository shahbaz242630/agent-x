// 6E3b (SEC-OAUTH-11): where the consent page may send the browser back to: only a web address, from its start.
import { describe, expect, it } from 'vitest';

import { isWebAddress } from './connections.ts';

describe('SEC-OAUTH-11 isWebAddress', () => {
  it.each([
    'https://chatgpt.com/cb?code=c',
    'http://127.0.0.1:53682/callback',
    'http://[::1]:8080/cb',
    'HTTP://localhost/cb',
    'Https://claude.ai/x',
  ])('takes %j: https, or http to the loopback, its scheme in any case as URLs allow', (address) => {
    expect(isWebAddress(address)).toBe(true);
  });

  it.each([
    'javascript:alert(1)',
    "javascript:fetch('https://evil.example')//",
    ' https://x',
    'data:text/html,https://x',
    '//evil.example',
    'https:evil.example',
    // 6F1 G5: plain http only to the loopback, as the server's rule.
    'HTTP://a',
    'http://evil.example/cb',
    'http://127.0.0.1.evil.example/cb',
    'http://localhost.evil.example/cb',
    'https://',
    '',
    null,
    undefined,
    42,
  ])('refuses %j', (address) => {
    expect(isWebAddress(address)).toBe(false);
  });
});

import { createServer } from 'node:http';

import { describe, expect, it } from 'vitest';

import { putAddPasskeyPageInFront } from './add-passkey-page.ts';

describe('SA6 the add-a-passkey page in front of the server', () => {
  it('refuses a server without exactly one request listener, so it never leaves one unwrapped', () => {
    const none = createServer();
    none.removeAllListeners('request');
    const two = createServer(() => undefined);
    two.on('request', () => undefined);

    expect(() => {
      putAddPasskeyPageInFront(none, () => true);
    }).toThrow('expects one request listener on its server, not 0');
    expect(() => {
      putAddPasskeyPageInFront(two, () => true);
    }).toThrow('not 2');
  });

  it('leaves a request without an address to the listener behind it', () => {
    const passed: unknown[] = [];
    const server = createServer((request) => passed.push(request.url));
    putAddPasskeyPageInFront(server, () => true);
    const [front] = server.listeners('request') as ((request: unknown, response: unknown) => void)[];

    front?.({ method: 'GET', url: undefined, headers: {} }, {});

    expect(passed).toEqual([undefined]);
  });
});

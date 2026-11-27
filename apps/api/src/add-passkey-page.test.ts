import type { RequestListener, Server } from 'node:http';

import { describe, expect, it } from 'vitest';

import { putAddPasskeyPageInFront } from './add-passkey-page.ts';

/** A stand-in for a server's request listeners, as far as the front layer reads and replaces them. */
function serverWith(...listeners: RequestListener[]): Server {
  const held = [...listeners];
  return {
    listeners: () => [...held],
    removeListener: (_event: string, listener: RequestListener) => {
      held.splice(held.indexOf(listener), 1);
    },
    on: (_event: string, listener: RequestListener) => {
      held.push(listener);
    },
  } as unknown as Server;
}

describe('SA6 the add-a-passkey page in front of the server', () => {
  it('refuses a server without exactly one request listener, so it never leaves one unwrapped', () => {
    expect(() => {
      putAddPasskeyPageInFront(serverWith(), () => true);
    }).toThrow('expects one request listener on its server, not 0');
    expect(() => {
      putAddPasskeyPageInFront(
        serverWith(
          () => undefined,
          () => undefined,
        ),
        () => true,
      );
    }).toThrow('not 2');
  });

  it('leaves a request without an address to the listener behind it', () => {
    const passed: unknown[] = [];
    const server = serverWith((request) => passed.push(request.url));
    putAddPasskeyPageInFront(server, () => true);
    const [front] = server.listeners('request') as ((request: unknown, response: unknown) => void)[];

    front?.({ method: 'GET', url: undefined, headers: {} }, {});

    expect(passed).toEqual([undefined]);
  });
});

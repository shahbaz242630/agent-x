import type { RequestListener, Server } from 'node:http';
import { runInNewContext } from 'node:vm';

import { describe, expect, it } from 'vitest';

import { ADD_PASSKEY_SCRIPT, putAddPasskeyPageInFront } from './add-passkey-page.ts';

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

/** What the page's script says when the device's prompt ends with an error of this name (null: the key is made). */
async function saidAfterPrompt(errorName: string | null): Promise<string> {
  const status = { textContent: '' };
  let clicked: (() => Promise<void>) | undefined;
  const button = {
    hidden: true,
    disabled: false,
    addEventListener: (_event: string, handler: () => Promise<void>) => {
      clicked = handler;
    },
  };
  const window = {
    location: { hash: `#${'a'.repeat(43)}`, pathname: '/add-passkey' },
    history: { replaceState: () => undefined },
    PublicKeyCredential: Object,
  };
  const document = { getElementById: (id: string) => (id === 'status' ? status : button) };
  const options = { publicKey: { challenge: 'AA', user: { id: 'AA' }, excludeCredentials: [{ id: 'AA' }] } };
  const fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve({ options }) });
  const navigator = {
    credentials: {
      create: () => {
        if (errorName === null) return Promise.reject(new Error('not reached in these tests'));
        const error = new Error('refused');
        error.name = errorName;
        return Promise.reject(error);
      },
    },
  };
  runInNewContext(ADD_PASSKEY_SCRIPT, { window, document, navigator, fetch, atob, btoa });
  await clicked?.();
  return status.textContent;
}

describe('SA6b the add-a-passkey page says why no passkey was made', () => {
  it('says the device already holds a passkey, and to use the phone or a security key', async () => {
    const said = await saidAfterPrompt('InvalidStateError');

    expect(said).toContain('already holds your passkey');
    expect(said).toContain('your phone');
    expect(said).toContain('security key');
    expect(said).toContain('start adding the passkey again');
  });

  it('says the prompt was closed or took too long', async () => {
    expect(await saidAfterPrompt('NotAllowedError')).toContain('closed or took too long');
  });

  it('says plainly that no passkey was made for any other refusal', async () => {
    const said = await saidAfterPrompt('AbortError');

    expect(said).toMatch(/^No passkey was made\. Go back/);
  });
});

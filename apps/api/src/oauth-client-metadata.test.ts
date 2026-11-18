// SEC-OAUTH-09 (6E3c): a client's metadata document fetched only from an
// allowlisted origin, through the outbound fetch's own rules, and refused
// for anything that could turn the fetch on us: an address off the list,
// plain http, a redirect, a body past 16 KB (whatever length it claims), a
// type that is no JSON, a server too slow. The network itself is a stand-in
// (`send`); what is kept of a valid document is oauth-clients.db.test.ts.
import { createOutboundFetch } from '@agentx/platform/outbound';
import { describe, expect, it } from 'vitest';

import { createClientMetadataFetch, MOST_DOCUMENT_BYTES } from './oauth-client-metadata.ts';

const CLAUDE = 'https://claude.ai';
const CLIENT_ID = `${CLAUDE}/oauth/mcp-oauth-client-metadata`;
const DOCUMENT = { client_id: CLIENT_ID, redirect_uris: ['https://claude.ai/api/mcp/auth_callback'] };

type Send = (url: URL, init: RequestInit) => Promise<Response>;

/** The fetcher over a stand-in network answering `send`, and every request that reached it. */
function fetcher(send: Send, { outbound = [CLAUDE], timeoutMs }: { outbound?: string[]; timeoutMs?: number } = {}) {
  const sent: { url: string; init: RequestInit }[] = [];
  const fetch = createOutboundFetch(outbound, (url, init) => {
    sent.push({ url: url.toString(), init });
    return send(url, init);
  });
  return {
    metadata: createClientMetadataFetch({ fetch, trusted: [CLAUDE], ...(timeoutMs ? { timeoutMs } : {}) }),
    sent,
  };
}

const json = (body: string, headers: Record<string, string> = {}) =>
  new Response(body, { status: 200, headers: { 'content-type': 'application/json', ...headers } });

describe('SEC-OAUTH-09 a client metadata document’s fetch', () => {
  it('fetches an allowlisted address, a plain GET asking for JSON, with no redirect followed', async () => {
    const { metadata, sent } = fetcher(() => Promise.resolve(json(JSON.stringify(DOCUMENT), {})));
    expect(metadata.listed(CLIENT_ID)).toBe(true);
    expect(await metadata.fetch(CLIENT_ID)).toEqual({ outcome: 'fetched', document: DOCUMENT });
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe(CLIENT_ID);
    expect(sent[0]?.init).toMatchObject({ method: 'GET', redirect: 'manual', headers: { accept: 'application/json' } });
    // No cookie, no token: nothing of anyone travels with it (ADR-013).
    expect(JSON.stringify(sent[0]?.init.headers)).not.toMatch(/cookie|authorization/i);
  });

  it.each([
    ['an origin off the allowlist', 'https://evil.example/client.json'],
    ['plain http', 'http://claude.ai/oauth/x'],
    ['a dot segment', 'https://claude.ai/a/../x'],
    ['a user in the address', 'https://me@claude.ai/x'],
    ['a registered client’s ID', 'axcl_0123456789abcdef0123456789abcdef'],
  ])('never fetches %s', async (_, clientId) => {
    const { metadata, sent } = fetcher(() => Promise.resolve(json('{}')));
    expect(metadata.listed(clientId)).toBe(false);
    expect(await metadata.fetch(clientId)).toEqual({ outcome: 'refused', reason: 'not_listed' });
    expect(sent).toEqual([]);
  });

  it('AG6: trusting a path prefix, fetches under it and never a neighbour on the same origin', async () => {
    const PAGES = 'https://nousresearch.github.io';
    const sent: string[] = [];
    const fetch = createOutboundFetch([PAGES], (url) => {
      sent.push(url.toString());
      return Promise.resolve(json('{}'));
    });
    const metadata = createClientMetadataFetch({ fetch, trusted: [`${PAGES}/hermes/`] });
    for (const clientId of [`${PAGES}/hermes-evil/client.json`, `${PAGES}/hermes/%2e%2e/evil/client.json`]) {
      expect(await metadata.fetch(clientId)).toEqual({ outcome: 'refused', reason: 'not_listed' });
    }
    expect(await metadata.fetch(`${PAGES}/hermes/client.json`)).toEqual({ outcome: 'fetched', document: {} });
    expect(sent).toEqual([`${PAGES}/hermes/client.json`]);
  });

  it('is refused by the outbound fetch for an origin listed but not on the outbound allowlist', async () => {
    const { metadata, sent } = fetcher(() => Promise.resolve(json('{}')), { outbound: [] });
    expect(await metadata.fetch(CLIENT_ID)).toEqual({ outcome: 'refused', reason: 'refused' });
    expect(sent).toEqual([]);
  });

  it('refuses a redirect, never following it', async () => {
    const { metadata, sent } = fetcher(() =>
      Promise.resolve(new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/' } })),
    );
    expect(await metadata.fetch(CLIENT_ID)).toEqual({ outcome: 'refused', reason: 'refused' });
    expect(sent).toHaveLength(1);
  });

  it.each([
    [
      'a status but 200',
      () => new Response('{}', { status: 404, headers: { 'content-type': 'application/json' } }),
      'status',
    ],
    [
      'a 203, though JSON',
      () => new Response('{}', { status: 203, headers: { 'content-type': 'application/json' } }),
      'status',
    ],
    ['HTML', () => new Response('<html>', { status: 200, headers: { 'content-type': 'text/html' } }), 'content_type'],
    ['text/json', () => new Response('{}', { status: 200, headers: { 'content-type': 'text/json' } }), 'content_type'],
    [
      'another JSON type',
      () => new Response('{}', { status: 200, headers: { 'content-type': 'application/jwk-set+json' } }),
      'content_type',
    ],
    ['no type', () => new Response('{}', { status: 200, headers: { 'content-type': '' } }), 'content_type'],
    ['text that is no JSON', () => json('{"client_id":'), 'not_json'],
    ['a body past 16 KB', () => json(`"${'x'.repeat(MOST_DOCUMENT_BYTES)}"`), 'too_large'],
    [
      'a body past 16 KB claiming to be short',
      () => json(`"${'x'.repeat(MOST_DOCUMENT_BYTES)}"`, { 'content-length': '10' }),
      'too_large',
    ],
  ])('refuses %s', async (_, answer, reason) => {
    const { metadata } = fetcher(() => Promise.resolve(answer()));
    expect(await metadata.fetch(CLIENT_ID)).toEqual({ outcome: 'refused', reason });
  });

  it('takes JSON with its charset, and an empty body as no JSON', async () => {
    const { metadata } = fetcher(() =>
      Promise.resolve(json(JSON.stringify(DOCUMENT), { 'content-type': 'Application/JSON; charset=utf-8' })),
    );
    expect(await metadata.fetch(CLIENT_ID)).toMatchObject({ outcome: 'fetched' });
    const empty = fetcher(() =>
      Promise.resolve(new Response(null, { status: 200, headers: { 'content-type': 'application/json' } })),
    );
    expect(await empty.metadata.fetch(CLIENT_ID)).toEqual({ outcome: 'refused', reason: 'not_json' });
  });

  it('gives up on a server too slow, headers or body', async () => {
    const hang = (_: URL, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          reject(new DOMException('aborted', 'AbortError'));
        });
      });
    const slow = fetcher(hang, { timeoutMs: 20 });
    expect(await slow.metadata.fetch(CLIENT_ID)).toEqual({ outcome: 'refused', reason: 'timeout' });
    const trickle = fetcher(
      (_, init) =>
        Promise.resolve(
          new Response(
            new ReadableStream({
              start(controller) {
                controller.enqueue(new TextEncoder().encode('{'));
                init.signal?.addEventListener('abort', () => {
                  controller.error(new DOMException('aborted', 'AbortError'));
                });
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          ),
        ),
      { timeoutMs: 20 },
    );
    expect(await trickle.metadata.fetch(CLIENT_ID)).toEqual({ outcome: 'refused', reason: 'timeout' });
  });

  it('calls a failed network unreadable', async () => {
    const { metadata } = fetcher(() => Promise.reject(new TypeError('fetch failed')));
    expect(await metadata.fetch(CLIENT_ID)).toEqual({ outcome: 'refused', reason: 'unreadable' });
  });
});

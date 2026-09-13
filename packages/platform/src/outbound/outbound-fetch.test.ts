import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { createOutboundFetch, OutboundRefused } from './outbound-fetch.ts';

const PARTNER = 'https://api.partner.example';

/** Stands in for the network: records each request and gives the answer it was set up with. */
function recordingSend(answer: () => Response = () => new Response('ok')) {
  const sent: { url: string; init: RequestInit }[] = [];
  const send = (url: URL, init: RequestInit): Promise<Response> => {
    sent.push({ url: url.href, init });
    return Promise.resolve(answer());
  };
  return { sent, send };
}

describe('SEC-WEB-05 outbound requests go only to allowlisted origins', () => {
  it('sends a request to an allowed origin, with redirects handed back rather than followed', async () => {
    const { sent, send } = recordingSend();
    const response = await createOutboundFetch([PARTNER], send)(`${PARTNER}/v1/payments?page=2`);

    expect(await response.text()).toBe('ok');
    expect(sent).toEqual([{ url: `${PARTNER}/v1/payments?page=2`, init: { redirect: 'manual' } }]);
  });

  it("keeps the caller's method, headers, body and signal", async () => {
    const { sent, send } = recordingSend();
    const headers = { 'content-type': 'application/json' };
    const signal = AbortSignal.timeout(5000);
    await createOutboundFetch([PARTNER], send)(new URL('/v1/payments', PARTNER), {
      method: 'POST',
      headers,
      body: '{"amount_minor":100}',
      signal,
      redirect: 'error',
    });

    expect(sent).toEqual([
      {
        url: `${PARTNER}/v1/payments`,
        init: { method: 'POST', headers, body: '{"amount_minor":100}', signal, redirect: 'manual' },
      },
    ]);
  });

  it.each([
    ['another host', 'https://evil.example/'],
    ['a subdomain of the allowed host', 'https://files.api.partner.example/'],
    ['a look-alike host that starts with the allowed one', 'https://api.partner.example.evil.example/'],
    ['the same host over plain http', 'http://api.partner.example/'],
    ['the same host on another port', 'https://api.partner.example:8443/'],
    ['a user name and password in the URL', 'https://user:pass@api.partner.example/'],
    ['a relative URL', '/v1/payments'],
    ['text that is not a URL', 'not a url'],
  ])('refuses %s, and sends nothing', async (_what, url) => {
    const { sent, send } = recordingSend();

    await expect(createOutboundFetch([PARTNER], send)(url)).rejects.toBeInstanceOf(OutboundRefused);
    expect(sent).toEqual([]);
  });

  it.each(['follow', 'manual'] as const)('refuses a caller that asks for redirect: %s', async (redirect) => {
    const { sent, send } = recordingSend();

    await expect(createOutboundFetch([PARTNER], send)(PARTNER, { redirect })).rejects.toThrow(
      'Outbound request refused: redirects are never followed',
    );
    expect(sent).toEqual([]);
  });

  it.each([
    ['dispatcher', { dispatcher: {} }],
    ['keepalive', { keepalive: true }],
  ])('refuses the fetch option %s, which it does not pass on', async (option, init) => {
    const { sent, send } = recordingSend();

    await expect(createOutboundFetch([PARTNER], send)(PARTNER, init as RequestInit)).rejects.toThrow(
      `Outbound request refused: the fetch option ${option} is not allowed`,
    );
    expect(sent).toEqual([]);
  });

  it.each([301, 302, 303, 307, 308])('refuses a %i redirect from an allowed origin', async (status) => {
    const { sent, send } = recordingSend(
      () => new Response(null, { status, headers: { location: 'https://evil.example/' } }),
    );

    await expect(createOutboundFetch([PARTNER], send)(`${PARTNER}/v1/payments`)).rejects.toThrow(
      `Outbound request refused: ${PARTNER} answered with a redirect, and redirects are never followed`,
    );
    expect(sent).toHaveLength(1);
  });

  it('passes other answers back as they are, errors included', async () => {
    const { send } = recordingSend(() => new Response('no', { status: 404 }));

    expect((await createOutboundFetch([PARTNER], send)(PARTNER)).status).toBe(404);
  });

  it('refuses everything when the allowlist is empty', async () => {
    const { sent, send } = recordingSend();

    await expect(createOutboundFetch([], send)(PARTNER)).rejects.toBeInstanceOf(OutboundRefused);
    expect(sent).toEqual([]);
  });

  it('names only the origin when it refuses, never the path or query, which can carry tokens', async () => {
    const refusal = createOutboundFetch([PARTNER], recordingSend().send)('https://evil.example/steal?token=abc123');

    await expect(refusal).rejects.toThrow(
      'Outbound request refused: https://evil.example is not on the outbound allowlist',
    );
    await expect(refusal).rejects.not.toThrow(/steal|token|abc123/);
  });
});

describe('SEC-PTR-07 the outbound client re-checks TLS certificate checking before every request', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('refuses to send once NODE_TLS_REJECT_UNAUTHORIZED=0 appears after start-up', async () => {
    const { sent, send } = recordingSend();
    const outbound = createOutboundFetch([PARTNER], send);
    await outbound(PARTNER);

    vi.stubEnv('NODE_TLS_REJECT_UNAUTHORIZED', '0');
    await expect(outbound(PARTNER)).rejects.toThrow(
      'Outbound request refused: TLS certificate checks are off (NODE_TLS_REJECT_UNAUTHORIZED), so nothing is sent',
    );
    expect(sent).toHaveLength(1);
  });
});

/** A local HTTP server on 127.0.0.1 that counts the requests it gets. */
async function startServer(handler: (path: string) => { status: number; location?: string }) {
  let hits = 0;
  const server: Server = createServer((request, response) => {
    hits += 1;
    const { status, location } = handler(request.url ?? '/');
    response.writeHead(status, { connection: 'close', ...(location === undefined ? {} : { location }) });
    response.end(status === 200 ? 'ok' : '');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { server, origin: `http://127.0.0.1:${port}`, hits: () => hits };
}

describe('SEC-WEB-05 with the real fetch, against servers on this machine only', () => {
  let allowed: Awaited<ReturnType<typeof startServer>>;
  let other: Awaited<ReturnType<typeof startServer>>;

  beforeAll(async () => {
    other = await startServer(() => ({ status: 200 }));
    allowed = await startServer((path) =>
      path === '/redirect' ? { status: 302, location: `${other.origin}/stolen` } : { status: 200 },
    );
  });

  afterAll(() => {
    for (const { server } of [allowed, other]) {
      server.closeAllConnections();
      server.close();
    }
  });

  it('fetches from an allowed origin', async () => {
    const response = await createOutboundFetch([allowed.origin])(`${allowed.origin}/ok`);

    expect(response.status).toBe(200);
    expect(await response.text()).toBe('ok');
  });

  it('refuses a redirect from an allowed origin to one that is not allowed, without following it', async () => {
    const before = allowed.hits();

    await expect(createOutboundFetch([allowed.origin])(`${allowed.origin}/redirect`)).rejects.toThrow(
      `Outbound request refused: ${allowed.origin} answered with a redirect, and redirects are never followed`,
    );
    expect(allowed.hits()).toBe(before + 1);
    expect(other.hits()).toBe(0);
  });

  it('refuses an origin that is not allowed without contacting it', async () => {
    await expect(createOutboundFetch([allowed.origin])(`${other.origin}/`)).rejects.toBeInstanceOf(OutboundRefused);
    expect(other.hits()).toBe(0);
  });
});

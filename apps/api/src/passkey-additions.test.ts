import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PasskeyAdditions } from '@agentx/core/modules/identity';
import { OwnPasskeysUnavailable } from '@agentx/core/modules/identity';
import { createOutboundFetch } from '@agentx/platform/outbound';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  ADD_PASSKEY_CSP,
  ADD_PASSKEY_HTML,
  ADD_PASSKEY_PATH,
  ADD_PASSKEY_SCRIPT,
  ADD_PASSKEY_SCRIPT_INTEGRITY,
  ADD_PASSKEY_SCRIPT_PATH,
  ADD_PASSKEY_STYLE,
  ADD_PASSKEY_STYLE_PATH,
} from './add-passkey-page.ts';
import { readConsoleFiles } from './console-files.ts';
import { liveSession, PASSKEY } from './live-session.helper.test.ts';
import { PERSON_KEYS_TENANT } from './my-activity.ts';
import { PAGE_CALLS } from './passkey-additions.ts';
import { closeServers, COOKIE, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';

const PAGE_ORIGIN = 'https://addkey.auth.agentx.example';
const PAGE_HOST = 'addkey.auth.agentx.example';
const APP_HOST = 'app.agentx.example';
const LIVE = liveSession('2026-11-26T09:00:00Z', { amr: PASSKEY, endless: true });
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c1';
const TICKET = 'T'.repeat(43);
const OPTIONS = {
  publicKey: {
    challenge: 'Y2g',
    rp: { id: 'auth.agentx.example', name: 'Agent X' },
    user: { id: 'dXNlcg', name: 'sara', displayName: 'Sara Khan' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60_000,
    excludeCredentials: [{ type: 'public-key', id: 'b2xk' }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    attestation: 'none',
  },
};
const CREDENTIAL = {
  id: 'Y3JlZA',
  rawId: 'Y3JlZA',
  type: 'public-key',
  response: { attestationObject: 'YXR0', clientDataJSON: 'Y2Rq' },
};

afterEach(closeServers);

/** Stand-in additions: each method answers as the test sets, and its calls are kept. */
function additions(changes: Partial<PasskeyAdditions> = {}) {
  return {
    begin: vi.fn<PasskeyAdditions['begin']>(() => Promise.resolve({ outcome: 'done', challengeId: CHALLENGE })),
    steppedUp: vi.fn<PasskeyAdditions['steppedUp']>(() => Promise.resolve()),
    ticket: vi.fn<PasskeyAdditions['ticket']>(() =>
      Promise.resolve({ outcome: 'done', ticket: TICKET, endsAt: new Date('2026-11-26T09:02:00Z') }),
    ),
    status: vi.fn<PasskeyAdditions['status']>(() => Promise.resolve('WAITING_FOR_KEY')),
    options: vi.fn<PasskeyAdditions['options']>(() => Promise.resolve({ outcome: 'done', options: OPTIONS })),
    confirm: vi.fn<PasskeyAdditions['confirm']>(() => Promise.resolve({ outcome: 'done' })),
    ...changes,
  };
}

const server = (stand: PasskeyAdditions | undefined, extra: Parameters<typeof routeServer>[0] = {}) =>
  routeServer({
    live: LIVE,
    passkeyAdditions: stand === undefined ? undefined : { additions: stand, origin: PAGE_ORIGIN },
    ...extra,
  });

/** The server with the page on SOCKET_PAGE_ORIGIN, for requests on a real socket. */
const socketServer = (stand: PasskeyAdditions, extra: Parameters<typeof routeServer>[0] = {}) =>
  routeServer({ live: LIVE, passkeyAdditions: { additions: stand, origin: SOCKET_PAGE_ORIGIN }, ...extra });

/** The person's own request on the app's host, with their session. */
const asPerson = (method: 'GET' | 'POST', url: string, key?: string) => ({
  method,
  url,
  headers: {
    host: APP_HOST,
    cookie: `__Host-agentx-session=${COOKIE}`,
    ...(method === 'POST' && { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' }),
    ...(key !== undefined && { 'idempotency-key': key }),
  },
  ...(method === 'POST' && { payload: '{}' }),
});

/**
 * The page's host as a real socket reaches it (its files are served ahead of Fastify, which inject never passes
 * through): `localhost`, beside the app's `127.0.0.1` on the same port, as the network only goes through the platform's
 * outbound fetch, which sends the Host its address names. The servers these requests reach use SOCKET_PAGE_ORIGIN.
 */
const SOCKET_PAGE_ORIGIN = 'http://localhost';
const socketHost = (host: string): string => (host === PAGE_HOST ? 'localhost' : '127.0.0.1');

/** A request on a real socket to `host` (the page's or the app's), through the platform's outbound fetch. */
const get = async (port: number, host: string, path: string, method = 'GET') => {
  const base = `http://${socketHost(host)}:${String(port)}`;
  const response = await createOutboundFetch([base])(`${base}${path}`, { method });
  return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() };
};

/** The server, listening on a port of its own: the port. */
const listening = async (app: Awaited<ReturnType<typeof routeServer>>): Promise<number> => {
  await app.listen({ host: '127.0.0.1', port: 0 });
  const [address] = app.addresses().filter((each) => typeof each !== 'string');
  return address?.port ?? 0;
};

/** A request of the page's, on its own host and from its own origin, unless told. */
const fromPage = (url: string, body: unknown, { host = PAGE_HOST, origin = PAGE_ORIGIN } = {}) => ({
  method: 'POST' as const,
  url,
  headers: { host, origin, 'content-type': 'application/json' },
  payload: JSON.stringify(body),
});

describe('SA6 the person’s routes for adding a passkey', () => {
  it('starts with the step-up to sign in again for, under the person’s own idempotency keys', async () => {
    const stand = additions();
    const app = await server(stand);

    const answer = await app.inject(asPerson('POST', '/v1/auth/passkeys/additions', 'k-1'));

    expect(answer.statusCode).toBe(202);
    expect(answer.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(stand.begin).toHaveBeenCalledWith(
      LIVE.sessionId,
      LIVE.userId,
      expect.objectContaining({ orgId: PERSON_KEYS_TENANT, operation: 'passkey.add', key: 'k-1' }),
    );
  });

  it('refuses a start without an idempotency key, or from another origin, doing nothing', async () => {
    const stand = additions();
    const app = await server(stand);

    const keyless = await app.inject(asPerson('POST', '/v1/auth/passkeys/additions'));
    const foreign = await app.inject({
      ...asPerson('POST', '/v1/auth/passkeys/additions', 'k-1'),
      headers: { ...asPerson('POST', '/v1/auth/passkeys/additions', 'k-1').headers, origin: PAGE_ORIGIN },
    });

    expect(keyless.json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_INVALID' } });
    expect(foreign.statusCode).toBe(403);
    expect(stand.begin).not.toHaveBeenCalled();
  });

  it('answers the start’s refusals and its key’s own answers', async () => {
    const app = await server(
      additions({
        begin: vi
          .fn<PasskeyAdditions['begin']>()
          .mockResolvedValueOnce({ outcome: 'refused', code: 'UNAUTHENTICATED' })
          .mockResolvedValueOnce({ outcome: 'conflict' })
          .mockResolvedValueOnce({ outcome: 'busy' }),
      }),
    );

    const answers = [];
    for (const key of ['a', 'b', 'c'])
      answers.push(await app.inject(asPerson('POST', '/v1/auth/passkeys/additions', key)));

    expect(answers.map((answer) => [answer.statusCode, answer.json<{ error: { code: string } }>().error.code])).toEqual(
      [
        [401, 'UNAUTHENTICATED'],
        [409, 'IDEMPOTENCY_KEY_REUSED'],
        [409, 'IDEMPOTENCY_KEY_BUSY'],
      ],
    );
  });

  it('gives the page’s ticket, and the page’s address with it in the fragment alone', async () => {
    const stand = additions();
    const app = await server(stand);

    const answer = await app.inject(asPerson('POST', `/v1/auth/passkeys/additions/${CHALLENGE}/confirm`, 'k-2'));

    expect(answer.statusCode).toBe(201);
    expect(answer.json()).toEqual({
      ticket: TICKET,
      page: `${PAGE_ORIGIN}${ADD_PASSKEY_PATH}#${TICKET}`,
      expiresAt: '2026-11-26T09:02:00.000Z',
    });
    expect(stand.ticket).toHaveBeenCalledWith(
      LIVE.sessionId,
      CHALLENGE,
      expect.objectContaining({ orgId: PERSON_KEYS_TENANT, operation: 'passkey.add.confirm' }),
    );
  });

  it.each([
    ['STEP_UP_FAILED', 403],
    ['PASSKEY_TICKET_ALREADY_ISSUED', 409],
  ] as const)('answers a ticket refused as %s with %s', async (code, status) => {
    const app = await server(additions({ ticket: () => Promise.resolve({ outcome: 'refused', code }) }));

    const answer = await app.inject(asPerson('POST', `/v1/auth/passkeys/additions/${CHALLENGE}/confirm`, 'k-3'));

    expect(answer.statusCode).toBe(status);
    expect(answer.json()).toMatchObject({ error: { code } });
  });

  it('answers an addition the session has none of, or another person’s, 404 as one that never existed', async () => {
    const app = await server(additions({ status: () => Promise.resolve('GONE') }));

    const answer = await app.inject(asPerson('GET', `/v1/auth/passkeys/additions/${CHALLENGE}`));

    expect(answer.statusCode).toBe(404);
    expect(answer.json()).toMatchObject({ error: { code: 'NOT_FOUND' } });
  });

  it('says where an addition of the session got to', async () => {
    const stand = additions();
    const app = await server(stand);

    const answer = await app.inject(asPerson('GET', `/v1/auth/passkeys/additions/${CHALLENGE}`));

    expect(answer.json()).toEqual({ status: 'WAITING_FOR_KEY' });
    expect(stand.status).toHaveBeenCalledWith(LIVE.sessionId, CHALLENGE);
  });

  it('refuses each to someone not signed in', async () => {
    const app = await server(additions());

    const answer = await app.inject({
      method: 'GET',
      url: `/v1/auth/passkeys/additions/${CHALLENGE}`,
      headers: { host: APP_HOST },
    });

    expect(answer.statusCode).toBe(401);
  });

  it('while adding is off, answers each 404', async () => {
    const app = await server(undefined);

    const answers = [
      await app.inject(asPerson('POST', '/v1/auth/passkeys/additions', 'k-4')),
      await app.inject(asPerson('POST', `/v1/auth/passkeys/additions/${CHALLENGE}/confirm`, 'k-5')),
      await app.inject(asPerson('GET', `/v1/auth/passkeys/additions/${CHALLENGE}`)),
      await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET })),
      await app.inject(fromPage('/v1/passkey-additions/confirm', { ticket: TICKET, credential: CREDENTIAL })),
    ];

    // The page's calls, with no page origin to come from, are a foreign write: refused before any route.
    expect(answers.map((answer) => answer.statusCode)).toEqual([404, 404, 404, 403, 403]);
    expect((await get(await listening(app), PAGE_HOST, ADD_PASSKEY_PATH)).status).toBe(404);
  });
});

describe('SA6 the add-a-passkey page’s host', () => {
  it.each([
    [ADD_PASSKEY_PATH, 'text/html; charset=utf-8', ADD_PASSKEY_HTML],
    [ADD_PASSKEY_SCRIPT_PATH, 'text/javascript; charset=utf-8', ADD_PASSKEY_SCRIPT],
    [ADD_PASSKEY_STYLE_PATH, 'text/css; charset=utf-8', ADD_PASSKEY_STYLE],
  ])('serves %s with the page’s own strict policy, never kept', async (path, type, body) => {
    const port = await listening(await socketServer(additions()));

    const answer = await get(port, PAGE_HOST, path);
    const head = await get(port, PAGE_HOST, path, 'HEAD');

    expect(answer.status).toBe(200);
    expect(answer.headers['content-type']).toBe(type);
    expect(answer.body).toBe(body);
    expect(answer.headers['content-security-policy']).toBe(ADD_PASSKEY_CSP);
    expect(answer.headers['cache-control']).toBe('no-store');
    expect(answer.headers['x-frame-options']).toBe('DENY');
    expect(answer.headers['x-content-type-options']).toBe('nosniff');
    expect([head.status, head.body]).toEqual([200, '']);
    // A write to the same path is no file of the page's: Fastify's, a plain 404 on that host.
    expect((await get(port, PAGE_HOST, path, 'POST')).status).toBe(404);
  });

  it('holds the page to its own script and style alone, framed by nothing, its script named by its hash', () => {
    const policy = Object.fromEntries(
      ADD_PASSKEY_CSP.split('; ').map((part): [string, string] => {
        const [name = '', ...values] = part.split(' ');
        return [name, values.join(' ')];
      }),
    );
    expect(policy).toEqual({
      'default-src': "'none'",
      'script-src': "'self'",
      'style-src': "'self'",
      'connect-src': "'self'",
      'base-uri': "'none'",
      'form-action': "'none'",
      'frame-ancestors': "'none'",
      'require-trusted-types-for': "'script'",
      'trusted-types': '',
    });
    expect(ADD_PASSKEY_SCRIPT_INTEGRITY).toBe(
      `sha256-${createHash('sha256').update(ADD_PASSKEY_SCRIPT).digest('base64')}`,
    );
    expect(ADD_PASSKEY_HTML).toContain(`integrity="${ADD_PASSKEY_SCRIPT_INTEGRITY}"`);
    // No inline script or style, no handler attribute, and nothing from another origin.
    // Its one script tag names its file; no inline script or style, no handler, nothing from another origin: in any case.
    expect(ADD_PASSKEY_HTML.match(/<script\b[^>]*>/gi)).toEqual([
      `<script src="${ADD_PASSKEY_SCRIPT_PATH}" integrity="${ADD_PASSKEY_SCRIPT_INTEGRITY}" defer>`,
    ]);
    expect(ADD_PASSKEY_HTML).not.toMatch(/<style\b|\son[a-z]+\s*=|https?:\/\//i);
    // The script writes text alone, and drops the ticket from the address.
    expect(ADD_PASSKEY_SCRIPT).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/);
    expect(ADD_PASSKEY_SCRIPT).toContain("window.history.replaceState(null, '', window.location.pathname)");
    expect(ADD_PASSKEY_SCRIPT).toContain("credentials: 'omit'");
  });

  it('serves none of the page’s files on the app’s host, and nothing else on the page’s host', async () => {
    const app = await server(additions());

    const elsewhere = {
      statusCode: (await get(await listening(await socketServer(additions())), APP_HOST, ADD_PASSKEY_PATH)).status,
    };
    const health = await app.inject({ method: 'GET', url: '/health', headers: { host: PAGE_HOST } });
    const session = await app.inject({
      method: 'GET',
      url: '/v1/auth/session',
      headers: { host: PAGE_HOST, cookie: `__Host-agentx-session=${COOKIE}` },
    });
    const ticket = await app.inject({
      ...asPerson('POST', `/v1/auth/passkeys/additions/${CHALLENGE}/confirm`, 'k-6'),
      headers: { ...asPerson('POST', '/x', 'k-6').headers, host: PAGE_HOST, origin: PAGE_ORIGIN },
    });

    expect([elsewhere.statusCode, health.statusCode, session.statusCode, ticket.statusCode]).toEqual([
      404, 404, 404, 404,
    ]);
  });

  it('hands out the options for the ticket, from the page’s own origin', async () => {
    const stand = additions();
    const app = await server(stand);

    const answer = await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }));

    expect(answer.statusCode).toBe(200);
    expect(answer.json()).toEqual({ options: OPTIONS });
    expect(stand.options).toHaveBeenCalledWith(TICKET);
  });

  it('hands out the options’ named fields alone, nothing else the login service said', async () => {
    const said = {
      publicKey: { ...OPTIONS.publicKey, extensions: { credProps: true }, hints: ['security-key'] },
      mediation: 'x',
    };
    const app = await server(additions({ options: () => Promise.resolve({ outcome: 'done', options: said }) }));

    const answer = await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }));

    expect(answer.json()).toEqual({ options: OPTIONS });
  });

  it('takes the key made, from the page’s own origin, and says it was added', async () => {
    const stand = additions();
    const app = await server(stand);

    const answer = await app.inject(
      fromPage('/v1/passkey-additions/confirm', { ticket: TICKET, credential: CREDENTIAL }),
    );

    expect(answer.statusCode).toBe(200);
    expect(stand.confirm).toHaveBeenCalledWith(TICKET, CREDENTIAL);
  });

  it('refuses a call from the app’s origin, another site or none, or on the app’s host, doing nothing', async () => {
    const stand = additions();
    const app = await server(stand);

    const answers = [
      await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }, { origin: PUBLIC_ORIGIN })),
      await app.inject(
        fromPage('/v1/passkey-additions/options', { ticket: TICKET }, { origin: 'https://evil.example' }),
      ),
      await app.inject({
        ...fromPage('/v1/passkey-additions/options', { ticket: TICKET }),
        headers: { host: PAGE_HOST, 'content-type': 'application/json' },
      }),
      await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }, { host: APP_HOST })),
    ];

    expect(answers.map((answer) => answer.statusCode)).toEqual([403, 403, 403, 404]);
    expect(stand.options).not.toHaveBeenCalled();
  });

  it.each([
    ['a ticket of another shape', { ticket: 'short' }],
    ['more than the ticket', { ticket: TICKET, more: 1 }],
  ])('refuses %s as the options’ body', async (_name, body) => {
    const stand = additions();
    const app = await server(stand);

    expect((await app.inject(fromPage('/v1/passkey-additions/options', body))).statusCode).toBe(400);
    expect(stand.options).not.toHaveBeenCalled();
  });

  it.each([
    ['a credential of another type', { ...CREDENTIAL, type: 'password' }],
    ['a credential value that isn’t base64url', { ...CREDENTIAL, rawId: 'not base64url!' }],
    ['a credential with more in it', { ...CREDENTIAL, extra: 'x' }],
  ])('refuses %s as the key made', async (_name, credential) => {
    const stand = additions();
    const app = await server(stand);

    expect(
      (await app.inject(fromPage('/v1/passkey-additions/confirm', { ticket: TICKET, credential }))).statusCode,
    ).toBe(400);
    expect(stand.confirm).not.toHaveBeenCalled();
  });

  it.each([
    ['PASSKEY_TICKET_INVALID', 409],
    ['PASSKEY_REFUSED', 422],
  ] as const)('answers a key refused as %s with %s', async (code, status) => {
    const app = await server(additions({ confirm: () => Promise.resolve({ outcome: 'refused', code }) }));

    const answer = await app.inject(
      fromPage('/v1/passkey-additions/confirm', { ticket: TICKET, credential: CREDENTIAL }),
    );

    expect(answer.statusCode).toBe(status);
    expect(answer.json()).toMatchObject({ error: { code } });
  });

  it('answers the person’s token refused, which its use case says as the key refused, 422, logging no alarm', async () => {
    const app = await server(
      additions({ options: () => Promise.resolve({ outcome: 'refused', code: 'PASSKEY_REFUSED' }) }),
    );

    const answer = await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }));

    expect(answer.statusCode).toBe(422);
    expect(answer.json()).toMatchObject({ error: { code: 'PASSKEY_REFUSED' } });
  });

  it('answers a used ticket at the options 409', async () => {
    const app = await server(
      additions({ options: () => Promise.resolve({ outcome: 'refused', code: 'PASSKEY_TICKET_INVALID' }) }),
    );

    expect((await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }))).statusCode).toBe(409);
  });

  it('answers the login service failing 503, to start again', async () => {
    const error = new OwnPasskeysUnavailable('asking for a passkey: it answered 500');
    const app = await server(additions({ options: () => Promise.reject(error), confirm: () => Promise.reject(error) }));

    const options = await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }));
    const confirm = await app.inject(
      fromPage('/v1/passkey-additions/confirm', { ticket: TICKET, credential: CREDENTIAL }),
    );

    expect([options.statusCode, confirm.statusCode]).toEqual([503, 503]);
    expect(options.json()).toMatchObject({ error: { code: 'SIGN_IN_UNAVAILABLE' } });
    expect(options.body).not.toContain(TICKET);
  });

  it('answers any other failure as the server’s own', async () => {
    const app = await server(additions({ options: () => Promise.reject(new Error('a bug')) }));

    expect((await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }))).statusCode).toBe(500);
  });

  it('holds each network to its own share of the page’s calls a minute', async () => {
    const app = await server(additions());

    const codes: number[] = [];
    for (let call = 0; call <= PAGE_CALLS.most; call += 1) {
      codes.push((await app.inject(fromPage('/v1/passkey-additions/options', { ticket: TICKET }))).statusCode);
    }

    expect(codes.slice(0, PAGE_CALLS.most).every((code) => code === 200)).toBe(true);
    expect(codes.at(-1)).toBe(429);
  });
});

describe('SA6 the console is never served on the page’s host', () => {
  let directory: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'agentx-addkey-'));
    await mkdir(join(directory, 'assets'), { recursive: true });
    await writeFile(join(directory, 'index.html'), '<!doctype html><title>Agent X console</title>', { mode: 0o600 });
  });

  afterAll(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it('serves the console on the app’s host, and on the page’s host the page alone', async () => {
    const port = await listening(await socketServer(additions(), { consoleFiles: await readConsoleFiles(directory) }));

    expect((await get(port, APP_HOST, '/more/passkeys')).body).toContain('Agent X console');
    const onPage = await get(port, PAGE_HOST, '/more/passkeys');
    expect(onPage.status).toBe(404);
    expect(onPage.body).not.toContain('Agent X console');
    expect((await get(port, PAGE_HOST, ADD_PASSKEY_PATH)).body).toBe(ADD_PASSKEY_HTML);
  });
});

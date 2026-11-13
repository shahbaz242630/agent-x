// SA1: the login service's public host gets the API's plain 404 and nothing
// else: no console page, no route, no health. Through Fastify's inject for the
// routes, and through a real server listening for the console's layer, which
// stands in front of Fastify where inject never reaches.
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createOutboundFetch } from '@agentx/platform/outbound';
import { afterEach, describe, expect, it } from 'vitest';

import { readConsoleFiles } from './console-files.ts';
import { CORRELATION_HEADER } from './correlation.ts';
import { loginHostCheck } from './login-host.ts';
import { closeServers, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SECURITY_HEADERS } from './security-headers.ts';

const LOGIN_ORIGIN = 'https://auth.agentx.example';
const PAGE = '<!doctype html><title>Agent X</title>';

const folders: string[] = [];

afterEach(async () => {
  await closeServers();
  await Promise.all(folders.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('which hosts are the login service’s (SA1)', () => {
  const isLogin = loginHostCheck(LOGIN_ORIGIN);

  it('is its host in any case, with a trailing dot, on any port, where the issuer names none', () => {
    for (const host of [
      'auth.agentx.example',
      'AUTH.AgentX.Example',
      'auth.agentx.example.',
      'auth.agentx.example:443',
      'auth.agentx.example:80',
      // Azure's edge may match the door's host whatever the port.
      'auth.agentx.example:8443',
    ]) {
      expect(isLogin(host), host).toBe(true);
    }
  });

  it('is never another host, no host, or a Host that isn’t a plain host', () => {
    for (const host of [
      undefined,
      '',
      'app.agentx.example',
      'ca-agentx-stg-api.internal.example',
      'auth.agentx.example.evil',
      'xauth.agentx.example',
      'auth.agentx.example/x',
      'user@auth.agentx.example',
      'auth.agentx.example?x',
      'auth.agentx.example#x',
      'auth agentx',
    ]) {
      expect(isLogin(host), String(host)).toBe(false);
    }
  });

  it('names a port where the issuer does: a local run’s login service beside the API on localhost', () => {
    const local = loginHostCheck('http://localhost:8081');
    expect(local('localhost:8081')).toBe(true);
    expect(local('LOCALHOST:8081')).toBe(true);
    expect(local('localhost:8080')).toBe(false);
    expect(local('localhost')).toBe(false);
    expect(local('localhost:443')).toBe(false);
  });

  it('is nothing at all without an issuer: sign-in is off', () => {
    expect(loginHostCheck(undefined)('auth.agentx.example')).toBe(false);
  });
});

/** The API's own 404, with the security headers and the correlation ID every answer carries. */
function expectPlain404(answer: { statusCode: number; headers: Record<string, unknown>; body: string }, what: string) {
  expect(answer.statusCode, what).toBe(404);
  expect(answer.headers['content-type'], what).toBe('application/json; charset=utf-8');
  const body = JSON.parse(answer.body) as { error: { code: string; correlationId: string } };
  expect(body.error.code, what).toBe('NOT_FOUND');
  expect(answer.headers[CORRELATION_HEADER], what).toBe(body.error.correlationId);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(answer.headers[name], what).toBe(value);
}

describe('the login service’s host on the API (SA1)', () => {
  const PATHS = [
    '/',
    '/debug',
    '/DEBUG',
    '/debug/ready',
    '/approvals',
    '/v1/agents',
    '/health',
    '/health/ready',
    '/mcp',
  ];

  it('answers every path, read or write, with the plain 404, whatever the Host’s case or port', async () => {
    const app = await routeServer({ loginOrigin: LOGIN_ORIGIN });
    for (const host of ['auth.agentx.example', 'AUTH.agentx.EXAMPLE:443', 'auth.agentx.example:8443']) {
      for (const path of PATHS) {
        expectPlain404(await app.inject({ url: path, headers: { host } }), `${host}${path}`);
      }
      expectPlain404(
        await app.inject({ method: 'POST', url: '/v1/agents', headers: { host, origin: PUBLIC_ORIGIN } }),
        `${host} POST`,
      );
    }
  });

  it('leaves the app host, an internal host and a forwarded host alone', async () => {
    const app = await routeServer({ loginOrigin: LOGIN_ORIGIN });
    for (const headers of [
      { host: 'app.agentx.example' },
      { host: 'ca-agentx-stg-api.internal.example' },
      // Only the Host that reached the server counts, never the one a client says it was sent to.
      { host: 'app.agentx.example', 'x-forwarded-host': 'auth.agentx.example' },
    ]) {
      expect((await app.inject({ url: '/health', headers })).statusCode, headers.host).toBe(200);
    }
  });

  it('leaves every host alone where there is no login service', async () => {
    const app = await routeServer({});
    expect((await app.inject({ url: '/health', headers: { host: 'auth.agentx.example' } })).statusCode).toBe(200);
  });
});

/** A port free on this machine now, for a login service whose origin must name it before the server starts (a throwaway API server, as node:net is out of bounds here). */
async function freePort(): Promise<number> {
  const probe = await routeServer({});
  await probe.listen({ host: '127.0.0.1', port: 0 });
  const address = probe.server.address();
  await probe.close();
  if (address === null || typeof address === 'string') throw new Error('no port');
  return address.port;
}

describe('the console’s files on the login service’s host (SA1)', () => {
  it('serves no page there, only the plain 404, while the app host still gets its page', async () => {
    const port = await freePort();
    // Two names for the same server: localhost:<port> is the login service's host here, 127.0.0.1:<port> the app's.
    const login = `http://localhost:${String(port)}`;
    const own = `http://127.0.0.1:${String(port)}`;
    const app = await routeServer({
      loginOrigin: login,
      consoleFiles: await readConsoleFiles(await consoleBuild()),
    });
    await app.listen({ host: '127.0.0.1', port });
    const fetch = createOutboundFetch([login, own]);
    for (const path of ['/', '/approvals', '/debug']) {
      const answer = await fetch(login + path);
      const text = await answer.text();
      expect(answer.status, path).toBe(404);
      expect(answer.headers.get('content-type'), path).toBe('application/json; charset=utf-8');
      expect(text, path).not.toContain('<!doctype html>');
      expect(JSON.parse(text), path).toMatchObject({ error: { code: 'NOT_FOUND' } });
    }
    const page = await fetch(`${own}/approvals`);
    expect(page.status).toBe(200);
    expect(await page.text()).toBe(PAGE);
  });
});

/** A console build of the page alone, in a folder of its own, removed after the test. */
async function consoleBuild(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'agentx-login-host-'));
  folders.push(dir);
  await writeFile(join(dir, 'index.html'), PAGE, { mode: 0o600 });
  return dir;
}

// ADR-010 §7, the portability proof: the whole product runs from
// deploy/compose with no cloud account and no internet. These tests look at
// the running stack from outside (through the edge, as a browser would) and
// from inside (through docker compose).
import { request as httpRequest } from 'node:http';

import { describe, expect, it } from 'vitest';

import { findLeaks } from '../../packages/testing/src/log-scan.ts';
import { API_ORIGIN, execIn, localLogins, LOGIN_ORIGIN, serviceLogs, serviceState } from './compose.ts';

/** The API's log lines, parsed. */
async function apiLog(): Promise<{ raw: string; lines: Record<string, unknown>[] }> {
  const raw = await serviceLogs('api');
  const lines = raw
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  return { raw, lines };
}

describe('ADR-010 §7 the stack from deploy/compose', () => {
  it('answers the health check through the edge, with the security headers and no server version', async () => {
    const response = await fetch(`${API_ORIGIN}/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'ok' });
    expect(response.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(response.headers.get('strict-transport-security')).toContain('max-age=');
    expect(response.headers.get('x-correlation-id')).toMatch(/^[0-9a-f-]{36}$/);
    expect(response.headers.get('server')).toBe('nginx');
  });

  it('SEC-WEB-01 refuses a write from another site through the edge', async () => {
    const response = await fetch(`${API_ORIGIN}/health`, {
      method: 'POST',
      headers: { origin: 'https://evil.example' },
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: { code: 'ORIGIN_REFUSED' } });
  });

  it('ran the set-up job to completion, and the server matched db/bootstrap', async () => {
    expect(await serviceState('db-setup')).toMatchObject({ State: 'exited', ExitCode: 0 });
    expect(await serviceLogs('db-setup')).toContain('"event":"db_setup.done"');
  });

  it('ran the migration job to completion before the API started', async () => {
    expect(await serviceState('migrate')).toMatchObject({ State: 'exited', ExitCode: 0 });
    const migrateLog = await serviceLogs('migrate');
    expect(migrateLog).toContain('"event":"migrate.done"');
    const { lines } = await apiLog();
    const own = lines.map((line) => String(line.event)).filter((event) => event.startsWith('api.'));
    expect(own.slice(0, 3)).toEqual(['api.starting', 'api.database_connected', 'api.listening']);
  });

  it('writes only JSON lines, with none of the generated logins in them', async () => {
    const { raw, lines } = await apiLog();
    expect(lines.length).toBeGreaterThan(0);
    expect(raw.split('\n').filter((line) => line !== '' && !line.startsWith('{'))).toEqual([]);
    expect(findLeaks(raw, localLogins())).toEqual([]);
    expect(findLeaks(await serviceLogs('migrate'), localLogins())).toEqual([]);
    expect(findLeaks(await serviceLogs('db-setup'), localLogins())).toEqual([]);
  });

  it('gives the API no way out: a call to the internet from inside fails to resolve', async () => {
    const probe = await execIn('api', [
      'node',
      '-e',
      "fetch('https://registry.npmjs.org/').then(() => process.exit(0), (e) => { console.log(e.cause?.code ?? e.message); process.exit(1); })",
    ]);
    expect(probe.code).toBe(1);
    expect(probe.stdout.trim()).toMatch(/^(EAI_AGAIN|ENOTFOUND)$/);
  });

  it('serves the login service through the edge, as the issuer the browser will see', async () => {
    const response = await fetch(`${LOGIN_ORIGIN}/.well-known/openid-configuration`);
    expect(response.status).toBe(200);
    const discovery = (await response.json()) as { issuer: string };
    expect(discovery.issuer).toBe(LOGIN_ORIGIN);
    expect((await fetch(`${LOGIN_ORIGIN}/ui/v2/login/ready`)).status).toBe(200);
  });

  it.each([8080, 8081])(
    'answers a request for any other host name on port %s with 421 (DNS rebinding)',
    async (port) => {
      // Node's fetch won't send a foreign Host header, so a plain request does.
      const status = await new Promise<number>((resolve, reject) => {
        const request = httpRequest(
          { host: '127.0.0.1', port, path: '/health', headers: { host: 'evil.example' } },
          (response) => {
            response.resume();
            resolve(response.statusCode ?? 0);
          },
        );
        request.on('error', reject);
        request.end();
      });
      expect(status).toBe(421);
    },
  );

  it("hides Zitadel's own debug and metrics pages behind the edge", async () => {
    expect((await fetch(`${LOGIN_ORIGIN}/debug/metrics`)).status).toBe(404);
    expect((await fetch(`${LOGIN_ORIGIN}/debug/ready`)).status).toBe(404);
  });
});

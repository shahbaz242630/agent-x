// SA1's smoke checks of the auth host, against a stand-in for staging's door.
import { describe, expect, it } from 'vitest';

import { authOriginOf, CHECKS, checkAuthDoor } from './auth-door.ts';

const AUTH = 'https://auth.example.test';
const NOW = new Date('2026-11-13T09:00:00Z');

interface Answer {
  readonly status: number;
  readonly type?: string;
  readonly body?: string;
}

const API_404: Answer = {
  status: 404,
  type: 'application/json; charset=utf-8',
  body: JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Not found.', correlationId: 'c' } }),
};
const DISCOVERY: Answer = { status: 200, type: 'application/json', body: JSON.stringify({ issuer: AUTH }) };
const PAGE: Answer = { status: 200, type: 'text/html; charset=utf-8', body: '<!DOCTYPE html><title>Agent X</title>' };

/** A door answering each path from `answers` in turn (the last one repeats), else the healthy answer. */
function door(answers: Record<string, (Answer | 'drop')[]> = {}) {
  const calls: {
    url: string;
    method: string | undefined;
    headers: Record<string, string>;
    body: string | undefined;
  }[] = [];
  const fetcher = async (
    url: string,
    init: { method?: string; headers: Record<string, string>; body?: string; signal: AbortSignal },
  ) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body });
    const path = url.slice(AUTH.length);
    const healthy = path === '/.well-known/openid-configuration' ? DISCOVERY : API_404;
    const queue = answers[path] ?? [healthy];
    const next = (queue.length > 1 ? queue.shift() : queue[0]) ?? healthy;
    if (next === 'drop') throw new TypeError('fetch failed');
    const headers = next.type === undefined ? {} : { 'content-type': next.type };
    return Promise.resolve(new Response(next.body ?? null, { status: next.status, headers }));
  };
  return { calls, fetcher };
}

const run = (fake: ReturnType<typeof door>, wakeMs = 30_000) => {
  let now = NOW.getTime();
  return checkAuthDoor(AUTH, {
    fetcher: fake.fetcher,
    now: () => new Date(now),
    wakeMs,
    pause: () => {
      now += 10_000;
      return Promise.resolve();
    },
  });
};

const lineOf = async (path: string, answers: (Answer | 'drop')[], wakeMs?: number) => {
  const result = await run(door({ [path]: answers }), wakeMs);
  expect(result.passed).toBe(false);
  const index = CHECKS.findIndex((check) => check.path === path);
  return result.lines[index];
};

describe('SA1: the smoke test of the auth host', () => {
  it('finds the auth host beside the app host, and refuses any other origin', () => {
    expect(authOriginOf('https://app.example.test')).toBe(AUTH);
    expect(authOriginOf('https://app.example.test:8443')).toBe('https://auth.example.test:8443');
    expect(() => authOriginOf('https://example.test')).toThrow(/must be the app host/);
  });

  it('passes a door that reaches Zitadel for discovery and gives the API’s 404 to the rest, naming no host', async () => {
    const fake = door();
    const said: string[] = [];
    let now = NOW.getTime();
    const result = await checkAuthDoor(
      AUTH,
      {
        fetcher: fake.fetcher,
        now: () => new Date(now),
        pause: () => {
          now += 1;
          return Promise.resolve();
        },
      },
      (line) => said.push(line),
    );
    expect(result).toEqual({ lines: CHECKS.map(({ name }) => `auth host ${name}: ok`), passed: true });
    expect(said).toEqual(result.lines);
    expect(result.lines.join('\n')).not.toContain('example.test');
    expect(fake.calls.map(({ url }) => url)).toEqual(CHECKS.map(({ path }) => `${AUTH}${path}`));
    // Zitadel's system API is asked as the console would ask a service: a gRPC-web POST.
    expect(fake.calls.at(-1)).toMatchObject({
      method: 'POST',
      headers: { 'content-type': 'application/grpc-web+proto' },
      body: '',
    });
  });

  it('fails our console’s page on the auth host, saying what broke and what next', async () => {
    expect(await lineOf('/', [PAGE])).toBe(
      "auth host GET /: answered 200 with a page, not the API's JSON 404: our console's page is reachable on the auth host; " +
        'check the API has AGENTX_OIDC_ISSUER set to the auth origin and the auth door still ends with "/" to the API (deploy/azure/apps.bicep, SA1)',
    );
    // A 404 that is a page, not the API's JSON, fails too.
    expect(await lineOf('/', [{ ...PAGE, status: 404 }])).toMatch(/^auth host GET \/: answered 404 with a page/);
  });

  it('fails the API’s health or Zitadel’s system API answering on the auth host', async () => {
    expect(await lineOf('/health', [{ status: 200, type: 'application/json', body: '{"status":"ok"}' }])).toMatch(
      /^auth host GET \/health: answered 200 with application\/json, not the API's JSON 404: the API's health is reachable/,
    );
    expect(
      await lineOf('/zitadel.system.v1.SystemService/ListInstances', [
        { status: 200, type: 'application/grpc-web+proto' },
      ]),
    ).toMatch(
      /answered 200 with application\/grpc-web\+proto, not the API's JSON 404: Zitadel's system API is reachable/,
    );
  });

  it('fails a 404 that is not the API’s own: no content type, not JSON, or another code', async () => {
    expect(await lineOf('/health', [{ status: 404 }])).toMatch(/answered 404 with no content type/);
    expect(await lineOf('/health', [{ status: 404, type: 'application/json', body: 'not json' }])).toMatch(
      /answered 404 with application\/json, not the API's JSON 404/,
    );
    expect(
      await lineOf('/health', [{ status: 404, type: 'application/json', body: '{"error":{"code":"OTHER"}}' }]),
    ).toMatch(/answered 404 with application\/json/);
    expect(await lineOf('/health', [{ status: 404, type: 'application/json', body: 'null' }])).toMatch(
      /answered 404 with application\/json/,
    );
  });

  it('fails discovery that is gone, not JSON, or names another issuer', async () => {
    const path = '/.well-known/openid-configuration';
    expect(await lineOf(path, [API_404])).toBe(
      "auth host GET /.well-known/openid-configuration: answered 404, not Zitadel's sign-in discovery: nobody can sign in; " +
        'check the auth door still sends /.well-known/ to Zitadel and Zitadel is up (Incident playbook)',
    );
    for (const body of ['<html>', JSON.stringify({ issuer: 'https://auth.elsewhere.test' }), 'null']) {
      expect(await lineOf(path, [{ status: 200, type: 'application/json', body }]), body).toMatch(
        /answered 200 \(application\/json\), but not with Zitadel's discovery for the auth origin/,
      );
    }
  });

  it('waits for a sleeping app, and fails one still asleep when the allowance runs out', async () => {
    const fake = door({ '/.well-known/openid-configuration': ['drop', { status: 503 }, DISCOVERY] });
    expect((await run(fake, 60_000)).passed).toBe(true);
    expect(await lineOf('/', [{ status: 502 }], 30_000)).toBe(
      'auth host GET /: answered 502 after 30 s: the auth host did not answer; check the auth door and its apps are running (Incident playbook)',
    );
  });
});

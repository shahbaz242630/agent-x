// SA1's smoke checks of the auth host, against a stand-in for staging's door.
import { describe, expect, it } from 'vitest';

import { authOriginOf, CHECKS, checkAuthDoor, checkSignInLands } from './auth-door.ts';

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

describe('PL-26: a sign-in lands on the login pages, never Zitadel’s hosted login', () => {
  const APP = 'https://app.example.test';
  const AUTHORIZE = `${AUTH}/oauth/v2/authorize?client_id=c&state=secret-state`;

  /** The API's sign-in and Zitadel's authorize, answering as given; every request kept. */
  function signIn(authorize: Response | 'drop', started: Response = redirect(AUTHORIZE)) {
    const calls: { url: string; redirect: string | undefined }[] = [];
    const fetcher = (url: string, init: { redirect?: 'manual' }) => {
      calls.push({ url, redirect: init.redirect });
      if (url === `${APP}/v1/auth/sign-in`) return Promise.resolve(started.clone());
      if (authorize === 'drop') return Promise.reject(new TypeError('fetch failed'));
      return Promise.resolve(authorize.clone());
    };
    return { calls, fetcher };
  }

  function redirect(location: string, status = 302): Response {
    return new Response(null, { status, headers: { location } });
  }

  const check = (fake: ReturnType<typeof signIn>) => {
    let now = NOW.getTime();
    return checkSignInLands(APP, AUTH, {
      fetcher: fake.fetcher,
      now: () => new Date(now),
      wakeMs: 20_000,
      pause: () => {
        now += 10_000;
        return Promise.resolve();
      },
    });
  };

  it('passes a sign-in Zitadel sends to /ui/v2/login, following neither redirect, naming no host or state', async () => {
    for (const location of ['/ui/v2/login/login?authRequest=V2_1', `${AUTH}/ui/v2/login/login?authRequest=V2_1`]) {
      const fake = signIn(redirect(location));
      const said: string[] = [];
      const result = await checkSignInLands(
        APP,
        AUTH,
        { fetcher: fake.fetcher, now: () => NOW, pause: () => Promise.resolve() },
        (line) => said.push(line),
      );
      expect(result).toEqual({ line: 'auth host GET /oauth/v2/authorize (a sign-in from the API): ok', passed: true });
      expect(said).toEqual([result.line]);
      expect(fake.calls).toEqual([
        { url: `${APP}/v1/auth/sign-in`, redirect: 'manual' },
        { url: AUTHORIZE, redirect: 'manual' },
      ]);
    }
  });

  it('fails a sign-in sent to the hosted login, another page, another host, or no redirect at all', async () => {
    const said = async (authorize: Response | 'drop'): Promise<string> => {
      const result = await check(signIn(authorize));
      expect(result.passed).toBe(false);
      expect(result.line).not.toMatch(/example\.test|secret-state/);
      return result.line;
    };
    expect(await said(redirect('/ui/login/login?authRequestID=1'))).toBe(
      "auth host GET /oauth/v2/authorize (a sign-in from the API): sent the browser to /ui/login/login, not the login pages (/ui/v2/login): a sign-in or an email link may land on Zitadel's hosted login, which the auth door keeps closed; " +
        "check Zitadel's login v2 is the instance's login (its base URI the auth host's /ui/v2/login) and the auth door sends /oauth/v2/ to Zitadel (deploy/azure/auth-door.json)",
    );
    expect(await said(redirect('https://elsewhere.example.test/ui/v2/login'))).toMatch(
      /sent the browser to another host,/,
    );
    expect(await said(new Response('{}', { status: 400 }))).toMatch(/: answered 400, not the login pages/);
    expect(await said(new Response(null, { status: 404 }))).toMatch(/: answered 404, not the login pages/);
    expect(await said('drop')).toMatch(/: answered no answer after 20 s: Zitadel did not answer;/);
  });

  it('fails when the API’s sign-in doesn’t send the browser to the auth host’s authorize', async () => {
    for (const started of [
      new Response('{}', { status: 503 }),
      new Response('{}', { status: 200 }),
      redirect('https://elsewhere.example.test/oauth/v2/authorize'),
      redirect(`${AUTH}/oauth/v2/other`),
      redirect('http://[bad'),
    ]) {
      const result = await check(signIn(redirect('/ui/v2/login'), started));
      expect(result.passed).toBe(false);
      expect(result.line).toMatch(
        started.status === 503
          ? /the API's sign-in answered 503 after 20 s: check the API is running$/
          : /the API's sign-in answered \d+, not a redirect to the auth host's \/oauth\/v2\/authorize/,
      );
    }
  });
});

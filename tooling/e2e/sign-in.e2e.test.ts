// SEC-HA-07 and SEC-WEB-04 end to end (B2-3b): a person signs in to the
// console through the API, in a real Chrome, against the compose stack's
// login service. The API is the OIDC client here (ADR-003 §5), registered by
// the suite's setup (api-sign-in.ts): it sends the browser to the login
// service, trades the code with its own secret, checks the ID token, and opens
// a session held in the database and named by a `__Host-` cookie. The tests
// look at the browser's cookies, at the API's log, and at the sessions table
// itself, as the database's admin. B4-4a: the login service's verified
// address comes back through its userinfo endpoint and is kept, sealed.
import { type Browser, type BrowserContext, chromium, type Cookie, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { findLeaks } from '../../packages/testing/src/log-scan.ts';
import { API_ORIGIN, execIn, localLogin, serviceLogs } from './compose.ts';
import { loginDriver, where } from './login-pages.ts';

const { password, users, api } = inject('e2e');
const user = users.signIn;

const SESSION_COOKIE = '__Host-agentx-session';
const FLOW_COOKIE = '__Host-agentx-flow';
const CALLBACK = `${API_ORIGIN}/v1/auth/callback`;
/** Where the person asked to go once signed in: any path on the API's origin (SEC-WEB-04). */
const RETURN_TO = '/v1/after-sign-in';

const { drive } = loginDriver({
  password,
  callback: new RegExp(`^${`${API_ORIGIN}${RETURN_TO}`.replaceAll('.', '[.]')}$`),
});

/** A query as the database's admin, its rows as plain text. The password goes by the CLI's environment. */
async function sql(query: string): Promise<string> {
  const run = await execIn(
    'db',
    [
      'psql',
      '--username',
      'postgres',
      '--dbname',
      'agentx',
      '--no-align',
      '--tuples-only',
      '--quiet',
      '--command',
      query,
    ],
    { PGPASSWORD: localLogin('AGENTX_LOCAL_POSTGRES_ADMIN_PASSWORD') },
  );
  if (run.code !== 0) throw new Error(`psql failed: ${run.stderr.trim()}`);
  return run.stdout.trim();
}

/** Zitadel's user IDs are digits; checked before one goes into a query. */
const subject = (): string => {
  if (!/^[0-9]{1,32}$/.test(user.userId)) throw new Error('the test user ID is not the digits Zitadel issues');
  return user.userId;
};

/** The person's open sessions, as the API stored them. */
const sessions = async (): Promise<{ count: number; amr: string[] }> => {
  const rows = await sql(
    'SELECT pg_catalog.array_to_string(s.amr, $$,$$) FROM identity.sessions s ' +
      `JOIN identity.users u ON u.id = s.user_id WHERE u.subject = '${subject()}'`,
  );
  const lines = rows === '' ? [] : rows.split(String.fromCharCode(10));
  return {
    count: lines.length,
    amr: (lines[0] ?? '')
      .split(',')
      .filter((method) => method !== '')
      .sort(),
  };
};

/** The API's log events, in order. */
const apiEvents = async (): Promise<string[]> =>
  (await serviceLogs('api'))
    .split(String.fromCharCode(10))
    .filter((line) => line.startsWith('{'))
    .map((line) => String((JSON.parse(line) as { event?: unknown }).event));

const cookieNamed = (cookies: Cookie[], name: string): Cookie | undefined =>
  cookies.find((cookie) => cookie.name === name);

let browser: Browser;
let context: BrowserContext;
let page: Page;
/** What the tests saw, for the checks that come after. */
const seen: { callbackUrl?: string; cookies: string[] } = { cookies: [] };

beforeAll(async () => {
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  context = await browser.newContext();
  page = await context.newPage();
});

afterAll(async () => {
  await context.close();
  await browser.close();
});

/** Starts a sign-in at the API and drives the login until the browser is back where it asked to go. */
async function signIn(): Promise<{ shown: string[]; callbackUrl: string; session: Cookie }> {
  const callback = page.waitForRequest((request) => request.url().startsWith(`${CALLBACK}?`), { timeout: 120_000 });
  await page.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=${encodeURIComponent(RETURN_TO)}`);
  const { stoppedAt, shown } = await drive(page, user, []);
  expect(stoppedAt, where(page)).toBe('callback');
  const request = await callback;
  expect((await request.response())?.status()).toBe(302);
  const cookies = await context.cookies(API_ORIGIN);
  expect(cookieNamed(cookies, FLOW_COOKIE)).toBeUndefined();
  const session = cookieNamed(cookies, SESSION_COOKIE);
  if (session === undefined) throw new Error('the API set no session cookie');
  seen.cookies.push(session.value);
  return { shown, callbackUrl: request.url(), session };
}

describe('SEC-HA-07 a sign-in through the API, in a real browser', () => {
  let first: Cookie;

  it('SEC-WEB-04 refuses to start a sign-in that would end on another site', async () => {
    const response = await page.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=${encodeURIComponent('//evil.example/')}`);
    expect(response?.status()).toBe(400);
    expect(cookieNamed(await context.cookies(API_ORIGIN), FLOW_COOKIE)).toBeUndefined();
  });

  it('asks for the password and the code, then opens a session: a __Host- cookie, and a row in the database', async () => {
    const { shown, callbackUrl, session } = await signIn();
    expect(shown).toEqual(['loginName', 'password', 'otp', 'callback']);
    expect(page.url()).toBe(`${API_ORIGIN}${RETURN_TO}`);
    expect(session).toMatchObject({ path: '/', secure: true, httpOnly: true, sameSite: 'Strict' });
    // The session's absolute timeout (12 hours by default), give or take the time the test took.
    expect(session.expires * 1000).toBeGreaterThan(Date.now() + 11 * 3600 * 1000);
    expect(await sessions()).toEqual({ count: 1, amr: ['mfa', 'otp', 'pwd'] });
    expect(await apiEvents()).toContain('auth.signed_in');
    seen.callbackUrl = callbackUrl;
    first = session;
  });

  it('B4-4a keeps the address the login service verified, sealed with the session: its text is nowhere in the table', async () => {
    const row = await sql(
      "SELECT pg_catalog.octet_length(e.email_ciphertext) || ',' || pg_catalog.position(pg_catalog.convert_to('agentx.localhost', 'UTF8') IN e.email_ciphertext) " +
        'FROM identity.session_emails e JOIN identity.sessions s ON s.id = e.session_id ' +
        `JOIN identity.users u ON u.id = s.user_id WHERE u.subject = '${subject()}'`,
    );
    const [length, found] = row.split(',').map(Number);
    // The nonce and the tag, then at least the domain's own length.
    expect(length).toBeGreaterThan(12 + 16 + 'agentx.localhost'.length);
    expect(found).toBe(0);
  });

  it('keeps only a hash of the cookie: its value is nowhere in the sessions table', async () => {
    if (!/^[A-Za-z0-9_-]{43}$/.test(first.value)) throw new Error('the cookie is not 32 random bytes as base64url');
    expect(await sql(`SELECT count(*) FROM identity.sessions s WHERE strpos(s::text, '${first.value}') > 0`)).toBe('0');
  });

  it('uses the flow once: the same callback address again is refused, and changes nothing', async () => {
    if (seen.callbackUrl === undefined) throw new Error('no sign-in came back to the callback');
    const response = await page.goto(seen.callbackUrl);
    expect(response?.status()).toBe(401);
    expect(await response?.json()).toMatchObject({ error: { code: 'SIGN_IN_FAILED' } });
    expect(cookieNamed(await context.cookies(API_ORIGIN), SESSION_COOKIE)?.value).toBe(first.value);
    expect((await sessions()).count).toBe(1);
  });

  it('signs in again without a question (the login still knows the person), with a new cookie and the old session ended', async () => {
    const { shown, session } = await signIn();
    expect(shown).toEqual(['callback']);
    expect(session.value).not.toBe(first.value);
    expect((await sessions()).count).toBe(1);
  });

  it('B2-4b answers a signed-in request: the browser reads its own session, which the request kept alive', async () => {
    const answer = await page.evaluate(async () => {
      const response = await fetch('/v1/auth/session');
      return { status: response.status, body: (await response.json()) as Record<string, unknown> };
    });
    expect(answer.status).toBe(200);
    expect(String(answer.body.userId)).toMatch(/^[0-9a-f-]{36}$/);
    expect([...(answer.body.methods as string[])].sort()).toEqual(['mfa', 'otp', 'pwd']);
    const idleEnds = Date.parse(String(answer.body.idleExpiresAt));
    // The stack's idle timeout (30 minutes) from this very request.
    expect(idleEnds).toBeGreaterThan(Date.now() + 29 * 60 * 1000);
    expect(idleEnds).toBeLessThanOrEqual(Date.parse(String(answer.body.expiresAt)));
  });

  it('signs out: the session ends and the cookie is cleared', async () => {
    const status = await page.evaluate(async () => (await fetch('/v1/auth/sign-out', { method: 'POST' })).status);
    expect(status).toBe(204);
    expect(cookieNamed(await context.cookies(API_ORIGIN), SESSION_COOKIE)).toBeUndefined();
    expect((await sessions()).count).toBe(0);
    expect(await apiEvents()).toContain('auth.signed_out');
  });

  it('B2-4b then refuses the same request as UNAUTHENTICATED, with the challenge that says how to sign in', async () => {
    const answer = await page.evaluate(async () => {
      const response = await fetch('/v1/auth/session');
      return { status: response.status, challenge: response.headers.get('www-authenticate') };
    });
    expect(answer).toEqual({
      status: 401,
      challenge: `Cookie realm="Agent X", form-action="/v1/auth/sign-in", cookie-name="${SESSION_COOKIE}"`,
    });
  });

  it("writes none of it to the API's log: not the client's secret, a cookie, or the code", async () => {
    const code = new URL(seen.callbackUrl ?? CALLBACK).searchParams.get('code');
    const planted = [api.clientSecret, ...seen.cookies, ...(code === null ? [] : [code])];
    expect(planted.length).toBeGreaterThanOrEqual(4);
    expect(findLeaks(await serviceLogs('api'), planted)).toEqual([]);
  });
});

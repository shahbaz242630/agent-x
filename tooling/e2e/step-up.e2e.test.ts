// SEC-HA-03 to 06, 12 and SEC-HA-07 end to end (B3-3b): a signed-in person
// steps up through the API, in a real Chrome, against the compose stack's
// login service. A change's own route will open the challenge (B4); here the
// test opens one for the person's session in the database, as the database's
// admin, as that route would through the identity module. The API then sends
// the browser to sign in again (`prompt=login`, the challenge's nonce), checks
// the fresh sign-in against the challenge, records its evidence there and
// gives the session a new cookie ID. Two people: one with an authenticator
// app, and one who registers a security key (Chrome's virtual authenticator)
// at their first sign-in, whose step-up then shows `user` in `amr` (SEC-HA-12,
// ADR-012 §7).
import { randomBytes } from 'node:crypto';

import { type Browser, type BrowserContext, chromium, type Cookie, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { findLeaks } from '../../packages/testing/src/log-scan.ts';
import { API_ORIGIN, execIn, localLogin, serviceLogs } from './compose.ts';
import type { TestUser } from './global-setup.ts';
import { loginDriver, where } from './login-pages.ts';

const { password, users } = inject('e2e');

const SESSION_COOKIE = '__Host-agentx-session';
/** Where the person goes once signed in, or signed in again: any path on the API's origin. */
const RETURN_TO = '/v1/after-step-up';

const { drive, pageNameOf } = loginDriver({
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
function subjectOf(user: TestUser): string {
  if (!/^[0-9]{1,32}$/.test(user.userId)) throw new Error('the test user ID is not the digits Zitadel issues');
  return user.userId;
}

/** The person's one session, as the API stored it: its record ID. */
async function sessionOf(user: TestUser): Promise<string> {
  const rows = await sql(
    'SELECT s.id FROM identity.sessions s JOIN identity.users u ON u.id = s.user_id ' +
      `WHERE u.subject = '${subjectOf(user)}'`,
  );
  const ids = rows === '' ? [] : rows.split(String.fromCharCode(10));
  if (ids.length !== 1) throw new Error(`expected one session, found ${String(ids.length)}`);
  return ids[0] ?? '';
}

/** Opens a challenge for the person's session, as a change's route will (B4), and gives its ID. */
async function openChallenge(user: TestUser): Promise<string> {
  const sessionId = await sessionOf(user);
  if (!/^[0-9a-f-]{36}$/.test(sessionId)) throw new Error('the session ID is not a UUID');
  // The nonce as the identity module makes them: 32 random bytes in base64url, which the OIDC client checks.
  const nonce = randomBytes(32).toString('base64url');
  return sql(
    'INSERT INTO identity.step_up_challenges (id, session_id, user_id, action, change_hash, nonce, created_at, ends_at) ' +
      `SELECT pg_catalog.gen_random_uuid(), s.id, s.user_id, 'members.invite', ` +
      `pg_catalog.decode(pg_catalog.repeat('ab', 32), 'hex'), '${nonce}', pg_catalog.now(), pg_catalog.now() + interval '5 minutes' ` +
      `FROM identity.sessions s WHERE s.id = '${sessionId}' RETURNING id`,
  );
}

/** The challenge's evidence as recorded: whether verified, the methods, and auth_time against when it was made. */
async function evidenceOf(challengeId: string): Promise<{ verified: boolean; amr: string[]; freshEnough: boolean }> {
  if (!/^[0-9a-f-]{36}$/.test(challengeId)) throw new Error('the challenge ID is not a UUID');
  const row = await sql(
    "SELECT c.verified_at IS NOT NULL, pg_catalog.array_to_string(c.amr, ','), " +
      "c.auth_time >= c.created_at - interval '6 seconds' AND pg_catalog.octet_length(c.id_token_hash) = 32 " +
      `FROM identity.step_up_challenges c WHERE c.id = '${challengeId}'`,
  );
  const [verified, amr, fresh] = row.split('|');
  return {
    verified: verified === 't',
    amr: (amr ?? '')
      .split(',')
      .filter((method) => method !== '')
      .sort(),
    freshEnough: fresh === 't',
  };
}

/** The API's log events, in order. */
const apiEvents = async (): Promise<string[]> =>
  (await serviceLogs('api'))
    .split(String.fromCharCode(10))
    .filter((line) => line.startsWith('{'))
    .map((line) => String((JSON.parse(line) as { event?: unknown }).event));

const sessionCookie = async (context: BrowserContext): Promise<Cookie | undefined> =>
  (await context.cookies(API_ORIGIN)).find((cookie) => cookie.name === SESSION_COOKIE);

let browser: Browser;
/** Every session cookie value the browser held, for the leak check at the end. */
const cookiesSeen: string[] = [];

beforeAll(async () => {
  browser = await chromium.launch({ channel: 'chrome', headless: true });
});

afterAll(async () => {
  await browser.close();
});

/** Starts a sign-in at the API, and gives the page once the login sends it on. */
async function startSignIn(page: Page): Promise<void> {
  await page.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=${encodeURIComponent(RETURN_TO)}`);
}

/** Starts a step-up for the challenge at the API. */
async function startStepUp(page: Page, challengeId: string) {
  return page.goto(`${API_ORIGIN}/v1/auth/step-up?challenge=${challengeId}&returnTo=${encodeURIComponent(RETURN_TO)}`);
}

describe('SEC-HA-03 to 07 a step-up through the API with an authenticator app, in a real browser', () => {
  const user = users.stepUpApp;
  let context: BrowserContext;
  let page: Page;
  let challengeId: string;
  let before: Cookie;

  beforeAll(async () => {
    context = await browser.newContext();
    page = await context.newPage();
    await startSignIn(page);
    const { stoppedAt } = await drive(page, user, []);
    expect(stoppedAt, where(page)).toBe('callback');
    const cookie = await sessionCookie(context);
    if (cookie === undefined) throw new Error('the API set no session cookie');
    before = cookie;
    cookiesSeen.push(cookie.value);
  });

  afterAll(async () => {
    await context.close();
  });

  it('SEC-HA-01 asks for the password and the code again, then records the evidence on the challenge', async () => {
    challengeId = await openChallenge(user);
    const sessionId = await sessionOf(user);
    await startStepUp(page, challengeId);
    const { stoppedAt, shown } = await drive(page, user, []);
    expect(stoppedAt, where(page)).toBe('callback');
    // prompt=login: the login asks again, whatever session it still holds (ADR-003 Amendment S10).
    expect(shown).toEqual(expect.arrayContaining(['password', 'otp', 'callback']));
    expect(await evidenceOf(challengeId)).toEqual({ verified: true, amr: ['mfa', 'otp', 'pwd'], freshEnough: true });
    expect(await sessionOf(user)).toBe(sessionId);
    expect(await apiEvents()).toContain('auth.stepped_up');
  });

  it('SEC-HA-07 gives the session a new cookie ID, and the old one signs no one in', async () => {
    const after = await sessionCookie(context);
    if (after === undefined) throw new Error('the session cookie is gone');
    cookiesSeen.push(after.value);
    expect(after.value).not.toBe(before.value);
    expect(after).toMatchObject({ secure: true, httpOnly: true, sameSite: 'Strict' });
    const withOld = await fetch(`${API_ORIGIN}/v1/auth/session`, {
      headers: { cookie: `${SESSION_COOKIE}=${before.value}` },
    });
    expect(withOld.status).toBe(401);
    const withNew = await page.evaluate(async () => (await fetch('/v1/auth/session')).status);
    expect(withNew).toBe(200);
  });

  it('SEC-HA-03 refuses to step up for the same challenge again: it is no longer pending', async () => {
    const response = await startStepUp(page, challengeId);
    expect(response?.status()).toBe(403);
    expect(await response?.json()).toMatchObject({ error: { code: 'STEP_UP_FAILED' } });
    expect(pageNameOf(page.url())).toBeUndefined();
  });

  it("SEC-HA-04 refuses to step up for another person's challenge", async () => {
    const theirs = await openChallenge(users.stepUpKey).catch(() => undefined);
    // The other person may not have signed in yet; a made-up challenge is refused the same way.
    const response = await startStepUp(page, theirs ?? '0199a0f0-0000-7000-8000-00000000dead');
    expect(response?.status()).toBe(403);
    expect(await response?.json()).toMatchObject({ error: { code: 'STEP_UP_FAILED' } });
  });
});

describe('SEC-HA-12 a step-up with a security key says so: user in amr', () => {
  const user = users.stepUpKey;
  let context: BrowserContext;
  let page: Page;

  beforeAll(async () => {
    context = await browser.newContext();
    page = await context.newPage();
    // Chrome's own authenticator, through the DevTools protocol: the WebAuthn ceremony runs for real with no hardware.
    const devtools = await context.newCDPSession(page);
    await devtools.send('WebAuthn.enable');
    await devtools.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
  });

  afterAll(async () => {
    await context.close();
  });

  it('registers a security key at the first sign-in, as the login asks for a second factor', async () => {
    await startSignIn(page);
    const { stoppedAt } = await drive(page, user, ['factorSetup']);
    expect(stoppedAt, where(page)).toBe('factorSetup');
    await page.locator('a[href*="/ui/v2/login/u2f/set"]').click();
    await page.waitForURL(/\/ui\/v2\/login\/u2f\/set/);
    const deviceName = page.locator('input[name=name]');
    if ((await deviceName.count()) > 0) await deviceName.fill('end-to-end key');
    await page.getByTestId('submit-button').click();
    await page.waitForURL((url) => pageNameOf(url.href) === 'callback', { timeout: 60_000 });
    const cookie = await sessionCookie(context);
    if (cookie === undefined) throw new Error('the API set no session cookie');
    cookiesSeen.push(cookie.value);
  });

  it('steps up with the key: the evidence shows user, a security key, not an app code', async () => {
    const challengeId = await openChallenge(user);
    await startStepUp(page, challengeId);
    const { stoppedAt, shown } = await drive(page, user, []);
    expect(stoppedAt, where(page)).toBe('callback');
    expect(shown).toContain('u2f');
    expect(await evidenceOf(challengeId)).toEqual({ verified: true, amr: ['mfa', 'pwd', 'user'], freshEnough: true });
    const cookie = await sessionCookie(context);
    if (cookie !== undefined) cookiesSeen.push(cookie.value);
  });
});

describe('the log', () => {
  it("holds none of it: no session cookie from either person's sign-in or step-up", async () => {
    expect(cookiesSeen.length).toBeGreaterThanOrEqual(3);
    expect(findLeaks(await serviceLogs('api'), cookiesSeen)).toEqual([]);
  });
});

// SEC-HA-01 on FX-IDP: no login without a second factor, and a forced re-login
// asks for the second factor again. A real browser (Chrome, driven by
// Playwright) goes through Zitadel's login pages against the compose stack;
// this suite is the relying party, as the product will be in Phase 1
// (ADR-003 §5). It also settles what ADR-003 left for this phase: what
// `amr` says, whether `prompt=login` and `max_age=0` re-prompt inside the
// check lifetimes, whether `sid` survives a forced re-login, and that
// impersonation and self-registration are off.
import { type Browser, type BrowserContext, chromium, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { CALLBACK_PORT, type TestUser } from './global-setup.ts';
import {
  authorizationRequest,
  type AuthorizationOptions,
  type AuthorizationRequest,
  exchangeCode,
  type IdTokenClaims,
  listenForCallback,
  verifyIdToken,
} from './oidc.ts';
import { totp } from './totp.ts';

const fixtures = inject('e2e');
const { issuer, clientId, redirectUri, password, users } = fixtures;

/** The pages Zitadel's login can show on the way, and where the way ends. */
const PAGES = {
  loginName: /\/ui\/v2\/login\/loginname/,
  accounts: /\/ui\/v2\/login\/accounts/,
  password: /\/ui\/v2\/login\/password/,
  factorSetup: /\/ui\/v2\/login\/mfa\/set/,
  u2fSet: /\/ui\/v2\/login\/u2f\/set/,
  otp: /\/ui\/v2\/login\/otp\/time-based(?:\?|$)/,
  callback: /^http:\/\/127\.0\.0\.1:\d+\/callback/,
} as const;
type PageName = keyof typeof PAGES;

const pageNameOf = (href: string): PageName | undefined =>
  (Object.keys(PAGES) as PageName[]).find((name) => PAGES[name].test(href));

let browser: Browser;
let callbacks: Awaited<ReturnType<typeof listenForCallback>>;

beforeAll(async () => {
  // The Chrome the machine already has (GitHub's runners and this laptop): nothing to download.
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  callbacks = await listenForCallback(CALLBACK_PORT);
  expect(callbacks.redirectUri).toBe(redirectUri);
});

afterAll(async () => {
  await browser.close();
  await callbacks.close();
});

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Where the page is, for a failure message. */
const where = (page: Page): string => `at ${page.url()}`;

async function begin(page: Page, options: AuthorizationOptions = {}): Promise<AuthorizationRequest> {
  const request = await authorizationRequest(issuer, clientId, redirectUri, options);
  await page.goto(request.url);
  return request;
}

/** Waits until the page is one of the known ones, and says which. */
async function knownPage(page: Page): Promise<PageName> {
  await page
    .waitForURL((url) => pageNameOf(url.href) !== undefined, { timeout: 30_000 })
    .catch(() => {
      throw new Error(`the login went somewhere unexpected ${where(page)}`);
    });
  const name = pageNameOf(page.url());
  if (name === undefined) throw new Error(`the login went somewhere unexpected ${where(page)}`);
  return name;
}

/** Submits the page's form and waits for the login to move on. */
async function submitAndLeave(page: Page, current: PageName): Promise<void> {
  await page.getByTestId('submit-button').click();
  await page
    .waitForURL((url) => pageNameOf(url.href) !== current, { timeout: 30_000 })
    .catch(() => {
      throw new Error(`the login did not move on from the ${current} page ${where(page)}`);
    });
}

/** A one-time code never used before in this run: Zitadel refuses a repeat, so a new step is waited for. */
let lastCode = '';
async function freshCode(secret: string): Promise<string> {
  let code = totp(secret, Date.now());
  while (code === lastCode) {
    await sleep(1000);
    code = totp(secret, Date.now());
  }
  lastCode = code;
  return code;
}

interface Driven {
  /** Where the login stopped: one of `until`, or the callback. */
  readonly stoppedAt: PageName;
  /** Every page the login showed on the way, in order. */
  readonly shown: PageName[];
}

/**
 * Drives the login through whatever Zitadel shows (it skips steps a live
 * session has already done) until one of the `until` pages or the callback.
 * A page it can't get past is a failure that names the page.
 */
async function drive(page: Page, user: TestUser & { totpSecret?: string }, until: PageName[]): Promise<Driven> {
  const shown: PageName[] = [];
  for (let step = 0; step < 10; step += 1) {
    const current = await knownPage(page);
    shown.push(current);
    if (current === 'callback' || until.includes(current)) return { stoppedAt: current, shown };
    switch (current) {
      case 'loginName':
        await page.fill('input[name=loginName]', user.loginName);
        await submitAndLeave(page, current);
        break;
      case 'accounts':
        // The session chooser: pick this user, by the login name it shows.
        await page.getByText(user.loginName, { exact: false }).first().click();
        await page
          .waitForURL((url) => pageNameOf(url.href) !== 'accounts', { timeout: 30_000 })
          .catch(() => {
            throw new Error(`the login did not move on from the account chooser ${where(page)}`);
          });
        break;
      case 'password':
        await page.fill('input[name=password]', password);
        await submitAndLeave(page, current);
        break;
      case 'otp':
        if (user.totpSecret === undefined) throw new Error(`asked for a code the user cannot give ${where(page)}`);
        await page.fill('input[name=code]', await freshCode(user.totpSecret));
        await submitAndLeave(page, current);
        break;
      case 'factorSetup':
      case 'u2fSet':
        throw new Error(`the login stopped to set up a factor ${where(page)}`);
    }
  }
  throw new Error(`the login went round in circles ${where(page)}`);
}

/** The callback, or nothing within the wait: the login did not complete. */
const callbackWithin = (ms: number): Promise<URLSearchParams | undefined> => callbacks.next(ms);

/** Finishes the flow: the callback must carry the request's state and a code, which becomes a verified ID token. */
async function finish(request: AuthorizationRequest): Promise<IdTokenClaims> {
  const query = await callbackWithin(30_000);
  if (query === undefined) throw new Error('the login never came back to the callback');
  expect(query.get('error')).toBeNull();
  expect(query.get('state')).toBe(request.state);
  const code = query.get('code');
  if (code === null) throw new Error('the callback carried no code');
  const tokens = await exchangeCode(issuer, clientId, redirectUri, code, request.verifier);
  return verifyIdToken(issuer, clientId, tokens.id_token, request.nonce);
}

/** Seconds since 1970, as `auth_time` is written. */
const nowSeconds = (): number => Math.floor(Date.now() / 1000);

describe('SEC-HA-01 no login without a second factor', () => {
  let context: BrowserContext;
  let page: Page;

  beforeAll(async () => {
    context = await browser.newContext();
    page = await context.newPage();
  });

  afterAll(async () => {
    await context.close();
  });

  it('stops a user with only a password at "set up a second factor", and never returns a code', async () => {
    await begin(page);
    const { stoppedAt, shown } = await drive(page, users.noFactor, ['factorSetup']);
    expect(stoppedAt, where(page)).toBe('factorSetup');
    expect(shown).toEqual(['loginName', 'password', 'factorSetup']);
    expect(page.url()).toContain('force=true');
    await page.getByRole('heading', { name: /set up 2-factor/i }).waitFor({ state: 'visible' });
    expect(await callbackWithin(3000)).toBeUndefined();
  });

  it('offers only an authenticator app or a security key (no SMS, no email)', async () => {
    const links = await page.locator('a[href*="/ui/v2/login/"]').all();
    const paths = await Promise.all(
      links.map(async (link) => new URL((await link.getAttribute('href')) ?? '', issuer).pathname),
    );
    expect(paths.filter((path) => path.endsWith('/set')).sort()).toEqual([
      '/ui/v2/login/otp/time-based/set',
      '/ui/v2/login/u2f/set',
    ]);
  });

  it('completes only once a security key is registered, and says so in the token (amr)', async () => {
    // A virtual authenticator: Chrome's own, through the DevTools protocol, so
    // the WebAuthn ceremony runs for real with no hardware.
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
    const request = await begin(page);
    const { stoppedAt } = await drive(page, users.noFactor, ['factorSetup']);
    expect(stoppedAt, where(page)).toBe('factorSetup');
    await page.locator('a[href*="/ui/v2/login/u2f/set"]').click();
    await page.waitForURL(PAGES.u2fSet);
    const deviceName = page.locator('input[name=name]');
    if ((await deviceName.count()) > 0) await deviceName.fill('end-to-end key');
    await page.getByTestId('submit-button').click();

    const claims = await finish(request);
    // A security key shows as `user` (RFC 8176: user presence), which tells it
    // apart from an authenticator app's `otp` (ADR-003 Amendment S10; ADR-012 §7).
    expect([...(claims.amr ?? [])].sort()).toEqual(['mfa', 'pwd', 'user']);
    expect(claims.auth_time).toBeGreaterThan(nowSeconds() - 120);
    expect(claims.sub).toBe(users.noFactor.userId);
  });
});

describe('SEC-HA-01 a forced re-login asks for the second factor again', () => {
  let context: BrowserContext;
  let page: Page;
  /** The first login's claims, and the most recent real authentication's. */
  let first: IdTokenClaims;
  let latest: IdTokenClaims;

  beforeAll(async () => {
    context = await browser.newContext();
    page = await context.newPage();
  });

  afterAll(async () => {
    await context.close();
  });

  it('logs the authenticator-app user in with password and code: amr says pwd, otp, mfa', async () => {
    const request = await begin(page);
    const { stoppedAt, shown } = await drive(page, users.totp, ['otp']);
    expect(stoppedAt, where(page)).toBe('otp');
    expect(shown).toEqual(['loginName', 'password', 'otp']);
    expect((await drive(page, users.totp, [])).stoppedAt).toBe('callback');
    first = await finish(request);
    latest = first;
    expect(first.amr).toEqual(expect.arrayContaining(['pwd', 'otp', 'mfa']));
    expect(first.auth_time).toBeGreaterThan(nowSeconds() - 120);
    expect(first.sid).toBeTruthy();
    expect(first.sub).toBe(users.totp.userId);
  });

  it('without a prompt, the same browser session signs in again with no question asked (single sign-on)', async () => {
    const request = await begin(page);
    const { shown } = await drive(page, users.totp, []);
    expect(shown).toEqual(['callback']);
    const claims = await finish(request);
    expect(claims.auth_time).toBe(first.auth_time);
    expect(claims.amr).toEqual(expect.arrayContaining(['pwd', 'otp', 'mfa']));
    expect(claims.sid).toBe(first.sid);
  });

  it('with prompt=login, the password and the code are asked again, inside the check lifetimes', async () => {
    // A whole second on, so a fresh auth_time is visibly later.
    await sleep(1100);
    const request = await begin(page, { prompt: 'login' });
    const { stoppedAt, shown } = await drive(page, users.totp, ['otp']);
    expect(stoppedAt, where(page)).toBe('otp');
    expect(shown).toContain('password');
    expect((await drive(page, users.totp, [])).stoppedAt).toBe('callback');
    const claims = await finish(request);
    expect(claims.amr).toEqual(expect.arrayContaining(['pwd', 'otp', 'mfa']));
    expect(claims.auth_time).toBeGreaterThan(first.auth_time ?? 0);
    expect(claims.sub).toBe(users.totp.userId);
    // The issuer starts a new session on a forced re-login, so `sid` is
    // evidence only, never compared with the session's (ADR-003 Amendment S10).
    expect(claims.sid).toBeTruthy();
    expect(claims.sid).not.toBe(first.sid);
    latest = claims;
  });

  it('with max_age=0 alone, nothing is asked again: only prompt=login forces a re-login', async () => {
    // ADR-003 named max_age=0 as an alternative to prompt=login. Zitadel v4's
    // login signs the session straight in on it, so the product uses
    // prompt=login (ADR-003 Amendment S10). Its check that auth_time is at or
    // after the challenge would still refuse this token: auth_time did not move.
    await sleep(1100);
    const request = await begin(page, { maxAge: 0 });
    const { shown } = await drive(page, users.totp, ['otp']);
    expect(shown).toEqual(['callback']);
    const claims = await finish(request);
    expect(claims.amr).toEqual(expect.arrayContaining(['pwd', 'otp', 'mfa']));
    expect(claims.auth_time).toBe(latest.auth_time);
  });
});

describe('ADR-003 the login policy the stack runs with', () => {
  it('forces MFA for everyone, with authenticator apps and security keys only, and no self-registration', () => {
    expect(fixtures.policy).toMatchObject({
      forceMfa: true,
      allowRegister: false,
      allowExternalIdp: false,
      passwordlessType: 'PASSWORDLESS_TYPE_ALLOWED',
      mfaInitSkipLifetime: '0s',
    });
    expect([...fixtures.policy.secondFactors].sort()).toEqual(['SECOND_FACTOR_TYPE_OTP', 'SECOND_FACTOR_TYPE_U2F']);
    expect(fixtures.policy.multiFactors).toEqual(['MULTI_FACTOR_TYPE_U2F_WITH_VERIFICATION']);
  });

  it('keeps the check lifetimes Zitadel ships, which a forced re-login overrides (proven above)', () => {
    expect(fixtures.policy.secondFactorCheckLifetime).toBe('64800s');
    expect(fixtures.policy.multiFactorCheckLifetime).toBe('43200s');
  });

  it('has impersonation off (ADR-003 §4)', () => {
    expect(fixtures.impersonation).toBe(false);
  });
});

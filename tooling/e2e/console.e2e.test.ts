// Phase 6 6A1 end to end: the console, built into the image and served by the
// API from its own origin, in a real Chrome against the compose stack. The
// page and its assets load with the API's security headers and break none of
// them (no CSP report, no failed asset); its sign-in goes through the login
// service and back to the page asked for; signed in, it reads the person's
// own organisations (this person is in none) and says so; an API address
// still answers the API's JSON.
import { type Browser, type BrowserContext, chromium, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { API_ORIGIN } from './compose.ts';
import { loginDriver, where } from './login-pages.ts';

const { password, users } = inject('e2e');
const user = users.console;

/** Where the console asks to come back to: one of its own pages. */
const RETURN_TO = '/payments';

const { drive } = loginDriver({
  password,
  callback: new RegExp('^' + (API_ORIGIN + RETURN_TO).replaceAll('.', '[.]') + '$'),
});

let browser: Browser;
let context: BrowserContext;
let page: Page;
/**
 * What went wrong on the console's own origin: a console error other than a
 * failed load (a CSP refusal is one), a request that failed, and an answer
 * over 399 the console doesn't expect. Expected: the 401 its first "who is
 * signed in?" gets before sign-in, and the browser's own /favicon.ico, which
 * the API answers 404. The login service's own pages are its own.
 */
const problems: string[] = [];
const EXPECTED = new Set([`401 ${API_ORIGIN}/v1/auth/session`, `404 ${API_ORIGIN}/favicon.ico`]);
const ours = (url: string): boolean => url.startsWith(`${API_ORIGIN}/`);

beforeAll(async () => {
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  context = await browser.newContext();
  page = await context.newPage();
  page.on('console', (message) => {
    // A failed load is Chrome's echo of an answer, judged by its status below.
    if (message.type() === 'error' && ours(page.url()) && !message.text().startsWith('Failed to load resource')) {
      problems.push(`console: ${message.text()}`);
    }
  });
  page.on('requestfailed', (request) => {
    if (ours(request.url())) problems.push(`failed: ${request.url()}`);
  });
  page.on('response', (response) => {
    const seen = `${String(response.status())} ${response.url()}`;
    if (ours(response.url()) && response.status() >= 400 && !EXPECTED.has(seen)) problems.push(`answer: ${seen}`);
  });
});

afterAll(async () => {
  await context.close();
  await browser.close();
});

describe('6A1 the console in a real browser, served by the API', () => {
  it('serves its page with the security headers, and its assets kept, with nothing the CSP refuses', async () => {
    const assets: { url: string; cacheControl: string | undefined }[] = [];
    page.on('response', (response) => {
      if (response.url().startsWith(`${API_ORIGIN}/assets/`)) {
        assets.push({ url: response.url(), cacheControl: response.headers()['cache-control'] });
      }
    });
    const response = await page.goto(`${API_ORIGIN}${RETURN_TO}`);
    expect(response?.status()).toBe(200);
    const headers = response?.headers() ?? {};
    expect(headers['content-security-policy']).toContain("script-src 'self'");
    expect(headers['cache-control']).toBe('no-store');
    await page.getByRole('heading', { name: 'Sign in to Agent X' }).waitFor({ timeout: 15_000 });
    expect(assets.length).toBeGreaterThan(0);
    for (const asset of assets) expect(asset.cacheControl, asset.url).toBe('public, max-age=31536000, immutable');
    expect(problems).toEqual([]);
  });

  it('signs in through the login service and comes back to the page asked for, which says they are in no organisation', async () => {
    await page.getByRole('button', { name: 'Sign in' }).click();
    const { stoppedAt } = await drive(page, user, []);
    expect(stoppedAt, where(page)).toBe('callback');
    expect(page.url()).toBe(`${API_ORIGIN}${RETURN_TO}`);
    await page.getByRole('heading', { name: "You're not in an organisation yet" }).waitFor({ timeout: 15_000 });
    expect(problems).toEqual([]);
  });

  it('still answers an API address with the API’s JSON, not the console', async () => {
    const answer = await page.evaluate(async () => {
      const response = await fetch('/v1/auth/organizations');
      return { status: response.status, type: response.headers.get('content-type'), body: await response.text() };
    });
    expect(answer.status).toBe(200);
    expect(answer.type).toMatch(/^application\/json/);
    expect(JSON.parse(answer.body)).toEqual({ organizations: [], unreadable: [] });
  });
});

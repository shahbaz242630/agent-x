// Drives Zitadel's login pages in a real browser, for the tests that sign in
// through them: login.e2e.test.ts, where the suite itself is the relying
// party, and sign-in.e2e.test.ts, where the API is. Each says where its login
// comes back to (`callback`); everything before that is the login's own.
import type { Page } from 'playwright';

import type { TestUser } from './global-setup.ts';
import { totp } from './totp.ts';

/** The pages Zitadel's login can show on the way. */
const LOGIN_PAGES = {
  loginName: /\/ui\/v2\/login\/loginname/,
  accounts: /\/ui\/v2\/login\/accounts/,
  password: /\/ui\/v2\/login\/password/,
  factorSetup: /\/ui\/v2\/login\/mfa\/set/,
  u2fSet: /\/ui\/v2\/login\/u2f\/set/,
  /** A security key asked for (B3-3b): the browser's own authenticator answers. */
  u2f: /\/ui\/v2\/login\/u2f(?:\?|$)/,
  otp: /\/ui\/v2\/login\/otp\/time-based(?:\?|$)/,
} as const;

type PageName = keyof typeof LOGIN_PAGES | 'callback';

interface Driven {
  /** Where the login stopped: one of `until`, or the callback. */
  readonly stoppedAt: PageName;
  /** Every page the login showed on the way, in order. */
  readonly shown: PageName[];
}

export interface LoginDriver {
  /** Which page an address is, if it is one of the known ones. */
  readonly pageNameOf: (href: string) => PageName | undefined;
  /**
   * Drives the login through whatever Zitadel shows (it skips steps a live
   * session has already done) until one of the `until` pages or the callback.
   * A page it can't get past is a failure that names the page.
   */
  readonly drive: (page: Page, user: TestUser & { totpSecret?: string }, until: PageName[]) => Promise<Driven>;
}

/** Where the page is, for a failure message. */
export const where = (page: Page): string => `at ${page.url()}`;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

const TOTP_STEP_MS = 30_000;
/** How long a sent form is waited for, the page then let settle, and the one resend waited for. */
const FIRST_WAIT_MS = 20_000;
const SETTLE_MS = 5_000;
const RETRY_WAIT_MS = 10_000;

export function loginDriver({ password, callback }: { password: string; callback: RegExp }): LoginDriver {
  const pages: Record<PageName, RegExp> = { ...LOGIN_PAGES, callback };
  const pageNameOf = (href: string): PageName | undefined =>
    (Object.keys(pages) as PageName[]).find((name) => pages[name].test(href));

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

  /**
   * Fills the page's form and submits it, and waits for the login to move on.
   * The login's pages are a React app: filled or clicked before its scripts
   * have taken over the page, the form keeps nothing, or the button does
   * nothing, and the page just sits there (S49–S53: "did not move on from the
   * password page", three times in one day). So a page that hasn't moved on
   * is let settle and sent once more, before the login is called stuck. A
   * retry that meets the page already leaving (the first send was only slow)
   * counts as moved on. The worst case is about what one send used to wait.
   */
  async function submitAndLeave(page: Page, current: PageName, fill?: () => Promise<void>): Promise<void> {
    const leaves = (timeout: number) =>
      page
        .waitForURL((url) => pageNameOf(url.href) !== current, { timeout })
        .then(() => true)
        .catch(() => false);
    const send = async () => {
      if (fill !== undefined) await fill();
      await page.getByTestId('submit-button').click();
    };
    await send();
    if (await leaves(FIRST_WAIT_MS)) return;
    await page.waitForLoadState('networkidle', { timeout: SETTLE_MS }).catch(() => undefined);
    if (pageNameOf(page.url()) !== current) return;
    try {
      await send();
    } catch (error) {
      // Navigating away mid-fill or mid-click: the first send got through after all.
      if (pageNameOf(page.url()) !== current) return;
      throw error;
    }
    if (await leaves(RETRY_WAIT_MS)) return;
    throw new Error(`the login did not move on from the ${current} page ${where(page)}`);
  }

  /**
   * A one-time code never used before by this driver (Zitadel refuses a
   * repeat, so a new step is waited for), and never from the last seconds of
   * a step, so it is still current when the login page checks it.
   */
  let lastCode = '';
  async function freshCode(secret: string): Promise<string> {
    const remaining = TOTP_STEP_MS - (Date.now() % TOTP_STEP_MS);
    if (remaining < 3000) await sleep(remaining + 100);
    let code = totp(secret, Date.now());
    while (code === lastCode) {
      await sleep(1000);
      code = totp(secret, Date.now());
    }
    lastCode = code;
    return code;
  }

  async function drive(page: Page, user: TestUser & { totpSecret?: string }, until: PageName[]): Promise<Driven> {
    const shown: PageName[] = [];
    for (let step = 0; step < 10; step += 1) {
      const current = await knownPage(page);
      shown.push(current);
      if (current === 'callback' || until.includes(current)) return { stoppedAt: current, shown };
      switch (current) {
        case 'loginName':
          await submitAndLeave(page, current, () => page.fill('input[name=loginName]', user.loginName));
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
          await submitAndLeave(page, current, () => page.fill('input[name=password]', password));
          break;
        case 'otp': {
          if (user.totpSecret === undefined) throw new Error(`asked for a code the user cannot give ${where(page)}`);
          const secret = user.totpSecret;
          // A new code on the resend: Zitadel refuses one used already.
          await submitAndLeave(page, current, async () => page.fill('input[name=code]', await freshCode(secret)));
          break;
        }
        case 'u2f': {
          // The page starts the key's ceremony by itself, its button disabled meanwhile, and moves
          // on once the browser's authenticator answers; the button is pressed only if it doesn't.
          const left = await page
            .waitForURL((url) => pageNameOf(url.href) !== 'u2f', { timeout: 15_000 })
            .then(() => true)
            .catch(() => false);
          if (!left) await submitAndLeave(page, current);
          break;
        }
        case 'factorSetup':
        case 'u2fSet':
          throw new Error(`the login stopped to set up a factor ${where(page)}`);
      }
    }
    throw new Error(`the login went round in circles ${where(page)}`);
  }

  return { pageNameOf, drive };
}

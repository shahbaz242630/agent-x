// 6D4a: a bank account's page and linking one, against a stand-in API. The
// page shows the account as the API gives it (never a number); an admin may
// check it with the bank and choose what happens when its consent runs out,
// in the API's words with none picked. Linking starts at the partner, opens
// its page in a new tab, keeps the link over the trip, and asks how it ended
// once back, each outcome said plainly; a start with no answer keeps its key.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const SOURCE = '0199a0f0-0000-7000-8000-0000000000f1';
const LINK = '0199a0f0-0000-7000-8000-0000000000f9';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const PAST = '2026-01-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';
const BANK_PAGE = 'https://bank.fake-partner.invalid/authorise/abc123';

const source = (change: Record<string, unknown> = {}) => ({
  id: SOURCE,
  status: 'ACTIVE',
  availability: 'ACTIVE',
  consentStatus: 'Authorised',
  consentExpiresAt: FUTURE,
  holderName: 'Staging Test Org 1 LLC',
  accountType: 'sme',
  hint: 'AE…6026',
  controls: {
    currency: 'AED',
    period: 'month',
    maxPaymentMinor: '5000000',
    maxPeriodMinor: '20000000',
    maxPeriodPayments: 100,
  },
  consentExpiry: 'pause',
  ...change,
});
const link = (change: Record<string, unknown> = {}) => ({
  id: LINK,
  status: 'open',
  expiresAt: FUTURE,
  createdAt: PAST,
  settledAt: null,
  sourceId: null,
  ...change,
});
const STATEMENTS = {
  statements: [
    {
      id: 'consent_expiry',
      version: 1,
      words: [
        { choice: 'cancel', text: 'Its requests are cancelled when the consent runs out.' },
        { choice: 'pause', text: 'Its requests are held until the consent is renewed.' },
      ],
    },
  ],
};

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown; key: string | null }[];

/** Answers `method path` with these in turn, the last one again after. */
const answer = (at: string, ...given: Answer[]) => answers.set(at, given);
const refused = (status: number, code: string) => ({ status, body: { error: { code } } });

function as(role: string, shown: Record<string, unknown> = source()) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: { userId: ME, authenticatedAt: PAST, methods: ['pwd'], idleExpiresAt: FUTURE, expiresAt: FUTURE },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
  answer('GET /v1/statements', { status: 200, body: STATEMENTS });
  answer('GET /v1/integrity-hold', {
    status: 200,
    body: { hold: { status: 'CLEAR', version: 1, since: PAST, reason: null, foundOn: null } },
  });
  answer(`GET /v1/funding-sources/${SOURCE}`, { status: 200, body: shown });
  answer('GET /v1/funding-sources', { status: 200, body: { sources: [shown], next: null, unchecked: [] } });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  sessionStorage.clear();
  vi.mocked(goTo).mockClear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, body, key: new Headers(init.headers).get('idempotency-key') });
      const queue = answers.get(`${method} ${path.split('?')[0] ?? path}`);
      const next = queue === undefined ? undefined : queue.length > 1 ? queue.shift() : queue[0];
      const { status, body: reply } = next ?? refused(404, 'NOT_FOUND');
      // Status 0: no answer at all, as the browser's fetch fails on a dropped connection.
      if (status === 0) return Promise.reject(new TypeError('Failed to fetch'));
      return Promise.resolve(new Response(JSON.stringify(reply ?? {}), { status }));
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open(path: string) {
  const history = createMemoryHistory({ initialEntries: [path] });
  render(<App queries={createQueries()} router={createConsoleRouter(history)} />);
  return history;
}

const posts = () => sent.filter((one) => one.method === 'POST');
const page = `/more/sources/${SOURCE}`;
const at = `/v1/funding-sources/${SOURCE}`;
const linkKey = `agentx.source-link.${ME}/${ORG.id}`;
const press = async (name: string | RegExp) => {
  await userEvent.click(await screen.findByRole('button', { name }));
};
const inDialog = async (name: string) => {
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name }));
};
const choose = async (text: RegExp) => {
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('radio', { name: text }));
};

describe('a bank account’s page (6D4a)', () => {
  it('shows the account as the API gives it, in plain words, with its limits to the fils', async () => {
    as('admin');
    open(page);
    expect(await screen.findByRole('heading', { name: 'Staging Test Org 1 LLC' })).toBeDefined();
    expect(screen.getByText('AE…6026')).toBeDefined();
    expect(screen.getByText('Small business')).toBeDefined();
    expect(screen.getByText(SOURCE)).toBeDefined();
    expect(screen.getAllByText('Active').length).toBeGreaterThan(0);
    expect(screen.getByText('Ready: it can pay')).toBeDefined();
    expect(screen.getByText('Authorised')).toBeDefined();
    expect(screen.getByText(/h left$/)).toBeDefined();
    expect(screen.getByText('AED 50,000.00')).toBeDefined();
    expect(screen.getByText('AED 200,000.00')).toBeDefined();
    expect(screen.getByText('Most payments a month')).toBeDefined();
    expect(screen.getByText('100')).toBeDefined();
    expect(screen.getByText(/its requests are held until the consent is renewed/)).toBeDefined();
    expect(screen.getByText(/To suspend or reactivate this account/)).toBeDefined();
  });

  it('opens from the account’s row on the Bank accounts list, where its brake stays', async () => {
    as('admin');
    const history = open('/more/sources');
    expect(await screen.findByRole('button', { name: 'Suspend Staging Test Org 1 LLC' })).toBeDefined();
    await userEvent.click(screen.getByRole('link', { name: 'Staging Test Org 1 LLC' }));
    expect(await screen.findByRole('heading', { name: 'Staging Test Org 1 LLC' })).toBeDefined();
    expect(history.location.pathname).toBe(page);
  });

  it('says a consent that ran out, a choice never made, and an account gone at the bank', async () => {
    as('admin', source({ consentExpiresAt: PAST, consentExpiry: null, availability: 'UNAVAILABLE', status: 'ENDED' }));
    open(page);
    expect(await screen.findByText('Ran out')).toBeDefined();
    expect(screen.getByText(/Not chosen yet, so its waiting and approved requests are cancelled/)).toBeDefined();
    expect(screen.getByText("Gone at the bank: it can't pay anything")).toBeDefined();
    // Ended: nothing to check or choose.
    expect(screen.queryByRole('button', { name: 'Check now' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Choose what happens' })).toBeNull();
  });

  it('shows a limit past what a number holds exactly, and one in another currency by its digits', async () => {
    as(
      'admin',
      source({
        controls: {
          currency: 'KWD',
          period: 'day',
          maxPaymentMinor: '9007199254740993123',
          maxPeriodMinor: '5',
          maxPeriodPayments: 3,
        },
      }),
    );
    open(page);
    expect(await screen.findByText('KWD 9,007,199,254,740,993.123')).toBeDefined();
    expect(screen.getByText('KWD 0.005')).toBeDefined();
    expect(screen.getByText('Most payments may add up to a day')).toBeDefined();
  });

  it('shows a viewer the account with nothing to press', async () => {
    as('viewer');
    open(page);
    expect(await screen.findByText(/Only an admin can check this account/)).toBeDefined();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it.each([
    ['an address that is no account’s ID', '/more/sources/not-an-id', undefined, /can't be found in this/],
    ['an account the API has none of', page, refused(404, 'NOT_FOUND'), /can't be found/],
    ['an account whose records failed', page, refused(503, 'INTEGRITY_FAILED'), /integrity/],
  ])('says %s plainly', { timeout: 10_000 }, async (_what, path, given, said) => {
    as('admin');
    if (given !== undefined) answer(`GET ${at}`, given);
    open(path);
    expect(await screen.findByText(said, {}, { timeout: 8000 })).toBeDefined();
    expect(screen.getByRole('link', { name: 'Back to bank accounts' })).toBeDefined();
  });

  it('keeps the account shown when a re-read fails, saying so in place', async () => {
    as('admin');
    answer(`POST ${at}/refresh`, refused(503, 'INTEGRITY_FAILED'));
    answer(`GET ${at}`, { status: 200, body: source() }, refused(503, 'INTEGRITY_FAILED'));
    open(page);
    await press('Check now');
    expect((await screen.findAllByText(/records failed Agent X's integrity check/)).length).toBeGreaterThan(0);
    expect(screen.getByRole('heading', { name: 'Staging Test Org 1 LLC' })).toBeDefined();
  });
});

describe('checking an account with the bank (6D4a)', () => {
  it('asks the partner with no body, and says it is done', async () => {
    as('admin');
    answer(`POST ${at}/refresh`, { status: 200, body: source({ availability: 'SUSPENDED' }) });
    open(page);
    await press('Check now');
    expect(await screen.findByText(/Checked: this page now shows/)).toBeDefined();
    expect(posts()).toEqual([expect.objectContaining({ path: `${at}/refresh`, body: {} })]);
  });

  it.each([
    ['the partner not answering', refused(503, 'PARTNER_UNAVAILABLE'), /The bank partner didn't answer/],
    ['no answer at all', { status: 0 }, /couldn't be reached/],
    ['a role that can’t', refused(403, 'FORBIDDEN'), /Your role in this organisation can't do this/],
    ['a code the console doesn’t know', refused(409, 'SOMETHING_NEW'), /reason SOMETHING_NEW/],
  ])('says %s plainly', async (_what, given, said) => {
    as('admin');
    answer(`POST ${at}/refresh`, given);
    open(page);
    await press('Check now');
    expect(await screen.findByText(said)).toBeDefined();
  });

  it('goes by passkey should the API ever ask for one', async () => {
    as('admin');
    answer(`POST ${at}/refresh`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    open(page);
    await press('Check now');
    await vi.waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    });
  });
});

describe('the consent-expiry choice (6D4a)', () => {
  it('offers both in the API’s words with none picked, and sends the one chosen with the words’ version', async () => {
    as('admin');
    answer(`POST ${at}/consent-expiry`, { status: 200, body: source({ consentExpiry: 'cancel' }) });
    open(page);
    await press('Choose what happens');
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(/held until the consent is renewed/)).toBeDefined();
    for (const radio of within(dialog).getAllByRole<HTMLInputElement>('radio')) expect(radio.checked).toBe(false);
    expect(within(dialog).getByRole<HTMLButtonElement>('button', { name: 'Save my choice' }).disabled).toBe(true);
    await choose(/cancelled when the consent runs out/);
    await inDialog('Save my choice');
    expect(await screen.findByText('Your choice is saved.')).toBeDefined();
    expect(posts()).toEqual([
      expect.objectContaining({
        path: `${at}/consent-expiry`,
        body: { consentExpiry: 'cancel', statementVersion: 1 },
      }),
    ]);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it.each([
    ['held after the consent ran out to cancel', 'PENDING_REQUESTS_CANCELLED', /can't be held now/],
    ['words changed since read', 'STATEMENT_CHANGED', /words you confirmed with have changed/],
    ['an account that ended meanwhile', 'SOURCE_NOT_USABLE', /has ended, so it can't be changed/],
  ])('says a refusal plainly: %s', async (_what, code, said) => {
    as('admin');
    answer(`POST ${at}/consent-expiry`, refused(409, code));
    open(page);
    await press('Choose what happens');
    await choose(/held until the consent is renewed/);
    await inDialog('Save my choice');
    expect(await screen.findByText(said)).toBeDefined();
  });

  it('goes back to sign-in when the session ended', async () => {
    as('admin');
    answer(`POST ${at}/consent-expiry`, refused(401, 'UNAUTHENTICATED'));
    open(page);
    await press('Choose what happens');
    await choose(/held until the consent is renewed/);
    await inDialog('Save my choice');
    expect(await screen.findByText(/session ended/i)).toBeDefined();
  });

  it('is cancelled with nothing sent', async () => {
    as('admin');
    open(page);
    await press('Choose what happens');
    await inDialog('Cancel');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(posts()).toHaveLength(0);
  });
});

describe('linking a bank account (6D4a)', () => {
  const start = 'POST /v1/funding-sources/link-sessions';
  const confirmAt = `POST /v1/funding-sources/link-sessions/${LINK}/confirm`;
  const started = { status: 201, body: { link: link(), authoriseUrl: BANK_PAGE } };

  const backFromBank = async (choice = /held until the consent is renewed/) => {
    await press("I'm back from my bank");
    await choose(choice);
    await inDialog('Check with my bank');
  };

  it('is offered to an admin alone', async () => {
    as('approver');
    open('/more/sources');
    expect(await screen.findByRole('button', { name: 'Suspend Staging Test Org 1 LLC' })).toBeDefined();
    expect(screen.queryByRole('heading', { name: 'Link a bank account' })).toBeNull();
  });

  it('starts at the partner, opens its page in a new tab, and keeps the link over the trip', async () => {
    as('admin');
    answer(start, started);
    open('/more/sources');
    await press('Start linking');
    const opened = await screen.findByRole('link', { name: "Open your bank's page (new tab)" });
    expect(opened.getAttribute('href')).toBe(BANK_PAGE);
    expect(opened.getAttribute('target')).toBe('_blank');
    expect(opened.getAttribute('rel')).toBe('noopener noreferrer');
    expect(JSON.parse(sessionStorage.getItem(linkKey) ?? 'null')).toEqual({ link: link(), authoriseUrl: BANK_PAGE });
    // No body: the start takes none.
    expect(posts()[0]?.body).toBeUndefined();
  });

  it('finds the link again after a reload, and says it linked, with a way to the account', async () => {
    as('admin');
    sessionStorage.setItem(linkKey, JSON.stringify({ link: link(), authoriseUrl: BANK_PAGE }));
    answer(confirmAt, {
      status: 200,
      body: { link: link({ status: 'linked', sourceId: SOURCE, settledAt: PAST }), source: source() },
    });
    const history = open('/more/sources');
    // The words are offered with none picked: nothing is checked until one is chosen.
    await press("I'm back from my bank");
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(/held until the consent is renewed/)).toBeDefined();
    expect(within(dialog).getByRole<HTMLButtonElement>('button', { name: 'Check with my bank' }).disabled).toBe(true);
    await choose(/held until the consent is renewed/);
    await inDialog('Check with my bank');
    expect(await screen.findByText('Linked: Staging Test Org 1 LLC, AE…6026.')).toBeDefined();
    expect(posts()).toEqual([expect.objectContaining({ body: { consentExpiry: 'pause', statementVersion: 1 } })]);
    expect(sessionStorage.getItem(linkKey)).toBeNull();
    await userEvent.click(screen.getByRole('link', { name: 'See the account' }));
    expect(history.location.pathname).toBe(page);
  });

  it('says the bank hasn’t answered yet on a 202, and keeps the link to ask again', async () => {
    as('admin');
    answer(start, started);
    answer(confirmAt, { status: 202, body: { link: link(), source: null } });
    open('/more/sources');
    await press('Start linking');
    await backFromBank();
    expect(await screen.findByText(/Your bank hasn't answered yet/)).toBeDefined();
    expect(sessionStorage.getItem(linkKey)).not.toBeNull();
    expect(screen.getByRole('button', { name: "I'm back from my bank" })).toBeDefined();
  });

  it.each([
    ['turned down or cancelled at the bank', 'rejected', /turned down at your bank, or you cancelled it there/],
    ['run out before approved', 'expired', /ran out before it was approved/],
    ['unknown to the partner', 'unknown', /doesn't know this link/],
    ['linked, the account not read', 'linked', /account can't be read just now/],
  ])('says a link %s, and starts afresh', async (_what, status, said) => {
    as('admin');
    answer(start, started);
    answer(confirmAt, { status: 200, body: { link: link({ status, settledAt: PAST }), source: null } });
    open('/more/sources');
    await press('Start linking');
    await backFromBank(/cancelled when the consent runs out/);
    expect(await screen.findByText(said)).toBeDefined();
    expect(sessionStorage.getItem(linkKey)).toBeNull();
    expect(screen.getByRole('button', { name: 'Start linking' })).toBeDefined();
  });

  it('forgets a link not this organisation’s, saying so', async () => {
    as('admin');
    sessionStorage.setItem(linkKey, JSON.stringify({ link: link(), authoriseUrl: BANK_PAGE }));
    answer(confirmAt, refused(404, 'NOT_FOUND'));
    open('/more/sources');
    await backFromBank();
    expect(await screen.findByText(/This link or account can't be found/)).toBeDefined();
    expect(sessionStorage.getItem(linkKey)).toBeNull();
  });

  it('keeps the link when the partner doesn’t answer the check', async () => {
    as('admin');
    sessionStorage.setItem(linkKey, JSON.stringify({ link: link(), authoriseUrl: BANK_PAGE }));
    answer(confirmAt, refused(503, 'PARTNER_UNAVAILABLE'));
    open('/more/sources');
    await backFromBank();
    expect(await screen.findByText(/The bank partner didn't answer/)).toBeDefined();
    expect(sessionStorage.getItem(linkKey)).not.toBeNull();
  });

  it('never opens a partner page that isn’t HTTPS, and forgets a link on request', async () => {
    as('admin');
    sessionStorage.setItem(linkKey, JSON.stringify({ link: link(), authoriseUrl: 'javascript:alert(1)' }));
    open('/more/sources');
    expect(await screen.findByText(/a page address Agent X won't open/)).toBeDefined();
    expect(screen.queryByRole('link', { name: /Open your bank's page/ })).toBeNull();
    await press('Forget this link');
    expect(await screen.findByRole('button', { name: 'Start linking' })).toBeDefined();
    expect(sessionStorage.getItem(linkKey)).toBeNull();
  });

  it.each(['http://bank.fake-partner.invalid/authorise/abc123', 'data:text/html,hi', 'not a page'])(
    'never opens a partner page by an address that isn’t HTTPS: %s',
    async (authoriseUrl) => {
      as('admin');
      sessionStorage.setItem(linkKey, JSON.stringify({ link: link(), authoriseUrl }));
      open('/more/sources');
      expect(await screen.findByText(/a page address Agent X won't open/)).toBeDefined();
      expect(screen.queryByRole('link', { name: /Open your bank's page/ })).toBeNull();
    },
  );

  it('ignores a kept link that isn’t one', async () => {
    as('admin');
    sessionStorage.setItem(linkKey, JSON.stringify({ link: { id: 'nope' }, authoriseUrl: BANK_PAGE }));
    open('/more/sources');
    expect(await screen.findByRole('button', { name: 'Start linking' })).toBeDefined();
  });

  it('finds the kept link for the person whatever case their ID comes in', async () => {
    as('admin');
    answer('GET /v1/auth/session', {
      status: 200,
      body: {
        userId: ME.toUpperCase(),
        authenticatedAt: PAST,
        methods: ['pwd'],
        idleExpiresAt: FUTURE,
        expiresAt: FUTURE,
      },
    });
    sessionStorage.setItem(linkKey, JSON.stringify({ link: link(), authoriseUrl: BANK_PAGE }));
    open('/more/sources');
    expect(await screen.findByRole('button', { name: "I'm back from my bank" })).toBeDefined();
  });

  it('ignores a kept link whose ID isn’t one, however whole the rest', async () => {
    as('admin');
    sessionStorage.setItem(linkKey, JSON.stringify({ link: link({ id: '../not-an-id' }), authoriseUrl: BANK_PAGE }));
    open('/more/sources');
    expect(await screen.findByRole('button', { name: 'Start linking' })).toBeDefined();
    expect(screen.queryByRole('button', { name: "I'm back from my bank" })).toBeNull();
  });

  it('forgets a kept link once its time at the bank has passed', async () => {
    as('admin');
    sessionStorage.setItem(linkKey, JSON.stringify({ link: link({ expiresAt: PAST }), authoriseUrl: BANK_PAGE }));
    open('/more/sources');
    expect(await screen.findByRole('button', { name: 'Start linking' })).toBeDefined();
    expect(sessionStorage.getItem(linkKey)).toBeNull();
  });

  it('says a key used before plainly', async () => {
    as('admin');
    answer(start, refused(409, 'IDEMPOTENCY_KEY_REUSED'));
    open('/more/sources');
    await press('Start linking');
    expect(await screen.findByText(/already used for an earlier request/)).toBeDefined();
  });

  it('asks again with the same key after no answer, and a fresh one once decided', async () => {
    as('admin');
    answer(start, { status: 0 }, refused(429, 'RATE_LIMITED'), refused(409, 'LINK_STARTS_SPENT'), started);
    open('/more/sources');
    await press('Start linking');
    expect(await screen.findByText(/couldn't be reached/)).toBeDefined();
    await press('Start linking');
    expect(await screen.findByText(/too many tries just now/)).toBeDefined();
    await press('Start linking');
    expect(await screen.findByText(/started as many links today/)).toBeDefined();
    await press('Start linking');
    expect(await screen.findByRole('link', { name: "Open your bank's page (new tab)" })).toBeDefined();
    const keys = posts().map((one) => one.key);
    expect(keys[1]).toBe(keys[0]);
    expect(keys[2]).toBe(keys[0]);
    expect(keys[3]).not.toBe(keys[0]);
  });

  it.each([
    ['while the first start is still being worked on', refused(409, 'IDEMPOTENCY_KEY_BUSY')],
    ['after the partner didn’t answer (a 5xx decides nothing)', refused(503, 'PARTNER_UNAVAILABLE')],
  ])('asks again with the same key %s', async (_what, first) => {
    as('admin');
    answer(start, first, started);
    open('/more/sources');
    await press('Start linking');
    await vi.waitFor(() => {
      expect(posts()).toHaveLength(1);
    });
    await press('Start linking');
    expect(await screen.findByRole('link', { name: "Open your bank's page (new tab)" })).toBeDefined();
    const keys = posts().map((one) => one.key);
    expect(keys[1]).toBe(keys[0]);
  });

  it('starts a new link with a fresh key once one was answered and forgotten', async () => {
    as('admin');
    answer(start, started);
    open('/more/sources');
    await press('Start linking');
    await press('Forget this link');
    await press('Start linking');
    await vi.waitFor(() => {
      expect(posts()).toHaveLength(2);
    });
    expect(posts()[1]?.key).not.toBe(posts()[0]?.key);
  });

  it('keeps nothing when storage is blocked, and still goes on', async () => {
    as('admin');
    answer(start, started);
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    try {
      open('/more/sources');
      await press('Start linking');
      expect(await screen.findByRole('link', { name: "Open your bank's page (new tab)" })).toBeDefined();
    } finally {
      setItem.mockRestore();
    }
  });
});

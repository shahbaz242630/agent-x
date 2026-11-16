// 6D4a: the integrity hold, against a stand-in API. An admin alone sees it,
// with a banner across the console while it is on; the page says since when
// and how it showed; an investigation is recorded (a conclusion, none
// picked, and a reference, confirmed); and clearing goes by passkey with the
// investigation chosen, after reading what it means, pinned to the hold as
// shown: a re-read that finds it moved on can't be confirmed.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const MINE = '0199a0f0-0000-7000-8000-0000000000b1';
const INVESTIGATION = '0199a0f0-0000-7000-8000-0000000000a7';
const OLDER = '0199a0f0-0000-7000-8000-0000000000a6';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const PAST = '2026-01-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';

const held = (change: Record<string, unknown> = {}) => ({
  hold: { status: 'HELD', version: 3, since: PAST, reason: 'seal', foundOn: 'spend_request', ...change },
});
const CLEAR = { hold: { status: 'CLEAR', version: 4, since: PAST, reason: null, foundOn: null } };
const investigation = (change: Record<string, unknown> = {}) => ({
  id: INVESTIGATION,
  holdVersion: 3,
  conclusion: 'CAUSE_REMOVED',
  reference: 'INC-2041',
  recordedBy: ME,
  recordedAt: PAST,
  ...change,
});

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown; key: string | null }[];

const answer = (at: string, ...given: Answer[]) => answers.set(at, given);
const refused = (status: number, code: string) => ({ status, body: { error: { code } } });

function as(role: string, hold: unknown = held()) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: { userId: ME, authenticatedAt: PAST, methods: ['pwd'], idleExpiresAt: FUTURE, expiresAt: FUTURE },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
  answer('GET /v1/members', {
    status: 200,
    body: { members: [{ id: MINE, userId: ME, role: 'admin', status: 'ACTIVE', joinedAt: PAST }] },
  });
  answer('GET /v1/integrity-hold', { status: 200, body: hold });
  answer('GET /v1/requests', { status: 200, body: { requests: [], next: null, unchecked: [] } });
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

const page = '/more/integrity-hold';
const keptAt = `agentx.hold-investigations.${ME}/${ORG.id}`;
const keep = (...kept: unknown[]) => {
  sessionStorage.setItem(keptAt, JSON.stringify(kept));
};
const posts = () => sent.filter((one) => one.method === 'POST');
const holdReads = () => sent.filter((one) => one.method === 'GET' && one.path === '/v1/integrity-hold');
const press = async (name: string | RegExp) => {
  await userEvent.click(await screen.findByRole('button', { name }));
};
const inDialog = async (name: string) => {
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name }));
};

describe('the hold’s banner and page (6D4a)', () => {
  it('says across the console that the organisation is held, for an admin, with a way to the hold', async () => {
    as('admin');
    const history = open('/approvals');
    const banner = await screen.findByRole('alert');
    expect(within(banner).getByText(/records were tampered with/)).toBeDefined();
    await userEvent.click(within(banner).getByRole('link', { name: 'See the hold' }));
    expect(history.location.pathname).toBe(page);
  });

  it('shows no banner while the hold is clear, and the page says so', async () => {
    as('admin', CLEAR);
    open(page);
    expect(await screen.findByText(/There is no hold/)).toBeDefined();
    expect(screen.queryByText(/records were tampered with/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Clear the hold' })).toBeNull();
  });

  it('never reads the hold for anyone but an admin, and shows them no way to it', async () => {
    as('approver');
    open('/more');
    expect(await screen.findByRole('heading', { name: 'More' })).toBeDefined();
    expect(screen.queryByRole('link', { name: 'See the integrity hold' })).toBeNull();
    open(page);
    expect(await screen.findByText('Only an admin can see and clear the integrity hold.')).toBeDefined();
    expect(holdReads()).toHaveLength(0);
  });

  it('is linked from More for an admin', async () => {
    as('admin');
    const history = open('/more');
    await userEvent.click(await screen.findByRole('link', { name: 'See the integrity hold' }));
    expect(history.location.pathname).toBe(page);
  });

  it('shows since when, how it showed and where, in plain words', async () => {
    as('admin');
    open(page);
    expect(await screen.findByText('On hold')).toBeDefined();
    expect(screen.getByText('A record was changed after it was sealed')).toBeDefined();
    expect(screen.getByText('spend request')).toBeDefined();
    expect(screen.getByText('3')).toBeDefined();
    expect(screen.getByText(/Record the investigation first/)).toBeDefined();
  });

  it.each([
    ['a sign it doesn’t know', { reason: 'brand_new' }, "Agent X's code brand_new"],
    ['none given', { reason: null, foundOn: null }, 'Not given'],
  ])('says %s plainly', async (_what, change, said) => {
    as('admin', held(change));
    open(page);
    expect((await screen.findAllByText(said)).length).toBeGreaterThan(0);
  });

  it.each([
    ['records failing their check', refused(503, 'INTEGRITY_FAILED'), /still fail Agent X's integrity check/],
    ['a role taken away', refused(403, 'FORBIDDEN'), /Only an admin can see/],
    ['no answer', { status: 500 }, /Try again/],
  ])('says a hold that can’t be read for %s', { timeout: 10_000 }, async (_what, given, said) => {
    as('admin');
    answer('GET /v1/integrity-hold', given);
    open(page);
    expect((await screen.findAllByText(said, {}, { timeout: 8000 })).length).toBeGreaterThan(0);
  });
});

describe('recording the investigation (6D4a)', () => {
  it('asks for a conclusion and a reference first, none picked, and says what is wrong in place', async () => {
    as('admin');
    open(page);
    for (const radio of await screen.findAllByRole<HTMLInputElement>('radio')) expect(radio.checked).toBe(false);
    await press('Record it');
    expect(await screen.findByText('Choose what the investigation found.')).toBeDefined();
    expect(screen.getByText(/Enter the incident's reference/)).toBeDefined();
    await userEvent.click(screen.getByRole('radio', { name: /no tampering/ }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Incident reference' }), 'has spaces');
    await press('Record it');
    expect(screen.getByText(/Enter the incident's reference/)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(posts()).toHaveLength(0);
  });

  it('confirms in plain words, records it, and offers it to clear with', async () => {
    as('admin');
    answer('POST /v1/integrity-hold/investigations', { status: 201, body: { investigation: investigation() } });
    open(page);
    await userEvent.click(await screen.findByRole('radio', { name: /cause was found and removed/ }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Incident reference' }), ' INC-2041 ');
    await press('Record it');
    expect(
      within(await screen.findByRole('dialog')).getByText(
        /hold number 3 found: The cause was found and removed. Incident reference: INC-2041./,
      ),
    ).toBeDefined();
    await inDialog('Record now');
    expect(await screen.findByText('The investigation is recorded.')).toBeDefined();
    expect(posts()).toEqual([
      expect.objectContaining({
        path: '/v1/integrity-hold/investigations',
        body: { conclusion: 'CAUSE_REMOVED', reference: 'INC-2041' },
      }),
    ]);
    expect(await screen.findByText(/Admin \(you\)/)).toBeDefined();
    expect(screen.getByRole('radio', { name: /INC-2041/ })).toBeDefined();
  });

  it('records again with the same key after no answer', async () => {
    as('admin');
    answer('POST /v1/integrity-hold/investigations', { status: 0 }, refused(409, 'NOT_ON_HOLD'), {
      status: 201,
      body: { investigation: investigation() },
    });
    open(page);
    await userEvent.click(await screen.findByRole('radio', { name: /no tampering/ }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Incident reference' }), 'INC-1');
    await press('Record it');
    await inDialog('Record now');
    expect(await screen.findByText(/couldn't be reached/)).toBeDefined();
    await press('Record it');
    await inDialog('Record now');
    expect(await screen.findByText(/isn't on hold any more/)).toBeDefined();
    await press('Record it');
    await inDialog('Record now');
    expect(await screen.findByText('The investigation is recorded.')).toBeDefined();
    const keys = posts().map((one) => one.key);
    expect(keys[1]).toBe(keys[0]);
    expect(keys[2]).not.toBe(keys[0]);
  });
});

describe('clearing the hold (6D4a)', () => {
  it('lists only this hold’s investigations kept in this window, ignoring anything else kept', async () => {
    as('admin');
    keep(
      investigation({ id: OLDER, reference: 'OLD-1', holdVersion: 2 }),
      { id: 'not-one' },
      investigation(),
      investigation({ id: OLDER, reference: 'INC-2042', conclusion: 'NO_TAMPERING' }),
    );
    open(page);
    const radios = await screen.findAllByRole('radio', { name: /\(INC-20/ });
    expect(radios.map((radio) => radio.closest('label')?.textContent)).toEqual([
      expect.stringContaining('INC-2042'),
      expect.stringContaining('INC-2041'),
    ]);
    expect(screen.queryByText(/OLD-1/)).toBeNull();
  });

  it('waits for an investigation to be chosen, says what clearing means, re-reads the hold, then goes by passkey', async () => {
    as('admin');
    keep(investigation());
    answer('POST /v1/integrity-hold/clear', { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    open(page);
    const clear = await screen.findByRole<HTMLButtonElement>('button', { name: 'Clear the hold' });
    expect(clear.disabled).toBe(true);
    await userEvent.click(screen.getByRole('radio', { name: /INC-2041/ }));
    const before = holdReads().length;
    await press('Clear the hold');
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/starts this organisation's money again/)).toBeDefined();
    expect(within(dialog).getByText('INC-2041')).toBeDefined();
    await vi.waitFor(() => {
      expect(within(dialog).getByRole<HTMLButtonElement>('button', { name: 'Continue with passkey' }).disabled).toBe(
        false,
      );
    });
    expect(holdReads().length).toBeGreaterThan(before);
    await inDialog('Continue with passkey');
    await vi.waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    });
    expect(posts()).toEqual([
      expect.objectContaining({ path: '/v1/integrity-hold/clear', body: { investigationId: INVESTIGATION } }),
    ]);
    const kept: unknown = JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');
    expect(kept).toEqual(
      expect.objectContaining({
        confirmPath: '/v1/integrity-hold/clear/confirm',
        body: { investigationId: INVESTIGATION },
      }),
    );
  });

  it('can’t be confirmed when the re-read finds the hold moved on since shown', async () => {
    as('admin');
    keep(investigation());
    answer('GET /v1/integrity-hold', { status: 200, body: held() }, { status: 200, body: held({ since: FUTURE }) });
    open(page);
    await userEvent.click(await screen.findByRole('radio', { name: /INC-2041/ }));
    await press('Clear the hold');
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(/The hold has changed since this page showed it/)).toBeDefined();
    expect(within(dialog).getByRole<HTMLButtonElement>('button', { name: 'Continue with passkey' }).disabled).toBe(
      true,
    );
    // What was shown stays in the dialog: the hold as it was when opened.
    expect(within(dialog).getAllByText(/2026/).length).toBeGreaterThan(0);
    expect(posts()).toHaveLength(0);
  });

  it('can’t be confirmed when the re-read fails', { timeout: 10_000 }, async () => {
    as('admin');
    keep(investigation());
    answer('GET /v1/integrity-hold', { status: 200, body: held() }, refused(503, 'INTEGRITY_FAILED'));
    open(page);
    await userEvent.click(await screen.findByRole('radio', { name: /INC-2041/ }));
    await press('Clear the hold');
    const dialog = await screen.findByRole('dialog');
    // A failure is tried again twice first (createQueries), so it is said after those.
    expect(
      await within(dialog).findByText(/couldn't check the hold is still as shown/, {}, { timeout: 8000 }),
    ).toBeDefined();
    expect(within(dialog).getByRole<HTMLButtonElement>('button', { name: 'Continue with passkey' }).disabled).toBe(
      true,
    );
    await inDialog('Cancel');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it.each([
    ['no investigation of the hold as it stands', refused(409, 'NO_INVESTIGATION'), /Record one first/],
    ['the hold cleared meanwhile', refused(409, 'NOT_ON_HOLD'), /isn't on hold any more/],
    ['records still failing', refused(503, 'INTEGRITY_FAILED'), /still fail Agent X's integrity check/],
    ['a clear done at once, no passkey asked', { status: 200, body: CLEAR }, /didn't ask for your passkey/],
  ])('says %s plainly, and never says it cleared', async (_what, given, said) => {
    as('admin');
    keep(investigation());
    answer('POST /v1/integrity-hold/clear', given);
    open(page);
    await userEvent.click(await screen.findByRole('radio', { name: /INC-2041/ }));
    await press('Clear the hold');
    const confirm = await within(await screen.findByRole('dialog')).findByRole<HTMLButtonElement>('button', {
      name: 'Continue with passkey',
    });
    await vi.waitFor(() => {
      expect(confirm.disabled).toBe(false);
    });
    await userEvent.click(confirm);
    expect((await screen.findAllByText(said)).length).toBeGreaterThan(0);
    expect(goTo).not.toHaveBeenCalled();
  });
});

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
    expect(screen.queryByRole('link', { name: 'Integrity hold' })).toBeNull();
    open(page);
    expect(await screen.findByText('Only an admin can see and clear the integrity hold.')).toBeDefined();
    expect(holdReads()).toHaveLength(0);
  });

  it('is linked from More for an admin', async () => {
    as('admin');
    const history = open('/more');
    await userEvent.click(await within(await screen.findByRole('main')).findByRole('link', { name: 'Integrity hold' }));
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
    ['an admin in the 7 days after a sign-in change', refused(403, 'SECOND_FACTOR_REMOVED'), /in the last 7 days/],
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

  it('opens nothing on choosing a conclusion after Record it was pressed without one', async () => {
    as('admin');
    open(page);
    await userEvent.type(await screen.findByRole('textbox', { name: 'Incident reference' }), 'INC-1');
    await press('Record it');
    expect(await screen.findByText('Choose what the investigation found.')).toBeDefined();
    await userEvent.click(screen.getByRole('radio', { name: /no tampering/ }));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it.each(['-INC-1', '.INC-1', '_INC-1'])(
    'refuses a reference that doesn’t start with a letter or digit: %s',
    async (typed) => {
      as('admin');
      open(page);
      await userEvent.click(await screen.findByRole('radio', { name: /no tampering/ }));
      await userEvent.type(screen.getByRole('textbox', { name: 'Incident reference' }), typed);
      await press('Record it');
      expect(await screen.findByText(/Enter the incident's reference/)).toBeDefined();
      expect(screen.queryByRole('dialog')).toBeNull();
      expect(posts()).toHaveLength(0);
    },
  );

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

  it('keeps the one recorded and drops any kept for an older hold', async () => {
    as('admin');
    keep(investigation({ id: OLDER, reference: 'OLD-1', holdVersion: 2 }));
    answer('POST /v1/integrity-hold/investigations', { status: 201, body: { investigation: investigation() } });
    open(page);
    await userEvent.click(await screen.findByRole('radio', { name: /cause was found and removed/ }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Incident reference' }), 'INC-2041');
    await press('Record it');
    await inDialog('Record now');
    expect(await screen.findByText('The investigation is recorded.')).toBeDefined();
    expect(JSON.parse(sessionStorage.getItem(keptAt) ?? 'null')).toEqual([investigation()]);
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
      investigation({ id: '../not-an-id', reference: 'BAD-1' }),
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
    expect(screen.queryByText(/BAD-1/)).toBeNull();
  });

  it('finds what was kept for the person whatever case their ID comes in', async () => {
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
    keep(investigation());
    open(page);
    expect(await screen.findByRole('radio', { name: /INC-2041/ })).toBeDefined();
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

  it('can’t be confirmed while the re-read is still on its way', async () => {
    as('admin');
    keep(investigation());
    open(page);
    await userEvent.click(await screen.findByRole('radio', { name: /INC-2041/ }));
    // The re-read the dialog makes as it opens never answers.
    vi.mocked(fetch).mockImplementationOnce(() => new Promise<Response>(() => undefined));
    await press('Clear the hold');
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/Checking the hold is still as shown/)).toBeDefined();
    expect(within(dialog).getByRole<HTMLButtonElement>('button', { name: 'Continue with passkey' }).disabled).toBe(
      true,
    );
  });

  it('can’t be confirmed when the re-read finds a newer hold set at the same moment', async () => {
    as('admin');
    keep(investigation());
    answer('GET /v1/integrity-hold', { status: 200, body: held() }, { status: 200, body: held({ version: 5 }) });
    open(page);
    await userEvent.click(await screen.findByRole('radio', { name: /INC-2041/ }));
    await press('Clear the hold');
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(/The hold has changed since this page showed it/)).toBeDefined();
    expect(within(dialog).getByRole<HTMLButtonElement>('button', { name: 'Continue with passkey' }).disabled).toBe(
      true,
    );
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

describe('the clear’s confirm, back from the passkey (6D4a)', () => {
  const confirmAt = 'POST /v1/integrity-hold/clear/confirm';
  const keptChange = `agentx.step-up.${CHALLENGE}`;
  const back = () => {
    sessionStorage.setItem(
      keptChange,
      JSON.stringify({
        challenge: CHALLENGE,
        label: 'Clear the integrity hold (investigation INC-2041)',
        confirmPath: '/v1/integrity-hold/clear/confirm',
        body: { investigationId: INVESTIGATION },
        organization: ORG.id,
        idempotencyKey: '0199a0f0-0000-7000-8000-0000000000c1',
      }),
    );
    open(`${page}?stepped=${CHALLENGE}`);
  };

  it.each([
    ['history not yet checked', refused(409, 'HISTORY_UNCHECKED'), /hasn't finished checking every request/],
    ['the hold changed meanwhile', refused(409, 'HOLD_CHANGED'), /The hold changed while this was being done/],
    ['a step-up for another hold', refused(403, 'STEP_UP_FAILED'), /wasn't for this hold as it stands now/],
  ])('says %s in the hold’s words, and ends it', async (_what, given, said) => {
    as('admin');
    answer(confirmAt, given);
    back();
    await press('Confirm');
    expect((await screen.findAllByText(said)).length).toBeGreaterThan(0);
    expect(screen.getByText(/Agent X didn't make this change: Clear the integrity hold/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull();
    expect(sessionStorage.getItem(keptChange)).toBeNull();
    expect(screen.queryByText(/couldn't be reached/)).toBeNull();
  });

  it('says a record failing its check as a result unknown, never as not made, and reads the hold again', async () => {
    as('admin');
    answer(confirmAt, refused(503, 'INTEGRITY_FAILED'));
    back();
    expect(await screen.findByText('On hold')).toBeDefined();
    const before = holdReads().length;
    await press('Confirm');
    expect(await screen.findByText(/couldn't confirm the result/)).toBeDefined();
    expect(screen.queryByText(/didn't make this change/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull();
    expect(sessionStorage.getItem(keptChange)).toBeNull();
    await vi.waitFor(() => {
      expect(holdReads().length).toBeGreaterThan(before);
    });
  });

  it('keeps Confirm and the change while the first try is busy, then confirms with the same key', async () => {
    as('admin');
    answer(confirmAt, refused(409, 'IDEMPOTENCY_KEY_BUSY'), refused(429, 'RATE_LIMITED'), { status: 200, body: CLEAR });
    back();
    await press('Confirm');
    expect(await screen.findByText(/still working on this, or there were too many tries/)).toBeDefined();
    expect(screen.queryByText(/didn't make this change/)).toBeNull();
    expect(sessionStorage.getItem(keptChange)).not.toBeNull();
    await press('Confirm');
    await vi.waitFor(() => {
      expect(posts()).toHaveLength(2);
    });
    await press('Confirm');
    expect(await screen.findByText(/^Done: Clear the integrity hold/)).toBeDefined();
    expect(new Set(posts().map((one) => one.key)).size).toBe(1);
  });

  it('ends the session on a 401 at the confirm, the change kept for the same address after signing in', async () => {
    as('admin');
    answer(confirmAt, refused(401, 'UNAUTHENTICATED'));
    back();
    await press('Confirm');
    expect(await screen.findByText(/Your session ended/)).toBeDefined();
    expect(screen.queryByText(/still fail|hasn't finished|refused or ran out/)).toBeNull();
    expect(sessionStorage.getItem(keptChange)).not.toBeNull();
    // Signed in again, back at `?stepped=`: the change is found, to confirm (the API then decides the challenge).
    cleanup();
    open(`${page}?stepped=${CHALLENGE}`);
    expect(await screen.findByText('Clear the integrity hold (investigation INC-2041)')).toBeDefined();
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeDefined();
  });

  it('keeps the change to try again after a failure on the way', async () => {
    as('admin');
    answer(confirmAt, { status: 0 }, { status: 200, body: CLEAR });
    back();
    await press('Confirm');
    expect(await screen.findByText(/couldn't be reached, so the change isn't made yet/)).toBeDefined();
    expect(sessionStorage.getItem(keptChange)).not.toBeNull();
    await press('Confirm');
    expect(await screen.findByText(/^Done: Clear the integrity hold/)).toBeDefined();
  });
});

describe('what an investigation’s answer and its key keep (6D4a)', () => {
  const fill = async (reference: string) => {
    await userEvent.click(await screen.findByRole('radio', { name: /no tampering/ }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Incident reference' }), reference);
  };
  const record = async () => {
    await press('Record it');
    await inDialog('Record now');
  };

  it('says one recorded against a newer hold plainly, and neither keeps nor offers it', async () => {
    as('admin');
    answer('POST /v1/integrity-hold/investigations', {
      status: 201,
      body: { investigation: investigation({ holdVersion: 5 }) },
    });
    open(page);
    await fill('INC-9');
    await record();
    expect(await screen.findByText(/against a newer hold than this page showed/)).toBeDefined();
    expect(screen.queryByText('The investigation is recorded.')).toBeNull();
    expect(sessionStorage.getItem(keptAt)).toBeNull();
    expect(screen.queryByRole('radio', { name: /INC-2041/ })).toBeNull();
  });

  it('records again with a fresh key once an answer came, even one against a newer hold', async () => {
    as('admin');
    answer('POST /v1/integrity-hold/investigations', {
      status: 201,
      body: { investigation: investigation({ holdVersion: 5 }) },
    });
    open(page);
    await fill('INC-9');
    await record();
    expect(await screen.findByText(/against a newer hold than this page showed/)).toBeDefined();
    await record();
    await vi.waitFor(() => {
      expect(posts()).toHaveLength(2);
    });
    expect(posts()[1]?.key).not.toBe(posts()[0]?.key);
  });

  it('records with a fresh key once the reference changes after no answer', async () => {
    as('admin');
    answer('POST /v1/integrity-hold/investigations', { status: 0 }, refused(409, 'IDEMPOTENCY_KEY_REUSED'));
    open(page);
    await fill('INC-1');
    await record();
    expect(await screen.findByText(/couldn't be reached/)).toBeDefined();
    await userEvent.type(screen.getByRole('textbox', { name: 'Incident reference' }), '2');
    await record();
    expect(await screen.findByText(/already used for an earlier request/)).toBeDefined();
    const keys = posts().map((one) => one.key);
    expect(keys[1]).not.toBe(keys[0]);
    expect(posts()[1]?.body).toEqual({ conclusion: 'NO_TAMPERING', reference: 'INC-12' });
  });

  it('records with a fresh key once the conclusion changes after no answer', async () => {
    as('admin');
    answer('POST /v1/integrity-hold/investigations', { status: 0 });
    open(page);
    await fill('INC-1');
    await record();
    expect(await screen.findByText(/couldn't be reached/)).toBeDefined();
    await userEvent.click(screen.getByRole('radio', { name: /cause was found and removed/ }));
    await record();
    await vi.waitFor(() => {
      expect(posts()).toHaveLength(2);
    });
    expect(posts()[1]?.key).not.toBe(posts()[0]?.key);
  });
});

describe('what is kept goes with the session (6D4a)', () => {
  const linkKept = `agentx.source-link.${ME}/${ORG.id}`;
  const stepUpKept = `agentx.step-up.${CHALLENGE}`;
  const keepBoth = () => {
    keep(investigation());
    sessionStorage.setItem(linkKept, JSON.stringify({ link: { id: OLDER, expiresAt: FUTURE }, authoriseUrl: 'x' }));
    sessionStorage.setItem(stepUpKept, '{}');
  };

  it('is forgotten on signing out, a step-up’s kept change too', async () => {
    as('admin');
    answer('POST /v1/auth/sign-out', { status: 200 });
    keepBoth();
    open('/more');
    await press('Sign out');
    await vi.waitFor(() => {
      expect(sessionStorage.getItem(keptAt)).toBeNull();
    });
    expect(sessionStorage.getItem(linkKept)).toBeNull();
    expect(sessionStorage.getItem(stepUpKept)).toBeNull();
  });

  it('is all kept when the session ends while the page is open (a 401), for signing in again', async () => {
    as('admin');
    answer('GET /v1/integrity-hold', refused(401, 'UNAUTHENTICATED'));
    keepBoth();
    open(page);
    expect(await screen.findByText(/session ended/i)).toBeDefined();
    expect(sessionStorage.getItem(keptAt)).not.toBeNull();
    expect(sessionStorage.getItem(linkKept)).not.toBeNull();
    expect(sessionStorage.getItem(stepUpKept)).toBe('{}');
  });

  it('still signs out when storage is blocked', async () => {
    as('admin');
    answer('POST /v1/auth/sign-out', { status: 200 });
    const key = vi.spyOn(Storage.prototype, 'key').mockImplementation(() => {
      throw new Error('blocked');
    });
    try {
      open('/more');
      await press('Sign out');
      await vi.waitFor(() => {
        expect(goTo).toHaveBeenCalledWith('/');
      });
    } finally {
      key.mockRestore();
    }
  });
});

// 6D3a: the mandates' screens against a stand-in API: the list, one
// mandate's page with its waiting draft beside the version in force, drafting
// one and a new version (every setting chosen, none picked; amounts typed
// exactly; the over-limit choice in the API's words; a draft's key held until
// the API decides), accepting by passkey (a carry's plan shown first),
// suspending (cancel or pause, none picked), resuming, revoking and the
// over-limit choice, each by passkey. Buttons show by role; refusals are said
// plainly.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';
import { dropAllTries, heldDraft } from '../held-tries.ts';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const MINE = '0199a0f0-0000-7000-8000-0000000000b1';
const MANDATE = '0199a0f0-0000-7000-8000-0000000000c1';
const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
const SUPPLIER = '0199a0f0-0000-7000-8000-0000000000d1';
const OTHER_SUPPLIER = '0199a0f0-0000-7000-8000-0000000000d2';
const SOURCE = '0199a0f0-0000-7000-8000-0000000000f1';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const REQUEST = '0199a0f0-0000-7000-8000-0000000000e1';
const PAST = '2026-01-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';

const version = (change: Record<string, unknown> = {}) => ({
  id: '0199a0f0-0000-7000-8000-000000000101',
  version: 1,
  purpose: 'Office supplies',
  currency: 'AED',
  perOrderLimitMinor: 250_000,
  monthlyLimitMinor: 2_000_000,
  approvalThresholdMinor: 100_000,
  supplierIds: [SUPPLIER],
  fundingSourceId: SOURCE,
  splitCheck: true,
  consentLimits: 'strict',
  endsAt: null,
  overLimit: 'refuse',
  termsHash: 'a'.repeat(64),
  draftedBy: MINE,
  draftedAt: PAST,
  consentWarnings: [],
  capWarnings: [],
  splitCheckWarning: null,
  ...change,
});
const DRAFT_VERSION = version({
  id: '0199a0f0-0000-7000-8000-000000000102',
  version: 2,
  perOrderLimitMinor: 300_000,
  termsHash: 'b'.repeat(64),
  splitCheck: false,
  splitCheckWarning: 'the split check is off',
  consentWarnings: ['the per-order limit is above the bank consent’s per payment'],
  capWarnings: ['the agent’s monthly cap is below the monthly limit'],
});
const mandate = (change: Record<string, unknown> = {}) => ({
  id: MANDATE,
  agentId: AGENT,
  timeZone: 'Asia/Dubai',
  splitWindowHours: 24,
  status: 'ACTIVE',
  acceptedBy: MINE,
  acceptedAt: PAST,
  current: version(),
  pending: null,
  agentMonthlyCap: { capMinor: 5_000_000, currency: 'AED', from: 'organization-policy' },
  ...change,
});
const SOURCE_LISTED = {
  id: SOURCE,
  status: 'ACTIVE',
  availability: 'ACTIVE',
  holderName: 'Gulf Office LLC',
  hint: 'AE…6026',
  controls: { currency: 'AED', period: 'month', maxPaymentMinor: '500000', maxPeriodMinor: '5000000' },
};
const STATEMENTS = {
  statements: [
    {
      id: 'over_limit',
      version: 1,
      words: [
        { choice: 'refuse', text: 'Above its limits: refused.' },
        { choice: 'approval', text: 'Above its limits: sent for approval.' },
      ],
    },
    {
      id: 'supersede',
      version: 2,
      words: [
        { choice: 'cancel', text: 'Pending requests are cancelled.' },
        { choice: 'carry', text: 'Pending requests are checked again.' },
      ],
    },
    {
      id: 'suspend',
      version: 4,
      words: [
        { choice: 'cancel', text: 'Its requests are cancelled.' },
        { choice: 'pause', text: 'Its requests are held.' },
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

const answer = (at: string, ...given: Answer[]) => answers.set(at, given);
const ASKED = { status: 202, body: { stepUpChallengeId: CHALLENGE } };
const refused = (status: number, code: string) => ({ status, body: { error: { code } } });
const posted = (path: string) => sent.filter((each) => each.method === 'POST' && each.path === path);
const kept = () =>
  JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null') as {
    confirmPath: string;
    body: Record<string, unknown>;
    label: string;
  } | null;

function as(role: string, shown: Record<string, unknown> = mandate()) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: {
      userId: ME,
      authenticatedAt: PAST,
      methods: ['pwd', 'user', 'mfa'],
      idleExpiresAt: FUTURE,
      expiresAt: FUTURE,
    },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
  answer('GET /v1/statements', { status: 200, body: STATEMENTS });
  answer('GET /v1/members', {
    status: 200,
    body: { members: [{ id: MINE, userId: ME, role: 'admin', status: 'ACTIVE', joinedAt: PAST }] },
  });
  answer(`GET /v1/mandates/${MANDATE}`, { status: 200, body: shown });
  answer('GET /v1/mandates', {
    status: 200,
    body: { mandates: [{ ...shown, purpose: 'Office supplies' }], next: null, unchecked: [] },
  });
  answer(`GET /v1/agents/${AGENT}`, {
    status: 200,
    body: {
      agent: { id: AGENT, name: 'Buyer bot', owner: MINE, status: 'ACTIVE', scopes: [], createdAt: PAST },
      keys: [],
    },
  });
  answer('GET /v1/agents', {
    status: 200,
    body: { agents: [{ id: AGENT, name: 'Buyer bot', status: 'ACTIVE' }], next: null, unchecked: [] },
  });
  answer('GET /v1/suppliers', {
    status: 200,
    body: {
      suppliers: [
        { id: SUPPLIER, displayName: 'Gulf Traders', status: 'VERIFIED' },
        { id: OTHER_SUPPLIER, displayName: 'Desert Paper', status: 'VERIFIED' },
      ],
      next: null,
      unchecked: [],
    },
  });
  answer('GET /v1/funding-sources', { status: 200, body: { sources: [SOURCE_LISTED], next: null, unchecked: [] } });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  sessionStorage.clear();
  dropAllTries();
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

/** The query cache of the page last opened: a test reads its data again, as a window's focus would. */
let queries = createQueries();

function open(path: string) {
  const history = createMemoryHistory({ initialEntries: [path] });
  queries = createQueries();
  render(<App queries={queries} router={createConsoleRouter(history)} />);
  return history;
}

/** The mandate read again with `shown` while a dialog is open. */
async function readAgainAs(shown: Record<string, unknown>) {
  answer(`GET /v1/mandates/${MANDATE}`, { status: 200, body: shown });
  await queries.invalidateQueries();
}

const dialog = () => within(screen.getByRole('dialog'));

describe('the mandates list', () => {
  it('lists each mandate with its agent and status, linked to its page, from More', async () => {
    as('admin');
    open('/more');
    await userEvent.click(await screen.findByRole('link', { name: 'Mandates' }));

    expect(await screen.findByRole('link', { name: 'Office supplies' })).toBeDefined();
    expect(await screen.findByText('For Buyer bot')).toBeDefined();
    expect(screen.getByText('In force')).toBeDefined();
    expect(screen.getByRole('link', { name: 'Draft a mandate' })).toBeDefined();
  });

  it('says when there are none, pages on, and tells a non-admin they can only read', async () => {
    as('viewer');
    answer(
      'GET /v1/mandates',
      { status: 200, body: { mandates: [], next: MANDATE, unchecked: ['x'] } },
      {
        status: 200,
        body: { mandates: [{ ...mandate(), status: 'REVOKED', purpose: 'Old' }], next: null, unchecked: [] },
      },
    );
    open('/more/mandates');

    expect(await screen.findByText(/can't be shown: their records failed/)).toBeDefined();
    expect(screen.getByText(/Only an admin can draft/)).toBeDefined();
    expect(screen.queryByRole('link', { name: 'Draft a mandate' })).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(await screen.findByRole('link', { name: 'Old' })).toBeDefined();
    expect(screen.getByText('Revoked')).toBeDefined();
  });

  it('says an empty list plainly, and a list that failed with a retry', async () => {
    as('admin');
    answer('GET /v1/mandates', refused(403, 'FORBIDDEN'), {
      status: 200,
      body: { mandates: [], next: null, unchecked: [] },
    });
    open('/more/mandates');
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Your organisation has no mandates yet.')).toBeDefined();
  });
});

describe('a mandate’s page', () => {
  it('shows everything the API gives, the waiting draft beside the version in force with its changes marked', async () => {
    as(
      'admin',
      mandate({ pending: DRAFT_VERSION, agentMonthlyCap: { capMinor: null, currency: null, from: 'not-set' } }),
    );
    open(`/more/mandates/${MANDATE}`);

    expect(await screen.findByRole('heading', { name: 'Office supplies', level: 1 })).toBeDefined();
    expect(await screen.findByRole('link', { name: 'Buyer bot' })).toBeDefined();
    expect(screen.getByText('Asia/Dubai')).toBeDefined();
    expect(screen.getByText('24 hours')).toBeDefined();
    expect(screen.getByText(/not chosen yet: every request is refused/)).toBeDefined();
    const table = within(screen.getByRole('table'));
    expect(table.getByText(/In force: version 1/)).toBeDefined();
    expect(table.getByText(/Waiting draft: version 2/)).toBeDefined();
    expect(table.getByText('AED 2,500.00')).toBeDefined();
    expect(table.getByText('AED 3,000.00')).toBeDefined();
    expect(await table.findAllByText('Gulf Traders')).toHaveLength(2);
    expect(await table.findAllByText('Gulf Office LLC (AE…6026)')).toHaveLength(2);
    expect(table.getAllByText('Changed')).toHaveLength(2);
    expect(screen.getByText(/Past the bank consent: the per-order limit/)).toBeDefined();
    expect(screen.getByText(/Past the agent's monthly cap: the agent’s monthly cap is below/)).toBeDefined();
    expect(screen.getByText(/Version 2: the split check is off\./)).toBeDefined();
    expect(screen.getByRole('link', { name: 'Draft a new version' })).toBeDefined();
  });

  it('names the cap, a first draft alone, and to a non-admin shows no action', async () => {
    as(
      'approver',
      mandate({ status: 'PENDING_ACCEPTANCE', current: null, pending: version(), acceptedAt: null, acceptedBy: null }),
    );
    open(`/more/mandates/${MANDATE}`);

    expect(await screen.findByText(/Its first version is waiting/)).toBeDefined();
    expect(screen.getByText("AED 50,000.00 · set by your organisation's policy")).toBeDefined();
    expect(screen.getByText(/Waiting draft: version 1/)).toBeDefined();
    expect(screen.getAllByText(/Only an admin can draft/)).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'Accept the waiting draft' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Draft a new version' })).toBeNull();
  });

  it('says a mandate not found, and an address naming none', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, refused(404, 'NOT_FOUND'));
    open(`/more/mandates/${MANDATE}`);
    expect(await screen.findByText(/This mandate can't be found/)).toBeDefined();
    cleanup();

    open('/more/mandates/not-an-id');
    expect(await screen.findByText(/This mandate can't be found/)).toBeDefined();
  });

  it('offers to read again a mandate that couldn’t be read', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, refused(403, 'FORBIDDEN'), { status: 200, body: mandate() });
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: 'Office supplies', level: 1 })).toBeDefined();
  });

  it('says a mandate failing its integrity check as itself, once read again', { timeout: 15_000 }, async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, refused(503, 'INTEGRITY_FAILED'));
    open(`/more/mandates/${MANDATE}`);
    expect(await screen.findByText(/failed Agent X's integrity check/, {}, { timeout: 10_000 })).toBeDefined();
  });

  it('says an ended mandate can do nothing more', async () => {
    as('admin', mandate({ status: 'REVOKED' }));
    open(`/more/mandates/${MANDATE}`);
    expect(await screen.findByText(/This mandate has ended/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Revoke' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Change what happens above the limits' })).toBeNull();
  });
});

describe('accepting the waiting draft', () => {
  it('a first version: shows its terms, then goes by passkey with nothing to choose', async () => {
    as(
      'admin',
      mandate({ status: 'PENDING_ACCEPTANCE', current: null, pending: version(), acceptedAt: null, acceptedBy: null }),
    );
    answer(`POST /v1/mandates/${MANDATE}/accept`, ASKED);
    open(`/more/mandates/${MANDATE}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
    expect(dialog().getByText(/Your passkey signs these exact terms/)).toBeDefined();
    expect(dialog().getByText('AED 2,500.00')).toBeDefined();
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));

    expect(posted(`/v1/mandates/${MANDATE}/accept`)[0]?.body).toEqual({ versionId: version().id });
    expect(goTo).toHaveBeenCalledOnce();
    // The confirm sends no version ID, which only the ask takes.
    expect(kept()?.body).toEqual({});
    expect(kept()?.confirmPath).toBe(`/v1/mandates/${MANDATE}/accept/confirm`);
  });

  it('a new version: the pending requests chosen in the API’s words, none picked, then by passkey', async () => {
    as('admin', mandate({ pending: DRAFT_VERSION }));
    answer(`POST /v1/mandates/${MANDATE}/accept`, {
      status: 202,
      body: { stepUpChallengeId: CHALLENGE, carry: null, carryLater: 0 },
    });
    open(`/more/mandates/${MANDATE}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
    const go = dialog().getByRole('button', { name: 'Continue with passkey' });
    await screen.findByText('Pending requests are cancelled.');
    expect(go).toHaveProperty('disabled', true);
    await userEvent.click(dialog().getByRole('radio', { name: 'Pending requests are cancelled.' }));
    await userEvent.click(go);

    expect(posted(`/v1/mandates/${MANDATE}/accept`)[0]?.body).toEqual({
      versionId: DRAFT_VERSION.id,
      pendingRequests: 'cancel',
    });
    expect(kept()?.body).toEqual({ pendingRequests: 'cancel', statementVersion: 2 });
  });

  it('a carry: what it will do to each pending request is shown before the passkey', async () => {
    as('admin', mandate({ pending: DRAFT_VERSION }));
    const carry = [
      {
        id: REQUEST,
        outcome: 'cancel',
        reasons: [{ code: 'OVER_PER_ORDER', message: 'Over the new per-order limit.' }],
      },
      { id: MANDATE, outcome: 'carry', reasons: [] },
    ];
    answer(`POST /v1/mandates/${MANDATE}/accept`, {
      status: 202,
      body: { stepUpChallengeId: CHALLENGE, carry, carryLater: 4 },
    });
    open(`/more/mandates/${MANDATE}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
    await userEvent.click(await screen.findByRole('radio', { name: 'Pending requests are checked again.' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));

    expect(await screen.findByText('Over the new per-order limit.')).toBeDefined();
    expect(screen.getByText(/4 more pending requests/)).toBeDefined();
    expect(screen.getByText('Carried over')).toBeDefined();
    expect(screen.getByText('Cancelled')).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));
    expect(goTo).toHaveBeenCalledOnce();
    expect(kept()?.body).toEqual({ pendingRequests: 'carry', statementVersion: 2 });
  });

  it('a carry with every request left for later says none are settled now', async () => {
    as('admin', mandate({ pending: DRAFT_VERSION }));
    answer(`POST /v1/mandates/${MANDATE}/accept`, {
      status: 202,
      body: { stepUpChallengeId: CHALLENGE, carry: [], carryLater: 3 },
    });
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
    await userEvent.click(await screen.findByRole('radio', { name: 'Pending requests are checked again.' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));
    expect(await screen.findByText('No pending requests are settled now.')).toBeDefined();
    expect(screen.getByText(/3 more pending requests/)).toBeDefined();
  });

  it('a carry with nothing pending goes straight to the passkey', async () => {
    as('admin', mandate({ pending: DRAFT_VERSION }));
    answer(`POST /v1/mandates/${MANDATE}/accept`, {
      status: 202,
      body: { stepUpChallengeId: CHALLENGE, carry: [], carryLater: 0 },
    });
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
    await userEvent.click(await screen.findByRole('radio', { name: 'Pending requests are checked again.' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));
    expect(goTo).toHaveBeenCalledOnce();
  });

  it('says a refusal, and an answer with no passkey asked, in plain words', async () => {
    as('admin', mandate({ pending: DRAFT_VERSION }));
    answer(`POST /v1/mandates/${MANDATE}/accept`, refused(409, 'MANDATE_NOT_WAITING'), { status: 200, body: {} });
    open(`/more/mandates/${MANDATE}`);
    const accept = async () => {
      await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
      await userEvent.click(await screen.findByRole('radio', { name: 'Pending requests are cancelled.' }));
      await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));
    };

    await accept();
    expect(await screen.findByText(/no longer the one waiting/)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
    await accept();
    expect(await screen.findByText(/without asking for your passkey/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('is pinned to the draft shown: one replaced while the dialog is open can’t be accepted', async () => {
    as('admin', mandate({ pending: DRAFT_VERSION }));
    answer(`POST /v1/mandates/${MANDATE}/accept`, ASKED);
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
    await userEvent.click(await dialog().findByRole('radio', { name: 'Pending requests are cancelled.' }));
    const go = dialog().getByRole('button', { name: 'Continue with passkey' });
    expect(go).toHaveProperty('disabled', false);

    const replaced = version({ id: '0199a0f0-0000-7000-8000-000000000103', version: 3, perOrderLimitMinor: 900_000 });
    await readAgainAs(mandate({ pending: replaced }));

    expect(await dialog().findByText(/This mandate changed while this was open/)).toBeDefined();
    // Still the terms first shown, never the new ones, and nothing can be confirmed.
    expect(dialog().getByText('AED 3,000.00')).toBeDefined();
    expect(dialog().queryByText('AED 9,000.00')).toBeNull();
    expect(go).toHaveProperty('disabled', true);
    await userEvent.click(go);
    expect(posted(`/v1/mandates/${MANDATE}/accept`)).toHaveLength(0);
  });

  it('is pinned to the draft shown: one accepted meanwhile can’t be accepted again', async () => {
    as('admin', mandate({ status: 'PENDING_ACCEPTANCE', current: null, pending: version() }));
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
    await readAgainAs(mandate());
    expect(await dialog().findByText(/This mandate changed while this was open/)).toBeDefined();
    expect(dialog().getByRole('button', { name: 'Continue with passkey' })).toHaveProperty('disabled', true);
  });

  it('sends the draft shown, not one read since, when nothing it depends on moved', async () => {
    as('admin', mandate({ status: 'PENDING_ACCEPTANCE', current: null, pending: version() }));
    answer(`POST /v1/mandates/${MANDATE}/accept`, ASKED);
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Accept the waiting draft' }));
    await readAgainAs(
      mandate({ status: 'PENDING_ACCEPTANCE', current: null, pending: version(), timeZone: 'Asia/Dubai' }),
    );
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));
    expect(posted(`/v1/mandates/${MANDATE}/accept`)[0]?.body).toEqual({ versionId: version().id });
  });

  it('says to resume a suspended mandate first', async () => {
    as('admin', mandate({ status: 'SUSPENDED', pending: DRAFT_VERSION }));
    open(`/more/mandates/${MANDATE}`);
    expect(await screen.findByText(/Resume it first, then accept the draft/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Accept the waiting draft' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Resume' })).toBeDefined();
  });
});

describe('suspending, resuming, revoking and the over-limit choice', () => {
  it('suspends by passkey, cancel or pause chosen in the API’s words with none picked', async () => {
    as('admin');
    answer(`POST /v1/mandates/${MANDATE}/suspend`, ASKED);
    open(`/more/mandates/${MANDATE}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Suspend' }));
    await screen.findByText('Its requests are held.');
    expect(dialog().getByRole('radio', { name: 'Its requests are held.' })).toHaveProperty('checked', false);
    expect(dialog().getByRole('radio', { name: 'Its requests are cancelled.' })).toHaveProperty('checked', false);
    await userEvent.click(dialog().getByRole('radio', { name: 'Its requests are held.' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));

    expect(posted(`/v1/mandates/${MANDATE}/suspend`)[0]?.body).toEqual({ pendingRequests: 'pause' });
    expect(kept()).toMatchObject({
      confirmPath: `/v1/mandates/${MANDATE}/suspend/confirm`,
      body: { pendingRequests: 'pause', statementVersion: 4 },
      label: 'Suspend the mandate "Office supplies"',
    });
  });

  it('resumes a suspended one by passkey', async () => {
    as('admin', mandate({ status: 'SUSPENDED' }));
    answer(`POST /v1/mandates/${MANDATE}/resume`, ASKED);
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Resume' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));
    expect(posted(`/v1/mandates/${MANDATE}/resume`)[0]?.body).toEqual({});
    expect(kept()?.confirmPath).toBe(`/v1/mandates/${MANDATE}/resume/confirm`);
  });

  it('revokes by passkey, warning it can’t be undone, and says a refusal', async () => {
    as('admin', mandate({ status: 'PENDING_ACCEPTANCE', current: null, pending: version() }));
    answer(`POST /v1/mandates/${MANDATE}/revoke`, refused(409, 'MANDATE_ENDED'), ASKED);
    open(`/more/mandates/${MANDATE}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    expect(dialog().getByText(/This can't be undone/)).toBeDefined();
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));
    expect(await screen.findByText(/This mandate has ended \(revoked or expired\)/)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();

    await userEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));
    expect(goTo).toHaveBeenCalledOnce();
  });

  it('chooses what happens above the limits by passkey, in the API’s words with none picked', async () => {
    as('admin', mandate({ current: version({ overLimit: 'not-chosen' }) }));
    answer(`POST /v1/mandates/${MANDATE}/over-limit`, ASKED);
    open(`/more/mandates/${MANDATE}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Change what happens above the limits' }));
    expect(dialog().getByText(/Now: Not chosen/)).toBeDefined();
    await userEvent.click(await dialog().findByRole('radio', { name: 'Above its limits: sent for approval.' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Continue with passkey' }));

    expect(posted(`/v1/mandates/${MANDATE}/over-limit`)[0]?.body).toEqual({ overLimit: 'approval' });
    expect(kept()?.body).toEqual({ overLimit: 'approval', statementVersion: 1 });
  });

  it.each([
    ['Suspend', { status: 'SUSPENDED' }],
    ['Revoke', { status: 'REVOKED' }],
    ['Change what happens above the limits', { current: version({ overLimit: 'approval' }) }],
  ])('a %s dialog says the mandate changed while it was open, and can’t be confirmed', async (button, change) => {
    as('admin');
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: button }));
    await readAgainAs(mandate(change));
    expect(await dialog().findByText(/This mandate changed while this was open/)).toBeDefined();
    expect(dialog().getByRole('button', { name: 'Continue with passkey' })).toHaveProperty('disabled', true);
  });

  it('cancels a dialog without sending anything', async () => {
    as('admin');
    open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sent.filter((each) => each.method === 'POST')).toHaveLength(0);
  });
});

/** Fills a new mandate's form as the admin would, every setting chosen. */
async function fillDraft() {
  await userEvent.click(await screen.findByRole('radio', { name: `Buyer bot · ${AGENT}` }));
  await userEvent.selectOptions(
    screen.getByRole('combobox', { name: 'Time zone its months are counted in' }),
    'Asia/Dubai',
  );
  await userEvent.type(screen.getByRole('textbox', { name: 'Split check window, in hours' }), '24');
  await userEvent.type(screen.getByRole('textbox', { name: 'What it is for' }), 'Office supplies');
  await userEvent.type(screen.getByRole('textbox', { name: 'Most for one request, in AED' }), '2,500.50');
  await userEvent.type(screen.getByRole('textbox', { name: 'Most in a month, in AED' }), '20000');
  await userEvent.type(screen.getByRole('textbox', { name: 'A person approves above, in AED' }), '1000');
  await userEvent.click(await screen.findByRole('checkbox', { name: /Gulf Traders/ }));
  await userEvent.click(await screen.findByRole('radio', { name: /Gulf Office LLC \(AE…6026\)/ }));
  await userEvent.click(screen.getByRole('radio', { name: /^Check them/ }));
  await userEvent.click(screen.getByRole('radio', { name: /^Strict/ }));
  await userEvent.click(screen.getByRole('radio', { name: 'Not until it is revoked' }));
}

const DRAFTED = {
  agentId: AGENT,
  timeZone: 'Asia/Dubai',
  splitWindowHours: 24,
  purpose: 'Office supplies',
  currency: 'AED',
  perOrderLimitMinor: 250_050,
  monthlyLimitMinor: 2_000_000,
  approvalThresholdMinor: 100_000,
  supplierIds: [SUPPLIER],
  fundingSourceId: SOURCE,
  splitCheck: true,
  consentLimits: 'strict',
  endsAt: null,
  overLimit: 'refuse',
  statementVersion: 1,
};

async function confirmDraft() {
  await userEvent.click(screen.getByRole('button', { name: 'Review' }));
  await userEvent.click(await dialog().findByRole('radio', { name: 'Above its limits: refused.' }));
  await userEvent.click(dialog().getByRole('button', { name: 'Draft it' }));
}

describe('drafting a mandate', () => {
  it('says every field and setting not given, none chosen for the admin', async () => {
    as('admin');
    open('/more/mandates/new');
    await userEvent.click(await screen.findByRole('button', { name: 'Review' }));

    for (const words of [
      'Choose the agent it is for.',
      'Choose a time zone.',
      'Type a whole number of hours from 1 to 744.',
      'Choose the bank account it pays from.',
      'Choose whether split orders are checked.',
      "Choose what happens above the bank consent's limits.",
      'Choose when it ends.',
      'Tick at least one supplier, and at most 100.',
    ]) {
      expect(screen.getByText(words)).toBeDefined();
    }
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('says limits that don’t nest, and an end in the past', async () => {
    as('admin');
    open('/more/mandates/new');
    await userEvent.type(await screen.findByRole('textbox', { name: 'Most for one request, in AED' }), '30000');
    await userEvent.type(screen.getByRole('textbox', { name: 'Most in a month, in AED' }), '20000');
    await userEvent.type(screen.getByRole('textbox', { name: 'A person approves above, in AED' }), '40000.123');
    await userEvent.click(screen.getByRole('radio', { name: 'On a date and time I choose' }));
    fireEvent.change(screen.getByLabelText('Ends at (your own time zone)'), { target: { value: '2020-01-01T10:00' } });
    await userEvent.click(screen.getByRole('button', { name: 'Review' }));

    expect(screen.getByText("The most for one request can't be above the most in a month.")).toBeDefined();
    expect(screen.getByText(/Type an amount above zero, such as 1000/)).toBeDefined();
    expect(screen.getByText('Choose a date and time in the future.')).toBeDefined();
  });

  it('drafts the terms exactly as typed and chosen, then opens the new mandate', async () => {
    as('admin');
    answer('POST /v1/mandates', {
      status: 201,
      body: mandate({ status: 'PENDING_ACCEPTANCE', current: null, pending: version() }),
    });
    const history = open('/more/mandates/new');
    await fillDraft();
    await userEvent.click(screen.getByRole('button', { name: 'Review' }));

    expect(dialog().getByText('AED 2,500.50')).toBeDefined();
    expect(dialog().getByText('Buyer bot')).toBeDefined();
    const go = dialog().getByRole('button', { name: 'Draft it' });
    await dialog().findByRole('radio', { name: 'Above its limits: refused.' });
    expect(go).toHaveProperty('disabled', true);
    await userEvent.click(dialog().getByRole('radio', { name: 'Above its limits: refused.' }));
    await userEvent.click(go);

    expect(posted('/v1/mandates')[0]?.body).toEqual(DRAFTED);
    await screen.findByRole('heading', { name: 'Office supplies', level: 1 });
    expect(history.location.pathname).toBe(`/more/mandates/${MANDATE}`);
  });

  it('holds a draft with no answer and asks again with the same key, never a second draft', async () => {
    as('admin');
    answer('POST /v1/mandates', { status: 0 }, refused(429, 'RATE_LIMITED'), { status: 201, body: mandate() });
    open('/more/mandates/new');
    await fillDraft();
    await confirmDraft();

    expect(await screen.findByText(/isn't known yet whether the draft was made/)).toBeDefined();
    expect(screen.getByRole('heading', { name: "Your draft hasn't been answered" })).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Review' })).toBeNull();
    const first = posted('/v1/mandates')[0]?.key;
    expect(heldDraft({ user: ME, organization: ORG.id, mandate: null })?.key).toBe(first);

    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText(/too many tries just now.*still held/s)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    await screen.findByRole('heading', { name: 'Office supplies', level: 1 });

    expect(posted('/v1/mandates').map(({ key, body }) => [key, body])).toEqual([
      [first, DRAFTED],
      [first, DRAFTED],
      [first, DRAFTED],
    ]);
    expect(heldDraft({ user: ME, organization: ORG.id, mandate: null })).toBeUndefined();
  });

  it('drops a held draft once the API refuses it past its gates', async () => {
    as('admin');
    answer('POST /v1/mandates', { status: 0 }, refused(409, 'MANDATE_OPEN'));
    open('/more/mandates/new');
    await fillDraft();
    await confirmDraft();
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByText(/already has a mandate waiting or in force/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Review' })).toBeDefined();
  });

  it('drops a held draft once the admin, warned, stops trying; until then it is there on coming back', async () => {
    as('admin');
    answer('POST /v1/mandates', { status: 0 });
    open('/more/mandates/new');
    await fillDraft();
    await confirmDraft();
    await screen.findByRole('button', { name: 'Stop trying' });
    cleanup();
    open('/more/mandates/new');
    await userEvent.click(await screen.findByRole('button', { name: 'Stop trying' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Cancel' }));
    expect(screen.getByRole('button', { name: 'Try again' })).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Stop trying' }));
    expect(dialog().getByText(/may already be made/)).toBeDefined();
    await userEvent.click(dialog().getByRole('button', { name: 'Stop trying' }));
    expect(await screen.findByRole('button', { name: 'Review' })).toBeDefined();
    expect(heldDraft({ user: ME, organization: ORG.id, mandate: null })).toBeUndefined();
  });

  it('forgets what was said of a held draft once the admin stops trying it', async () => {
    as('admin');
    answer('POST /v1/mandates', { status: 0 });
    open('/more/mandates/new');
    await fillDraft();
    await confirmDraft();
    expect(await screen.findByText(/isn't known yet whether the draft was made/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Stop trying' }));
    await userEvent.click(dialog().getByRole('button', { name: 'Stop trying' }));
    expect(await screen.findByRole('button', { name: 'Review' })).toBeDefined();
    expect(screen.queryByText(/isn't known yet whether the draft was made/)).toBeNull();
  });

  it('a held draft refused as sent again says the first try may have made it, and ends the hold', async () => {
    as('admin');
    answer('POST /v1/mandates', { status: 0 }, refused(400, 'BAD_REQUEST'));
    open('/more/mandates/new');
    await fillDraft();
    await confirmDraft();
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByText(/the first try may have made it\. Check the Mandates list/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Review' })).toBeDefined();
    expect(heldDraft({ user: ME, organization: ORG.id, mandate: null })).toBeUndefined();
  });

  it('refuses to review amounts in a currency it can’t type them in', async () => {
    as('admin');
    answer('GET /v1/funding-sources', {
      status: 200,
      body: {
        sources: [{ ...SOURCE_LISTED, controls: { ...SOURCE_LISTED.controls, currency: 'A1' } }],
        next: null,
        unchecked: [],
      },
    });
    open('/more/mandates/new');
    await userEvent.click(await screen.findByRole('radio', { name: /Gulf Office LLC/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Review' }));
    expect(screen.getByText(/Amounts can't be typed in this bank account's currency/)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('pages on through the agents, leaves out suspended ones, and keeps an agent linked to but not listed yet', async () => {
    const later = '0199a0f0-0000-7000-8000-0000000000a2';
    const unlisted = '0199a0f0-0000-7000-8000-0000000000a9';
    as('admin');
    answer(
      'GET /v1/agents',
      {
        status: 200,
        body: {
          agents: [
            { id: AGENT, name: 'Buyer bot', status: 'ACTIVE' },
            { id: unlisted.replace('a9', 'a8'), name: 'Stopped bot', status: 'SUSPENDED' },
          ],
          next: AGENT,
          unchecked: [],
        },
      },
      {
        status: 200,
        body: { agents: [{ id: later, name: 'Later bot', status: 'ACTIVE' }], next: null, unchecked: [] },
      },
    );
    answer('POST /v1/mandates', { status: 201, body: mandate() });
    open(`/more/mandates/new?agent=${unlisted}`);

    expect(await screen.findByRole('radio', { name: unlisted })).toHaveProperty('checked', true);
    expect(await screen.findByRole('radio', { name: `Buyer bot · ${AGENT}` })).toHaveProperty('checked', false);
    expect(screen.queryByRole('radio', { name: /Stopped bot/ })).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Show more agents' }));
    expect(await screen.findByRole('radio', { name: `Later bot · ${later}` })).toBeDefined();

    await userEvent.selectOptions(
      screen.getByRole('combobox', { name: 'Time zone its months are counted in' }),
      'Asia/Dubai',
    );
    await userEvent.type(screen.getByRole('textbox', { name: 'Split check window, in hours' }), '24');
    await userEvent.type(screen.getByRole('textbox', { name: 'What it is for' }), 'Office supplies');
    await userEvent.type(screen.getByRole('textbox', { name: 'Most for one request, in AED' }), '2500');
    await userEvent.type(screen.getByRole('textbox', { name: 'Most in a month, in AED' }), '20000');
    await userEvent.type(screen.getByRole('textbox', { name: 'A person approves above, in AED' }), '1000');
    await userEvent.click(await screen.findByRole('checkbox', { name: /Gulf Traders/ }));
    await userEvent.click(await screen.findByRole('radio', { name: /Gulf Office LLC \(AE…6026\)/ }));
    await userEvent.click(screen.getByRole('radio', { name: /^Check them/ }));
    await userEvent.click(screen.getByRole('radio', { name: /^Strict/ }));
    await userEvent.click(screen.getByRole('radio', { name: 'Not until it is revoked' }));
    await userEvent.click(screen.getByRole('button', { name: 'Review' }));
    // The confirm names the agent always: by its ID while no list read names it.
    expect(dialog().getByText('Agent')).toBeDefined();
    expect(dialog().getByText(unlisted)).toBeDefined();
  });

  it('ignores an agent link that names no agent ID', async () => {
    as('admin');
    open('/more/mandates/new?agent=not-an-id');
    expect(await screen.findByRole('radio', { name: `Buyer bot · ${AGENT}` })).toHaveProperty('checked', false);
    expect(screen.queryByRole('radio', { name: 'not-an-id' })).toBeNull();
  });

  it('says a first send’s refusal and keeps the form', async () => {
    as('admin');
    answer('POST /v1/mandates', refused(409, 'MANDATE_PAST_CONSENT'));
    open('/more/mandates/new');
    await fillDraft();
    await confirmDraft();
    expect(await screen.findByText(/go past the bank consent/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Review' })).toBeDefined();
  });

  it('starts with the agent the agent page linked from, and is an admin’s alone', async () => {
    as('admin');
    open(`/agents/${AGENT}`);
    await userEvent.click(await screen.findByRole('link', { name: 'Draft a mandate for this agent' }));
    expect(await screen.findByRole('radio', { name: `Buyer bot · ${AGENT}` })).toHaveProperty('checked', true);
    cleanup();

    as('developer');
    open('/more/mandates/new');
    expect(await screen.findByText(/Only an admin can draft/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Review' })).toBeNull();
  });
});

describe('drafting a new version', () => {
  it('fills in the terms in force and asks every setting again, none picked, what is in force said beside it', async () => {
    as('admin', mandate({ current: version({ endsAt: FUTURE }) }));
    answer(`POST /v1/mandates/${MANDATE}/supersede`, { status: 200, body: mandate({ pending: DRAFT_VERSION }) });
    const history = open(`/more/mandates/${MANDATE}`);
    await userEvent.click(await screen.findByRole('link', { name: 'Draft a new version' }));

    expect(await screen.findByRole('heading', { name: 'A new version of "Office supplies"' })).toBeDefined();
    expect(screen.getByRole('textbox', { name: 'Most for one request, in AED' })).toHaveProperty('value', '2500.00');
    expect(screen.getByRole('radio', { name: /^Check them/ })).toHaveProperty('checked', false);
    expect(screen.getByText(/In force now: Checked/)).toBeDefined();
    expect(screen.getByText(/In force now: Strict/)).toBeDefined();
    expect(await screen.findByRole('checkbox', { name: /Gulf Traders/ })).toHaveProperty('checked', true);

    const perOrder = screen.getByRole('textbox', { name: 'Most for one request, in AED' });
    await userEvent.clear(perOrder);
    await userEvent.type(perOrder, '3000');
    await userEvent.click(screen.getByRole('checkbox', { name: /Desert Paper/ }));
    await userEvent.click(screen.getByRole('checkbox', { name: /Gulf Traders/ }));
    await userEvent.click(screen.getByRole('radio', { name: /^Don't check them/ }));
    await userEvent.click(screen.getByRole('radio', { name: /^Flexible/ }));
    await userEvent.click(screen.getByRole('radio', { name: 'Not until it is revoked' }));
    await userEvent.click(screen.getByRole('button', { name: 'Review' }));
    await userEvent.click(await dialog().findByRole('radio', { name: 'Above its limits: sent for approval.' }));
    answer(`GET /v1/mandates/${MANDATE}`, { status: 200, body: mandate({ pending: DRAFT_VERSION }) });
    await userEvent.click(dialog().getByRole('button', { name: 'Draft it' }));

    expect(posted(`/v1/mandates/${MANDATE}/supersede`)[0]?.body).toEqual({
      purpose: 'Office supplies',
      currency: 'AED',
      perOrderLimitMinor: 300_000,
      monthlyLimitMinor: 2_000_000,
      approvalThresholdMinor: 100_000,
      supplierIds: [OTHER_SUPPLIER],
      fundingSourceId: SOURCE,
      splitCheck: false,
      consentLimits: 'flexible',
      endsAt: null,
      overLimit: 'approval',
      statementVersion: 1,
    });
    await screen.findByText(/Waiting draft: version 2/);
    expect(history.location.pathname).toBe(`/more/mandates/${MANDATE}`);
  });

  it('pages on through the suppliers to choose from, and reads a mandate again that couldn’t be read', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, refused(403, 'FORBIDDEN'), { status: 200, body: mandate() });
    answer(
      'GET /v1/suppliers',
      {
        status: 200,
        body: {
          suppliers: [{ id: SUPPLIER, displayName: 'Gulf Traders', status: 'VERIFIED' }],
          next: SUPPLIER,
          unchecked: [],
        },
      },
      {
        status: 200,
        body: {
          suppliers: [{ id: OTHER_SUPPLIER, displayName: 'Desert Paper', status: 'VERIFIED' }],
          next: null,
          unchecked: [],
        },
      },
    );
    open(`/more/mandates/${MANDATE}/new-version`);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Show more' }));
    expect(await screen.findByRole('checkbox', { name: /Desert Paper/ })).toHaveProperty('checked', false);
  });

  it('keeps a prefilled supplier and account not listed yet, by ID', async () => {
    const unlisted = '0199a0f0-0000-7000-8000-0000000000d9';
    as('admin', mandate({ current: version({ supplierIds: [unlisted] }) }));
    answer('GET /v1/funding-sources', { status: 200, body: { sources: [], next: null, unchecked: [] } });
    open(`/more/mandates/${MANDATE}/new-version`);
    expect(await screen.findByRole('checkbox', { name: new RegExp(unlisted) })).toHaveProperty('checked', true);
    expect(await screen.findByRole('radio', { name: SOURCE })).toHaveProperty('checked', true);
  });

  it('is offered for no ended mandate, to no one but an admin, and says a mandate not found', async () => {
    as('admin', mandate({ status: 'EXPIRED' }));
    open(`/more/mandates/${MANDATE}/new-version`);
    expect(await screen.findByText(/This mandate has ended/)).toBeDefined();
    cleanup();

    as('viewer');
    open(`/more/mandates/${MANDATE}/new-version`);
    expect(await screen.findByText(/Only an admin can draft/)).toBeDefined();
    cleanup();

    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, refused(404, 'NOT_FOUND'));
    open(`/more/mandates/${MANDATE}/new-version`);
    expect(await screen.findByText(/This mandate can't be found/)).toBeDefined();
  });
});

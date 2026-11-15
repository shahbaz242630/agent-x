// 6C1: payments in the console, against a stand-in API. The list newest
// first, filtered by the address's `?status=` (kept over a reload), a page at
// a time, saying any payment that couldn't be shown; the exception list, each
// saying why it is there; one payment in full with its history newest first,
// downloadable as the API gave it (CO6). Marking an UNKNOWN payment failed
// (decision 38): an admin proposes with the bank's reference, checked by the
// API's rule first; a second admin confirms the proposal its ask answered;
// any admin withdraws it; each confirmed in words, then by passkey, the
// words' version kept for the confirm (CO3); refusals in plain words.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const OTHER_ADMIN = '0199a0f0-0000-7000-8000-000000000022';
const ID = '0199a0f0-0000-7000-8000-0000000000a9';
const SECOND = '0199a0f0-0000-7000-8000-0000000000b9';
const REQUEST = '0199a0f0-0000-7000-8000-0000000000a1';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const LONG_AGO = '2026-10-20T05:00:00.000Z';
const MARK_WORDS = 'Marking this payment failed frees its invoice, so it could be paid twice.';

const listed = (id: string, overrides: Record<string, unknown> = {}) => ({
  id,
  spendRequestId: REQUEST,
  status: 'SUCCEEDED',
  amountMinor: 250_000,
  currency: 'AED',
  supplier: { id: '0199a0f0-0000-7000-8000-0000000000d1', name: 'Gulf Office Supplies LLC' },
  bankReference: 'AX-7Q2M9',
  partnerReference: null,
  bankStatus: null,
  rejectCode: null,
  createdAt: LONG_AGO,
  changedAt: '2026-10-26T05:00:00.000Z',
  contradicted: false,
  ...overrides,
});

const proposal = (proposedBy = OTHER_ADMIN) => ({
  id: '0199a0f0-0000-7000-8000-0000000000f9',
  paymentId: ID,
  evidenceRef: 'ENBD/2026/88812',
  proposedBy,
  status: 'OPEN',
  proposedAt: '2026-10-26T07:00:00.000Z',
});

const TIMELINE = [
  {
    at: '2026-10-20T05:00:00.000Z',
    what: 'transaction.opened',
    status: 'SUBMISSION_PENDING',
    by: { type: 'system', id: 'api' },
    via: null,
    evidenceRef: null,
  },
  {
    at: '2026-10-21T05:00:00.000Z',
    what: 'transaction.unknown',
    status: 'UNKNOWN',
    by: { type: 'system', id: 'worker' },
    via: 'bank_check',
    evidenceRef: 'RJCT-AC04',
  },
  {
    at: '2026-10-26T07:00:00.000Z',
    what: 'failure_proposal.made',
    status: null,
    by: { type: 'user', id: OTHER_ADMIN },
    via: null,
    evidenceRef: 'ENBD/2026/88812',
  },
];

const details = (overrides: Record<string, unknown> = {}) => ({
  ...listed(ID, { status: 'UNKNOWN', partnerReference: 'PSP-1182', bankStatus: 'PDNG', rejectCode: 'AC04' }),
  markFailed: { markableFrom: '2026-10-21T05:00:00.000Z', openProposal: null },
  timeline: TIMELINE,
  earlier: false,
  ...overrides,
});

const page = (payments: readonly unknown[], extra: Record<string, unknown> = {}) => ({
  status: 200,
  body: { payments, next: null, unchecked: [], ...extra },
});

const STATEMENTS = {
  statements: [{ id: 'mark_failed', version: 1, words: [{ choice: 'confirm', text: MARK_WORDS }] }],
};

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown }[];

/** Answers `method path` with these in turn, the last one again after. */
const answer = (key: string, ...given: Answer[]) => answers.set(key, given);

function signedIn(role = 'admin', userId = ME) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: {
      userId,
      authenticatedAt: '2026-10-26T05:00:00.000Z',
      methods: ['pwd', 'user', 'mfa'],
      idleExpiresAt: '2026-10-26T05:30:00.000Z',
      expiresAt: '2026-10-26T17:00:00.000Z',
    },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
  answer('GET /v1/statements', { status: 200, body: STATEMENTS });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  localStorage.clear();
  sessionStorage.clear();
  vi.mocked(goTo).mockClear();
  // The page a step-up comes back to is the window's own address, which the memory history doesn't move.
  window.history.replaceState(null, '', '/');
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, body });
      const queue = answers.get(`${method} ${path.split('?')[0] ?? path}`);
      const next = queue === undefined ? undefined : queue.length > 1 ? queue.shift() : queue[0];
      const { status, body: reply } = next ?? { status: 404, body: { error: { code: 'NOT_FOUND' } } };
      return Promise.resolve(new Response(JSON.stringify(reply ?? {}), { status }));
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function open(path: string) {
  const router = createConsoleRouter(createMemoryHistory({ initialEntries: [path] }));
  render(<App queries={createQueries()} router={router} />);
  return router;
}

const sentTo = (method: string, path: string) => sent.filter((one) => one.method === method && one.path === path);
const kept = (): unknown => JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');
/** The `at`th of what was found, which the test has just counted. */
function nth<T>(found: readonly T[], at: number): T {
  const one = found[at];
  if (one === undefined) throw new Error(`Nothing found at ${String(at)}`);
  return one;
}
const PROPOSAL_PATH = `/v1/payments/${ID}/failure-proposal`;

describe('the payments list (6C1)', () => {
  it('lists the payments newest first with amount, supplier, status, bank reference and a contradicted tag', async () => {
    signedIn();
    answer('GET /v1/payments', page([listed(ID, { contradicted: true }), listed(SECOND, { status: 'PROCESSING' })]));
    open('/payments');
    const rows = await screen.findAllByRole('link', { name: /Gulf Office Supplies LLC/ });
    expect(rows).toHaveLength(2);
    expect(rows[0]?.getAttribute('href')).toBe(`/payments/${ID}`);
    expect(within(nth(rows, 0)).getByText('Bank disagrees')).toBeDefined();
    expect(within(nth(rows, 0)).getByText('AED 2,500.00')).toBeDefined();
    expect(within(nth(rows, 0)).getAllByText('AX-7Q2M9')).toHaveLength(1);
    expect(within(nth(rows, 1)).getByText(/Being processed by the bank/)).toBeDefined();
    expect(sentTo('GET', '/v1/payments?limit=50')).toHaveLength(1);
  });

  it('filters by group through the address, kept on a reload, and back to every payment', async () => {
    signedIn();
    answer('GET /v1/payments', page([listed(ID)]));
    const router = open('/payments?status=failed');
    const filter = await screen.findByLabelText('Show');
    expect((filter as HTMLSelectElement).value).toBe('failed');
    await waitFor(() => {
      expect(sentTo('GET', '/v1/payments?limit=50&status=failed')).toHaveLength(1);
    });
    await userEvent.selectOptions(filter, 'unknown');
    await waitFor(() => {
      expect(router.state.location.searchStr).toBe('?status=unknown');
    });
    expect(sentTo('GET', '/v1/payments?limit=50&status=unknown')).toHaveLength(1);
    await userEvent.selectOptions(filter, 'all');
    await waitFor(() => {
      expect(router.state.location.searchStr).toBe('');
    });
  });

  it('asks for every payment when the address names a group the API doesn’t take, and says an empty group', async () => {
    signedIn();
    answer('GET /v1/payments', page([]));
    open('/payments?status=everything');
    expect(await screen.findByText('No payment has been made yet.')).toBeDefined();
    expect(sentTo('GET', '/v1/payments?limit=50')).toHaveLength(1);
    cleanup();
    open('/payments?status=reversed');
    expect(await screen.findByText('No payment is in this group.')).toBeDefined();
  });

  it('reads the next page on Show more, and says how many couldn’t be shown', async () => {
    signedIn();
    answer(
      'GET /v1/payments',
      page([listed(ID)], { next: 'cursor-2', unchecked: [SECOND] }),
      page([listed(SECOND, { supplier: { id: SECOND, name: 'Desert Print FZE' } })]),
    );
    open('/payments');
    expect(await screen.findByText(/1 payment\(s\) can't be shown/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(await screen.findByText('Desert Print FZE')).toBeDefined();
    expect(sentTo('GET', '/v1/payments?limit=50&after=cursor-2')).toHaveLength(1);
  });

  it('says a list that couldn’t load failed, and reads it again on a retry', async () => {
    signedIn();
    answer('GET /v1/payments', { status: 403, body: { error: { code: 'FORBIDDEN' } } }, page([listed(ID)]));
    open('/payments');
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Gulf Office Supplies LLC')).toBeDefined();
  });

  it('reaches the list from the Payments tab', async () => {
    signedIn();
    answer('GET /v1/payments', page([]));
    open('/approvals');
    await userEvent.click(await screen.findByRole('link', { name: 'Payments' }));
    expect(await screen.findByRole('heading', { name: 'Payments' })).toBeDefined();
  });
});

describe('the exception list (BR-17)', () => {
  it('lists each payment to follow up, saying why it is there', async () => {
    signedIn();
    answer(
      'GET /v1/payments/exceptions',
      page([
        listed(ID, { status: 'UNKNOWN' }),
        listed(SECOND, { contradicted: true, supplier: { id: SECOND, name: 'Desert Print FZE' } }),
      ]),
    );
    open('/payments');
    await userEvent.click(await screen.findByRole('link', { name: 'To follow up' }));
    const unknown = (await screen.findByText('Gulf Office Supplies LLC')).closest('a') as HTMLElement;
    expect(within(unknown).getByText(/The bank's answer never came/)).toBeDefined();
    const contradicted = screen.getByText('Desert Print FZE').closest('a') as HTMLElement;
    expect(within(contradicted).getByText(/The bank's latest word disagrees/)).toBeDefined();
    // The why line says it: no tag beside it.
    expect(within(contradicted).queryByText('Bank disagrees')).toBeNull();
    expect(sentTo('GET', '/v1/payments/exceptions?limit=50')).toHaveLength(1);
    expect(screen.queryByLabelText('Show')).toBeNull();
  });

  it('says when there is nothing to follow up', async () => {
    signedIn();
    answer('GET /v1/payments/exceptions', page([]));
    open('/payments/exceptions');
    expect(await screen.findByText(/Nothing to follow up/)).toBeDefined();
  });
});

describe('one payment’s page (6C1)', () => {
  it('shows it in full, from its link in its organisation, with its history newest first', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, { status: 200, body: details() });
    open(`/payments/${ID}?org=${ORG.id}`);
    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
    expect(screen.getAllByText('Outcome unknown').length).toBeGreaterThan(0);
    expect(screen.getByText('PSP-1182')).toBeDefined();
    expect(screen.getByText('PDNG')).toBeDefined();
    expect(screen.getByText('AC04')).toBeDefined();
    expect(screen.getByRole('link', { name: REQUEST }).getAttribute('href')).toBe(`/approvals/${REQUEST}`);
    const events = within(screen.getByRole('list')).getAllByRole('listitem');
    expect(events.map((one) => one.querySelector('.mono')?.textContent)).toEqual([
      'failure_proposal.made',
      'transaction.unknown',
      'transaction.opened',
    ]);
    expect(within(nth(events, 0)).getByText(/By a person/).textContent).toBe(`By a person ${OTHER_ADMIN}`);
    expect(within(nth(events, 1)).getByText(/By Agent X/).textContent).toBe('By Agent X worker · via bank_check');
    expect(within(nth(events, 1)).getByText('RJCT-AC04')).toBeDefined();
    expect(screen.queryByText(/Older events aren't shown/)).toBeNull();
    expect(sent.find((one) => one.path === `/v1/payments/${ID}`)).toBeDefined();
  });

  it('says older events aren’t shown, and leaves out facts the API has none for', async () => {
    signedIn('viewer');
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ ...listed(ID, { contradicted: true }), markFailed: null, earlier: true }),
    });
    open(`/payments/${ID}`);
    expect(await screen.findByText(/Older events aren't shown here/)).toBeDefined();
    expect(screen.getAllByText(/The bank's latest word disagrees/)).toHaveLength(1);
    expect(screen.queryByText("Payment partner's reference")).toBeNull();
  });

  it('downloads the payment and its history as the API gave them, named by its ID (CO6)', async () => {
    signedIn();
    const body = details();
    answer(`GET /v1/payments/${ID}`, { status: 200, body });
    const made: Blob[] = [];
    const revoke = vi.fn();
    // jsdom makes no object URLs: stand-ins that keep the file made.
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn((file: Blob) => {
        made.push(file);
        return 'blob:payment';
      }),
      revokeObjectURL: revoke,
    });
    let saved: { href: string; download: string } | undefined;
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click(this: HTMLAnchorElement) {
      saved = { href: this.href, download: this.download };
    });
    open(`/payments/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Download history' }));
    expect(saved).toEqual({ href: 'blob:payment', download: `payment-${ID}.json` });
    expect(nth(made, 0).type).toBe('application/json');
    expect(JSON.parse(await nth(made, 0).text())).toEqual(body);
    // Freed only once the click has been handled.
    await waitFor(() => {
      expect(revoke).toHaveBeenCalledWith('blob:payment');
    });
  });

  it('says a payment this organisation doesn’t have, or an address naming none, can’t be found', async () => {
    signedIn();
    open(`/payments/${ID}`);
    expect(await screen.findByText(/This payment can't be found/)).toBeDefined();
    cleanup();
    open('/payments/not-a-payment');
    expect(await screen.findByText(/This payment can't be found/)).toBeDefined();
    expect(sent.some((one) => one.path.startsWith('/v1/payments/not'))).toBe(false);
  });

  it('says a payment whose records failed the integrity check, and one that couldn’t load, with a retry', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, { status: 503, body: { error: { code: 'INTEGRITY_FAILED' } } });
    open(`/payments/${ID}`);
    expect(await screen.findByText(/failed Agent X's integrity check/, {}, { timeout: 8000 })).toBeDefined();
    cleanup();
    answer(`GET /v1/payments/${ID}`, { status: 403, body: { error: { code: 'FORBIDDEN' } } });
    open(`/payments/${ID}`);
    expect(await screen.findByRole('button', { name: 'Try again' })).toBeDefined();
  });
});

describe('marking a payment failed (CO6, decision 38)', () => {
  it('shows nothing to press to anyone but an admin, nor for a payment that isn’t UNKNOWN', async () => {
    signedIn('approver');
    answer(`GET /v1/payments/${ID}`, { status: 200, body: details() });
    open(`/payments/${ID}`);
    expect(await screen.findByRole('heading', { name: 'History' })).toBeDefined();
    expect(screen.queryByRole('heading', { name: 'Mark as failed' })).toBeNull();
    cleanup();
    signedIn();
    answer(`GET /v1/payments/${ID}`, { status: 200, body: details({ status: 'SUCCEEDED', markFailed: null }) });
    open(`/payments/${ID}`);
    expect(await screen.findByRole('heading', { name: 'History' })).toBeDefined();
    expect(screen.queryByRole('heading', { name: 'Mark as failed' })).toBeNull();
  });

  it('says from when it can be proposed, before then', async () => {
    signedIn();
    const soon = new Date(Date.now() + 3_600_000).toISOString();
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: soon, openProposal: null } }),
    });
    open(`/payments/${ID}`);
    expect(await screen.findByText(/an admin can propose marking it failed, once your bank/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Propose marking it failed' })).toBeNull();
  });

  it('checks the bank’s reference by the API’s rule before anything is sent', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, { status: 200, body: details() });
    open(`/payments/${ID}`);
    const field = await screen.findByLabelText("Your bank's reference for its written confirmation");
    expect(field.getAttribute('maxlength')).toBe('64');
    expect(field.tagName).toBe('INPUT');
    for (const wrong of ['ab', '-ENBD-1', 'ENBD 1']) {
      await userEvent.clear(field);
      await userEvent.type(field, wrong);
      await userEvent.click(screen.getByRole('button', { name: 'Propose marking it failed' }));
      expect(await screen.findByText(/This isn't a reference Agent X can keep/)).toBeDefined();
      expect(field.getAttribute('aria-invalid')).toBe('true');
      expect(screen.queryByRole('dialog')).toBeNull();
    }
    // Typing again clears what was said.
    await userEvent.type(field, 'x');
    expect(screen.queryByText(/This isn't a reference Agent X can keep/)).toBeNull();
    expect(sent.filter((one) => one.method === 'POST')).toHaveLength(0);
  });

  it('proposes with the reference and the consequence, confirmed in the API’s words, by passkey (CO3)', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, { status: 200, body: details() });
    answer(`POST ${PROPOSAL_PATH}`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    window.history.replaceState(null, '', `/payments/${ID}?org=${ORG.id}`);
    open(`/payments/${ID}?org=${ORG.id}`);
    await userEvent.type(
      await screen.findByLabelText("Your bank's reference for its written confirmation"),
      '  ENBD/2026/88812 ',
    );
    await userEvent.click(screen.getByRole('button', { name: 'Propose marking it failed' }));
    const dialog = await screen.findByRole('dialog', { name: 'Propose marking this payment failed?' });
    expect(await within(dialog).findByText(MARK_WORDS)).toBeDefined();
    expect(within(dialog).getByText('ENBD/2026/88812')).toBeDefined();
    const buttons = within(dialog).getAllByRole('button');
    expect(buttons.map((one) => one.textContent)).toEqual(['Cancel', 'Continue with passkey']);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));
    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`challenge=${CHALLENGE}`));
    });
    expect(sentTo('POST', PROPOSAL_PATH)[0]?.body).toEqual({
      evidenceRef: 'ENBD/2026/88812',
      confirmed: 'invoice_can_be_paid_again',
    });
    expect(kept()).toMatchObject({
      label: 'Propose marking AED 2,500.00 to Gulf Office Supplies LLC failed',
      confirmPath: `${PROPOSAL_PATH}/confirm`,
      body: { evidenceRef: 'ENBD/2026/88812', confirmed: 'invoice_can_be_paid_again', statementVersion: 1 },
      organization: ORG.id,
    });
    // The page's own query comes back with the step-up (CO5).
    const address = new URL(vi.mocked(goTo).mock.calls[0]?.[0] ?? '', 'https://app.example');
    expect(address.searchParams.get('returnTo')).toBe(`/payments/${ID}?org=${ORG.id}&stepped=${CHALLENGE}`);
  });

  it('shows the open proposal, and confirms it as the second admin with the proposal its ask answered', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: LONG_AGO, openProposal: proposal() } }),
    });
    answer(`POST ${PROPOSAL_PATH}/approve`, {
      status: 202,
      body: { stepUpChallengeId: CHALLENGE, proposal: { ...proposal(), evidenceRef: 'ENBD/2026/99999' } },
    });
    open(`/payments/${ID}`);
    const mark = await screen.findByRole('region', { name: 'Mark as failed' });
    expect(within(mark).getByText(OTHER_ADMIN)).toBeDefined();
    expect(within(mark).getByText('ENBD/2026/88812')).toBeDefined();
    expect(screen.queryByLabelText("Your bank's reference for its written confirmation")).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Confirm it failed' }));
    const dialog = await screen.findByRole('dialog', { name: 'Confirm this payment failed?' });
    // The reference the ask answered, as it stands now, is the one confirmed.
    expect(within(dialog).getByText('ENBD/2026/99999')).toBeDefined();
    expect(await within(dialog).findByText(MARK_WORDS)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
    expect(sentTo('POST', `${PROPOSAL_PATH}/approve`)[0]?.body).toEqual({ confirmed: 'invoice_can_be_paid_again' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));
    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`challenge=${CHALLENGE}`));
    });
    expect(kept()).toMatchObject({
      label: 'Mark AED 2,500.00 to Gulf Office Supplies LLC failed',
      confirmPath: `${PROPOSAL_PATH}/approve/confirm`,
      body: { confirmed: 'invoice_can_be_paid_again', statementVersion: 1 },
    });
  });

  it('keeps nothing when the second admin backs out of the confirm, and marks their own proposal as theirs', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: LONG_AGO, openProposal: proposal(ME) } }),
    });
    answer(`POST ${PROPOSAL_PATH}/approve`, {
      status: 202,
      body: { stepUpChallengeId: CHALLENGE, proposal: proposal(ME) },
    });
    open(`/payments/${ID}`);
    expect(await screen.findByText(/\(you\)/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Confirm it failed' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sessionStorage).toHaveLength(0);
    expect(goTo).not.toHaveBeenCalled();
  });

  it('marks a proposal theirs whatever the case of their ID: a UUID’s letters may come either way', async () => {
    signedIn('admin', ME.toUpperCase());
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: LONG_AGO, openProposal: proposal(ME) } }),
    });
    open(`/payments/${ID}`);
    const mark = await screen.findByRole('region', { name: 'Mark as failed' });
    expect(within(mark).getByText(/\(you\)/)).toBeDefined();
  });

  it('withdraws in its own confirm, an empty body, by passkey', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: LONG_AGO, openProposal: proposal() } }),
    });
    answer(`POST ${PROPOSAL_PATH}/withdraw`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    open(`/payments/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Withdraw proposal' }));
    const dialog = await screen.findByRole('dialog', { name: 'Withdraw the proposal?' });
    expect(within(dialog).getByText(/the payment stays as it is/)).toBeDefined();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));
    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`challenge=${CHALLENGE}`));
    });
    expect(sentTo('POST', `${PROPOSAL_PATH}/withdraw`)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({ confirmPath: `${PROPOSAL_PATH}/withdraw/confirm`, body: {} });
  });

  it('never says a step done when its ask is answered with no passkey asked, and reads the payment again', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: LONG_AGO, openProposal: proposal() } }),
    });
    answer(`POST ${PROPOSAL_PATH}/approve`, { status: 200, body: { id: ID, status: 'FAILED' } });
    answer(`POST ${PROPOSAL_PATH}/withdraw`, { status: 200, body: proposal() });
    open(`/payments/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm it failed' }));
    expect(await screen.findByText(/answered without asking for your passkey/)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
    await waitFor(() => {
      expect(sentTo('GET', `/v1/payments/${ID}`)).toHaveLength(2);
    });
    await userEvent.click(screen.getByRole('button', { name: 'Withdraw proposal' }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    await waitFor(() => {
      expect(sentTo('GET', `/v1/payments/${ID}`)).toHaveLength(3);
    });
    expect(screen.getByText(/answered without asking for your passkey/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
    expect(sessionStorage).toHaveLength(0);
  });

  it('says a proposal’s refused reference in its own words', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, { status: 200, body: details() });
    answer(`POST ${PROPOSAL_PATH}`, { status: 400, body: { error: { code: 'BAD_REQUEST' } } });
    open(`/payments/${ID}`);
    await userEvent.type(await screen.findByLabelText("Your bank's reference for its written confirmation"), 'ENBD-1');
    await userEvent.click(screen.getByRole('button', { name: 'Propose marking it failed' }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(await screen.findByText(/couldn't accept the bank's reference/)).toBeDefined();
  });

  it.each([
    ['PAYMENT_NOT_UNKNOWN', 409, /outcome is known now/],
    ['PAYMENT_TOO_RECENT', 409, /less than a day ago/],
    ['FAILURE_PROPOSAL_OPEN', 409, /already proposed/],
    ['NO_FAILURE_PROPOSAL', 409, /no proposal open/],
    ['FAILURE_PROPOSAL_TOO_RECENT', 409, /only a day after making it/],
    ['FAILURE_PROPOSAL_YOURS', 403, /You made this proposal/],
    ['FAILURE_PROPOSAL_GRANTED_BY_PROPOSER', 403, /made you an admin/],
    ['FAILURE_PROPOSAL_CONFIRMER_TOO_NEW', 403, /less than 14 days ago/],
    ['FAILURE_PROPOSAL_ALONE_LOCKED', 409, /one admin alone can't confirm/],
    ['BAD_REQUEST', 400, /couldn't accept this step as it was sent/],
    ['FORBIDDEN', 403, /Only an admin can mark a payment failed/],
    ['NOT_FOUND', 404, /can't be found in this organisation any more/],
    ['SOMETHING_NEW', 409, /didn't make this change \(reason SOMETHING_NEW\)/],
  ])('says a refused approve plainly and reads the payment again: %s', async (code, status, said) => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: LONG_AGO, openProposal: proposal() } }),
    });
    answer(`POST ${PROPOSAL_PATH}/approve`, { status, body: { error: { code } } });
    open(`/payments/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm it failed' }));
    expect(await screen.findByText(said)).toBeDefined();
    await waitFor(() => {
      expect(sentTo('GET', `/v1/payments/${ID}`).length).toBeGreaterThan(1);
    });
    expect(goTo).not.toHaveBeenCalled();
  });

  it.each([
    ['INTEGRITY_FAILED', /failed Agent X's integrity check/],
    ['UNAVAILABLE', /couldn't be reached/],
  ])('says a withdraw that failed on the way: %s', async (code, said) => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: LONG_AGO, openProposal: proposal() } }),
    });
    answer(`POST ${PROPOSAL_PATH}/withdraw`, { status: 503, body: { error: { code } } });
    open(`/payments/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Withdraw proposal' }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('says a browser that keeps no storage can’t propose, and changes nothing', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, { status: 200, body: details() });
    answer(`POST ${PROPOSAL_PATH}`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError');
    });
    open(`/payments/${ID}`);
    await userEvent.type(await screen.findByLabelText("Your bank's reference for its written confirmation"), 'ENBD-1');
    await userEvent.click(screen.getByRole('button', { name: 'Propose marking it failed' }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(await screen.findByText(/This browser keeps no site storage/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('goes to sign-in, saying the session ended, when a step is answered 401', async () => {
    signedIn();
    answer(`GET /v1/payments/${ID}`, {
      status: 200,
      body: details({ markFailed: { markableFrom: LONG_AGO, openProposal: proposal() } }),
    });
    answer(`POST ${PROPOSAL_PATH}/approve`, { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } });
    open(`/payments/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm it failed' }));
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });
});

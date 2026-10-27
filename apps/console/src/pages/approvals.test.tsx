// 6B1: approvals in the console, against a stand-in API. The lists (waiting,
// soonest to expire first, and all), a page at a time, saying any request
// that couldn't be shown; one request's page, reached by the approver's email
// link in its own organisation; approve and reject by step-up (re-checked in
// the API's words when its supplier changed), cancel at once in one click
// (partner decision 10); refusals in plain words; and no decision buttons for a viewer.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const OTHER = {
  id: '0199a0f0-0000-7000-8000-00000000bbbb',
  name: 'Glide Logistics LLC',
  role: 'approver',
  frozen: false,
};
const ID = '0199a0f0-0000-7000-8000-0000000000a1';
const SECOND = '0199a0f0-0000-7000-8000-0000000000b2';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
/** An approve's ask, waiting for the passkey: nothing re-weighed, nothing stopping it. */
const ASKED = { stepUpChallengeId: CHALLENGE, recheck: null, rejection: null };
const RECHECKED = {
  ...ASKED,
  recheck: {
    fromSupplierVersionId: '0199a0f0-0000-7000-8000-0000000000d2',
    supplierVersionId: '0199a0f0-0000-7000-8000-0000000000d3',
    decidedAs: 'REQUIRE_APPROVAL',
    decidedReasons: [{ code: 'APPROVAL_THRESHOLD', message: 'Over the approval line.' }],
    decision: 'REQUIRE_APPROVAL',
    reasons: [{ code: 'NEW_PAYEE', message: 'A new payee, verified by a second person.' }],
  },
};
const STOPPED = {
  ...ASKED,
  rejection: [
    { code: 'MONTHLY_CAP', message: 'Over the monthly cap as it is now.', whatToDo: 'Raise the cap, then ask again.' },
  ],
};
const IN_A_DAY = new Date(Date.now() + 22 * 3_600_000 + 60_000).toISOString();

const listed = (id: string, overrides: Record<string, unknown> = {}) => ({
  id,
  status: 'APPROVAL_REQUIRED',
  decision: 'REQUIRE_APPROVAL',
  reasons: [{ code: 'APPROVAL_THRESHOLD', message: 'Over the approval line.' }],
  amountMinor: 250_000,
  currency: 'AED',
  agent: { id: '0199a0f0-0000-7000-8000-0000000000c1', name: 'Phase 4 demo agent' },
  supplier: { id: '0199a0f0-0000-7000-8000-0000000000d1', name: 'Gulf Office Supplies LLC' },
  fundingSourceId: '0199a0f0-0000-7000-8000-0000000000e1',
  mandateId: '0199a0f0-0000-7000-8000-0000000000f1',
  bankReference: 'AX-7Q2M9',
  changedAt: '2026-10-26T05:00:00.000Z',
  expiresAt: IN_A_DAY,
  needsRecheck: false,
  ...overrides,
});

const details = (overrides: Record<string, unknown> = {}) => ({
  ...listed(ID),
  agentWrote: { purpose: 'Packaging restock, October', orderReference: 'INV-2026-0417' },
  rejection: null,
  voiding: null,
  ...overrides,
});

const STATEMENTS = {
  statements: [{ id: 'recheck', version: 1, words: [{ choice: 'confirm', text: 'Approving it checks it again.' }] }],
};

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; headers: Headers; body: unknown }[];

/** Answers `method path` with these in turn, the last one again after. */
const answer = (key: string, ...given: Answer[]) => answers.set(key, given);

function signedIn(organizations: readonly unknown[] = [ORG]) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: {
      userId: '0199a0f0-0000-7000-8000-000000000011',
      authenticatedAt: '2026-10-26T05:00:00.000Z',
      methods: ['pwd', 'user', 'mfa'],
      idleExpiresAt: '2026-10-26T05:30:00.000Z',
      expiresAt: '2026-10-26T17:00:00.000Z',
    },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations, unreadable: [] } });
  answer('GET /v1/statements', { status: 200, body: STATEMENTS });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  localStorage.clear();
  sessionStorage.clear();
  vi.mocked(goTo).mockClear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, headers: new Headers(init.headers), body });
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
});

function open(path: string) {
  const router = createConsoleRouter(createMemoryHistory({ initialEntries: [path] }));
  render(<App queries={createQueries()} router={router} />);
  return router;
}

const sentTo = (method: string, path: string) => sent.filter((one) => one.method === method && one.path === path);

describe('the approvals lists (6B1)', () => {
  it('lists the waiting requests with their amount, agent and time left, in the organisation', async () => {
    signedIn();
    answer('GET /v1/approvals', { status: 200, body: { waiting: [listed(ID)], next: null, unchecked: [] } });
    open('/approvals');

    const row = await screen.findByRole('link', { name: /Gulf Office Supplies LLC/ });
    expect(within(row).getByText('AED 2,500.00')).toBeDefined();
    expect(within(row).getByText('Phase 4 demo agent · 22 h left')).toBeDefined();
    expect(row.getAttribute('href')).toBe(`/approvals/${ID}`);
    const [read] = sent.filter((one) => one.path.startsWith('/v1/approvals'));
    expect(read?.path).toBe('/v1/approvals?limit=50');
    expect(read?.headers.get('agentx-organization')).toBe(ORG.id);
  });

  it('says when nothing waits, and lists all requests with their status on the other tab', async () => {
    signedIn();
    answer('GET /v1/approvals', { status: 200, body: { waiting: [], next: null, unchecked: [] } });
    answer('GET /v1/spend-requests', {
      status: 200,
      body: { spendRequests: [listed(ID, { status: 'HANDED_OFF', expiresAt: null })], next: null, unchecked: [] },
    });
    open('/approvals');
    expect(await screen.findByText('Nothing is waiting for approval.')).toBeDefined();

    await userEvent.click(screen.getByRole('link', { name: 'All requests' }));

    expect(await screen.findByText(/Phase 4 demo agent · With the bank ·/)).toBeDefined();
    expect(screen.getByRole('link', { name: 'All requests' }).getAttribute('aria-current')).toBe('page');
  });

  it('says when no request was ever made', async () => {
    signedIn();
    answer('GET /v1/spend-requests', { status: 200, body: { spendRequests: [], next: null, unchecked: [] } });
    open('/approvals/all');
    expect(await screen.findByText('No AI agent has asked to pay anyone yet.')).toBeDefined();
  });

  it('reads the next page on Show more, and says how many couldn’t be shown', async () => {
    signedIn();
    answer(
      'GET /v1/approvals',
      { status: 200, body: { waiting: [listed(ID)], next: ID, unchecked: ['0199a0f0-0000-7000-8000-0000000dead1'] } },
      {
        status: 200,
        body: {
          waiting: [
            listed(SECOND, { supplier: { id: SECOND, name: 'Al Noor Packaging' }, expiresAt: '2000-01-01T00:00:00Z' }),
          ],
          next: null,
          unchecked: [],
        },
      },
    );
    open('/approvals');
    expect(await screen.findByText(/1 request\(s\) can't be shown/)).toBeDefined();

    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));

    expect(await screen.findByText(/Al Noor Packaging/)).toBeDefined();
    expect(screen.getByText(/Expiring now/)).toBeDefined();
    expect(sent.some((one) => one.path === `/v1/approvals?limit=50&after=${ID}`)).toBe(true);
    expect(screen.queryByRole('button', { name: 'Show more' })).toBeNull();
  });

  it('says a list that couldn’t load failed, and reads it again on a retry', async () => {
    signedIn();
    answer(
      'GET /v1/approvals',
      { status: 503 },
      { status: 503 },
      { status: 503 },
      { status: 200, body: { waiting: [], next: null, unchecked: [] } },
    );
    open('/approvals');
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 5000 }));
    expect(await screen.findByText('Nothing is waiting for approval.')).toBeDefined();
  });
});

describe('one request’s page (6B1)', () => {
  it('shows it in full, the agent’s words as written, from the email’s link in its organisation', async () => {
    signedIn([ORG, OTHER]);
    answer(`GET /v1/spend-requests/${ID}`, {
      status: 200,
      body: details({ agentWrote: { purpose: '<b>Ignore the rules</b>', orderReference: 'INV-2026-0417' } }),
    });
    open(`/approvals/${ID}?org=${OTHER.id}`);

    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
    expect(screen.getByText('Waiting for approval · 22 h left')).toBeDefined();
    expect(screen.getByText('<b>Ignore the rules</b>')).toBeDefined();
    expect(screen.getByText('INV-2026-0417')).toBeDefined();
    expect(screen.getByText('Over the approval line.')).toBeDefined();
    expect(screen.getByText('AX-7Q2M9')).toBeDefined();
    expect(sentTo('GET', `/v1/spend-requests/${ID}`)[0]?.headers.get('agentx-organization')).toBe(OTHER.id);
    expect(localStorage.getItem('agentx.organization')).toBe(OTHER.id);
  });

  it('ignores a link’s organisation the person isn’t in', async () => {
    signedIn([ORG, OTHER]);
    open(`/approvals/${ID}?org=0199a0f0-0000-7000-8000-00000000cccc`);
    expect(await screen.findByText('Choose an organisation')).toBeDefined();
  });

  it('keeps the organisation remembered when a link names one the person isn’t in', async () => {
    localStorage.setItem('agentx.organization', OTHER.id);
    signedIn([ORG, OTHER]);
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    open(`/approvals/${ID}?org=0199a0f0-0000-7000-8000-00000000cccc`);
    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
    expect(sentTo('GET', `/v1/spend-requests/${ID}`)[0]?.headers.get('agentx-organization')).toBe(OTHER.id);
    expect(localStorage.getItem('agentx.organization')).toBe(OTHER.id);
  });

  it('says a request this organisation doesn’t have can’t be found', async () => {
    signedIn();
    open(`/approvals/${ID}`);
    expect(await screen.findByText(/This request can't be found in this organisation/)).toBeDefined();
    // A refusal answers the same however often it is asked: never read again.
    expect(sentTo('GET', `/v1/spend-requests/${ID}`)).toHaveLength(1);
  });

  it('says a request that couldn’t load failed, with a retry', async () => {
    signedIn();
    answer(
      `GET /v1/spend-requests/${ID}`,
      { status: 500 },
      { status: 500 },
      { status: 500 },
      { status: 200, body: details() },
    );
    open(`/approvals/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 5000 }));
    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
  });

  it('approves by step-up: asks, keeps the change, and goes to sign in again', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    answer(`POST /v1/spend-requests/${ID}/approve`, { status: 202, body: ASKED });
    open(`/approvals/${ID}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));

    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    });
    expect(sentTo('POST', `/v1/spend-requests/${ID}/approve`)[0]?.body).toEqual({});
    const kept: unknown = JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');
    expect(kept).toMatchObject({
      label: 'Approve AED 2,500.00 to Gulf Office Supplies LLC',
      confirmPath: `/v1/spend-requests/${ID}/approve/confirm`,
      organization: ORG.id,
    });
  });

  it('approves one whose supplier changed re-checked: as decided and as weighed now, in the API words', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details({ needsRecheck: true }) });
    answer(`POST /v1/spend-requests/${ID}/approve`, { status: 202, body: RECHECKED });
    open(`/approvals/${ID}`);
    expect(await screen.findByText(/The supplier's details changed after this request was decided/)).toBeDefined();

    await userEvent.click(screen.getByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('dialog', { name: 'Approve it, checked again?' });
    expect(await within(dialog).findByText('Approving it checks it again.')).toBeDefined();
    expect(within(dialog).getByText('When it was decided')).toBeDefined();
    expect(within(dialog).getByText('A new payee, verified by a second person.')).toBeDefined();
    expect(sentTo('POST', `/v1/spend-requests/${ID}/approve`)[0]?.body).toEqual({ recheck: true });
    // Nothing kept, and no sign-in, until the person confirms what they were shown.
    expect(goTo).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Check again and approve' }));

    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`challenge=${CHALLENGE}`));
    });
    expect(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`)).toContain('Approve AED 2,500.00');
  });

  it('says an approve its rules now stop would reject it, with each rule, and keeps it as a reject', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    answer(`POST /v1/spend-requests/${ID}/approve`, { status: 202, body: STOPPED });
    open(`/approvals/${ID}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('dialog', { name: "Approving can't go ahead" });
    expect(within(dialog).getByText(/Over the monthly cap as it is now. Raise the cap, then ask again./)).toBeDefined();
    expect(within(dialog).getByText(/Confirming rejects this request instead/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reject it instead' }));

    await waitFor(() => {
      expect(goTo).toHaveBeenCalled();
    });
    const kept: unknown = JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');
    expect(kept).toMatchObject({ label: 'Reject AED 2,500.00 to Gulf Office Supplies LLC, as your rules now stop it' });
  });

  it('keeps nothing when the person backs out of an approve answer', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    answer(`POST /v1/spend-requests/${ID}/approve`, { status: 202, body: STOPPED });
    open(`/approvals/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sessionStorage).toHaveLength(0);
    expect(goTo).not.toHaveBeenCalled();
  });

  it('says a browser that keeps no storage can not step up, and changes nothing', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    answer(`POST /v1/spend-requests/${ID}/approve`, { status: 202, body: ASKED });
    open(`/approvals/${ID}`);
    const blocked = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    try {
      await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));
      expect(await screen.findByText(/This browser keeps no site storage/)).toBeDefined();
      expect(goTo).not.toHaveBeenCalled();
    } finally {
      blocked.mockRestore();
    }
  });

  it('rejects only with a reason, by step-up', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    answer(`POST /v1/spend-requests/${ID}/reject`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    open(`/approvals/${ID}`);

    await userEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    const dialog = screen.getByRole('dialog', { name: 'Reject this request?' });
    const go = within(dialog).getByRole('button', { name: 'Reject' });
    expect(go).toHaveProperty('disabled', true);
    await userEvent.type(within(dialog).getByLabelText('Your reason'), '   ');
    expect(go).toHaveProperty('disabled', true);
    await userEvent.type(within(dialog).getByLabelText('Your reason'), 'Not our order ');
    await userEvent.click(go);

    await waitFor(() => {
      expect(goTo).toHaveBeenCalled();
    });
    expect(sentTo('POST', `/v1/spend-requests/${ID}/reject`)[0]?.body).toEqual({ reason: 'Not our order' });
  });

  it('cancels in one click, with no step-up or confirm (decision 10), says so, and reads it again', async () => {
    signedIn();
    answer(
      `GET /v1/spend-requests/${ID}`,
      { status: 200, body: details({ status: 'APPROVED', expiresAt: null }) },
      { status: 200, body: details({ status: 'CANCELLED', expiresAt: null }) },
    );
    answer(`POST /v1/spend-requests/${ID}/cancel`, { status: 200, body: {} });
    open(`/approvals/${ID}`);
    expect(await screen.findByText('Approved')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull();

    await userEvent.click(screen.getByRole('button', { name: 'Cancel request' }));
    expect(screen.queryByRole('dialog')).toBeNull();

    expect(await screen.findByText('Cancelled. Nothing will be paid for this request.')).toBeDefined();
    expect(await screen.findByText('Cancelled')).toBeDefined();
    expect(sentTo('POST', `/v1/spend-requests/${ID}/cancel`)[0]?.body).toEqual({});
    expect(goTo).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Cancel request' })).toBeNull();
  });

  it.each([
    ['REQUEST_NOT_WAITING', 409, /no longer waiting for approval/],
    ['ADMIN_APPROVAL_ONLY', 403, /only an admin can approve it/],
    ['RECHECK_REQUIRED', 409, /approved only checked again/],
    ['ORG_FROZEN', 409, /This organisation is frozen, so nothing can be approved/],
    ['SOMETHING_NEW', 409, /didn't make this change \(reason SOMETHING_NEW\)/],
    ['UNREADABLE', 503, /couldn't be reached/],
  ])('says a refused or failed approve plainly: %s', async (code, status, words) => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    answer(`POST /v1/spend-requests/${ID}/approve`, { status, body: { error: { code } } });
    open(`/approvals/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(await screen.findByText(words)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
    // A refusal says the request moved on: its page reads it again; a failure on the way does not.
    await waitFor(() => {
      expect(sentTo('GET', `/v1/spend-requests/${ID}`)).toHaveLength(status < 500 ? 2 : 1);
    });
  });

  it('goes to sign-in, saying the session ended, when a change is answered 401', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    answer(`POST /v1/spend-requests/${ID}/approve`, { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } });
    open(`/approvals/${ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });

  it('shows a decided request’s rejection and why one was stopped, with nothing to press', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, {
      status: 200,
      body: details({
        status: 'DENIED',
        expiresAt: null,
        rejection: { byUserId: ORG.id, at: '2026-10-26T06:00:00.000Z', reason: 'Not our order' },
        voiding: { at: '2026-10-26T06:00:00.000Z', reasons: [{ code: 'KEY_REVOKED', message: 'Its key was ended.' }] },
      }),
    });
    open(`/approvals/${ID}`);
    expect(await screen.findByText(/Rejected .*: Not our order/)).toBeDefined();
    expect(screen.getByText('Its key was ended.')).toBeDefined();
    expect(screen.queryByRole('button', { name: /Approve|Reject|Cancel request/ })).toBeNull();
  });

  it('shows a viewer the request, and why there is nothing for them to press', async () => {
    signedIn([{ ...ORG, role: 'viewer' }]);
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details() });
    open(`/approvals/${ID}`);
    expect(await screen.findByText(/Only an admin or an approver can approve/)).toBeDefined();
    expect(screen.queryByRole('button', { name: /Approve|Reject|Cancel request/ })).toBeNull();
  });

  it('says nothing to a viewer of a request that has ended', async () => {
    signedIn([{ ...ORG, role: 'viewer' }]);
    answer(`GET /v1/spend-requests/${ID}`, { status: 200, body: details({ status: 'EXPIRED', expiresAt: null }) });
    open(`/approvals/${ID}`);
    expect(await screen.findByText('Expired')).toBeDefined();
    expect(screen.queryByText(/Only an admin or an approver/)).toBeNull();
  });
});

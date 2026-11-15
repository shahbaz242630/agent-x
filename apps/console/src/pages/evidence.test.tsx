// 6C2: a request's evidence in the console, against a stand-in API. An admin
// reaches it from the request's page (every request, a denied one too); the
// page downloads the bundle once a visit (one POST, one idempotency key, even
// under StrictMode's double effects), says the download is logged, shows it in
// plain sections and its events with their hashes, prints, and saves the API's
// answer as `evidence-<id>.json`. Only an admin; refusals in plain words, a
// retry the same download; a 401 ends the session.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StrictMode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const ID = '0199a0f0-0000-7000-8000-0000000000a1';
const RECORD = '0199a0f0-0000-7000-8000-0000000000e1';
const APPROVED_EVENT = '0199a0f0-0000-7000-8000-0000000000e2';
const PATH = `/v1/spend-requests/${ID}/evidence-exports`;
const AT = '2026-10-26T05:00:00.000Z';

const event = (seq: string, id: string, action: string, actor: Record<string, unknown>) => ({
  seq,
  id,
  recordedAt: AT,
  actor: { email: null, shownFrom: 'agent_x', ...actor },
  action,
  subject: { type: 'spend_request', id: ID, version: 1 },
  details: [{ name: 'status', value: 'HANDED_OFF' }],
  hash: `${seq}a`.repeat(16),
  prevHash: `${seq}b`.repeat(16),
});

const ADMIN = { type: 'user', id: ME, name: 'Shahbaz Admin', email: 'admin@example.com' };
const AGENT = { type: 'agent', id: '0199a0f0-0000-7000-8000-0000000000c1', name: 'Phase 4 demo agent' };

const handedOff = () => ({
  id: RECORD,
  recordSeq: '41',
  upToSeq: '42',
  spendRequest: {
    id: ID,
    status: 'HANDED_OFF',
    decision: 'REQUIRE_APPROVAL',
    reasons: [{ code: 'OVER_APPROVAL_THRESHOLD', message: 'Over the amount that needs approval.' }],
    amountMinor: 250_000,
    currency: 'AED',
    orderReference: 'INV-2026-0042',
    bankReference: 'AX-7Q2M9',
    purpose: 'Printer toner for the Dubai office',
    idempotencyKey: 'agent-key-0042',
    inputHash: 'f00dfeed',
    decidedAt: AT,
    changedAt: AT,
    expiresAt: null,
  },
  agent: { id: AGENT.id, name: AGENT.name, keyId: '0199a0f0-0000-7000-8000-0000000000c9' },
  mandate: {
    id: '0199a0f0-0000-7000-8000-0000000000b1',
    versionId: '0199a0f0-0000-7000-8000-0000000000b2',
    acceptance: event('3', '0199a0f0-0000-7000-8000-0000000000e3', 'mandate.accepted', ADMIN),
  },
  policies: {
    organizationPolicyVersionId: '0199a0f0-0000-7000-8000-0000000000f1',
    mandatePolicyVersionId: null,
  },
  supplier: {
    id: '0199a0f0-0000-7000-8000-0000000000d1',
    name: 'Gulf Office Supplies LLC',
    version: {
      id: '0199a0f0-0000-7000-8000-0000000000d2',
      number: 2,
      name: 'Gulf Office Supplies',
      verification: null,
    },
  },
  fundingSource: {
    id: '0199a0f0-0000-7000-8000-0000000000aa',
    holderName: 'Staging Test Org 1 LLC',
    hint: 'AE…6026',
    partner: 'lean',
  },
  approval: {
    eventId: APPROVED_EVENT,
    byUserId: ME,
    at: AT,
    changeHash: 'c0ffee',
    stepUpChallengeId: 'challenge-1',
  },
  rejection: null,
  voiding: null,
  reservation: { state: 'FINALISED', amountMinor: 250_000, currency: 'AED', month: '2026-10', reservedAt: AT },
  payment: {
    instruction: {
      id: '0199a0f0-0000-7000-8000-0000000000a7',
      route: 'AANI',
      routeReason: 'instant rail available',
      partner: 'lean',
      partnerLegalEntityId: 'LEAN-AE-001',
      partnerLicenceRef: 'CBUAE-RPS-77',
      paymentReference: 'AX-7Q2M9 INV-2026-0042',
      intentHash: 'abc123intent',
      createdAt: AT,
    },
    id: '0199a0f0-0000-7000-8000-0000000000a9',
    status: 'SUCCEEDED',
    partnerReference: 'PSP-1182',
    bankStatus: 'ACSC',
    rejectCode: null,
    bankChangedAt: null,
    createdAt: AT,
    changedAt: AT,
    reconciliation: { contradicted: true, markableFrom: null, openProposalId: null },
  },
  events: [
    event('40', APPROVED_EVENT, 'spend_request.approved', ADMIN),
    event('41', RECORD, 'spend_request.evidence_exported', ADMIN),
  ],
});

/** A request denied before any person saw it: no mandate, nothing held, no payment, nothing in the log to name. */
const denied = () => ({
  ...handedOff(),
  spendRequest: {
    ...handedOff().spendRequest,
    status: 'DENIED',
    decision: 'DENY',
    reasons: [],
    decidedAt: null,
    inputHash: null,
  },
  mandate: null,
  approval: null,
  rejection: {
    eventId: '0199a0f0-0000-7000-8000-0000000000e9',
    byUserId: ME,
    at: AT,
    changeHash: null,
    stepUpChallengeId: null,
    reason: 'Not a supplier we use',
  },
  voiding: {
    eventId: '0199a0f0-0000-7000-8000-0000000000e8',
    at: AT,
    reasons: [{ code: 'MANDATE_ENDED', message: 'Its mandate ended.' }],
  },
  reservation: null,
  payment: null,
  events: [event('7', RECORD, 'spend_request.decided', AGENT)],
});

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown; key: string | null }[];

/** Answers `method path` with these in turn, the last one again after. */
const answer = (key: string, ...given: Answer[]) => answers.set(key, given);
const refusal = (status: number, code: string): Answer => ({ status, body: { error: { code } } });

function signedIn(role = 'admin') {
  answer('GET /v1/auth/session', {
    status: 200,
    body: {
      userId: ME,
      authenticatedAt: AT,
      methods: ['pwd', 'user', 'mfa'],
      idleExpiresAt: '2026-10-26T05:30:00.000Z',
      expiresAt: '2026-10-26T17:00:00.000Z',
    },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  localStorage.clear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, body, key: new Headers(init.headers).get('idempotency-key') });
      const queue = answers.get(`${method} ${path.split('?')[0] ?? path}`);
      const next = queue === undefined ? undefined : queue.length > 1 ? queue.shift() : queue[0];
      const { status, body: reply } = next ?? refusal(404, 'NOT_FOUND');
      return Promise.resolve(new Response(JSON.stringify(reply ?? {}), { status }));
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function open(path: string, strict = false) {
  const router = createConsoleRouter(createMemoryHistory({ initialEntries: [path] }));
  const app = <App queries={createQueries()} router={router} />;
  render(strict ? <StrictMode>{app}</StrictMode> : app);
  return router;
}

const posts = () => sent.filter((one) => one.method === 'POST' && one.path === PATH);

/** The one found, which the test has just looked for. */
function found<T>(one: T | null | undefined): T {
  if (one === null || one === undefined) throw new Error('Nothing found');
  return one;
}

/** The text beside a fact's label in the section headed `section`. */
function fact(section: string, label: string): string {
  const part = found(screen.getByRole('heading', { name: section }).closest('section'));
  const term = within(part).getByText(label, { selector: 'dt' });
  return term.nextElementSibling?.textContent ?? '';
}

describe('reaching a request’s evidence (6C2)', () => {
  it('offers an admin the evidence from the request’s page, saying opening it is logged', async () => {
    signedIn();
    answer(`GET /v1/spend-requests/${ID}`, {
      status: 200,
      body: {
        id: ID,
        status: 'DENIED',
        decision: 'DENY',
        reasons: [],
        amountMinor: 250_000,
        currency: 'AED',
        agent: { id: AGENT.id, name: AGENT.name },
        supplier: { id: '0199a0f0-0000-7000-8000-0000000000d1', name: 'Gulf Office Supplies LLC' },
        fundingSourceId: '0199a0f0-0000-7000-8000-0000000000aa',
        mandateId: null,
        bankReference: 'AX-7Q2M9',
        changedAt: AT,
        expiresAt: null,
        needsRecheck: false,
        agentWrote: { purpose: 'Toner', orderReference: 'INV-1' },
        rejection: null,
        voiding: null,
      },
    });
    answer(`POST ${PATH}`, { status: 201, body: { evidence: denied() } });
    open(`/approvals/${ID}`);
    const link = await screen.findByRole('link', { name: 'Evidence' });
    expect(link.getAttribute('href')).toBe(`/approvals/${ID}/evidence`);
    expect(screen.getByText(/Opening it records a download in the audit log/)).toBeDefined();
    // Nothing is downloaded until it is opened.
    expect(posts()).toHaveLength(0);
    await userEvent.click(link);
    expect(await screen.findByRole('heading', { name: 'The request' })).toBeDefined();
    expect(posts()).toHaveLength(1);
  });

  it('offers no one but an admin the evidence', async () => {
    signedIn('approver');
    answer(`GET /v1/spend-requests/${ID}`, { status: 404, body: { error: { code: 'NOT_FOUND' } } });
    open(`/approvals/${ID}`);
    expect(await screen.findByText(/This request can't be found/)).toBeDefined();
    expect(screen.queryByRole('link', { name: 'Evidence' })).toBeNull();
  });
});

describe('a request’s evidence page (6C2)', () => {
  it('downloads it once a visit, even with StrictMode’s second run, and says the download is logged', async () => {
    signedIn();
    answer(`POST ${PATH}`, { status: 201, body: { evidence: handedOff() } });
    open(`/approvals/${ID}/evidence`, true);
    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
    expect(screen.getByText(/the audit log records each download with who made it/)).toBeDefined();
    expect(posts()).toHaveLength(1);
    expect(posts()[0]?.body).toEqual({});
    expect(posts()[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
    expect(sent.find((one) => one.path.startsWith('/v1/spend-requests/') && one.method === 'GET')).toBeUndefined();
    // Read again later (a re-render, another tab back), it is never downloaded twice.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(posts()).toHaveLength(1);
  });

  it('shows the bundle in plain sections: request, decision, supplier, approval, money held and payment', async () => {
    signedIn();
    answer(`POST ${PATH}`, { status: 201, body: { evidence: handedOff() } });
    open(`/approvals/${ID}/evidence`);
    await screen.findByRole('heading', { name: 'The request' });
    expect(screen.getByText(/As it stood at audit event #42. This download is event #41/)).toBeDefined();
    expect(fact('The request', 'Where it stands')).toBe('With the bank');
    expect(fact('The request', 'Invoice or order')).toBe('INV-2026-0042');
    expect(fact('The request', 'The agent wrote')).toBe('Printer toner for the Dubai office');
    expect(fact('The request', "Agent's idempotency key")).toBe('agent-key-0042');
    expect(fact('The request', 'Expires')).toBe('None');
    expect(fact('The decision', 'Decided')).toBe('Needs approval');
    expect(fact('The decision', 'Why')).toBe('Over the amount that needs approval.');
    expect(fact('The decision', 'Hash of what it weighed')).toBe('f00dfeed');
    expect(fact('The decision', 'Mandate version')).toBe('0199a0f0-0000-7000-8000-0000000000b2');
    expect(fact('The decision', 'Mandate accepted')).toMatch(/#3 By Shahbaz Admin \(admin@example.com\)/);
    expect(fact('The decision', 'Mandate policy version')).toBe('None');
    expect(fact('Supplier and bank account', 'Details decided under')).toBe('Version 2: Gulf Office Supplies');
    expect(fact('Supplier and bank account', 'Those details verified')).toBe('None found in the log');
    expect(fact('Supplier and bank account', 'Paid from')).toBe('Staging Test Org 1 LLC · AE…6026');
    expect(fact('Approval and money held', 'Approved')).toMatch(/By Shahbaz Admin \(admin@example.com\) /);
    expect(fact('Approval and money held', 'Approval bound to (hash)')).toBe('c0ffee');
    expect(fact('Approval and money held', 'Rejected')).toBe('None');
    expect(fact('Approval and money held', 'Money held')).toMatch(/^Paid: AED 2,500.00 in 2026-10, from /);
    expect(fact('The payment', 'Where it stands')).toBe('Paid');
    expect(fact('The payment', 'Route')).toBe('AANI · instant rail available');
    expect(fact('The payment', "Partner's licence reference")).toBe('CBUAE-RPS-77');
    expect(fact('The payment', 'Instruction hash')).toBe('abc123intent');
    expect(fact('The payment', 'Reconciliation')).toMatch(/The bank's latest word disagrees/);
    expect(fact('The payment', 'Open proposal to mark it failed')).toBe('None');
  });

  it('lists every signed event oldest first, each with who, what, about what and its hashes in mono', async () => {
    signedIn();
    answer(`POST ${PATH}`, { status: 201, body: { evidence: handedOff() } });
    open(`/approvals/${ID}/evidence`);
    const table = await screen.findByRole('table');
    expect(screen.getByRole('heading', { name: 'Every signed event (2), oldest first' })).toBeDefined();
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map((row) => row.querySelector('td')?.textContent)).toEqual(['40', '41']);
    const first = found(rows[0]);
    expect(within(first).getByText('spend_request.approved')).toBeDefined();
    expect(within(first).getByText(/Shahbaz Admin \(admin@example.com\)/)).toBeDefined();
    const hashes = first.querySelector('.hashes');
    expect(hashes?.classList.contains('mono')).toBe(true);
    expect(hashes?.textContent).toBe(`Hash ${'40a'.repeat(16)}Before it ${'40b'.repeat(16)}`);
  });

  it('says a denied request’s parts that never happened, and names a reject from its ID when its event isn’t there', async () => {
    signedIn();
    answer(`POST ${PATH}`, { status: 201, body: { evidence: denied() } });
    open(`/approvals/${ID}/evidence`);
    await screen.findByRole('heading', { name: 'The payment' });
    expect(screen.getByText('Never sent to the bank: there is no payment.')).toBeDefined();
    expect(fact('The decision', 'Mandate')).toBe('None in force');
    expect(screen.queryByText('Mandate version')).toBeNull();
    expect(fact('The decision', 'Why')).toBe('None');
    expect(fact('The decision', 'Decided at')).toBe('None');
    expect(fact('Approval and money held', 'Approved')).toBe('None');
    expect(fact('Approval and money held', 'Rejected')).toMatch(
      /· Not a supplier we use 0199a0f0-0000-7000-8000-000000000011$/,
    );
    expect(fact('Approval and money held', 'Stopped before it was paid')).toMatch(/ · Its mandate ended\.$/);
    expect(fact('Approval and money held', 'Money held')).toBe('None');
    expect(screen.queryByText('Approval bound to (hash)')).toBeNull();
  });

  it('prints the page as shown', async () => {
    signedIn();
    answer(`POST ${PATH}`, { status: 201, body: { evidence: handedOff() } });
    const print = vi.spyOn(window, 'print').mockImplementation(() => undefined);
    open(`/approvals/${ID}/evidence`);
    await userEvent.click(await screen.findByRole('button', { name: 'Print' }));
    expect(print).toHaveBeenCalledOnce();
    // Printing reads nothing more, so logs nothing more.
    expect(posts()).toHaveLength(1);
  });

  it('saves the API’s answer as it came, named evidence-<id>.json, with no second download', async () => {
    signedIn();
    const body = { evidence: handedOff() };
    answer(`POST ${PATH}`, { status: 201, body });
    const made: Blob[] = [];
    // jsdom makes no object URLs: stand-ins that keep the file made.
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn((file: Blob) => {
        made.push(file);
        return 'blob:evidence';
      }),
      revokeObjectURL: vi.fn(),
    });
    let saved: { href: string; download: string } | undefined;
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click(this: HTMLAnchorElement) {
      saved = { href: this.href, download: this.download };
    });
    open(`/approvals/${ID}/evidence`);
    await userEvent.click(await screen.findByRole('button', { name: 'Download JSON' }));
    expect(saved).toEqual({ href: 'blob:evidence', download: `evidence-${ID}.json` });
    expect(made[0]?.type).toBe('application/json');
    expect(JSON.parse((await made[0]?.text()) ?? '')).toEqual(body);
    expect(posts()).toHaveLength(1);
  });
});

describe('the evidence refused or failed (6C2)', () => {
  it('says each refusal in plain words, and a retry is the same download (the same key)', async () => {
    signedIn();
    answer(`POST ${PATH}`, refusal(409, 'EVIDENCE_EXPORTS_SPENT'), { status: 201, body: { evidence: handedOff() } });
    open(`/approvals/${ID}/evidence`);
    expect(await screen.findByText(/You've downloaded evidence 5 times in the last hour/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: 'The request' })).toBeDefined();
    expect(posts()).toHaveLength(2);
    expect(posts()[1]?.key).toBe(posts()[0]?.key);
  });

  it.each([
    ['EVIDENCE_TOO_LARGE', 409, /more than 2,000 events/],
    ['EVIDENCE_CHANGED_WHILE_READING', 409, /kept changing while Agent X read it/],
    ['FORBIDDEN', 403, /Only an admin can download a request's evidence/],
    ['INTEGRITY_FAILED', 503, /failed Agent X's integrity check, so its evidence can't be downloaded/],
    ['SOMETHING_NEW', 409, /reason SOMETHING_NEW/],
    ['INTERNAL', 500, /couldn't be reached/],
  ])('says %s in plain words', async (code, status, words) => {
    signedIn();
    answer(`POST ${PATH}`, refusal(status, code));
    open(`/approvals/${ID}/evidence`);
    expect(await screen.findByText(words)).toBeDefined();
  });

  it('says a request this organisation doesn’t have can’t be found, and asks nothing for an address naming none', async () => {
    signedIn();
    open(`/approvals/${ID}/evidence`);
    expect(await screen.findByText(/This request can't be found/)).toBeDefined();
    cleanup();
    sent = [];
    open('/approvals/not-a-request/evidence');
    expect(await screen.findByText(/This request can't be found/)).toBeDefined();
    expect(sent.filter((one) => one.method === 'POST')).toHaveLength(0);
  });

  it('downloads nothing for anyone but an admin, and says so', async () => {
    signedIn('viewer');
    open(`/approvals/${ID}/evidence`);
    expect(await screen.findByText(/Only an admin can download a request's evidence/)).toBeDefined();
    expect(screen.queryByText(/the audit log records each download with who made it/)).toBeNull();
    expect(posts()).toHaveLength(0);
  });

  it('goes to sign-in, saying the session ended, when the download is answered 401', async () => {
    signedIn();
    answer(`POST ${PATH}`, refusal(401, 'UNAUTHENTICATED'));
    open(`/approvals/${ID}/evidence`);
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });

  it('goes back to the request', async () => {
    signedIn();
    answer(`POST ${PATH}`, refusal(409, 'EVIDENCE_TOO_LARGE'));
    answer(`GET /v1/spend-requests/${ID}`, refusal(404, 'NOT_FOUND'));
    const router = open(`/approvals/${ID}/evidence`);
    await userEvent.click(await screen.findByRole('link', { name: 'Back to the request' }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/approvals/${ID}`);
    });
  });
});

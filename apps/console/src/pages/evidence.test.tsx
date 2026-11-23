// 6C2, 6C2c: a request's evidence in the console, against a stand-in API. An
// admin reaches it from the request's page (every request, a denied one too);
// the page reads the bundle with a GET (decision 24: a page read, not logged)
// and never downloads on opening, a remount or a re-render; it says reading
// isn't logged and a download is, shows it in plain sections and its events
// with their hashes, and prints. "Download JSON" is the logged download, one
// POST a press with its own idempotency key (pressing again after a failure is
// the same download), saving the API's answer as `evidence-<id>.json`. Only an
// admin; refusals in plain words; a 401 ends the session.
import { createMemoryHistory } from '@tanstack/react-router';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StrictMode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const ID = '0199a0f0-0000-7000-8000-0000000000a1';
const RECORD = '0199a0f0-0000-7000-8000-0000000000e1';
const APPROVED_EVENT = '0199a0f0-0000-7000-8000-0000000000e2';
const READ = `/v1/spend-requests/${ID}/evidence`;
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

/** A request handed off and paid, as read on screen: no record of its own. */
const handedOff = () => ({
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

/** The same bundle as downloaded: its own record first. */
const downloaded = () => ({ evidence: { id: RECORD, recordSeq: '43', ...handedOff(), upToSeq: '43' } });

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

function open(path: string, strict = false, queries = createQueries()) {
  const router = createConsoleRouter(createMemoryHistory({ initialEntries: [path] }));
  const app = <App queries={queries} router={router} />;
  render(strict ? <StrictMode>{app}</StrictMode> : app);
  return router;
}

const posts = () => sent.filter((one) => one.method === 'POST' && one.path === PATH);
const reads = () => sent.filter((one) => one.method === 'GET' && one.path === READ);

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

/** Files the page saves, and what each held: jsdom makes no object URLs, so stand-ins keep them. */
function savedFiles() {
  const files: { name: string; file: Blob }[] = [];
  let made: Blob | undefined;
  vi.stubGlobal('URL', {
    createObjectURL: vi.fn((file: Blob) => {
      made = file;
      return 'blob:evidence';
    }),
    revokeObjectURL: vi.fn(),
  });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click(this: HTMLAnchorElement) {
    if (made !== undefined) files.push({ name: this.download, file: made });
  });
  return files;
}

describe('reaching a request’s evidence (6C2)', () => {
  it('offers an admin the evidence from the request’s page, saying reading it isn’t logged', async () => {
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
        payment: null,
      },
    });
    answer(`GET ${READ}`, { status: 200, body: { evidence: denied() } });
    open(`/approvals/${ID}`);
    const link = await screen.findByRole('link', { name: 'Evidence' });
    expect(link.getAttribute('href')).toBe(`/approvals/${ID}/evidence`);
    expect(screen.getByText(/Reading it isn't logged; a download is recorded in the audit log/)).toBeDefined();
    // Nothing is read until it is opened.
    expect(reads()).toHaveLength(0);
    await userEvent.click(link);
    expect(await screen.findByRole('heading', { name: 'The request' })).toBeDefined();
    expect(reads()).toHaveLength(1);
    expect(posts()).toHaveLength(0);
  });

  it('offers no one but an admin the evidence', async () => {
    signedIn('approver');
    answer(`GET /v1/spend-requests/${ID}`, { status: 404, body: { error: { code: 'NOT_FOUND' } } });
    open(`/approvals/${ID}`);
    expect(await screen.findByText(/This request can't be found/)).toBeDefined();
    expect(screen.queryByRole('link', { name: 'Evidence' })).toBeNull();
  });
});

describe('a request’s evidence page (6C2, 6C2c)', () => {
  it('reads it with a GET, even under StrictMode, never downloads it, and says reading isn’t logged', async () => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    open(`/approvals/${ID}/evidence`, true);
    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
    expect(screen.getByText(/Reading this page isn't logged/)).toBeDefined();
    expect(screen.getByText(/the audit log records each download with who made it/)).toBeDefined();
    expect(reads().length).toBeGreaterThanOrEqual(1);
    expect(reads()[0]?.key).toBeNull();
    // Left open (a re-render, the clock ticking), it is never downloaded.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(posts()).toHaveLength(0);
  });

  it('S206 V8 shows the agent’s words as text, never markup, each isolated so a direction override can’t reorder the page', async () => {
    // Built here, so no file holds a raw control: a right-to-left override, a right-to-left isolate, a left-to-right one.
    const [override, isolate, leftIsolate] = [0x20_2e, 0x20_67, 0x20_66].map((point) => String.fromCodePoint(point));
    const written = {
      purpose: `<img src=x onerror="alert(1)">Toner ${override}gnp.exe`,
      orderReference: `INV-${isolate}<script>alert(2)</script>`,
      idempotencyKey: `key-${leftIsolate}<b>bold</b>`,
    };
    const evidence = handedOff();
    signedIn();
    answer(`GET ${READ}`, {
      status: 200,
      body: { evidence: { ...evidence, spendRequest: { ...evidence.spendRequest, ...written } } },
    });
    open(`/approvals/${ID}/evidence`);

    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
    for (const text of Object.values(written)) {
      const shown = screen.getByText(text);
      expect(shown.tagName).toBe('BDI');
      expect(shown.textContent).toBe(text);
      expect(shown.children).toHaveLength(0);
      expect(shown.closest('dl')?.querySelector('img, script, b')).toBeNull();
    }
  });

  it('S206 V8 shows a request denied for a supplier the organisation doesn’t have: not one of yours, no details', async () => {
    const evidence = handedOff();
    signedIn();
    answer(`GET ${READ}`, {
      status: 200,
      body: { evidence: { ...evidence, supplier: { id: evidence.supplier.id, name: null, version: null } } },
    });
    open(`/approvals/${ID}/evidence`);

    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
    expect(fact('Supplier and bank account', 'Supplier')).toBe('Not one of your suppliers');
    expect(fact('Supplier and bank account', 'Details decided under')).toBe('None');
    expect(fact('Supplier and bank account', 'Those details verified')).toBe('None');
  });

  it('S206 V8 shows a request denied for a bank account the organisation doesn’t have: not one of yours', async () => {
    const evidence = handedOff();
    signedIn();
    const fundingSource = { id: evidence.fundingSource.id, holderName: null, hint: null, partner: null };
    answer(`GET ${READ}`, { status: 200, body: { evidence: { ...evidence, fundingSource } } });
    open(`/approvals/${ID}/evidence`);

    expect(await screen.findByRole('heading', { name: 'AED 2,500.00' })).toBeDefined();
    expect(fact('Supplier and bank account', 'Paid from')).toBe('Not one of your bank accounts');
    expect(fact('Supplier and bank account', 'Linked through')).toBe('None');
  });

  it('reads it again, and still downloads nothing, when the page remounts after the shell failed and came back', async () => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    const queries = createQueries();
    open(`/approvals/${ID}/evidence`, false, queries);
    await screen.findByRole('heading', { name: 'The request' });
    // The session read again fails (staging waking): the shell shows its failure, and the page is gone.
    const session = answers.get('GET /v1/auth/session') ?? [];
    answer('GET /v1/auth/session', refusal(403, 'FORBIDDEN'), ...session);
    await act(async () => {
      await queries.refetchQueries({ queryKey: ['session'] });
    });
    const retry = await screen.findByRole('button', { name: 'Try again' });
    expect(screen.queryByRole('heading', { name: 'The request' })).toBeNull();
    await userEvent.click(retry);
    expect(await screen.findByRole('heading', { name: 'The request' })).toBeDefined();
    expect(posts()).toHaveLength(0);
  });

  it('shows the bundle in plain sections: request, decision, supplier, approval, money held and payment', async () => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    open(`/approvals/${ID}/evidence`);
    await screen.findByRole('heading', { name: 'The request' });
    expect(screen.getByText('As it stood at audit event #42.')).toBeDefined();
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
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
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
    answer(`GET ${READ}`, { status: 200, body: { evidence: denied() } });
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

  it('prints the page as read, downloading nothing', async () => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    const print = vi.spyOn(window, 'print').mockImplementation(() => undefined);
    open(`/approvals/${ID}/evidence`);
    await userEvent.click(await screen.findByRole('button', { name: 'Print' }));
    expect(print).toHaveBeenCalledOnce();
    expect(posts()).toHaveLength(0);
  });

  it('downloads it once a press, each with its own key, saving the API’s answer as evidence-<id>.json', async () => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    answer(`POST ${PATH}`, { status: 201, body: downloaded() });
    const files = savedFiles();
    open(`/approvals/${ID}/evidence`);
    const button = await screen.findByRole('button', { name: 'Download JSON' });
    expect(posts()).toHaveLength(0);

    await userEvent.click(button);
    await waitFor(() => {
      expect(files).toHaveLength(1);
    });
    expect(posts()).toHaveLength(1);
    expect(posts()[0]?.body).toEqual({});
    expect(posts()[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
    expect(files[0]?.name).toBe(`evidence-${ID}.json`);
    expect(files[0]?.file.type).toBe('application/json');
    expect(JSON.parse((await files[0]?.file.text()) ?? '')).toEqual(downloaded());

    // A second press is a second download.
    await userEvent.click(button);
    await waitFor(() => {
      expect(files).toHaveLength(2);
    });
    expect(posts()).toHaveLength(2);
    expect(posts()[1]?.key).not.toBe(posts()[0]?.key);
  });
});

describe('a download on its way (6C2c)', () => {
  it('holds the button while a download is on its way: a second press sends nothing', async () => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    answer(`POST ${PATH}`, { status: 201, body: downloaded() });
    const files = savedFiles();
    const { promise: held, resolve: release } = Promise.withResolvers<undefined>();
    const answering = found(vi.mocked(fetch).getMockImplementation());
    vi.mocked(fetch).mockImplementation(async (...asked) => {
      const reply = await answering(...asked);
      if (asked[1]?.method === 'POST') await held;
      return reply;
    });
    open(`/approvals/${ID}/evidence`);
    const button = await screen.findByRole('button', { name: 'Download JSON' });

    await userEvent.click(button);
    await waitFor(() => {
      expect(button).toHaveProperty('disabled', true);
    });
    await userEvent.click(button);
    expect(posts()).toHaveLength(1);

    release(undefined);
    await waitFor(() => {
      expect(files).toHaveLength(1);
    });
    expect(button).toHaveProperty('disabled', false);
    expect(posts()).toHaveLength(1);
  });
});

describe('the evidence refused or failed (6C2, 6C2c)', () => {
  it('says a download refused in plain words beside the button, the evidence still shown; pressing again is the same download', async () => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    answer(`POST ${PATH}`, refusal(409, 'EVIDENCE_EXPORTS_SPENT'), { status: 201, body: downloaded() });
    const files = savedFiles();
    open(`/approvals/${ID}/evidence`);
    const button = await screen.findByRole('button', { name: 'Download JSON' });
    await userEvent.click(button);
    expect(await screen.findByText(/You've downloaded evidence 20 times in the last hour/)).toBeDefined();
    expect(screen.getByRole('heading', { name: 'The request' })).toBeDefined();
    expect(files).toHaveLength(0);

    await userEvent.click(button);
    await waitFor(() => {
      expect(files).toHaveLength(1);
    });
    expect(screen.queryByText(/You've downloaded evidence 20 times/)).toBeNull();
    expect(posts()).toHaveLength(2);
    expect(posts()[1]?.key).toBe(posts()[0]?.key);
  });

  it.each([
    ['EVIDENCE_TOO_LARGE', 409, /more than 2,000 events/],
    ['INTEGRITY_FAILED', 503, /failed Agent X's integrity check, so its evidence can't be shown or downloaded/],
  ])('says a download refused %s in plain words', async (code, status, words) => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    answer(`POST ${PATH}`, refusal(status, code));
    open(`/approvals/${ID}/evidence`);
    await userEvent.click(await screen.findByRole('button', { name: 'Download JSON' }));
    expect(await screen.findByText(words)).toBeDefined();
  });

  it.each([
    ['EVIDENCE_TOO_LARGE', 409, /more than 2,000 events/],
    ['EVIDENCE_CHANGED_WHILE_READING', 409, /kept changing while Agent X read it/],
    ['FORBIDDEN', 403, /Only an admin can see or download a request's evidence/],
    ['INTEGRITY_FAILED', 503, /failed Agent X's integrity check, so its evidence can't be shown or downloaded/],
    ['SOMETHING_NEW', 409, /reason SOMETHING_NEW/],
    ['INTERNAL', 500, /couldn't be reached/],
  ])(
    'says a read refused %s in plain words, downloading nothing',
    async (code, status, words) => {
      signedIn();
      answer(`GET ${READ}`, refusal(status, code));
      open(`/approvals/${ID}/evidence`);
      // A failure on the way (500) is read again twice first, as every query is: a few seconds.
      expect(await screen.findByText(words, {}, { timeout: 6000 })).toBeDefined();
      expect(posts()).toHaveLength(0);
    },
    10_000,
  );

  it('reads it again on "try again", downloading nothing', async () => {
    signedIn();
    answer(`GET ${READ}`, refusal(409, 'EVIDENCE_CHANGED_WHILE_READING'), {
      status: 200,
      body: { evidence: handedOff() },
    });
    open(`/approvals/${ID}/evidence`);
    await screen.findByText(/kept changing while Agent X read it/);
    // A refusal is never read again by itself.
    expect(reads()).toHaveLength(1);
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: 'The request' })).toBeDefined();
    expect(reads()).toHaveLength(2);
    expect(posts()).toHaveLength(0);
  });

  it('says a request this organisation doesn’t have can’t be found, and asks nothing for an address naming none', async () => {
    signedIn();
    open(`/approvals/${ID}/evidence`);
    expect(await screen.findByText(/This request can't be found/)).toBeDefined();
    cleanup();
    sent = [];
    open('/approvals/not-a-request/evidence');
    expect(await screen.findByText(/This request can't be found/)).toBeDefined();
    expect(sent.filter((one) => one.path.includes('/evidence'))).toHaveLength(0);
  });

  it('reads nothing for anyone but an admin, and says so', async () => {
    signedIn('viewer');
    open(`/approvals/${ID}/evidence`);
    expect(await screen.findByText(/Only an admin can see or download a request's evidence/)).toBeDefined();
    expect(screen.queryByText(/the audit log records each download with who made it/)).toBeNull();
    expect(sent.filter((one) => one.path.includes('/evidence'))).toHaveLength(0);
  });

  it('goes to sign-in, saying the session ended, when the read is answered 401', async () => {
    signedIn();
    answer(`GET ${READ}`, refusal(401, 'UNAUTHENTICATED'));
    open(`/approvals/${ID}/evidence`);
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });

  it('goes to sign-in, saying the session ended, when the download is answered 401', async () => {
    signedIn();
    answer(`GET ${READ}`, { status: 200, body: { evidence: handedOff() } });
    answer(`POST ${PATH}`, refusal(401, 'UNAUTHENTICATED'));
    open(`/approvals/${ID}/evidence`);
    await userEvent.click(await screen.findByRole('button', { name: 'Download JSON' }));
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });

  it('goes back to the request', async () => {
    signedIn();
    answer(`GET ${READ}`, refusal(409, 'EVIDENCE_TOO_LARGE'));
    answer(`GET /v1/spend-requests/${ID}`, refusal(404, 'NOT_FOUND'));
    const router = open(`/approvals/${ID}/evidence`);
    await userEvent.click(await screen.findByRole('link', { name: 'Back to the request' }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/approvals/${ID}`);
    });
  });
});

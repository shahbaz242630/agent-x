// 6D3b: the organisation's policy, a mandate's, and the simulator, against a
// stand-in API. Every member reads the rules in force in plain words; an
// admin changes them in the shared editor, every choice theirs with none
// picked, checked in place, then the preview of the requests waiting for
// approval it would reject, the admin's choice for them in the API's words,
// a confirm with the API's words for each choice, and the passkey, sending
// exactly the rules chosen and the versions of the words shown. The
// simulator sends a test request as typed and says what it would get, and
// that nothing was made.
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
const MANDATE = '0199a0f0-0000-7000-8000-0000000000c1';
const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
const SUPPLIER_A = '0199a0f0-0000-7000-8000-0000000000d1';
const SUPPLIER_B = '0199a0f0-0000-7000-8000-0000000000d2';
const SUPPLIER_C = '0199a0f0-0000-7000-8000-0000000000d3';
const SOURCE = '0199a0f0-0000-7000-8000-0000000000f1';
const OTHER_SOURCE = '0199a0f0-0000-7000-8000-0000000000f2';
const REQUEST = '0199a0f0-0000-7000-8000-0000000000e1';
const OTHER_REQUEST = '0199a0f0-0000-7000-8000-0000000000e2';
const OTHER_MANDATE = '0199a0f0-0000-7000-8000-0000000000c2';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const PAST = '2026-01-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';

const STATEMENTS = {
  statements: [
    {
      id: 'monthly_cap',
      version: 1,
      words: [
        { choice: 'amount', text: 'Each agent may spend at most this amount in its month.' },
        { choice: 'none', text: 'No organisation-wide cap: each agent is held only to its mandates.' },
      ],
    },
    { id: 'approval_wait', version: 1, words: [{ choice: 'confirm', text: 'Requests asked from now on wait this.' }] },
    {
      id: 'waiting_requests',
      version: 4,
      words: [
        { choice: 'reject', text: 'Each request listed is rejected at once.' },
        { choice: 'leave', text: 'The requests listed keep waiting.' },
      ],
    },
  ],
};

const VERSION = {
  id: '0199a0f0-0000-7000-8000-0000000000aa',
  version: 3,
  currency: 'AED',
  perOrderCap: { capMinor: 100_000, over: 'DENY' },
  monthlyCapMinor: 500_000,
  approvalThresholdMinor: 50_000,
  supplierIds: null,
  rulesHash: 'abc',
  madeBy: MINE,
  madeAt: PAST,
};

const orgPolicy = (change: Record<string, unknown> = {}) => ({
  scope: 'organization',
  id: ORG.id,
  mandateId: null,
  current: VERSION,
  monthlyCapChoice: 'amount',
  approvalWaitHours: 48,
  approvalWaitInForceHours: 48,
  suggestedMonthlyCapMinor: 2_000_000,
  ...change,
});

const mandatePolicy = (change: Record<string, unknown> = {}) => ({
  scope: 'mandate',
  id: MANDATE,
  mandateId: MANDATE,
  current: null,
  monthlyCapChoice: null,
  approvalWaitHours: null,
  approvalWaitInForceHours: null,
  suggestedMonthlyCapMinor: 2_000_000,
  ...change,
});

const TERMS = {
  currency: 'AED',
  perOrderLimitMinor: 200_000,
  monthlyLimitMinor: 1_000_000,
  approvalThresholdMinor: 100_000,
  supplierIds: [SUPPLIER_A, SUPPLIER_B],
  fundingSourceId: SOURCE,
};
const MANDATE_READ = { id: MANDATE, agentId: AGENT, status: 'ACTIVE', current: TERMS, pending: null };

const NO_WAITING = { rejected: [], more: false };
const WAITING_ONE = {
  rejected: [
    {
      id: REQUEST,
      agentId: AGENT,
      amountMinor: 150_000,
      currency: 'AED',
      reasons: [{ code: 'PER_ORDER_CAP', message: 'Over the cap per request.', whatToDo: 'Raise the cap.' }],
    },
  ],
  more: true,
};

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown }[];

const answer = (at: string, ...given: Answer[]) => answers.set(at, given);
const ok = (body: unknown) => ({ status: 200, body });
const refused = (status: number, code: string) => ({ status, body: { error: { code } } });

function as(role: string) {
  answer(
    'GET /v1/auth/session',
    ok({
      userId: ME,
      authenticatedAt: PAST,
      methods: ['pwd', 'user', 'mfa'],
      idleExpiresAt: FUTURE,
      expiresAt: FUTURE,
    }),
  );
  answer('GET /v1/auth/organizations', ok({ organizations: [{ ...ORG, role }], unreadable: [] }));
  answer('GET /v1/statements', ok(STATEMENTS));
  answer('GET /v1/members', ok({ members: [{ id: MINE, userId: ME, role: 'admin', status: 'ACTIVE' }] }));
  answer(
    'GET /v1/suppliers',
    ok({
      suppliers: [
        { id: SUPPLIER_A, displayName: 'Gulf Traders', status: 'VERIFIED' },
        { id: SUPPLIER_B, displayName: 'Desert Office', status: 'VERIFIED' },
        { id: SUPPLIER_C, displayName: 'Creek Paper', status: 'VERIFIED' },
      ],
      next: null,
      unchecked: [],
    }),
  );
  answer(
    'GET /v1/agents',
    ok({ agents: [{ id: AGENT, name: 'Buyer bot', status: 'ACTIVE' }], next: null, unchecked: [] }),
  );
  answer(
    'GET /v1/funding-sources',
    ok({
      sources: [
        { id: SOURCE, holderName: 'Main account', hint: '…1234', status: 'ACTIVE' },
        { id: OTHER_SOURCE, holderName: 'Spare account', hint: '…5678', status: 'ACTIVE' },
      ],
      next: null,
      unchecked: [],
    }),
  );
  answer('GET /v1/policies/organization', ok(orgPolicy()));
  answer(`GET /v1/mandates/${MANDATE}`, ok(MANDATE_READ));
  answer(`GET /v1/mandates/${MANDATE}/policy`, ok(mandatePolicy()));
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
      sent.push({ method, path, body });
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

const ORG_AT = '/v1/policies/organization';
const MANDATE_AT = `/v1/mandates/${MANDATE}/policy`;
const posts = () => sent.filter((one) => one.method === 'POST');
const sentTo = (path: string) => posts().filter((one) => one.path === path);
const kept = (): unknown => JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');
const press = async (name: string | RegExp) => {
  await userEvent.click(await screen.findByRole('button', { name }));
};
const pick = async (name: string) => {
  await userEvent.click(await screen.findByRole('radio', { name }));
};
const inDialog = async (name: string) => {
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name }));
};
/** Types into the nth amount field shown (in the editor's order: per request, month, threshold). */
const amount = async (nth: number, typed: string) => {
  const field = screen.getAllByLabelText('Amount in AED')[nth];
  if (field === undefined) throw new Error(`No amount field ${String(nth)}`);
  await userEvent.clear(field);
  await userEvent.type(field, typed);
};

/** Makes every organisation choice: a cap of AED 1,500 sent for approval above, AED 8,000 a month, approval above AED 750, any supplier, 24 hours. */
async function chooseAll() {
  await press('Change the rules');
  await pick('A cap on each request');
  await amount(0, '1,500');
  await pick('Sent to a person to approve');
  await pick('A cap each month');
  await amount(1, '8000');
  await pick('Yes, above an amount');
  await amount(2, '750.25');
  await pick("Any supplier an agent's mandate allows");
  await pick('24 hours');
}

const ORG_RULES = {
  currency: 'AED',
  perOrderCap: { capMinor: 150_000, over: 'REQUIRE_APPROVAL' },
  monthlyCapMinor: 800_000,
  approvalThresholdMinor: 75_025,
  supplierIds: null,
  monthlyCapChoice: 'amount',
  approvalWaitHours: 24,
};

describe('the organisation’s policy (6D3b)', () => {
  it('shows every member the rules in force in plain words, who made them, and the wait chosen', async () => {
    as('viewer');
    open('/more/policy');
    expect(await screen.findByRole('heading', { name: 'Organisation policy' })).toBeDefined();
    expect(screen.getByText('Up to AED 1,000.00; above it, refused')).toBeDefined();
    expect(screen.getByText('AED 5,000.00')).toBeDefined();
    expect(screen.getByText('Above AED 500.00')).toBeDefined();
    expect(screen.getByText('No list of its own')).toBeDefined();
    expect(await screen.findByText(/^Version 3, made by Admin \(you\)/)).toBeDefined();
    expect(screen.getByText('Requests wait 48 hours for approval.')).toBeDefined();
    expect(screen.getByText('Only an admin can change these rules.')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Change the rules' })).toBeNull();
  });

  it('is linked from More', async () => {
    as('viewer');
    const history = open('/more');
    await userEvent.click(await screen.findByRole('link', { name: 'Organisation policy' }));
    expect(history.location.pathname).toBe('/more/policy');
  });

  it('says a monthly cap not chosen yet stops every agent, and a wait not chosen is 72 hours for now', async () => {
    as('admin');
    answer(
      `GET ${ORG_AT}`,
      ok(orgPolicy({ monthlyCapChoice: null, approvalWaitHours: null, approvalWaitInForceHours: 72 })),
    );
    open('/more/policy');
    expect(await screen.findByText(/no agent can spend until an admin chooses/)).toBeDefined();
    expect(screen.getByText('Not chosen yet')).toBeDefined();
    expect(screen.getByText(/hasn't been chosen yet: 72 hours for now/)).toBeDefined();
  });

  it('says a cap of none as the organisation chose it, and no rules set at all', async () => {
    as('admin');
    answer(
      `GET ${ORG_AT}`,
      ok(orgPolicy({ monthlyCapChoice: 'none', current: { ...VERSION, monthlyCapMinor: null } })),
    );
    open('/more/policy');
    expect(await screen.findByText('No organisation-wide cap')).toBeDefined();
    cleanup();
    answer(`GET ${ORG_AT}`, ok(orgPolicy({ current: null, monthlyCapChoice: null })));
    open('/more/policy');
    expect(await screen.findByText('No organisation rules have been set yet.')).toBeDefined();
  });

  it('says a policy it can’t read plainly, with a retry', async () => {
    as('admin');
    answer(`GET ${ORG_AT}`, refused(503, 'INTEGRITY_FAILED'));
    open('/more/policy');
    expect(await screen.findByText(/failed Agent X's integrity check/, {}, { timeout: 8000 })).toBeDefined();
    cleanup();
    answer(`GET ${ORG_AT}`, refused(403, 'FORBIDDEN'), ok(orgPolicy()));
    open('/more/policy');
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 8000 }));
    expect(await screen.findByRole('heading', { name: 'Organisation policy' })).toBeDefined();
  });

  it('shows more suppliers to tick on asking', async () => {
    as('admin');
    answer(
      'GET /v1/suppliers',
      ok({
        suppliers: [{ id: SUPPLIER_A, displayName: 'Gulf Traders', status: 'VERIFIED' }],
        next: SUPPLIER_A,
        unchecked: [],
      }),
      ok({
        suppliers: [{ id: SUPPLIER_C, displayName: 'Creek Paper', status: 'VERIFIED' }],
        next: null,
        unchecked: [],
      }),
    );
    open('/more/policy');
    await press('Change the rules');
    await pick('Only the suppliers I tick');
    expect(await screen.findByRole('checkbox', { name: 'Gulf Traders' })).toBeDefined();
    expect(screen.queryByRole('checkbox', { name: 'Creek Paper' })).toBeNull();
    await press('Show more suppliers');
    expect(await screen.findByRole('checkbox', { name: 'Creek Paper' })).toBeDefined();
  });

  it('picks no choice for the admin, and sends nothing until each is made', async () => {
    as('admin');
    open('/more/policy');
    await press('Change the rules');
    for (const radio of screen.getAllByRole<HTMLInputElement>('radio')) expect(radio.checked).toBe(false);
    await press('Check what this changes');
    expect(screen.getByText('Choose whether each request has a cap.')).toBeDefined();
    expect(screen.getByText('Choose whether there is a monthly cap.')).toBeDefined();
    expect(screen.getByText(/Choose whether requests above an amount/)).toBeDefined();
    expect(screen.getByText('Choose which suppliers may be paid.')).toBeDefined();
    expect(screen.getByText('Choose how long requests wait for approval.')).toBeDefined();
    expect(posts()).toHaveLength(0);
  });

  it('fills the amounts with the rules in force to keep or change, never chosen', async () => {
    as('admin');
    open('/more/policy');
    await press('Change the rules');
    await pick('A cap on each request');
    expect(screen.getByLabelText<HTMLInputElement>('Amount in AED').value).toBe('1000.00');
    // The rule for an amount, with an example in the currency's own decimals.
    expect(screen.getByText('Digits only, with no more decimals than AED has, such as 2500.50.')).toBeDefined();
  });

  it('says amounts it can’t read and rules out of order in place, before anything is sent', async () => {
    as('admin');
    open('/more/policy');
    await chooseAll();
    await amount(0, '1500.505');
    await press('Check what this changes');
    expect(screen.getByText(/Enter the cap: an amount above zero/)).toBeDefined();
    await amount(0, '9000');
    await press('Check what this changes');
    expect(screen.getByText("The cap on each request can't be above the monthly cap.")).toBeDefined();
    expect(posts()).toHaveLength(0);
  });

  it('checks the change, then confirms it with the API’s words and goes by passkey, sending exactly the rules chosen', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(NO_WAITING));
    answer(`POST ${ORG_AT}/change`, { status: 202, body: { stepUpChallengeId: CHALLENGE, waiting: NO_WAITING } });
    open('/more/policy');
    await chooseAll();
    await press('Check what this changes');
    expect(await screen.findByText(/No request waiting for approval would be rejected/)).toBeDefined();
    expect(sentTo(`${ORG_AT}/change/preview`)[0]?.body).toStrictEqual(ORG_RULES);

    await press('Continue with passkey');
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Up to AED 1,500.00; above it, a person must approve')).toBeDefined();
    expect(within(dialog).getByText('Requests wait 24 hours for approval.')).toBeDefined();
    expect(await within(dialog).findByText('Each agent may spend at most this amount in its month.')).toBeDefined();
    expect(within(dialog).getByText('Requests asked from now on wait this.')).toBeDefined();
    await inDialog('Continue with passkey');

    expect(sentTo(`${ORG_AT}/change`)[0]?.body).toStrictEqual(ORG_RULES);
    expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    expect(kept()).toMatchObject({
      confirmPath: `${ORG_AT}/change/confirm`,
      body: { ...ORG_RULES, monthlyCapStatementVersion: 1, approvalWaitStatementVersion: 1 },
    });
    expect(kept()).not.toHaveProperty('body.waitingStatementVersion');
  });

  it('sends a monthly cap of none as the choice of none, confirmed in the API’s words for it', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(NO_WAITING));
    answer(`POST ${ORG_AT}/change`, { status: 202, body: { stepUpChallengeId: CHALLENGE, waiting: NO_WAITING } });
    open('/more/policy');
    await chooseAll();
    await pick("No organisation-wide cap: each agent is held only to its mandates' own limits");
    await pick('No cap on each request');
    await pick('No threshold of its own');
    await press('Check what this changes');
    await press('Continue with passkey');
    expect(
      await screen.findByText(/No organisation-wide cap: each agent is held only to its mandates\.$/),
    ).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo(`${ORG_AT}/change`)[0]?.body).toStrictEqual({
      currency: 'AED',
      perOrderCap: null,
      monthlyCapMinor: null,
      approvalThresholdMinor: null,
      supplierIds: null,
      monthlyCapChoice: 'none',
      approvalWaitHours: 24,
    });
  });

  it('sends only the suppliers ticked', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(NO_WAITING));
    open('/more/policy');
    await chooseAll();
    await pick('Only the suppliers I tick');
    await press('Check what this changes');
    expect(screen.getByText('Tick 1 to 100 suppliers.')).toBeDefined();
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Desert Office' }));
    await userEvent.click(screen.getByRole('checkbox', { name: 'Creek Paper' }));
    await userEvent.click(screen.getByRole('checkbox', { name: 'Desert Office' }));
    await press('Check what this changes');
    await screen.findByText(/No request waiting for approval would be rejected/);
    expect(sentTo(`${ORG_AT}/change/preview`)[0]?.body).toMatchObject({ supplierIds: [SUPPLIER_C] });
  });

  it('lists the waiting requests it would reject, and asks what happens to them with none picked', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(WAITING_ONE));
    answer(`POST ${ORG_AT}/change`, { status: 202, body: { stepUpChallengeId: CHALLENGE, waiting: WAITING_ONE } });
    open('/more/policy');
    await chooseAll();
    await press('Check what this changes');
    expect(await screen.findByRole('link', { name: 'Buyer bot' })).toBeDefined();
    expect(screen.getByText('AED 1,500.00')).toBeDefined();
    expect(screen.getByText('Over the cap per request. Raise the cap.')).toBeDefined();
    expect(screen.getByText('Others not listed here would be rejected too.')).toBeDefined();
    const reject = await screen.findByRole<HTMLInputElement>('radio', {
      name: 'Each request listed is rejected at once.',
    });
    expect(reject.checked).toBe(false);

    await press('Continue with passkey');
    expect(screen.getByText('Choose what happens to the waiting requests.')).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();

    await pick('The requests listed keep waiting.');
    await press('Continue with passkey');
    expect(
      await within(await screen.findByRole('dialog')).findByText('The requests listed keep waiting.'),
    ).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo(`${ORG_AT}/change`)[0]?.body).toStrictEqual({ ...ORG_RULES, waitingRequests: 'leave' });
    expect(kept()).toMatchObject({ body: { waitingRequests: 'leave', waitingStatementVersion: 4 } });
  });

  it('shows the waiting requests again when the ask weighed others than the preview, and goes nowhere', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(NO_WAITING));
    answer(`POST ${ORG_AT}/change`, { status: 202, body: { stepUpChallengeId: CHALLENGE, waiting: WAITING_ONE } });
    open('/more/policy');
    await chooseAll();
    await press('Check what this changes');
    await press('Continue with passkey');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/changed since you checked. Read the list again/)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(await screen.findByRole('link', { name: 'Buyer bot' })).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
    expect(kept()).toBeNull();
  });

  it('holds when the ask and the preview each list waiting requests, but not the same ones', async () => {
    const other = {
      rejected: [{ ...WAITING_ONE.rejected[0], id: OTHER_REQUEST, amountMinor: 160_000 }],
      more: false,
    };
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(WAITING_ONE));
    answer(`POST ${ORG_AT}/change`, { status: 202, body: { stepUpChallengeId: CHALLENGE, waiting: other } });
    open('/more/policy');
    await chooseAll();
    await press('Check what this changes');
    await pick('Each request listed is rejected at once.');
    await press('Continue with passkey');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/changed since you checked. Read the list again/)).toBeDefined();
    expect(sentTo(`${ORG_AT}/change`)[0]?.body).toMatchObject({ waitingRequests: 'reject' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(goTo).not.toHaveBeenCalled();
    expect(kept()).toBeNull();
    // The ask's own list is shown, and the choice made for the old one is gone: the admin chooses again.
    expect(await screen.findByText('AED 1,600.00')).toBeDefined();
    expect(screen.queryByText('Others not listed here would be rejected too.')).toBeNull();
    expect(
      screen.getByRole<HTMLInputElement>('radio', { name: 'Each request listed is rejected at once.' }).checked,
    ).toBe(false);
  });

  it('refuses a change the API made with no passkey asked, never saying it done', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(NO_WAITING));
    answer(`POST ${ORG_AT}/change`, ok(orgPolicy()));
    open('/more/policy');
    await chooseAll();
    await press('Check what this changes');
    await press('Continue with passkey');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/answered without asking for your passkey/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('asks to check again when the waiting requests moved before the ask', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(NO_WAITING));
    answer(`POST ${ORG_AT}/change`, refused(409, 'WAITING_CHOICE_REQUIRED'));
    open('/more/policy');
    await chooseAll();
    await press('Check what this changes');
    await press('Continue with passkey');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/Press Check what this changes again/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Continue with passkey' })).toBeNull();
  });

  it('says a preview refused plainly', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, refused(409, 'POLICY_CHANGES_SPENT'));
    open('/more/policy');
    await chooseAll();
    await press('Check what this changes');
    expect(await screen.findByText(/as many times today as Agent X allows/)).toBeDefined();
  });

  it('forgets the check once a rule changes, and everything once cancelled', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(NO_WAITING));
    open('/more/policy');
    await chooseAll();
    await press('Check what this changes');
    await screen.findByText(/No request waiting for approval would be rejected/);
    await pick('48 hours');
    expect(screen.queryByText(/No request waiting for approval would be rejected/)).toBeNull();
    await press('Check what this changes');
    await press('Continue with passkey');
    // Cancelling the confirm sends nothing.
    await inDialog('Cancel');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sentTo(`${ORG_AT}/change`)).toHaveLength(0);
    await press('Cancel');
    await press('Change the rules');
    expect(screen.getByRole<HTMLInputElement>('radio', { name: '48 hours' }).checked).toBe(false);
  });

  it('holds the confirm while the API’s words can’t be read', async () => {
    as('admin');
    answer(`POST ${ORG_AT}/change/preview`, ok(NO_WAITING));
    open('/more/policy');
    await chooseAll();
    answer('GET /v1/statements', refused(500, 'INTERNAL'));
    await press('Check what this changes');
    await press('Continue with passkey');
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(/couldn't load what this change does/, {}, { timeout: 8000 })).toBeDefined();
    expect(within(dialog).getByRole<HTMLButtonElement>('button', { name: 'Continue with passkey' }).disabled).toBe(
      true,
    );
  });
});

/** Makes every mandate choice: a cap of AED 1,000 refused above, AED 5,000 a month, no threshold, only Gulf Traders. */
async function chooseMandate() {
  await press('Change the rules');
  await pick('A cap on each request');
  await amount(0, '1000');
  await pick('Refused');
  await pick('A cap each month');
  await amount(1, '5000');
  await pick('No threshold of its own');
  await pick('Only the suppliers I tick');
  await userEvent.click(await screen.findByRole('checkbox', { name: 'Gulf Traders' }));
}

describe('a mandate’s own policy (6D3b)', () => {
  const page = `/more/mandates/${MANDATE}/policy`;

  it('shows the mandate’s terms it is held within, and that it has no rules of its own', async () => {
    as('viewer');
    open(page);
    expect(await screen.findByRole('heading', { name: "This mandate's own policy" })).toBeDefined();
    expect(await screen.findByText('AED 2,000.00')).toBeDefined();
    expect(screen.getByText('AED 10,000.00')).toBeDefined();
    expect(screen.getByText(/only its terms and the organisation's rules apply/)).toBeDefined();
    expect(await screen.findByText('Gulf Traders')).toBeDefined();
    // A viewer can't try requests: no link to the simulator.
    expect(screen.queryByRole('link', { name: 'Try a request in the simulator' })).toBeNull();
  });

  it('links to the mandate and, for those who may, to the simulator', async () => {
    as('developer');
    const history = open(page);
    await userEvent.click(await screen.findByRole('link', { name: 'Try a request in the simulator' }));
    expect(history.location.pathname).toBe(`/more/mandates/${MANDATE}/simulate`);
    await userEvent.click(await screen.findByRole('link', { name: '← The mandate' }));
    expect(history.location.pathname).toBe(`/more/mandates/${MANDATE}`);
  });

  it('offers only the mandate’s own suppliers, and says a rule past its terms before sending', async () => {
    as('admin');
    open(page);
    await chooseMandate();
    expect(screen.queryByRole('checkbox', { name: 'Creek Paper' })).toBeNull();
    // No wait to choose for a mandate: the organisation's alone.
    expect(screen.queryByRole('radio', { name: '24 hours' })).toBeNull();
    await amount(0, '2000.01');
    await press('Check what this changes');
    expect(screen.getByText(/can't be above the mandate's own limit per request/)).toBeDefined();
    expect(posts()).toHaveLength(0);
  });

  it('changes it by passkey with its rules alone, no organisation choices', async () => {
    as('admin');
    answer(`POST ${MANDATE_AT}/change/preview`, ok(NO_WAITING));
    answer(`POST ${MANDATE_AT}/change`, { status: 202, body: { stepUpChallengeId: CHALLENGE, waiting: NO_WAITING } });
    open(page);
    await chooseMandate();
    await press('Check what this changes');
    await press('Continue with passkey');
    await inDialog('Continue with passkey');
    const rules = {
      currency: 'AED',
      perOrderCap: { capMinor: 100_000, over: 'DENY' },
      monthlyCapMinor: 500_000,
      approvalThresholdMinor: null,
      supplierIds: [SUPPLIER_A],
    };
    expect(sentTo(`${MANDATE_AT}/change/preview`)[0]?.body).toStrictEqual(rules);
    expect(sentTo(`${MANDATE_AT}/change`)[0]?.body).toStrictEqual(rules);
    expect(kept()).toMatchObject({ confirmPath: `${MANDATE_AT}/change/confirm`, body: rules });
  });

  it('says the API’s refusal of a rule past the mandate plainly', async () => {
    as('admin');
    answer(`POST ${MANDATE_AT}/change/preview`, refused(409, 'POLICY_WIDER_THAN_MANDATE'));
    open(page);
    await chooseMandate();
    await press('Check what this changes');
    expect(await screen.findByText(/A rule goes past the mandate's own terms/)).toBeDefined();
  });

  it.each([
    ['an address that is no mandate’s ID', '/more/mandates/not-an-id/policy', undefined],
    ['a mandate the API has none of', page, refused(404, 'NOT_FOUND')],
  ])('says %s plainly', async (_what, path, given) => {
    as('admin');
    if (given !== undefined) answer(`GET ${MANDATE_AT}`, given);
    open(path);
    expect(
      await screen.findByText("This mandate can't be found in this organisation.", {}, { timeout: 8000 }),
    ).toBeDefined();
  });

  it('offers a retry when the mandate’s terms can’t be read, and no editor without them', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, refused(403, 'FORBIDDEN'), ok(MANDATE_READ));
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 8000 }));
    expect(await screen.findByRole('button', { name: 'Change the rules' })).toBeDefined();
  });

  it('says a mandate with no terms has none to hold rules within', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, ok({ ...MANDATE_READ, current: null, pending: null }));
    open(page);
    expect(await screen.findByText('This mandate has no terms to hold rules within yet.')).toBeDefined();
  });

  it.each(['REVOKED', 'EXPIRED'])('says a mandate %s has ended, with no editor and no simulator', async (status) => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, ok({ ...MANDATE_READ, status }));
    open(page);
    expect(await screen.findByText("This mandate has ended, so its rules can't be changed.")).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Change the rules' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Try a request in the simulator' })).toBeNull();
  });

  it('keeps the editor and the draft in it when a re-read of the mandate fails', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, ok(MANDATE_READ), refused(403, 'FORBIDDEN'));
    answer(`POST ${MANDATE_AT}/change/preview`, ok(NO_WAITING));
    open(page);
    await chooseMandate();
    // The check's answer has everything shown read again: the mandate's re-read fails.
    await press('Check what this changes');
    expect(await screen.findByText(/No request waiting for approval would be rejected/)).toBeDefined();
    await vi.waitFor(() => {
      expect(sent.filter((one) => one.method === 'GET' && one.path === `/v1/mandates/${MANDATE}`)).toHaveLength(2);
    });
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
    expect(screen.getByRole<HTMLInputElement>('radio', { name: 'Refused' }).checked).toBe(true);
    expect(screen.getByRole<HTMLInputElement>('checkbox', { name: 'Gulf Traders' }).checked).toBe(true);
    expect(screen.getByText(/No request waiting for approval would be rejected/)).toBeDefined();
  });
});

describe('the simulator (6D3b)', () => {
  const page = `/more/mandates/${MANDATE}/simulate`;
  const SIMULATE_AT = `/v1/mandates/${MANDATE}/policy/simulate`;
  const SIMULATED = {
    decision: 'REQUIRE_APPROVAL',
    reasons: [{ code: 'APPROVAL_THRESHOLD', message: 'Above the approval threshold.' }],
    mandateId: MANDATE,
    versions: { mandate: null, organizationPolicy: null, mandatePolicy: null },
    proposed: { organizationPolicy: false, mandatePolicy: false },
    monthlyCapFrom: 'organization-policy',
    month: '2026-11',
    monthSpentMinor: 12_345,
  };

  async function fillRequest() {
    await userEvent.type(await screen.findByLabelText('Amount in AED'), '1,250.50');
    await screen.findByRole('option', { name: 'Gulf Traders' });
    await userEvent.selectOptions(screen.getByLabelText('Supplier to pay'), SUPPLIER_A);
    await screen.findByRole('option', { name: "Main account · …1234 (this mandate's)" });
    await userEvent.selectOptions(screen.getByLabelText('Bank account to pay from'), SOURCE);
  }

  it('is not offered to a viewer', async () => {
    as('viewer');
    open(page);
    expect(await screen.findByText(/Only an admin, an approver or a developer can use the simulator/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Try it' })).toBeNull();
  });

  it('picks nothing for the person and sends nothing until the request is whole', async () => {
    as('approver');
    open(page);
    await press('Try it');
    expect(screen.getByText('Enter an amount above zero, with no more decimals than the currency has.')).toBeDefined();
    expect(screen.getByText('Choose a supplier.')).toBeDefined();
    expect(screen.getByText('Choose a bank account.')).toBeDefined();
    expect(screen.getByText('Choose which rules weigh it.')).toBeDefined();
    expect(posts()).toHaveLength(0);
  });

  it('tries a request with the rules in force, and says what it would get and that nothing was made', async () => {
    as('developer');
    answer(`POST ${SIMULATE_AT}`, ok(SIMULATED));
    open(page);
    await fillRequest();
    await userEvent.type(screen.getByLabelText('Order number (optional)'), 'PO-77');
    await pick('The rules in force now');
    await press('Try it');
    expect(await screen.findByText('It would wait for a person to approve it.')).toBeDefined();
    expect(sentTo(SIMULATE_AT)[0]?.body).toStrictEqual({
      amountMinor: 125_050,
      currency: 'AED',
      supplierId: SUPPLIER_A,
      fundingSourceId: SOURCE,
      orderReference: 'PO-77',
    });
    expect(screen.getByText('Needs approval')).toBeDefined();
    expect(screen.getByText('Above the approval threshold.')).toBeDefined();
    expect(screen.getByText("From the organisation's rules")).toBeDefined();
    expect(screen.getByText('AED 123.45')).toBeDefined();
    expect(screen.getByText('Weighed with the rules in force now.')).toBeDefined();
    expect(screen.getByText('This was only a test: nothing was made, held or sent.')).toBeDefined();

    // Changing the request takes the answer away: it no longer says what this one would get.
    await userEvent.type(screen.getByLabelText('Amount in AED'), '0');
    expect(screen.queryByText('It would wait for a person to approve it.')).toBeNull();
  });

  it('tries proposed rules for the mandate’s policy, each choice the person’s, and shows them weighed', async () => {
    as('admin');
    answer(
      `POST ${SIMULATE_AT}`,
      ok({ ...SIMULATED, decision: 'DENY', proposed: { organizationPolicy: false, mandatePolicy: true } }),
    );
    open(page);
    await fillRequest();
    await pick("My proposed rules for this mandate's policy");
    await press('Try it');
    expect(screen.getByText('Choose whether each request has a cap.')).toBeDefined();
    expect(posts()).toHaveLength(0);

    await pick('No cap on each request');
    await pick("No cap of its own: the organisation's applies");
    await pick('Yes, above an amount');
    await amount(1, '100');
    await pick('Any supplier the mandate allows');
    await press('Try it');
    expect(await screen.findByText('It would be refused.')).toBeDefined();
    expect(sentTo(SIMULATE_AT)[0]?.body).toStrictEqual({
      amountMinor: 125_050,
      currency: 'AED',
      supplierId: SUPPLIER_A,
      fundingSourceId: SOURCE,
      whatIf: {
        mandatePolicy: {
          currency: 'AED',
          perOrderCap: null,
          monthlyCapMinor: null,
          approvalThresholdMinor: 10_000,
          supplierIds: null,
        },
      },
    });
    expect(screen.getAllByText("Proposed rules for this mandate's policy")).toHaveLength(2);
    expect(screen.getByText('Above AED 100.00')).toBeDefined();
  });

  it('tries proposed rules for both policies', async () => {
    as('admin');
    answer(`POST ${SIMULATE_AT}`, ok({ ...SIMULATED, decision: 'ALLOW', reasons: [] }));
    open(page);
    await fillRequest();
    await pick('My proposed rules for both');
    // The mandate's editor first, then the organisation's: each its own every choice.
    for (const name of ['No cap on each request', 'No threshold of its own']) {
      for (const radio of screen.getAllByRole('radio', { name })) await userEvent.click(radio);
    }
    await pick("No cap of its own: the organisation's applies");
    await pick("No organisation-wide cap: each agent is held only to its mandates' own limits");
    await pick('Any supplier the mandate allows');
    await pick("Any supplier an agent's mandate allows");
    await press('Try it');
    expect(await screen.findByText('It would be allowed, with no one asked.')).toBeDefined();
    const none = {
      currency: 'AED',
      perOrderCap: null,
      monthlyCapMinor: null,
      approvalThresholdMinor: null,
      supplierIds: null,
    };
    expect(sentTo(SIMULATE_AT)[0]?.body).toMatchObject({ whatIf: { organizationPolicy: none, mandatePolicy: none } });
    expect(screen.getByText('No organisation-wide cap')).toBeDefined();
  });

  it('says an order number the API would refuse, and a refusal plainly', async () => {
    as('admin');
    answer(`POST ${SIMULATE_AT}`, refused(409, 'MANDATE_NOT_IN_FORCE'));
    open(page);
    await fillRequest();
    await userEvent.type(screen.getByLabelText('Order number (optional)'), ' PO');
    await pick('The rules in force now');
    await press('Try it');
    expect(screen.getByText(/An order number is 1 to 100 characters/)).toBeDefined();
    expect(posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText('Order number (optional)'));
    await press('Try it');
    expect(await screen.findByText(/isn't the agent's mandate in force/)).toBeDefined();
  });

  it('says a mandate it can’t find plainly', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, refused(404, 'NOT_FOUND'));
    open(page);
    expect(
      await screen.findByText("This mandate can't be found in this organisation.", {}, { timeout: 8000 }),
    ).toBeDefined();
  });

  it('offers a retry when the mandate can’t be read', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, refused(403, 'FORBIDDEN'), ok(MANDATE_READ));
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 8000 }));
    expect(await screen.findByRole('button', { name: 'Try it' })).toBeDefined();
  });

  it('says a mandate with no terms has none to try', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, ok({ ...MANDATE_READ, current: null, pending: null }));
    open(page);
    expect(await screen.findByText('This mandate has no terms to hold rules within yet.')).toBeDefined();
  });

  it('offers nothing to try under a mandate that has ended, and says why', async () => {
    as('admin');
    answer(`GET /v1/mandates/${MANDATE}`, ok({ ...MANDATE_READ, status: 'EXPIRED' }));
    open(page);
    expect(await screen.findByText('This mandate has ended, so there is nothing to try under it.')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Try it' })).toBeNull();
  });

  it.each([
    ['another mandate', OTHER_MANDATE, true],
    ['this mandate, written in capitals', MANDATE.toUpperCase(), false],
  ])('says when the agent’s mandate in force weighed is %s', async (_what, weighed, other) => {
    as('admin');
    answer(`POST ${SIMULATE_AT}`, ok({ ...SIMULATED, mandateId: weighed, monthlyCapFrom: 'mandate-policy' }));
    open(page);
    await fillRequest();
    await pick('The rules in force now');
    await press('Try it');
    expect(await screen.findByText('It would wait for a person to approve it.')).toBeDefined();
    const notice = screen.queryByText(/The agent's mandate in force is another one/);
    if (other) {
      expect(notice).not.toBeNull();
      expect(screen.getByText("From its mandate's own rules")).toBeDefined();
    } else {
      expect(notice).toBeNull();
      expect(screen.getByText("From this mandate's own rules")).toBeDefined();
    }
  });
});

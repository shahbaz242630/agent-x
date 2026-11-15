// 6B2: the brakes in the console, against a stand-in API. Suspending an
// agent (the kill switch), a supplier or a bank account and freezing the
// organisation are one confirm in the API's own words, a choice for pending
// requests none picked for the person, and done at once: never a passkey.
// Reactivating and unfreezing go by the shared step-up, a supplier's and an
// unfreeze's choice asked first and the version of the words shown kept for
// the confirm (CO3). Buttons show by role; refusals are said plainly.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const AGENT = '0199a0f0-0000-7000-8000-0000000000c1';
const TWIN = '0199a0f0-0000-7000-8000-0000000000c2';
const SUPPLIER = '0199a0f0-0000-7000-8000-0000000000d1';
const SOURCE = '0199a0f0-0000-7000-8000-0000000000e1';
const ENDED = '0199a0f0-0000-7000-8000-0000000000e2';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';

const agent = (id: string, status = 'ACTIVE') => ({
  id,
  name: 'Phase 4 demo agent',
  owner: '0199a0f0-0000-7000-8000-000000000011',
  status,
  scopes: ['requests:write'],
  createdAt: '2026-10-26T05:00:00.000Z',
});
const supplier = (status: string) => ({
  id: SUPPLIER,
  status,
  displayName: 'Gulf Office Supplies LLC',
  changeWaiting: false,
  coolingOffUntil: null,
  verifiedBy: null,
});
const source = (id: string, status: string) => ({
  id,
  status,
  holderName: 'Staging Test Org 1 LLC',
  hint: '•••• 4821',
});
const page = (key: string, items: readonly unknown[], extra: Record<string, unknown> = {}) => ({
  status: 200,
  body: { [key]: items, next: null, unchecked: [], ...extra },
});

const words = (cancel: string, pause: string) => [
  { choice: 'cancel', text: cancel },
  { choice: 'pause', text: pause },
];
const STATEMENTS = {
  statements: [
    { id: 'suspend', version: 4, words: words('Every request under it is cancelled now.', 'Its requests are held.') },
    { id: 'reactivate', version: 3, words: words('A fresh start: cancelled now.', 'Un-pause: they stand again.') },
    { id: 'freeze', version: 3, words: words('Every request is cancelled now.', 'Its requests are held as they are.') },
    { id: 'unfreeze', version: 2, words: words('A fresh start for all.', 'Un-pause: the held stand again.') },
  ],
};

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown }[];

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

const as = (role: string, frozen = false) => {
  signedIn([{ ...ORG, role, frozen }]);
};

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
});

function open(path: string) {
  render(
    <App queries={createQueries()} router={createConsoleRouter(createMemoryHistory({ initialEntries: [path] }))} />,
  );
}

const sentTo = (method: string, path: string) => sent.filter((one) => one.method === method && one.path === path);
const kept = (): unknown => JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');

/** Opens the pop-up from a row's button, picks a choice by its words, and confirms. */
async function confirmChoice(button: string, choice: RegExp, confirm: string) {
  await userEvent.click(await screen.findByRole('button', { name: button }));
  const dialog = await screen.findByRole('dialog');
  const go = within(dialog).getByRole('button', { name: confirm });
  // None is picked for the person (decisions 8, 11): Confirm waits for a choice.
  expect(go.hasAttribute('disabled')).toBe(true);
  await userEvent.click(await within(dialog).findByLabelText(choice));
  await userEvent.click(go);
}

describe('the kill switch: suspending an agent (6B2)', () => {
  it('lists the agents with their IDs, and says which are suspended', async () => {
    signedIn();
    answer('GET /v1/agents', page('agents', [agent(AGENT), agent(TWIN, 'SUSPENDED')]));
    open('/agents');
    expect(await screen.findByText(AGENT)).toBeDefined();
    expect(screen.getByText(TWIN)).toBeDefined();
    expect(screen.getByText('Suspended')).toBeDefined();
    expect(screen.getAllByRole('button', { name: 'Suspend Phase 4 demo agent' })).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'Reactivate Phase 4 demo agent' })).toHaveLength(1);
    expect(sentTo('GET', '/v1/agents?limit=50')).toHaveLength(1);
  });

  it('suspends in one confirm with the choice made, at once and with no passkey, and reads the list again', async () => {
    signedIn();
    answer('GET /v1/agents', page('agents', [agent(AGENT)]), page('agents', [agent(AGENT, 'SUSPENDED')]));
    answer(`POST /v1/agents/${AGENT}/suspend`, { status: 200, body: { agent: agent(AGENT, 'SUSPENDED'), keys: [] } });
    open('/agents');

    await confirmChoice('Suspend Phase 4 demo agent', /Its requests are held/, 'Suspend now');

    expect(await screen.findByText('Phase 4 demo agent is suspended.')).toBeDefined();
    expect(sentTo('POST', `/v1/agents/${AGENT}/suspend`)[0]?.body).toEqual({
      pendingRequests: 'pause',
      statementVersion: 4,
    });
    expect(goTo).not.toHaveBeenCalled();
    expect(sessionStorage).toHaveLength(0);
    expect(await screen.findByRole('button', { name: 'Reactivate Phase 4 demo agent' })).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('shows the suspend words afresh, cancel first, and sends nothing when backed out of', async () => {
    signedIn();
    answer('GET /v1/agents', page('agents', [agent(AGENT)]));
    open('/agents');
    await userEvent.click(await screen.findByRole('button', { name: 'Suspend Phase 4 demo agent' }));
    const dialog = await screen.findByRole('dialog');
    const options = await within(dialog).findAllByRole('radio');
    expect(options.map((one) => one.getAttribute('value'))).toEqual(['cancel', 'pause']);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sent.filter((one) => one.method === 'POST')).toHaveLength(0);
  });

  it('lets a developer suspend an agent but not reactivate one', async () => {
    as('developer');
    answer('GET /v1/agents', page('agents', [agent(AGENT), agent(TWIN, 'SUSPENDED')]));
    open('/agents');
    expect(await screen.findByRole('button', { name: 'Suspend Phase 4 demo agent' })).toBeDefined();
    expect(screen.queryByRole('button', { name: /Reactivate/ })).toBeNull();
  });

  it('shows an approver the agents and why there is nothing to press', async () => {
    as('approver');
    answer('GET /v1/agents', page('agents', [agent(AGENT)]));
    open('/agents');
    expect(await screen.findByText(/Only an admin or a developer can suspend an agent/)).toBeDefined();
    expect(screen.queryByRole('button', { name: /Suspend/ })).toBeNull();
  });

  it('reactivates by passkey straight away, keeping the change for the confirm', async () => {
    signedIn();
    answer('GET /v1/agents', page('agents', [agent(AGENT, 'SUSPENDED')]));
    answer(`POST /v1/agents/${AGENT}/reactivate`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    open('/agents');
    await userEvent.click(await screen.findByRole('button', { name: 'Reactivate Phase 4 demo agent' }));
    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    });
    expect(sentTo('POST', `/v1/agents/${AGENT}/reactivate`)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({
      label: 'Reactivate Phase 4 demo agent',
      confirmPath: `/v1/agents/${AGENT}/reactivate/confirm`,
      body: {},
      organization: ORG.id,
    });
  });

  it('says a browser that keeps no storage can’t reactivate, and changes nothing', async () => {
    signedIn();
    answer('GET /v1/agents', page('agents', [agent(AGENT, 'SUSPENDED')]));
    answer(`POST /v1/agents/${AGENT}/reactivate`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError');
    });
    open('/agents');
    await userEvent.click(await screen.findByRole('button', { name: 'Reactivate Phase 4 demo agent' }));
    expect(await screen.findByText(/This browser keeps no site storage/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });

  it.each([
    ['STATEMENT_CHANGED', 409, /The words you confirmed with have changed/],
    ['FORBIDDEN', 403, /Your role in this organisation can't do this/],
    ['SOMETHING_NEW', 409, /didn't make this change \(reason SOMETHING_NEW\)/],
    ['UNREADABLE', 503, /couldn't be reached/],
  ])('says a refused or failed suspend plainly: %s', async (code, status, said) => {
    signedIn();
    answer('GET /v1/agents', page('agents', [agent(AGENT)]));
    answer(`POST /v1/agents/${AGENT}/suspend`, { status, body: { error: { code } } });
    open('/agents');
    await confirmChoice('Suspend Phase 4 demo agent', /Every request under it is cancelled/, 'Suspend now');
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
    // A refusal says it moved on, so the list reads again; a failure on the way does not.
    await waitFor(() => {
      expect(sentTo('GET', '/v1/agents?limit=50')).toHaveLength(status < 500 ? 2 : 1);
    });
  });

  it('goes to sign-in, saying the session ended, when a suspend is answered 401', async () => {
    signedIn();
    answer('GET /v1/agents', page('agents', [agent(AGENT)]));
    answer(`POST /v1/agents/${AGENT}/suspend`, { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } });
    open('/agents');
    await confirmChoice('Suspend Phase 4 demo agent', /Its requests are held/, 'Suspend now');
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });

  it('says when there are no agents, and a list that failed to load, with a retry', async () => {
    signedIn();
    // A refusal isn't retried by itself (a 5xx is, twice), so the retry shows at once.
    answer('GET /v1/agents', { status: 403, body: { error: { code: 'FORBIDDEN' } } }, page('agents', []));
    open('/agents');
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('This organisation has no agents yet.')).toBeDefined();
  });

  it('reads the next page on Show more, and says how many couldn’t be shown', async () => {
    signedIn();
    answer(
      'GET /v1/agents',
      page('agents', [agent(AGENT)], { next: 'cursor-2', unchecked: [TWIN] }),
      page('agents', [agent(TWIN)]),
    );
    open('/agents');
    expect(await screen.findByText(/1 can't be shown/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(await screen.findByText(TWIN)).toBeDefined();
    expect(sent.some((one) => one.path === '/v1/agents?limit=50&after=cursor-2')).toBe(true);
  });
});

describe('suppliers’ and bank accounts’ brakes (6B2)', () => {
  it('suspends a supplier at once with the choice made', async () => {
    signedIn();
    answer('GET /v1/suppliers', page('suppliers', [supplier('VERIFIED')]));
    answer(`POST /v1/suppliers/${SUPPLIER}/suspend`, { status: 200, body: {} });
    open('/more/suppliers');
    expect(await screen.findByText('Verified')).toBeDefined();
    await confirmChoice('Suspend Gulf Office Supplies LLC', /Every request under it is cancelled/, 'Suspend now');
    expect(await screen.findByText('Gulf Office Supplies LLC is suspended.')).toBeDefined();
    expect(sentTo('POST', `/v1/suppliers/${SUPPLIER}/suspend`)[0]?.body).toEqual({
      pendingRequests: 'cancel',
      statementVersion: 4,
    });
    expect(goTo).not.toHaveBeenCalled();
  });

  it('reactivates a supplier with its choice asked first, the words’ version kept for the confirm', async () => {
    signedIn();
    answer('GET /v1/suppliers', page('suppliers', [supplier('SUSPENDED')]));
    answer(`POST /v1/suppliers/${SUPPLIER}/reactivate`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    open('/more/suppliers');
    await confirmChoice('Reactivate Gulf Office Supplies LLC', /Un-pause: they stand again/, 'Continue with passkey');
    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`challenge=${CHALLENGE}`));
    });
    expect(sentTo('POST', `/v1/suppliers/${SUPPLIER}/reactivate`)[0]?.body).toEqual({ pendingRequests: 'pause' });
    expect(kept()).toMatchObject({
      confirmPath: `/v1/suppliers/${SUPPLIER}/reactivate/confirm`,
      body: { pendingRequests: 'pause', statementVersion: 3 },
    });
  });

  it('says a supplier’s un-pause its suspension cancelled can’t stand again', async () => {
    signedIn();
    answer('GET /v1/suppliers', page('suppliers', [supplier('SUSPENDED')]));
    answer(`POST /v1/suppliers/${SUPPLIER}/reactivate`, {
      status: 409,
      body: { error: { code: 'PENDING_REQUESTS_CANCELLED' } },
    });
    open('/more/suppliers');
    await confirmChoice('Reactivate Gulf Office Supplies LLC', /Un-pause/, 'Continue with passkey');
    expect(await screen.findByText(/Choose the option that cancels them instead/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('suspends a bank account, offers nothing for an ended one, and reactivates by passkey', async () => {
    signedIn();
    answer('GET /v1/funding-sources', page('sources', [source(SOURCE, 'ACTIVE'), source(ENDED, 'ENDED')]));
    answer(`POST /v1/funding-sources/${SOURCE}/suspend`, { status: 200, body: {} });
    open('/more/sources');
    expect(await screen.findByText('Ended')).toBeDefined();
    expect(screen.getAllByRole('button', { name: /Suspend|Reactivate/ })).toHaveLength(1);
    await confirmChoice('Suspend Staging Test Org 1 LLC', /Its requests are held/, 'Suspend now');
    expect(await screen.findByText('Staging Test Org 1 LLC is suspended.')).toBeDefined();
    expect(sentTo('POST', `/v1/funding-sources/${SOURCE}/suspend`)[0]?.body).toEqual({
      pendingRequests: 'pause',
      statementVersion: 4,
    });
    expect(goTo).not.toHaveBeenCalled();
    expect(sessionStorage).toHaveLength(0);
  });

  it('never says a brake done when the API asks a passkey for it, and never steps up for one', async () => {
    signedIn();
    answer('GET /v1/funding-sources', page('sources', [source(SOURCE, 'ACTIVE')]));
    answer(`POST /v1/funding-sources/${SOURCE}/suspend`, { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    open('/more/sources');
    await confirmChoice('Suspend Staging Test Org 1 LLC', /Its requests are held/, 'Suspend now');
    expect(await screen.findByText(/asked for a passkey for this brake/)).toBeDefined();
    expect(screen.queryByText(/is suspended\./)).toBeNull();
    expect(goTo).not.toHaveBeenCalled();
    expect(sessionStorage).toHaveLength(0);
  });

  it('lets an approver suspend a supplier, and shows a viewer why there is nothing to press', async () => {
    as('viewer');
    answer('GET /v1/suppliers', page('suppliers', [supplier('VERIFIED')]));
    open('/more/suppliers');
    expect(await screen.findByText(/Only an admin or an approver can suspend a supplier/)).toBeDefined();
    expect(screen.queryByRole('button', { name: /Suspend/ })).toBeNull();
  });

  it('reaches both lists from More', async () => {
    signedIn();
    open('/more');
    expect(await screen.findByRole('link', { name: 'Suppliers' })).toBeDefined();
    expect(screen.getByRole('link', { name: 'Bank accounts' }).getAttribute('href')).toBe('/more/sources');
  });
});

describe('freezing the organisation (6B2, decisions 10, 11 and 14)', () => {
  it('freezes in one confirm, cancel first, at once and with no passkey, and says it is frozen', async () => {
    signedIn();
    answer(
      'GET /v1/auth/organizations',
      { status: 200, body: { organizations: [ORG], unreadable: [] } },
      { status: 200, body: { organizations: [{ ...ORG, frozen: true }], unreadable: [] } },
    );
    answer('POST /v1/organization/freeze', { status: 200, body: { organization: { id: ORG.id, status: 'FROZEN' } } });
    open('/more');
    await userEvent.click(await screen.findByRole('button', { name: 'Freeze organisation' }));
    const options = await within(await screen.findByRole('dialog')).findAllByRole('radio');
    expect(options.map((one) => one.getAttribute('value'))).toEqual(['cancel', 'pause']);
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }));

    await confirmChoice('Freeze organisation', /Every request is cancelled now/, 'Freeze now');

    expect(await screen.findByText('Frozen. No agent can spend until an admin unfreezes it.')).toBeDefined();
    expect(sentTo('POST', '/v1/organization/freeze')[0]?.body).toEqual({
      pendingRequests: 'cancel',
      confirmed: true,
      statementVersion: 3,
    });
    expect(goTo).not.toHaveBeenCalled();
    expect(await screen.findByText(/This organisation is frozen/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Unfreeze organisation' })).toBeDefined();
  });

  it('unfreezes by passkey only with a reason, its choice asked first and the words’ version kept', async () => {
    as('admin', true);
    answer('POST /v1/organization/unfreeze', { status: 202, body: { stepUpChallengeId: CHALLENGE } });
    open('/more');
    await userEvent.click(await screen.findByRole('button', { name: 'Unfreeze organisation' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(await within(dialog).findByLabelText(/Un-pause: the held stand again/));
    const go = within(dialog).getByRole('button', { name: 'Continue with passkey' });
    expect(go.hasAttribute('disabled')).toBe(true);
    const reason = within(dialog).getByLabelText('Why are you unfreezing it?');
    // One line of up to 200 characters, as the API keeps it.
    expect(reason.getAttribute('maxlength')).toBe('200');
    expect(reason.tagName).toBe('INPUT');
    await userEvent.type(reason, '  Alert checked: a test.  ');
    await userEvent.click(go);
    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`challenge=${CHALLENGE}`));
    });
    expect(sentTo('POST', '/v1/organization/unfreeze')[0]?.body).toEqual({
      reason: 'Alert checked: a test.',
      pendingRequests: 'pause',
    });
    expect(kept()).toMatchObject({
      label: 'Unfreeze Staging-Test-Org-1',
      confirmPath: '/v1/organization/unfreeze/confirm',
      body: { reason: 'Alert checked: a test.', pendingRequests: 'pause', statementVersion: 2 },
    });
  });

  it('says plainly a reason the API can’t keep, changing nothing', async () => {
    as('admin', true);
    answer('POST /v1/organization/unfreeze', { status: 400, body: { error: { code: 'BAD_REQUEST' } } });
    open('/more');
    await userEvent.click(await screen.findByRole('button', { name: 'Unfreeze organisation' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(await within(dialog).findByLabelText(/A fresh start for all/));
    await userEvent.type(within(dialog).getByLabelText('Why are you unfreezing it?'), 'Call 050 123 4567');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));
    expect(await screen.findByText(/no phone or account numbers/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('lets only an admin unfreeze, and a viewer not freeze', async () => {
    as('approver', true);
    open('/more');
    expect(await screen.findByText('Only an admin can unfreeze the organisation.')).toBeDefined();
    expect(screen.queryByRole('button', { name: /freeze/i })).toBeNull();
    cleanup();
    as('viewer');
    open('/more');
    expect(await screen.findByText('Only an admin or an approver can freeze the organisation.')).toBeDefined();
    expect(screen.queryByRole('button', { name: /freeze/i })).toBeNull();
  });
});

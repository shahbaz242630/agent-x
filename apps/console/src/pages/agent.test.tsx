// 6D1: an agent's page and the Agents tab's register, against a stand-in API.
// The page shows the agent, its owner and its keys (never a secret); rotating
// asks the old key's fate in the API's `old_key` words (none picked) and goes
// by passkey with the version of the words kept for the confirm; revoking says
// the agent stops with that key at once; an admin hands an agent only to
// another active admin or developer; registering checks the API's rules
// before sending. Buttons show by role; refusals are said plainly.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const AGENT = '0199a0f0-0000-7000-8000-0000000000c1';
const LIVE = '0199a0f0-0000-7000-8000-0000000000f1';
const REVOKED = '0199a0f0-0000-7000-8000-0000000000f2';
const EXPIRED = '0199a0f0-0000-7000-8000-0000000000f3';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const MINE = '0199a0f0-0000-7000-8000-0000000000b1';
const DEVELOPER = '0199a0f0-0000-7000-8000-0000000000b2';
const APPROVER = '0199a0f0-0000-7000-8000-0000000000b3';
const GONE = '0199a0f0-0000-7000-8000-0000000000b4';

const member = (id: string, userId: string, role: string, status = 'ACTIVE') => ({
  id,
  userId,
  role,
  status,
  joinedAt: '2026-10-01T05:00:00.000Z',
});
const MEMBERS = [
  member(MINE, ME, 'admin'),
  member(DEVELOPER, '0199a0f0-0000-7000-8000-000000000022', 'developer'),
  member(APPROVER, '0199a0f0-0000-7000-8000-000000000033', 'approver'),
  member(GONE, '0199a0f0-0000-7000-8000-000000000044', 'developer', 'DEACTIVATED'),
];
const agent = (owner = MINE) => ({
  id: AGENT,
  name: 'Invoice agent',
  owner,
  status: 'ACTIVE',
  scopes: ['requests:write', 'suppliers:read'],
  createdAt: '2026-10-26T05:00:00.000Z',
});
const key = (id: string, status: string, expiresAt: string) => ({
  id,
  status,
  scopes: ['requests:write'],
  expiresAt,
});
const KEYS = [
  key(LIVE, 'ACTIVE', '2099-01-01T00:00:00.000Z'),
  key(REVOKED, 'REVOKED', '2099-01-01T00:00:00.000Z'),
  key(EXPIRED, 'ACTIVE', '2020-01-01T00:00:00.000Z'),
];
const STATEMENTS = {
  statements: [
    {
      id: 'old_key',
      version: 1,
      words: [
        { choice: 'overlap', text: 'The old key keeps working for 24 hours.' },
        { choice: 'end_now', text: 'The old key stops at once.' },
      ],
    },
  ],
};

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown }[];

/** Answers `method path` with these in turn, the last one again after. */
const answer = (at: string, ...given: Answer[]) => answers.set(at, given);
const ASKED = { status: 202, body: { stepUpChallengeId: CHALLENGE } };

function as(
  role: string,
  { owner = MINE, keys = KEYS, connections = [] }: { owner?: string; keys?: unknown[]; connections?: unknown[] } = {},
) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: {
      userId: ME,
      authenticatedAt: '2026-10-26T05:00:00.000Z',
      methods: ['pwd', 'user', 'mfa'],
      idleExpiresAt: '2026-10-26T05:30:00.000Z',
      expiresAt: '2026-10-26T17:00:00.000Z',
    },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
  answer('GET /v1/statements', { status: 200, body: STATEMENTS });
  answer('GET /v1/members', { status: 200, body: { members: MEMBERS } });
  answer(`GET /v1/agents/${AGENT}`, { status: 200, body: { agent: agent(owner), keys } });
  answer(`GET /v1/agents/${AGENT}/connections`, { status: 200, body: { connections } });
  answer('GET /v1/agents', { status: 200, body: { agents: [agent(owner)], next: null, unchecked: [] } });
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
  const history = createMemoryHistory({ initialEntries: [path] });
  render(<App queries={createQueries()} router={createConsoleRouter(history)} />);
  return history;
}

const sentTo = (method: string, path: string) => sent.filter((one) => one.method === method && one.path === path);
const kept = (): unknown => JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');
const page = `/agents/${AGENT}`;
const keyAt = `/v1/agents/${AGENT}/keys/${LIVE}`;

describe('an agent’s page (6D1)', () => {
  it('shows the agent, who is responsible, what it may do and its keys, never a secret', async () => {
    as('admin');
    open(page);

    expect(await screen.findByRole('heading', { name: 'Invoice agent' })).toBeDefined();
    expect(screen.getAllByText(AGENT).length).toBeGreaterThan(0);
    expect(await screen.findByText('Admin (you)')).toBeDefined();
    expect(screen.getAllByText('Ask to pay suppliers').length).toBeGreaterThan(0);
    expect(screen.getByText("See your organisation's suppliers")).toBeDefined();
    expect(screen.getByText(LIVE)).toBeDefined();
    expect(screen.getByText(/^Works until/)).toBeDefined();
    expect(screen.getByText('Revoked')).toBeDefined();
    expect(screen.getByText(/^Expired/)).toBeDefined();
    // Only the live key can be changed: a revoked or expired one has no button.
    expect(screen.getAllByRole('button', { name: /^Rotate key/ })).toHaveLength(1);
    expect(screen.getByRole('button', { name: `Rotate key ${LIVE}` })).toBeDefined();
    expect(screen.getByRole('button', { name: `Revoke key ${LIVE}` })).toBeDefined();
    expect(sentTo('GET', `/v1/agents/${AGENT}`)).toHaveLength(1);
    expect(screen.queryByText(/axk_/)).toBeNull();
  });

  it('opens from the agent’s row on the Agents tab', async () => {
    as('admin');
    const history = open('/agents');

    await userEvent.click(await screen.findByRole('link', { name: 'Invoice agent' }));

    expect(await screen.findByRole('heading', { name: 'Invoice agent' })).toBeDefined();
    expect(history.location.pathname).toBe(page);
  });

  it('says an agent with no keys has none', async () => {
    as('admin', { keys: [] });
    open(page);
    expect(await screen.findByText('This agent has no keys.')).toBeDefined();
  });

  it('names an owner it can’t find among the members plainly, and offers no hand-over without them', async () => {
    as('admin');
    answer('GET /v1/members', { status: 500, body: { error: { code: 'UNAVAILABLE' } } });
    open(page);
    expect(await screen.findByRole('heading', { name: 'Invoice agent' })).toBeDefined();
    expect(screen.getByText('A member')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Hand over' })).toBeNull();
  });

  it.each([
    ['an address that is no agent’s ID', '/agents/not-an-id', undefined, /can't be found in this organisation/],
    ['an agent the API has none of', page, { status: 404, body: { error: { code: 'NOT_FOUND' } } }, /can't be found/],
    [
      'an agent whose records failed',
      page,
      { status: 503, body: { error: { code: 'INTEGRITY_FAILED' } } },
      /integrity/,
    ],
  ])('says %s plainly', { timeout: 10_000 }, async (_what, path, given, said) => {
    as('admin');
    if (given !== undefined) answer(`GET /v1/agents/${AGENT}`, given);
    open(path);
    // A 503 is read again twice before it is said (the queries' retry).
    expect(await screen.findByText(said, {}, { timeout: 8000 })).toBeDefined();
    expect(screen.getByRole('link', { name: 'Back to agents' })).toBeDefined();
  });

  it('offers to try again after a read that failed', async () => {
    as('admin');
    answer(
      `GET /v1/agents/${AGENT}`,
      { status: 403, body: { error: { code: 'FORBIDDEN' } } },
      { status: 200, body: { agent: agent(), keys: KEYS } },
    );
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: 'Invoice agent' })).toBeDefined();
  });
});

describe('rotating and revoking a key (6D1)', () => {
  it('rotates with the old key’s fate chosen in the API’s words, none picked, then the passkey', async () => {
    as('admin');
    answer(`POST ${keyAt}/rotate`, ASKED);
    open(page);

    await userEvent.click(await screen.findByRole('button', { name: `Rotate key ${LIVE}` }));
    const dialog = await screen.findByRole('dialog');
    const go = within(dialog).getByRole('button', { name: 'Continue with passkey' });
    const options = await within(dialog).findAllByRole('radio');
    expect(options.map((one) => one.getAttribute('value'))).toEqual(['overlap', 'end_now']);
    expect(go.hasAttribute('disabled')).toBe(true);
    await userEvent.click(within(dialog).getByLabelText('The old key stops at once.'));
    await userEvent.click(go);

    expect(sentTo('POST', `${keyAt}/rotate`)[0]?.body).toEqual({ oldKey: 'end_now' });
    expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    expect(kept()).toMatchObject({
      label: `Rotate key ${LIVE} of Invoice agent`,
      confirmPath: `${keyAt}/rotate/confirm`,
      body: { oldKey: 'end_now', statementVersion: 1 },
      organization: ORG.id,
    });
  });

  it('revokes after saying the agent stops working with that key at once, then the passkey', async () => {
    as('admin');
    answer(`POST ${keyAt}/revoke`, ASKED);
    open(page);

    await userEvent.click(await screen.findByRole('button', { name: `Revoke key ${LIVE}` }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/The agent stops working with this key at once/)).toBeDefined();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));

    expect(sentTo('POST', `${keyAt}/revoke`)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({ confirmPath: `${keyAt}/revoke/confirm`, body: {} });
    expect(goTo).toHaveBeenCalledOnce();
  });

  it('sends nothing when the confirm is backed out of', async () => {
    as('admin');
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: `Revoke key ${LIVE}` }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sent.filter((one) => one.method === 'POST')).toHaveLength(0);
  });

  it.each([
    ['AGENT_KEYS_FULL', 409, /still in its 24-hour overlap/],
    ['AGENT_KEY_NOT_LIVE', 409, /revoked or has expired/],
    ['SOMETHING_NEW', 409, /reason SOMETHING_NEW/],
    ['INTEGRITY_FAILED', 503, /failed Agent X's integrity check/],
    ['UNAVAILABLE', 500, /couldn't be reached/],
  ])('says a rotation refused or failed with %s plainly, and reads the agent again', async (code, status, said) => {
    as('admin');
    answer(`POST ${keyAt}/rotate`, { status, body: { error: { code } } });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: `Rotate key ${LIVE}` }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(await within(dialog).findByLabelText('The old key keeps working for 24 hours.'));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));

    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(goTo).not.toHaveBeenCalled();
    if (status < 500) expect(sentTo('GET', `/v1/agents/${AGENT}`).length).toBeGreaterThan(1);
  });

  it('refuses a change answered with no passkey asked, as nothing (and no key) was made', async () => {
    as('admin');
    answer(`POST ${keyAt}/revoke`, { status: 200, body: { agent: agent(), keys: KEYS } });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: `Revoke key ${LIVE}` }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(await screen.findByText(/answered without asking for your passkey/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('goes to the sign-in page when the session ended', async () => {
    as('admin');
    answer(`POST ${keyAt}/revoke`, { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: `Revoke key ${LIVE}` }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });

  it('lets a developer revoke any agent’s key, and rotate only their own agent’s', async () => {
    as('developer', { owner: DEVELOPER });
    open(page);
    expect(await screen.findByRole('button', { name: `Revoke key ${LIVE}` })).toBeDefined();
    // The members read in (the owner named by role), so a hand-over would be drawn by now.
    expect(await screen.findByText('Developer')).toBeDefined();
    expect(screen.queryByRole('button', { name: /^Rotate key/ })).toBeNull();
    expect(screen.queryByLabelText('Hand it to')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Hand over' })).toBeNull();
    cleanup();

    as('developer', { owner: MINE });
    open(page);
    expect(await screen.findByRole('button', { name: `Rotate key ${LIVE}` })).toBeDefined();
  });

  it.each(['approver', 'viewer'])('shows an %s the keys and why there is nothing to press', async (role) => {
    as(role);
    open(page);
    expect(await screen.findByText(/Only an admin or a developer can rotate or revoke a key/)).toBeDefined();
    expect(screen.queryByRole('button', { name: /^(Rotate|Revoke) key/ })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Hand over' })).toBeNull();
  });
});

describe('handing an agent over (6D1)', () => {
  it('offers only the other active admins and developers, and hands over by passkey', async () => {
    as('admin');
    answer(`POST /v1/agents/${AGENT}/owner`, ASKED);
    open(page);

    const choose = await screen.findByLabelText('Hand it to');
    const offered = within(choose)
      .getAllByRole('option')
      .map((one) => one.getAttribute('value'));
    expect(offered).toEqual(['', DEVELOPER]);
    const button = screen.getByRole('button', { name: 'Hand over' });
    expect(button.hasAttribute('disabled')).toBe(true);
    await userEvent.selectOptions(choose, DEVELOPER);
    await userEvent.click(button);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/Every key it has stops at once/)).toBeDefined();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));

    expect(sentTo('POST', `/v1/agents/${AGENT}/owner`)[0]?.body).toEqual({ owner: DEVELOPER });
    expect(kept()).toMatchObject({
      label: 'Hand Invoice agent to a new responsible person',
      confirmPath: `/v1/agents/${AGENT}/owner/confirm`,
      body: { owner: DEVELOPER },
    });
  });

  it('says when no one else can take it over', async () => {
    as('admin', { owner: DEVELOPER });
    answer('GET /v1/members', { status: 200, body: { members: [MEMBERS[0], MEMBERS[1]] } });
    answer(`GET /v1/agents/${AGENT}`, { status: 200, body: { agent: agent(DEVELOPER), keys: KEYS } });
    open(page);
    // The admin themself can take it over from the developer.
    const offered = within(await screen.findByLabelText('Hand it to')).getAllByRole('option');
    expect(offered.map((one) => one.textContent)).toContain(`Admin (you) · ${MINE}`);
    cleanup();

    as('admin');
    answer('GET /v1/members', { status: 200, body: { members: [MEMBERS[0]] } });
    open(page);
    expect(await screen.findByText('No other admin or developer can take it over.')).toBeDefined();
  });

  it('says a hand-over refused plainly', async () => {
    as('admin');
    answer(`POST /v1/agents/${AGENT}/owner`, { status: 409, body: { error: { code: 'AGENT_OWNER_NOT_ELIGIBLE' } } });
    open(page);
    await userEvent.selectOptions(await screen.findByLabelText('Hand it to'), DEVELOPER);
    await userEvent.click(screen.getByRole('button', { name: 'Hand over' }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(await screen.findByText(/only an active admin or developer can/)).toBeDefined();
  });
});

describe('registering an agent (6D1)', () => {
  async function fill(name: string, scopes: readonly string[]) {
    await userEvent.click(await screen.findByRole('button', { name: 'Register an agent' }));
    if (name !== '') await userEvent.type(screen.getByLabelText('Its name'), name);
    for (const scope of scopes) await userEvent.click(screen.getByLabelText(scope));
    await userEvent.click(screen.getByRole('button', { name: 'Register' }));
  }

  it('registers with the name and the scopes ticked, in the API’s order, then the passkey', async () => {
    as('developer');
    answer('POST /v1/agents', ASKED);
    open('/agents');

    await fill('Payables bot', ["See your organisation's suppliers", 'Ask to pay suppliers']);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/makes its first key/)).toBeDefined();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));

    const body = { name: 'Payables bot', scopes: ['requests:write', 'suppliers:read'] };
    expect(sentTo('POST', '/v1/agents')[0]?.body).toEqual(body);
    expect(kept()).toMatchObject({ label: 'Register the agent Payables bot', confirmPath: '/v1/agents/confirm', body });
    expect(goTo).toHaveBeenCalledOnce();
  });

  it('ticks nothing for the person, and says in place what the API would refuse before sending', async () => {
    as('admin');
    open('/agents');
    await fill('', []);
    expect(await screen.findByText(/This name can't be used/)).toBeDefined();

    await userEvent.type(screen.getByLabelText('Its name'), ' padded');
    await userEvent.click(screen.getByRole('button', { name: 'Register' }));
    expect(screen.getByText(/This name can't be used/)).toBeDefined();

    await userEvent.clear(screen.getByLabelText('Its name'));
    await userEvent.type(screen.getByLabelText('Its name'), 'Payables bot');
    expect(screen.queryByText(/This name can't be used/)).toBeNull();
    expect(screen.getAllByRole('checkbox').every((box) => !(box as HTMLInputElement).checked)).toBe(true);
    await userEvent.click(screen.getByRole('button', { name: 'Register' }));
    expect(screen.getByText('Tick at least one thing it may do.')).toBeDefined();

    // Ticked and unticked again: still none.
    await userEvent.click(screen.getByLabelText('See its own payment requests'));
    expect(screen.queryByText('Tick at least one thing it may do.')).toBeNull();
    await userEvent.click(screen.getByLabelText('See its own payment requests'));
    await userEvent.click(screen.getByRole('button', { name: 'Register' }));
    expect(screen.getByText('Tick at least one thing it may do.')).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sent.filter((one) => one.method === 'POST')).toHaveLength(0);
  });

  it('closes the form and the confirm without sending anything', async () => {
    as('admin');
    open('/agents');
    await fill('Payables bot', ['Ask to pay suppliers']);
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByLabelText('Its name')).toBeNull();
    expect(screen.getByRole('button', { name: 'Register an agent' })).toBeDefined();
    expect(sent.filter((one) => one.method === 'POST')).toHaveLength(0);
  });

  it('says a registration refused plainly', async () => {
    as('admin');
    answer('POST /v1/agents', { status: 409, body: { error: { code: 'AGENT_ADDS_SPENT' } } });
    open('/agents');
    await fill('Payables bot', ['Ask to pay suppliers']);
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(await screen.findByText(/registered as many agents today/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('takes a valid name of 100 characters beyond the basic plane, counting characters as the API does', async () => {
    as('admin');
    answer('POST /v1/agents', ASKED);
    open('/agents');
    const name = String.fromCodePoint(0x1d400).repeat(100);
    await userEvent.click(await screen.findByRole('button', { name: 'Register an agent' }));
    const field = screen.getByLabelText('Its name');
    expect(field.getAttribute('maxLength')).toBe('200');
    // Pasted in one go: 200 UTF-16 units, within the field's limit.
    fireEvent.change(field, { target: { value: name } });
    await userEvent.click(screen.getByLabelText('Ask to pay suppliers'));
    await userEvent.click(screen.getByRole('button', { name: 'Register' }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(sentTo('POST', '/v1/agents')[0]?.body).toEqual({ name, scopes: ['requests:write'] });
  });

  it.each(['approver', 'viewer'])('offers an %s no register', async (role) => {
    as(role);
    open('/agents');
    expect(await screen.findByRole('link', { name: 'Invoice agent' })).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Register an agent' })).toBeNull();
  });
});

describe('an agent’s connected apps (6E3b)', () => {
  const connection = (keyId: string, status: string, more: Record<string, unknown> = {}) => ({
    keyId,
    clientId: 'axcl_0123456789abcdef0123456789abcdef',
    clientName: 'Claude Desktop',
    redirectHost: '127.0.0.1:33418',
    via: 'code',
    scopes: ['requests:read'],
    madeBy: MINE,
    createdAt: '2026-11-01T05:00:00.000Z',
    expiresAt: '2099-01-01T00:00:00.000Z',
    lastConnectedAt: '2026-11-02T05:00:00.000Z',
    status,
    ...more,
  });
  const CONNECTIONS = [
    connection(LIVE, 'ACTIVE'),
    connection(REVOKED, 'REVOKED', { clientName: 'Old app', redirectHost: 'old.example.test', madeBy: DEVELOPER }),
    connection(EXPIRED, 'EXPIRED', {
      clientName: 'Device app',
      redirectHost: null,
      via: 'device',
      lastConnectedAt: null,
      expiresAt: '2020-01-01T00:00:00.000Z',
    }),
  ];
  const revokeAt = `/v1/agents/${AGENT}/connections/${LIVE}/revoke`;

  it('lists each app by what it says, its host in bold, who allowed it, and where it stands', async () => {
    as('admin', { connections: CONNECTIONS });
    open(page);
    expect(await screen.findByRole('heading', { name: 'Connected apps' })).toBeDefined();
    expect((await screen.findByText('127.0.0.1:33418')).tagName).toBe('STRONG');
    expect(screen.getAllByText(/^Allowed .* by Admin \(you\)$/)).toHaveLength(2);
    expect(screen.getByText(/^Allowed .* by Developer$/)).toBeDefined();
    expect(screen.getAllByText(/^Last connected/)).toHaveLength(2);
    expect(screen.getByText('Not connected yet')).toBeDefined();
    expect(screen.getByText('Connected from a device')).toBeDefined();
    expect(screen.getAllByText(/^Revoked$/).length).toBeGreaterThan(1);
    expect(screen.getAllByText(/^Expired/).length).toBeGreaterThan(1);
    // Only the live one can be revoked.
    expect(screen.getAllByRole('button', { name: /^Revoke the connection of/ })).toHaveLength(1);
    expect(sentTo('GET', `/v1/agents/${AGENT}/connections`)).toHaveLength(1);
  });

  it('says an agent with no connected app has none', async () => {
    as('admin');
    open(page);
    expect(await screen.findByText('No app is connected to this agent.')).toBeDefined();
  });

  it('revokes after saying the app stops at once, then the passkey', async () => {
    as('admin', { connections: CONNECTIONS });
    answer(`POST ${revokeAt}`, ASKED);
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke the connection of Claude Desktop' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/The app stops working as this agent at once/)).toBeDefined();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue with passkey' }));

    expect(sentTo('POST', revokeAt)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({
      label: 'Revoke the connection of Claude Desktop to Invoice agent',
      confirmPath: `${revokeAt}/confirm`,
      body: {},
      organization: ORG.id,
    });
    expect(goTo).toHaveBeenCalledOnce();
  });

  it('says a connection already revoked plainly, and reads them again', async () => {
    as('admin', { connections: CONNECTIONS });
    answer(`POST ${revokeAt}`, { status: 409, body: { error: { code: 'CONNECTION_REVOKED' } } });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke the connection of Claude Desktop' }));
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue with passkey' }),
    );
    expect(await screen.findByText('This connection is already revoked. Nothing was changed.')).toBeDefined();
    expect(sentTo('GET', `/v1/agents/${AGENT}/connections`).length).toBeGreaterThan(1);
    expect(goTo).not.toHaveBeenCalled();
  });

  it('shows an approver the apps and why there is nothing to press', async () => {
    as('approver', { connections: CONNECTIONS });
    open(page);
    expect(await screen.findByText(/Only an admin can revoke a connection/)).toBeDefined();
    expect(screen.queryByRole('button', { name: /^Revoke the connection of/ })).toBeNull();
  });

  it('lets a developer revoke only on an agent they are responsible for', async () => {
    as('developer', { owner: DEVELOPER, connections: CONNECTIONS });
    open(page);
    expect(await screen.findByText(/a developer on an agent they are responsible for/)).toBeDefined();
    // The members read in (the owner named by role), so the rule is decided by now.
    expect(await screen.findByText('Developer')).toBeDefined();
    expect(screen.queryByRole('button', { name: /^Revoke the connection of/ })).toBeNull();
    cleanup();

    as('developer', { owner: MINE, connections: CONNECTIONS });
    open(page);
    expect(await screen.findByRole('button', { name: 'Revoke the connection of Claude Desktop' })).toBeDefined();
  });

  it('offers to read the apps again when they couldn’t be read', async () => {
    as('admin');
    answer(
      `GET /v1/agents/${AGENT}/connections`,
      { status: 403, body: { error: { code: 'FORBIDDEN' } } },
      { status: 200, body: { connections: CONNECTIONS } },
    );
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('button', { name: 'Revoke the connection of Claude Desktop' })).toBeDefined();
  });
});

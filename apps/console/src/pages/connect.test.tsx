// 6E3b: the `/connect` page an MCP app's authorize sends the browser to,
// against a stand-in API. The app is named by what it says it is, the host it
// sends the person back to in bold, warned of as this computer's or as a
// website Agent X doesn't know; the organisation and agent are picked (a
// developer's own agents alone), the ticks limited to what was asked and the
// agent holds, a write scope never ticked for the person. Allow goes by the
// shared step-up and comes back to confirm with the choices kept; the confirm
// sends the browser back to the app, once. Deny tells the app no. 6E3c: an
// app named by its metadata document is shown as verified by its host; a
// device's request has no address to go back to, is warned of as a device,
// and once answered goes back to `/device`.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ME = '0199a0f0-0000-7000-8000-000000000011';
const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const OTHER = {
  id: '0199a0f0-0000-7000-8000-00000000bbbb',
  name: 'Staging-Test-Org-2',
  role: 'developer',
  frozen: false,
};
const VIEWING = {
  id: '0199a0f0-0000-7000-8000-00000000cccc',
  name: 'Staging-Test-Org-3',
  role: 'viewer',
  frozen: false,
};
const REQ = '0199a0f0-0000-7000-8000-0000000000e1';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const MINE = '0199a0f0-0000-7000-8000-0000000000b1';
const THEIRS = '0199a0f0-0000-7000-8000-0000000000b2';
const AGENT = '0199a0f0-0000-7000-8000-0000000000c1';
const OTHER_AGENT = '0199a0f0-0000-7000-8000-0000000000c2';
const SUSPENDED = '0199a0f0-0000-7000-8000-0000000000c3';
const page = `/connect?request=${REQ}`;
const at = `/v1/oauth/requests/${REQ}`;
const BACK = 'http://127.0.0.1:33418/callback?code=axc_x&state=s&iss=https%3A%2F%2Fagentx.test';

const request = (loopback = true) => ({
  id: REQ,
  via: 'code',
  client: { id: 'axcl_0123456789abcdef0123456789abcdef', name: 'Claude Desktop', verifiedBy: null },
  redirectUri: loopback ? 'http://127.0.0.1:33418/callback' : 'https://app.example.test/callback',
  redirectHost: loopback ? '127.0.0.1:33418' : 'app.example.test',
  loopback,
  scopesAsked: ['requests:read', 'requests:write', 'suppliers:read'],
  resource: 'https://agentx.test/v1/mcp',
  endsAt: '2099-01-01T00:00:00.000Z',
});
const agent = (id: string, name: string, owner: string, status = 'ACTIVE') => ({
  id,
  name,
  owner,
  status,
  scopes: ['requests:read', 'requests:write', 'sources:read'],
  createdAt: '2026-10-26T05:00:00.000Z',
});
const AGENTS = [
  agent(AGENT, 'Invoice agent', MINE),
  agent(OTHER_AGENT, 'Their agent', THEIRS),
  agent(SUSPENDED, 'Stopped agent', MINE, 'SUSPENDED'),
];
const member = (id: string, userId: string, role: string) => ({
  id,
  userId,
  role,
  status: 'ACTIVE',
  joinedAt: '2026-10-01T05:00:00.000Z',
});

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown; organization: string | null }[];

const answer = (to: string, ...given: Answer[]) => answers.set(to, given);
const ASKED = { status: 202, body: { stepUpChallengeId: CHALLENGE } };

function as(organizations: unknown[], { signedIn = true, loopback = true } = {}) {
  answer(
    'GET /v1/auth/session',
    signedIn
      ? {
          status: 200,
          body: {
            userId: ME,
            authenticatedAt: '2026-10-26T05:00:00.000Z',
            methods: ['pwd', 'user', 'mfa'],
            idleExpiresAt: '2026-10-26T05:30:00.000Z',
            expiresAt: '2026-10-26T17:00:00.000Z',
          },
        }
      : { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } },
  );
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations, unreadable: [] } });
  answer(`GET ${at}`, { status: 200, body: request(loopback) });
  answer('GET /v1/agents', { status: 200, body: { agents: AGENTS, next: null, unchecked: [] } });
  answer('GET /v1/members', {
    status: 200,
    body: { members: [member(MINE, ME, 'developer'), member(THEIRS, '0199a0f0-0000-7000-8000-000000000022', 'admin')] },
  });
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
      sent.push({ method, path, body, organization: new Headers(init.headers).get('agentx-organization') });
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
const pickedAgent = () => screen.findByLabelText<HTMLSelectElement>('The agent it acts as');
const box = (name: string) => screen.getByLabelText<HTMLInputElement>(name);

/** A consent kept for the step-up, as Allow keeps it. */
function keptConsent(scopes = ['requests:read', 'requests:write']) {
  sessionStorage.setItem(
    `agentx.step-up.${CHALLENGE}`,
    JSON.stringify({
      challenge: CHALLENGE,
      label: 'Connect Claude Desktop as Invoice agent',
      confirmPath: `${at}/consent/confirm`,
      body: { agentId: AGENT, scopes },
      organization: ORG.id,
      idempotencyKey: '0199a0f0-0000-7000-8000-0000000001d0',
    }),
  );
}

/** Answers that are no web address of the app's: a script, one hiding a web address after it, one with a space first. */
const NO_WEB_ADDRESS = ['javascript:alert(1)', "javascript:fetch('https://evil.example')//", ' https://x'];
describe('the connect page before a request is read (6E3b)', () => {
  it.each([
    ['unknown_client', /isn't registered with Agent X/],
    ['unregistered_redirect', /an address it didn't register/],
    ['temporarily_unavailable', /can't take new connections just now/],
    ['constructor', /couldn't open this request/],
  ])('explains a %s problem and sends the browser nowhere', async (problem, said) => {
    as([ORG]);
    open(`/connect?problem=${problem}`);
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.getByRole('heading', { name: "This app can't be connected" })).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('says a page opened without a request needs the app’s link', async () => {
    as([ORG]);
    open('/connect?request=not-an-id');
    expect(await screen.findByText(/needs the link the app opened/)).toBeDefined();
    expect(sentTo('GET', at)).toHaveLength(0);
  });

  it('signs a signed-out person in, coming back to the same request', async () => {
    as([ORG], { signedIn: false });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Sign in' }));
    const returnTo = new URLSearchParams({ returnTo: page }).toString();
    expect(goTo).toHaveBeenCalledWith(`/v1/auth/sign-in?${returnTo}`);
  });

  it('says a request that ended, was answered or is another browser’s can’t be answered', async () => {
    as([ORG]);
    answer(`GET ${at}`, { status: 404, body: { error: { code: 'NOT_FOUND' } } });
    open(page);
    expect(await screen.findByText(/has ended, was answered already, or was opened in another browser/)).toBeDefined();
  });

  it('offers to try again when the request couldn’t be read', async () => {
    as([ORG]);
    answer(`GET ${at}`, { status: 403, body: { error: { code: 'FORBIDDEN' } } }, { status: 200, body: request() });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByText(/says it is “Claude Desktop”/)).toBeDefined();
  });
});

describe('who asks and what for (6E3b)', () => {
  it('names the app by what it says, the host in bold, and warns of an app on this computer', async () => {
    as([ORG]);
    open(page);
    expect(await screen.findByText(/An app that says it is “Claude Desktop”/)).toBeDefined();
    const host = screen.getByText('127.0.0.1:33418');
    expect(host.tagName).toBe('STRONG');
    expect(screen.getByText(/This is an app on this computer, not a website/)).toBeDefined();
    expect(screen.queryByText(/doesn't know this website/)).toBeNull();
    expect(screen.getByRole('heading', { name: 'What it asks to do' })).toBeDefined();
    expect(screen.getAllByText('Ask to pay suppliers').length).toBeGreaterThan(0);
  });

  it('warns of a website Agent X doesn’t know', async () => {
    as([ORG], { loopback: false });
    open(page);
    expect(await screen.findByText(/doesn't know this website. Allow only if app.example.test/)).toBeDefined();
    expect(screen.getByText('app.example.test').tagName).toBe('STRONG');
    expect(screen.queryByText(/an app on this computer/)).toBeNull();
  });
});

describe('choosing the organisation, the agent and the ticks (6E3b)', () => {
  it('offers only organisations the person may connect in, and only active agents', async () => {
    as([ORG, OTHER, VIEWING]);
    open(page);
    const org = await screen.findByLabelText<HTMLSelectElement>('Organisation');
    const offered = Array.from(org.options).map((one) => one.value);
    expect(offered).toEqual(['', ORG.id, OTHER.id]);
    // None chosen yet: Deny alone.
    expect(screen.queryByLabelText('The agent it acts as')).toBeNull();
    await userEvent.selectOptions(org, ORG.id);
    const agents = Array.from((await pickedAgent()).options).map((one) => one.value);
    expect(agents).toEqual(['', AGENT, OTHER_AGENT]);
    expect(screen.getByRole('link', { name: 'Register an agent' }).getAttribute('href')).toBe(`/agents?org=${ORG.id}`);
  });

  it('shows a developer only the agents they are responsible for', async () => {
    as([{ ...ORG, role: 'developer' }]);
    open(page);
    const agents = Array.from((await pickedAgent()).options).map((one) => one.value);
    expect(agents).toEqual(['', AGENT]);
  });

  it('says when there is no agent to connect', async () => {
    as([{ ...ORG, role: 'developer' }]);
    answer('GET /v1/agents', { status: 200, body: { agents: [AGENTS[1]], next: null, unchecked: [] } });
    open(page);
    expect(await screen.findByText(/no active agent here you can connect/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Allow' }).hasAttribute('disabled')).toBe(true);
  });

  it('reads every page of agents', async () => {
    as([ORG]);
    answer(
      'GET /v1/agents',
      { status: 200, body: { agents: [AGENTS[0]], next: AGENT, unchecked: [] } },
      { status: 200, body: { agents: [AGENTS[1]], next: null, unchecked: [] } },
    );
    open(page);
    const select = await pickedAgent();
    expect(Array.from(select.options).map((one) => one.value)).toEqual(['', AGENT, OTHER_AGENT]);
  });

  it('reads at most 20 pages of agents, however many the API says follow', async () => {
    as([ORG]);
    answer('GET /v1/agents', { status: 200, body: { agents: [], next: AGENT, unchecked: [] } });
    open(page);
    expect(await screen.findByText(/no active agent here you can connect/)).toBeDefined();
    expect(sent.filter((one) => one.path.startsWith('/v1/agents?'))).toHaveLength(20);
  });

  it('ticks only what was asked and the agent holds, never a write scope', async () => {
    as([ORG]);
    open(page);
    await userEvent.selectOptions(await screen.findByLabelText('The agent it acts as'), AGENT);
    expect(box('See its own payment requests').checked).toBe(true);
    expect(box('Ask to pay suppliers').checked).toBe(false);
    expect(screen.queryByLabelText("See your organisation's suppliers")).toBeNull();
    expect(screen.queryByLabelText('See the bank accounts it may pay from')).toBeNull();
    expect(screen.getByText(/Asked for, but this agent can't: See your organisation's suppliers/)).toBeDefined();
  });

  it('says an agent that can do nothing asked, and lets nothing be allowed', async () => {
    as([ORG]);
    answer('GET /v1/agents', {
      status: 200,
      body: { agents: [{ ...AGENTS[0], scopes: ['sources:read'] }], next: null, unchecked: [] },
    });
    open(page);
    await userEvent.selectOptions(await screen.findByLabelText('The agent it acts as'), AGENT);
    expect(screen.getByText(/can't do anything the app asks for/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Allow' }).hasAttribute('disabled')).toBe(true);
  });

  it('says a person who is no admin or developer anywhere can’t connect', async () => {
    as([VIEWING]);
    open(page);
    expect(await screen.findByText(/Only an admin or a developer of an organisation can connect/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Allow' })).toBeNull();
  });

  it('offers to read the agents again when they couldn’t be read', async () => {
    as([ORG]);
    answer(
      'GET /v1/agents',
      { status: 403, body: { error: { code: 'FORBIDDEN' } } },
      { status: 200, body: { agents: AGENTS, next: null, unchecked: [] } },
    );
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByLabelText('The agent it acts as')).toBeDefined();
  });
});

describe('allowing and denying (6E3b)', () => {
  it('asks for the connection in the organisation chosen, then signs in again', async () => {
    as([ORG]);
    answer(`POST ${at}/consent`, ASKED);
    open(page);
    await userEvent.selectOptions(await screen.findByLabelText('The agent it acts as'), AGENT);
    await userEvent.click(box('Ask to pay suppliers'));
    await userEvent.click(screen.getByRole('button', { name: 'Allow' }));

    const [asked] = sentTo('POST', `${at}/consent`);
    // In the API's order, whatever order they were ticked in.
    expect(asked?.body).toEqual({ agentId: AGENT, scopes: ['requests:read', 'requests:write'] });
    expect(asked?.organization).toBe(ORG.id);
    expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    expect(JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null')).toMatchObject({
      label: 'Connect Claude Desktop as Invoice agent',
      confirmPath: `${at}/consent/confirm`,
      organization: ORG.id,
    });
  });

  it('allows nothing with nothing ticked', async () => {
    as([ORG]);
    open(page);
    await userEvent.selectOptions(await screen.findByLabelText('The agent it acts as'), AGENT);
    await userEvent.click(box('See its own payment requests'));
    await userEvent.click(screen.getByRole('button', { name: 'Allow' }));
    expect(screen.getByText('Tick at least one thing it may do.')).toBeDefined();
    expect(sentTo('POST', `${at}/consent`)).toHaveLength(0);
  });

  it.each([
    ['CONNECTIONS_FULL', /already has 10 apps connected/],
    ['FORBIDDEN', /a developer connects only agents they are responsible for/],
    ['SOMETHING_NEW', /reason SOMETHING_NEW/],
    ['INTEGRITY_FAILED', /failed Agent X's integrity check/],
  ])('says a consent refused with %s plainly', async (code, said) => {
    as([ORG]);
    answer(`POST ${at}/consent`, { status: code === 'INTEGRITY_FAILED' ? 503 : 409, body: { error: { code } } });
    open(page);
    await userEvent.selectOptions(await screen.findByLabelText('The agent it acts as'), AGENT);
    await userEvent.click(screen.getByRole('button', { name: 'Allow' }));
    expect(await screen.findByText(said)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('tells the app no, and sends the browser back to it', async () => {
    as([ORG, OTHER]);
    const denied = 'https://app.example.test/callback?error=access_denied&state=s';
    answer(`POST ${at}/deny`, { status: 200, body: { redirectTo: denied } });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Deny' }));
    const [deny] = sentTo('POST', `${at}/deny`);
    expect(deny?.body).toEqual({});
    expect(deny?.organization).toBe(ORG.id);
    expect(goTo).toHaveBeenCalledWith(denied);
  });

  it.each(NO_WEB_ADDRESS)('never follows a deny’s answer that is no web address: %j', async (redirectTo) => {
    as([ORG]);
    answer(`POST ${at}/deny`, { status: 200, body: { redirectTo } });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Deny' }));
    expect(await screen.findByText(/couldn't be reached/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });
});

describe('back from signing in again (6E3b)', () => {
  const back = `${page}&stepped=${CHALLENGE}`;

  it('confirms the connection kept and sends the browser back to the app with its code', async () => {
    as([ORG]);
    keptConsent();
    answer(`POST ${at}/consent/confirm`, { status: 201, body: { redirectTo: BACK, connection: {} } });
    open(back);
    expect(await screen.findByText('Connect Claude Desktop as Invoice agent')).toBeDefined();
    expect(screen.getByText('127.0.0.1:33418').tagName).toBe('STRONG');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    const [confirmed] = sentTo('POST', `${at}/consent/confirm`);
    expect(confirmed?.body).toEqual({
      agentId: AGENT,
      scopes: ['requests:read', 'requests:write'],
      stepUpChallengeId: CHALLENGE,
    });
    expect(confirmed?.organization).toBe(ORG.id);
    expect(goTo).toHaveBeenCalledWith(BACK);
    expect(await screen.findByText('Sending you back to the app…')).toBeDefined();
    expect(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`)).toBeNull();
  });

  it('keeps the choices when the connection isn’t made after all', async () => {
    as([ORG]);
    keptConsent();
    open(back);
    await userEvent.click(await screen.findByRole('button', { name: "Don't make it" }));
    const select = await pickedAgent();
    expect(select.value).toBe(AGENT);
    // As they were ticked, the write scope too.
    expect(box('Ask to pay suppliers').checked).toBe(true);
    expect(box('See its own payment requests').checked).toBe(true);
    expect(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`)).toBeNull();
  });

  it('never sends a kept tick the agent no longer holds', async () => {
    as([ORG]);
    keptConsent(['requests:read', 'requests:write']);
    answer('GET /v1/agents', {
      status: 200,
      body: { agents: [{ ...AGENTS[0], scopes: ['requests:read', 'sources:read'] }], next: null, unchecked: [] },
    });
    answer(`POST ${at}/consent`, ASKED);
    open(back);
    await userEvent.click(await screen.findByRole('button', { name: "Don't make it" }));
    expect((await pickedAgent()).value).toBe(AGENT);
    expect(screen.queryByLabelText('Ask to pay suppliers')).toBeNull();
    expect(box('See its own payment requests').checked).toBe(true);
    await userEvent.click(screen.getByRole('button', { name: 'Allow' }));
    expect(sentTo('POST', `${at}/consent`)[0]?.body).toEqual({ agentId: AGENT, scopes: ['requests:read'] });
  });

  it('confirms nothing kept for another request', async () => {
    const otherAt = '/v1/oauth/requests/0199a0f0-0000-7000-8000-0000000000e2';
    as([ORG]);
    sessionStorage.setItem(
      `agentx.step-up.${CHALLENGE}`,
      JSON.stringify({
        challenge: CHALLENGE,
        label: 'Connect Claude Desktop as Invoice agent',
        confirmPath: `${otherAt}/consent/confirm`,
        body: { agentId: AGENT, scopes: ['requests:read'] },
        organization: ORG.id,
        idempotencyKey: '0199a0f0-0000-7000-8000-0000000001d0',
      }),
    );
    open(back);
    expect(await screen.findByText(/can't be found in this window/)).toBeDefined();
    expect(await pickedAgent()).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull();
    expect(sentTo('POST', `${at}/consent/confirm`)).toHaveLength(0);
    expect(sentTo('POST', `${otherAt}/consent/confirm`)).toHaveLength(0);
  });

  it('says a confirm made on an earlier try has no way back to the app', async () => {
    as([ORG]);
    keptConsent();
    answer(`POST ${at}/consent/confirm`, { status: 201, body: { redirectTo: null, connection: {} } });
    open(back);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/connected on your first try/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('says a confirm refused, and reads the request again', async () => {
    as([ORG]);
    keptConsent();
    answer(`POST ${at}/consent/confirm`, { status: 409, body: { error: { code: 'CONNECTION_AGENT_NOT_ACTIVE' } } });
    open(back);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/This agent is suspended/)).toBeDefined();
    expect(screen.getByText(/didn't make this change: Connect Claude Desktop as Invoice agent/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(await screen.findByLabelText('The agent it acts as')).toBeDefined();
    expect(sentTo('GET', at).length).toBeGreaterThan(1);
  });

  it('offers the confirm again after an undecided answer or a failure on the way', async () => {
    as([ORG]);
    keptConsent();
    answer(
      `POST ${at}/consent/confirm`,
      { status: 409, body: { error: { code: 'IDEMPOTENCY_KEY_BUSY' } } },
      { status: 500, body: { error: { code: 'UNAVAILABLE' } } },
      { status: 201, body: { redirectTo: BACK, connection: {} } },
    );
    open(back);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/still working on this/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/couldn't be reached/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(goTo).toHaveBeenCalledWith(BACK);
  });

  it('goes to sign in when the session ended at the confirm', async () => {
    as([ORG]);
    keptConsent();
    answer(`POST ${at}/consent/confirm`, { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } });
    open(back);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/Sign in to choose which of your agents/)).toBeDefined();
    expect(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`)).not.toBeNull();
  });

  it.each(NO_WEB_ADDRESS)('never follows a confirm’s answer that is no web address: %j', async (redirectTo) => {
    as([ORG]);
    keptConsent();
    answer(`POST ${at}/consent/confirm`, { status: 201, body: { redirectTo } });
    open(back);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/couldn't be reached/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('says a change kept for nothing here can’t be found, and offers the choice afresh', async () => {
    as([ORG]);
    open(back);
    expect(await screen.findByText(/can't be found in this window/)).toBeDefined();
    expect(await screen.findByLabelText('The agent it acts as')).toBeDefined();
  });

  it('says a sign-in that failed, and forgets what was kept for it', async () => {
    as([ORG]);
    keptConsent();
    open(`${page}&stepUpFailed=${CHALLENGE}`);
    expect(await screen.findByText(/Signing in again didn't go through/)).toBeDefined();
    expect(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`)).toBeNull();
  });
});

describe('an app named by its document, and a device (6E3c)', () => {
  const DEVICE_REQUEST = {
    ...request(),
    via: 'device',
    redirectUri: null,
    redirectHost: null,
    loopback: false,
  };

  it('shows an app named by its metadata document as published by its host, in bold', async () => {
    as([ORG]);
    answer(`GET ${at}`, {
      status: 200,
      body: {
        ...request(false),
        client: { id: 'https://claude.ai/oauth/x', name: 'Claude', verifiedBy: 'claude.ai' },
      },
    });
    open(page);
    expect(
      await screen.findByText(/“Claude” asks to act as one of your agents. Its name and addresses are published by/),
    ).toBeDefined();
    expect(screen.getByText('claude.ai').tagName).toBe('STRONG');
    expect(screen.queryByText(/says it is/)).toBeNull();
  });

  it('warns of a device, with no address to go back to', async () => {
    as([ORG]);
    answer(`GET ${at}`, { status: 200, body: DEVICE_REQUEST });
    open(page);
    expect(await screen.findByText(/This is a device, such as a server or a command line/)).toBeDefined();
    expect(screen.queryByText(/sends you back to/)).toBeNull();
    // Named only by what it says it is: a device is never shown as published by a host (6E3c review).
    expect(screen.getByText(/An app that says it is “Claude Desktop”/)).toBeDefined();
    expect(screen.queryByText(/published by/)).toBeNull();
  });

  it('tells a device no, and goes to the device page to say so', async () => {
    as([ORG]);
    answer(`GET ${at}`, { status: 200, body: DEVICE_REQUEST });
    answer(`POST ${at}/deny`, { status: 200, body: { redirectTo: null } });
    open(page);
    await userEvent.click(await screen.findByRole('button', { name: 'Deny' }));
    expect(goTo).toHaveBeenCalledWith('/device?answered=denied');
  });

  it('confirms a device’s connection and goes to the device page, as the device takes its tokens itself', async () => {
    as([ORG]);
    answer(`GET ${at}`, { status: 200, body: DEVICE_REQUEST });
    keptConsent();
    answer(`POST ${at}/consent/confirm`, { status: 201, body: { redirectTo: null, connection: { via: 'device' } } });
    open(`${page}&stepped=${CHALLENGE}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(goTo).toHaveBeenCalledWith('/device?answered=allowed');
  });
});

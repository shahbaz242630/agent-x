// 6D4b: the two pages a link with a token in its fragment opens, against a
// stand-in API. An invitation's acceptance (`/invitations/accept#token=…`),
// signed in, perhaps a member of no organisation yet; and a registered
// contact's confirm of a factor reset (CO9, `/factor-resets/confirm#token=…`),
// signed in or not. Each reads the token once, cleans the address of it at
// once, sends nothing until pressed, and sends the token only to its own API
// call: never to storage, the address, the query cache, or anywhere else.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';
import { arrivedIn } from '../arrived-token.ts';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ME = '0199a0f0-0000-7000-8000-000000000011';
const ORG = '0199a0f0-0000-7000-8000-00000000aaaa';
const INVITATION = '0199a0f0-0000-7000-8000-0000000000e1';
const PAST = '2026-01-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';
/** An invitation's token: 43 base64url characters. */
const INVITED = 'Zm9yIHRlc3RzIG9ubHkgLSBub3QgYSByZWFsIG9uZQ_';
/** A contact's link token: the API's own alphabet, dots included. */
const CONTACTED = `${ORG}.0199a0f0-0000-7000-8000-0000000000f1.words_and-more`;

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown }[];

const answer = (at: string, ...given: Answer[]) => answers.set(at, given);
const refused = (status: number, code: string) => ({ status, body: { error: { code } } });

function signedIn(organizations: readonly unknown[] = []) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: { userId: ME, authenticatedAt: PAST, methods: ['user', 'mfa'], idleExpiresAt: FUTURE, expiresAt: FUTURE },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations, unreadable: [] } });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  sessionStorage.clear();
  localStorage.clear();
  vi.mocked(goTo).mockClear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, body });
      const queue = answers.get(`${method} ${path.split('?')[0] ?? path}`);
      const next = queue === undefined ? undefined : queue.length > 1 ? queue.shift() : queue[0];
      const { status, body: reply } = next ?? refused(401, 'UNAUTHENTICATED');
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
  const queries = createQueries();
  render(<App queries={queries} router={createConsoleRouter(history)} />);
  return { history, queries };
}

/** Everything a store holds, as one text. */
const held = (store: Storage): string =>
  Array.from(
    { length: store.length },
    (_, at) => `${store.key(at) ?? ''}=${store.getItem(store.key(at) ?? '') ?? ''}`,
  ).join(' ');

const posts = () => sent.filter((one) => one.method === 'POST');
const press = async (name: string | RegExp) => {
  await userEvent.click(await screen.findByRole('button', { name }));
};

/** Nowhere the page could have kept the token: storage, the address, the query cache, any request but `allowed`. */
function nowhere(token: string, opened: ReturnType<typeof open>, allowed: string) {
  expect(held(sessionStorage)).not.toContain(token);
  expect(held(localStorage)).not.toContain(token);
  expect(opened.history.location.href).not.toContain(token);
  expect(opened.history.location.hash).toBe('');
  const cached = opened.queries
    .getQueryCache()
    .getAll()
    .map((query) => query.state.data);
  expect(JSON.stringify(cached)).not.toContain(token);
  for (const one of sent) {
    if (one.path !== allowed) {
      expect(one.path).not.toContain(token);
      expect(JSON.stringify(one.body ?? null)).not.toContain(token);
    }
  }
}

describe('accepting an invitation (6D4b)', () => {
  const page = `/invitations/accept#token=${INVITED}`;

  it('waits for the press, cleans the address at once, and sends the token to the acceptance alone', async () => {
    signedIn();
    answer('POST /v1/invitations/accept', {
      status: 200,
      body: {
        organizationId: ORG,
        invitation: { id: INVITATION, role: 'developer', status: 'ACCEPTED', expiresAt: FUTURE },
      },
    });
    const opened = open(page);
    expect(await screen.findByText(/Nothing happens until you press Accept/)).toBeDefined();
    expect(opened.history.location.hash).toBe('');
    expect(posts()).toHaveLength(0);
    await press('Accept');
    expect(await screen.findByText("You've joined the organisation as Developer.")).toBeDefined();
    expect(posts()).toEqual([{ method: 'POST', path: '/v1/invitations/accept', body: { token: INVITED } }]);
    expect(screen.getByRole('link', { name: 'Open Agent X' })).toBeDefined();
    nowhere(INVITED, opened, '/v1/invitations/accept');
  });

  it('shows the invitation’s ID to give an admin, when an admin confirms them next', async () => {
    signedIn([{ id: ORG, name: 'Other org', role: 'viewer', frozen: false }]);
    answer('POST /v1/invitations/accept', {
      status: 200,
      body: {
        organizationId: ORG,
        invitation: { id: INVITATION, role: 'admin', status: 'AWAITING_CONFIRMATION', expiresAt: FUTURE },
      },
    });
    open(page);
    await press('Accept');
    expect(await screen.findByText(/An admin of the organisation confirms you before you join/)).toBeDefined();
    expect(screen.getByText(INVITATION)).toBeDefined();
  });

  it.each([
    ['INVITATION_INVALID', 403, /verified email isn't the invited address/],
    ['INVITATION_CLOSED', 409, /no longer open/],
    ['ALREADY_A_MEMBER', 409, /already a member/],
    ['UNAVAILABLE', 500, /couldn't be reached/],
  ])('says an acceptance refused with %s plainly, and can be pressed again', async (code, status, said) => {
    signedIn();
    answer('POST /v1/invitations/accept', refused(status, code));
    open(page);
    await press('Accept');
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Accept' }).disabled).toBe(false);
  });

  it('says to sign in first when no one is, leaving for the sign-in with nothing of the token', async () => {
    const opened = open(page);
    expect(await screen.findByText(/Sign in first, with the sign-in whose verified email/)).toBeDefined();
    await press('Sign in');
    expect(goTo).toHaveBeenCalledWith('/v1/auth/sign-in?returnTo=%2Finvitations%2Faccept');
    nowhere(INVITED, opened, '');
  });

  it('says to sign in again when the session ended on the press', async () => {
    signedIn();
    open(page);
    answer('POST /v1/invitations/accept', refused(401, 'UNAUTHENTICATED'));
    await press('Accept');
    answer('GET /v1/auth/session', refused(401, 'UNAUTHENTICATED'));
    expect(await screen.findByText(/Sign in first/)).toBeDefined();
  });

  it.each([
    ['no link at all', '/invitations/accept', /needs the invitation link/],
    ['a token of the wrong form', '/invitations/accept#token=short', /incomplete or broken/],
  ])('says %s plainly, sending nothing', async (_what, path, said) => {
    signedIn();
    open(path);
    expect(await screen.findByText(said)).toBeDefined();
    expect(posts()).toHaveLength(0);
  });
});

describe('a registered contact confirming a reset (CO9)', () => {
  const page = `/factor-resets/confirm#token=${CONTACTED}`;

  it('works signed out: says what it does, waits for the tick and the press, and sends the token alone', async () => {
    answer('POST /v1/factor-resets/confirm', { status: 200, body: { coolingOffUntil: FUTURE } });
    const opened = open(page);
    expect(await screen.findByText(/removed 24 hours from now, unless an admin cancels/)).toBeDefined();
    expect(opened.history.location.hash).toBe('');
    expect(screen.getByRole<HTMLInputElement>('checkbox').checked).toBe(false);
    await press('Confirm the reset');
    expect(await screen.findByText(/Tick that you've checked it first/)).toBeDefined();
    expect(posts()).toHaveLength(0);

    await userEvent.click(screen.getByRole('checkbox'));
    await press('Confirm the reset');
    expect(await screen.findByText(/Nothing else is needed from you/)).toBeDefined();
    expect(posts()).toEqual([{ method: 'POST', path: '/v1/factor-resets/confirm', body: { token: CONTACTED } }]);
    nowhere(CONTACTED, opened, '/v1/factor-resets/confirm');
  });

  it('works signed in too, before any organisation is chosen', async () => {
    signedIn([
      { id: ORG, name: 'One', role: 'admin', frozen: false },
      { id: INVITATION, name: 'Two', role: 'admin', frozen: false },
    ]);
    answer('POST /v1/factor-resets/confirm', { status: 200, body: { coolingOffUntil: FUTURE } });
    open(page);
    await userEvent.click(await screen.findByRole('checkbox'));
    await press('Confirm the reset');
    expect(await screen.findByRole('heading', { name: 'Reset confirmed' })).toBeDefined();
  });

  it.each([
    ['NOT_FOUND', 404, /isn't one Agent X sent, or it no longer works/],
    ['CONTACT_NOT_ACTIVE', 409, /no longer a registered contact/],
    ['RESET_CLOSED', 409, /already sent, ended or ran out/],
    ['RATE_LIMITED', 429, /Too many tries/],
    ['UNAVAILABLE', 0, /couldn't be reached/],
  ])('says a confirm refused with %s plainly, and can be pressed again', async (code, status, said) => {
    answer('POST /v1/factor-resets/confirm', status === 0 ? { status: 0 } : refused(status, code));
    open(page);
    await userEvent.click(await screen.findByRole('checkbox'));
    await press('Confirm the reset');
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Confirm the reset' }).disabled).toBe(false);
  });

  it.each([
    ['no link at all', '/factor-resets/confirm', /needs the link from your email/],
    ['a token of the wrong form', '/factor-resets/confirm#token=has%20a%20space', /incomplete or broken/],
  ])('says %s plainly, sending nothing', async (_what, path, said) => {
    open(path);
    expect(await screen.findByText(said)).toBeDefined();
    expect(posts()).toHaveLength(0);
  });
});

describe('reading a token from a fragment (6D4b)', () => {
  it('finds a token wherever it is kept: the control for the checks that it is kept nowhere', () => {
    sessionStorage.setItem('kept', `token=${INVITED}`);
    localStorage.setItem(`token=${CONTACTED}`, '');
    expect(held(sessionStorage)).toContain(INVITED);
    expect(held(localStorage)).toContain(CONTACTED);
  });

  it.each([
    ['token=abc', { token: 'abc' }],
    ['#token=abc', { token: 'abc' }],
    ['other=1&token=abc', { token: 'abc' }],
    ['token=a+b', 'malformed'],
    ['token=', 'malformed'],
    ['', 'none'],
    ['other=abc', 'none'],
  ])('reads %s as %o', (hash, arrived) => {
    expect(arrivedIn(hash, /^[a-c]{1,3}$/)).toEqual(arrived);
  });
});

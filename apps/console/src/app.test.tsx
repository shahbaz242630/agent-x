// 6A1: the console's frame in a browser-like page, against a stand-in API (a
// stubbed fetch that answers by address). Who is signed in decides the page:
// the sign-in page, choosing an organisation, or the shell; a session ending
// mid-use goes back to sign-in, saying so; a failure says so with a retry.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from './app.tsx';

vi.mock('./navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('./navigate.ts');

const SESSION = {
  userId: '0199a0f0-0000-7000-8000-000000000011',
  authenticatedAt: '2026-10-26T05:00:00.000Z',
  methods: ['pwd', 'user', 'mfa'],
  idleExpiresAt: '2026-10-26T05:30:00.000Z',
  expiresAt: '2026-10-26T17:00:00.000Z',
};
const ORG_A = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ORG_B = { id: '0199a0f0-0000-7000-8000-00000000bbbb', name: 'Glide Logistics LLC', role: 'viewer', frozen: true };

interface Answer {
  status: number;
  body?: unknown;
}
let answers: Record<string, Answer | Answer[]>;
let asked: { method: string; path: string; headers: Headers }[];

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

beforeEach(() => {
  asked = [];
  localStorage.clear();
  vi.mocked(goTo).mockClear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      asked.push({ method: init.method ?? 'GET', path, headers: new Headers(init.headers) });
      const found = answers[`${init.method ?? 'GET'} ${path}`];
      const answer = Array.isArray(found) ? (found.length > 1 ? found.shift() : found[0]) : found;
      if (answer === undefined) return Promise.resolve(json(404, { error: { code: 'NOT_FOUND' } }));
      return Promise.resolve(json(answer.status, answer.body ?? {}));
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const signedIn = (organizations: unknown[], unreadable: string[] = []) => {
  answers = {
    'GET /v1/auth/session': { status: 200, body: SESSION },
    'GET /v1/auth/organizations': { status: 200, body: { organizations, unreadable } },
  };
};

function open(path = '/') {
  const router = createConsoleRouter(createMemoryHistory({ initialEntries: [path] }));
  render(<App queries={createQueries()} router={router} />);
  return router;
}

describe('the console’s frame (6A1)', () => {
  it('shows no one signed in the sign-in page, which goes to sign-in and back to the page asked for', async () => {
    answers = { 'GET /v1/auth/session': { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } } };
    open('/payments');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign in' }));
    expect(screen.getByText(/Sign in with your work account/)).toBeDefined();
    expect(goTo).toHaveBeenCalledWith(expect.stringMatching(/^\/v1\/auth\/sign-in\?returnTo=/));
  });

  it('opens the one organisation straight away, on approvals, with the tabs', async () => {
    signedIn([ORG_A]);
    const router = open('/');
    expect(await screen.findByText('Staging-Test-Org-1')).toBeDefined();
    expect(screen.getByText('Payments waiting for your approval will appear here.')).toBeDefined();
    expect(router.state.location.pathname).toBe('/approvals');
    expect(screen.getByRole('link', { name: 'Approvals' }).getAttribute('aria-current')).toBe('page');
    expect(screen.queryByRole('button', { name: 'Switch organisation' })).toBeNull();
  });

  it('asks a person in several to choose, remembers the choice, and lets them switch back', async () => {
    signedIn([ORG_A, ORG_B]);
    open('/agents');
    await userEvent.click(await screen.findByRole('button', { name: /Glide Logistics LLC/ }));
    expect(await screen.findByText(/This organisation is frozen/)).toBeDefined();
    expect(screen.getByText("Your organisation's agents and their keys will appear here.")).toBeDefined();
    expect(localStorage.getItem('agentx.organization')).toBe(ORG_B.id);
    await userEvent.click(screen.getByRole('button', { name: 'Switch organisation' }));
    expect(await screen.findByText('Choose an organisation')).toBeDefined();
    expect(localStorage.getItem('agentx.organization')).toBeNull();
  });

  it('opens the organisation remembered, if the person still belongs to it', async () => {
    localStorage.setItem('agentx.organization', ORG_B.id);
    signedIn([ORG_A, ORG_B]);
    open('/payments');
    expect(await screen.findByText(/Glide Logistics LLC/)).toBeDefined();
    expect(screen.getByText('Every payment and its timeline will appear here.')).toBeDefined();
  });

  it('says how to join when the person is in none, and that one can’t be checked when it can’t', async () => {
    signedIn([], ['0199a0f0-0000-7000-8000-00000000dead']);
    open('/');
    expect(await screen.findByText("You're not in an organisation yet")).toBeDefined();
    expect(screen.getByText(/can't be checked right now/)).toBeDefined();
  });

  it('shows an unreadable organisation beside those to choose from', async () => {
    signedIn([ORG_A, ORG_B], ['0199a0f0-0000-7000-8000-00000000dead']);
    open('/');
    expect(await screen.findByText('Choose an organisation')).toBeDefined();
    expect(screen.getByText(/can't be checked right now/)).toBeDefined();
    expect(screen.getByText('Frozen')).toBeDefined();
  });

  it('says a page that couldn’t load failed, and loads it on a retry', async () => {
    answers = {
      'GET /v1/auth/session': [{ status: 503 }, { status: 503 }, { status: 503 }, { status: 200, body: SESSION }],
      'GET /v1/auth/organizations': { status: 200, body: { organizations: [ORG_A], unreadable: [] } },
    };
    open('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 5000 }));
    expect(await screen.findByText('Staging-Test-Org-1')).toBeDefined();
  });

  it('says the organisations couldn’t load when they can’t', async () => {
    answers = {
      'GET /v1/auth/session': { status: 200, body: SESSION },
      'GET /v1/auth/organizations': { status: 500 },
    };
    open('/');
    expect(await screen.findByText('Something went wrong', {}, { timeout: 5000 })).toBeDefined();
  });

  it('goes back to sign-in, saying the session ended, when a request is answered 401 mid-use', async () => {
    answers = {
      'GET /v1/auth/session': { status: 200, body: SESSION },
      'GET /v1/auth/organizations': { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } },
    };
    open('/');
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
    // A 401 is never retried.
    expect(asked.filter((one) => one.path === '/v1/auth/organizations')).toHaveLength(1);
  });

  it('shows when the session ends, and signs out, then starts afresh', async () => {
    signedIn([ORG_A]);
    answers['POST /v1/auth/sign-out'] = { status: 200, body: {} };
    open('/more');
    expect(await screen.findByText(/Signed in until/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith('/');
    });
    const signOut = asked.find((one) => one.path === '/v1/auth/sign-out');
    expect(signOut?.method).toBe('POST');
  });

  it('starts afresh even when signing out fails', async () => {
    signedIn([ORG_A]);
    answers['POST /v1/auth/sign-out'] = { status: 503 };
    open('/more');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    await waitFor(() => {
      expect(goTo).toHaveBeenCalledWith('/');
    });
  });

  it('says a page that isn’t there isn’t, with the way back', async () => {
    signedIn([ORG_A]);
    open('/nowhere');
    expect(await screen.findByText('Page not found')).toBeDefined();
    expect(screen.getByRole('link', { name: 'Go to approvals' })).toBeDefined();
  });

  it('carries on when the browser blocks storage', async () => {
    const blocked = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    const blockedSet = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    try {
      signedIn([ORG_A, ORG_B]);
      open('/');
      await userEvent.click(await screen.findByRole('button', { name: /Staging-Test-Org-1/ }));
      expect(await screen.findByText('Payments waiting for your approval will appear here.')).toBeDefined();
    } finally {
      blocked.mockRestore();
      blockedSet.mockRestore();
    }
  });
});

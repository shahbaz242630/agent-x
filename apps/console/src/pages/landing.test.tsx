// CO11: the public front page, once launched (launch.ts): its one Sign in, its
// other ways in, the invitation said plainly, and its notes. Until launch a
// visitor sees the private way in instead (shell.test.tsx).
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';
import { markSignedOut } from './signed-out.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
vi.mock('../launch.ts', () => ({ LAUNCHED: true }));
const { goTo } = await import('../navigate.ts');

let answers: Record<string, { status: number; body?: unknown }>;

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.mocked(goTo).mockClear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const answer = answers[`${init.method ?? 'GET'} ${path}`] ?? {
        status: 404,
        body: { error: { code: 'NOT_FOUND' } },
      };
      return Promise.resolve(
        new Response(JSON.stringify(answer.body ?? {}), {
          status: answer.status,
          headers: { 'content-type': 'application/json' },
        }),
      );
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const signedOut = () => {
  answers = { 'GET /v1/auth/session': { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } } };
};

function open(path: string) {
  const router = createConsoleRouter(createMemoryHistory({ initialEntries: [path] }));
  render(<App queries={createQueries()} router={router} />);
  return router;
}

describe('the front page (CO11)', () => {
  it('has one Sign in, plus the hero and closing ways in, each back to the page asked for', async () => {
    signedOut();
    open('/payments');
    expect(await screen.findByRole('heading', { level: 1, name: /Your agents pay suppliers/ })).toBeDefined();
    expect(screen.getAllByRole('button', { name: 'Sign in' })).toHaveLength(1);
    await userEvent.click(screen.getByRole('button', { name: /Sign in to the console/ }));
    await userEvent.click(screen.getByRole('button', { name: /Go to the console/ }));
    expect(vi.mocked(goTo).mock.calls.every(([to]) => to.startsWith('/v1/auth/sign-in?returnTo='))).toBe(true);
    expect(goTo).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/accounts are by invitation/)).toBeDefined();
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('says once that the person signed out, after a sign-out', async () => {
    signedOut();
    markSignedOut();
    open('/');
    expect(await screen.findByText(/You've signed out/)).toBeDefined();
    cleanup();
    open('/');
    await screen.findByRole('button', { name: 'Sign in' });
    expect(screen.queryByText(/You've signed out/)).toBeNull();
  });

  it('goes on without the note where the tab keeps nothing', async () => {
    signedOut();
    const stored = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    const read = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    markSignedOut();
    open('/');
    await screen.findByRole('button', { name: 'Sign in' });
    expect(screen.queryByText(/You've signed out/)).toBeNull();
    stored.mockRestore();
    read.mockRestore();
  });
});

// 6E3c (RFC 8628 §3.3): the `/device` page a device tells its person to open,
// against a stand-in API, drawn before any organisation is chosen. The code
// typed (or filled in from the device's link) finds the device's request and
// goes on to `/connect` to answer it; a code that finds nothing, too many
// tries, or a failure each say so; signed out, the person signs in and comes
// back with the code kept. Answered, the page says to go back to the device.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const REQ = '0199a0f0-0000-7000-8000-0000000000e1';
const LOOKUP = '/v1/oauth/device/lookup';
const SESSION = {
  userId: '0199a0f0-0000-7000-8000-000000000011',
  authenticatedAt: '2026-10-26T05:00:00.000Z',
  methods: ['pwd', 'user', 'mfa'],
  idleExpiresAt: '2026-10-26T05:30:00.000Z',
  expiresAt: '2026-10-26T17:00:00.000Z',
};

let lookups: { status: number; body: unknown }[];
let sent: { path: string; body: unknown }[];
let signedIn: boolean;

beforeEach(() => {
  lookups = [];
  sent = [];
  signedIn = true;
  vi.mocked(goTo).mockClear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ path, body });
      if (path === '/v1/auth/session') {
        return Promise.resolve(
          signedIn
            ? new Response(JSON.stringify(SESSION), { status: 200 })
            : new Response(JSON.stringify({ error: { code: 'UNAUTHENTICATED' } }), { status: 401 }),
        );
      }
      const next = lookups.shift() ?? { status: 404, body: { error: { code: 'NOT_FOUND' } } };
      return Promise.resolve(new Response(JSON.stringify(next.body), { status: next.status }));
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

const codeBox = () => screen.findByLabelText<HTMLInputElement>('Code');

describe('the device page (6E3c)', () => {
  it('finds the device’s request by the code typed, and goes on to answer it on /connect', async () => {
    lookups = [{ status: 200, body: { requestId: REQ } }];
    open('/device');
    expect(await screen.findByText(/Only type a code your own device showed you just now/)).toBeDefined();
    await userEvent.type(await codeBox(), 'bcdf-ghjk');
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(sent.filter(({ path }) => path === LOOKUP).map(({ body }) => body)).toEqual([{ userCode: 'bcdf-ghjk' }]);
    expect(goTo).toHaveBeenCalledWith(`/connect?request=${REQ}`);
  });

  it('fills the code in from the device’s link', async () => {
    open('/device?user_code=BCDF-GHJK');
    expect((await codeBox()).value).toBe('BCDF-GHJK');
  });

  it.each([
    [404, 'NOT_FOUND', /No device is waiting with that code/],
    [429, 'RATE_LIMITED', /Too many codes typed in the last minute/],
    [500, 'INTERNAL', /couldn't look the code up just now/],
  ])('says a lookup answered %i plainly, and goes nowhere', async (status, code, said) => {
    lookups = [{ status, body: { error: { code } } }];
    open('/device?user_code=BCDF-GHJK');
    await userEvent.click(await screen.findByRole('button', { name: 'Continue' }));
    expect(await screen.findByText(said)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('sends a person whose session ended at the lookup to sign in, the code kept', async () => {
    lookups = [{ status: 401, body: { error: { code: 'UNAUTHENTICATED' } } }];
    open('/device?user_code=BCDF-GHJK');
    await userEvent.click(await screen.findByRole('button', { name: 'Continue' }));
    const returnTo = new URLSearchParams({ returnTo: '/device?user_code=BCDF-GHJK' }).toString();
    expect(goTo).toHaveBeenCalledWith(`/v1/auth/sign-in?${returnTo}`);
  });

  it('signs a signed-out person in first, coming back with the code', async () => {
    signedIn = false;
    open('/device?user_code=BCDF-GHJK');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign in' }));
    const returnTo = new URLSearchParams({ returnTo: '/device?user_code=BCDF-GHJK' }).toString();
    expect(goTo).toHaveBeenCalledWith(`/v1/auth/sign-in?${returnTo}`);
    expect(screen.queryByLabelText('Code')).toBeNull();
  });

  it('signs in to the bare page when no code was given', async () => {
    signedIn = false;
    open('/device');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign in' }));
    expect(goTo).toHaveBeenCalledWith(`/v1/auth/sign-in?${new URLSearchParams({ returnTo: '/device' }).toString()}`);
  });

  it.each([
    ['allowed', /The device is connected. Go back to it/],
    ['denied', /You told the device no/],
  ])('says to go back to the device once it was %s', async (answered, said) => {
    open(`/device?answered=${answered}`);
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.queryByLabelText('Code')).toBeNull();
  });

  it('sends nothing for an empty code', async () => {
    open('/device');
    expect((await screen.findByRole<HTMLButtonElement>('button', { name: 'Continue' })).disabled).toBe(true);
  });
});

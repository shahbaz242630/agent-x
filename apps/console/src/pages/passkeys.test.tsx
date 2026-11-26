// SA6: adding a passkey inside Agent X, against a stand-in API. Reached from
// More; says always that adding one at the login service directly starts 7
// days of developer or viewer powers; starts with a step-up that comes back to
// `?adding=<id>`; back, asks for the add-a-passkey page as it loads and links
// it in a new tab, keeping it out of the address and storage; checks until the
// key is added or gone, the person signed out, or ten minutes pass.
import { createMemoryHistory } from '@tanstack/react-router';
import { act, cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';
import { CHECK_EVERY_MS, CHECK_FOR_MS } from './passkeys.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'viewer', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const CHALLENGE = '0199a0f0-0000-7000-8000-00000000c0de';
const TICKET = 'A'.repeat(43);
const PAGE = `https://addkey.auth.example.test/add-passkey#${TICKET}`;
const AT = '2026-11-15T05:00:00.000Z';
const SEVEN_DAYS =
  'Adding a passkey or security key at the login service directly, rather than here, limits your account to developer or viewer powers for 7 days.';
const ADDITIONS = '/v1/auth/passkeys/additions';
const TICKET_PATH = `${ADDITIONS}/${CHALLENGE}/confirm`;
const STATUS_PATH = `${ADDITIONS}/${CHALLENGE}`;

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
/** Each route's answers in turn; the last one repeats. */
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; headers: Headers; body: BodyInit | null | undefined }[];

const refused = (status: number, code: string): Answer => ({ status, body: { error: { code } } });
const ticket = (expiresAt = new Date(Date.now() + 120_000).toISOString()): Answer => ({
  status: 201,
  body: { ticket: TICKET, page: PAGE, expiresAt },
});
const status = (now: string): Answer => ({ status: 200, body: { status: now } });

beforeEach(() => {
  answers = new Map([
    [
      'GET /v1/auth/session',
      [
        {
          status: 200,
          body: {
            userId: ME,
            authenticatedAt: AT,
            methods: ['pwd', 'otp', 'mfa'],
            idleExpiresAt: '2026-11-16T05:30:00.000Z',
            expiresAt: '2026-11-16T17:00:00.000Z',
          },
        },
      ],
    ],
    ['GET /v1/auth/organizations', [{ status: 200, body: { organizations: [ORG], unreadable: [] } }]],
  ]);
  sent = [];
  localStorage.clear();
  sessionStorage.clear();
  vi.mocked(goTo).mockClear();
  vi.useFakeTimers({ shouldAdvanceTime: true });
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      sent.push({ method, path, headers: new Headers(init.headers), body: init.body });
      const queue = answers.get(`${method} ${path.split('?')[0] ?? path}`);
      const found = (queue !== undefined && queue.length > 1 ? queue.shift() : queue?.[0]) ?? refused(404, 'NOT_FOUND');
      return Promise.resolve(new Response(JSON.stringify(found.body ?? {}), { status: found.status }));
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function open(path: string) {
  const router = createConsoleRouter(createMemoryHistory({ initialEntries: [path] }));
  render(<App queries={createQueries()} router={router} />);
  return router;
}

const asked = (method: string, path: string) => sent.filter((one) => one.method === method && one.path === path);
const checks = () => asked('GET', STATUS_PATH).length;
/** Lets the page's next check run. */
const nextCheck = () => act(() => vi.advanceTimersByTimeAsync(CHECK_EVERY_MS));

describe('Your passkeys (SA6)', () => {
  it('is reached from More, says the 7 days always, and says when adding here is switched off', async () => {
    open('/more');
    await userEvent.click(await within(await screen.findByRole('main')).findByRole('link', { name: 'Your passkeys' }));
    expect(await screen.findByRole('heading', { name: 'Your passkeys', level: 1 })).toBeDefined();
    expect(screen.getByText(SEVEN_DAYS)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Add a passkey' }));
    expect(await screen.findByText("Adding a passkey here isn't switched on yet.")).toBeDefined();
    expect(screen.getByText(SEVEN_DAYS)).toBeDefined();
  });

  it('starts with a step-up that comes back to this page with the addition', async () => {
    answers.set(`POST ${ADDITIONS}`, [{ status: 202, body: { stepUpChallengeId: CHALLENGE } }]);
    open('/more/passkeys');
    await userEvent.click(await screen.findByRole('button', { name: 'Add a passkey' }));
    await vi.waitFor(() => {
      expect(goTo).toHaveBeenCalledOnce();
    });
    const [start] = asked('POST', ADDITIONS);
    expect(start?.headers.get('idempotency-key')).toMatch(/^[0-9a-f-]{36}$/);
    expect(start?.body).toBeNull();
    const address = new URL(String(vi.mocked(goTo).mock.calls[0]?.[0]), 'https://app.example.test');
    expect(address.pathname).toBe('/v1/auth/step-up');
    expect(address.searchParams.get('challenge')).toBe(CHALLENGE);
    expect(address.searchParams.get('returnTo')).toBe(`/more/passkeys?adding=${CHALLENGE}`);
  });

  it('refuses an answer that names no step-up, never leaving the page', async () => {
    answers.set(`POST ${ADDITIONS}`, [{ status: 200, body: {} }]);
    open('/more/passkeys');
    await userEvent.click(await screen.findByRole('button', { name: 'Add a passkey' }));
    expect(await screen.findByText(/STEP_UP_NOT_ASKED/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('back from the step-up, gets the page at once and links it in a new tab, kept out of the address and storage', async () => {
    answers.set(`POST ${TICKET_PATH}`, [ticket()]);
    answers.set(`GET ${STATUS_PATH}`, [status('WAITING_FOR_KEY')]);
    const router = open(`/more/passkeys?adding=${CHALLENGE}`);
    const link = await screen.findByRole('link', { name: 'Open the page to make your new passkey' });
    expect(link.getAttribute('href')).toBe(PAGE);
    expect(link.getAttribute('target')).toBe('_blank');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    expect(screen.getByText(SEVEN_DAYS)).toBeDefined();
    const [asking] = asked('POST', TICKET_PATH);
    expect(asking?.headers.get('idempotency-key')).toMatch(/^[0-9a-f-]{36}$/);
    expect(asked('POST', TICKET_PATH)).toHaveLength(1);
    expect(router.state.location.href).not.toContain(TICKET);
    expect(window.location.href).not.toContain(TICKET);
    const stored = [localStorage, sessionStorage].flatMap((storage) =>
      Object.keys(storage).map((key) => `${key}=${storage.getItem(key) ?? ''}`),
    );
    expect(stored.join('\n')).not.toContain(TICKET);
    expect(screen.getByText('Waiting for your new passkey.')).toBeDefined();
  });

  it('checks every few seconds until the passkey is added, then stops and says it signs them out', async () => {
    answers.set(`POST ${TICKET_PATH}`, [ticket()]);
    answers.set(`GET ${STATUS_PATH}`, [status('STEPPED_UP'), status('WAITING_FOR_KEY'), status('ADDED')]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    await screen.findByRole('link', { name: 'Open the page to make your new passkey' });
    expect(checks()).toBe(0);
    await nextCheck();
    await nextCheck();
    expect(checks()).toBe(2);
    expect(screen.getByText('Waiting for your new passkey.')).toBeDefined();
    await nextCheck();
    expect(await screen.findByText('Your new passkey is added.')).toBeDefined();
    expect(screen.getByText(/Agent X signs you out within a few minutes/)).toBeDefined();
    expect(screen.queryByRole('link', { name: 'Open the page to make your new passkey' })).toBeNull();
    await nextCheck();
    await nextCheck();
    expect(checks()).toBe(3);
  });

  it('says a passkey that wasn’t added, offering to start again', async () => {
    answers.set(`POST ${TICKET_PATH}`, [ticket()]);
    answers.set(`GET ${STATUS_PATH}`, [refused(404, 'NOT_FOUND')]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    await screen.findByRole('link', { name: 'Open the page to make your new passkey' });
    await nextCheck();
    expect(await screen.findByText(/Your new passkey wasn't added/)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Start again' })).toBeDefined();
    await nextCheck();
    expect(checks()).toBe(1);
  });

  it('stops checking once signed out, as adding a passkey ends every session', async () => {
    answers.set(`POST ${TICKET_PATH}`, [ticket()]);
    answers.set(`GET ${STATUS_PATH}`, [status('WAITING_FOR_KEY'), refused(401, 'UNAUTHENTICATED')]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    await screen.findByRole('link', { name: 'Open the page to make your new passkey' });
    await nextCheck();
    await nextCheck();
    expect(await screen.findByText(/You're signed out. If you just added a passkey, that is why/)).toBeDefined();
    await nextCheck();
    expect(checks()).toBe(2);
  });

  it('keeps checking past a failure on the way, stops on any other refusal, and stops after ten minutes', async () => {
    answers.set(`POST ${TICKET_PATH}`, [ticket(new Date(Date.now() + CHECK_FOR_MS * 2).toISOString())]);
    answers.set(`GET ${STATUS_PATH}`, [{ status: 503, body: {} }, status('WAITING_FOR_KEY')]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    await screen.findByRole('link', { name: 'Open the page to make your new passkey' });
    await nextCheck();
    await nextCheck();
    expect(checks()).toBe(2);
    await act(() => vi.advanceTimersByTimeAsync(CHECK_FOR_MS));
    expect(await screen.findByText(/Agent X stopped checking/)).toBeDefined();
    const stoppedAt = checks();
    await nextCheck();
    expect(checks()).toBe(stoppedAt);
  });

  it('stops checking on a refusal that asking again won’t change', async () => {
    answers.set(`POST ${TICKET_PATH}`, [ticket()]);
    answers.set(`GET ${STATUS_PATH}`, [refused(403, 'FORBIDDEN')]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    await screen.findByRole('link', { name: 'Open the page to make your new passkey' });
    await nextCheck();
    expect(await screen.findByText(/Agent X stopped checking/)).toBeDefined();
    await nextCheck();
    expect(checks()).toBe(1);
  });

  it('stops checking when the page is left', async () => {
    answers.set(`POST ${TICKET_PATH}`, [ticket()]);
    answers.set(`GET ${STATUS_PATH}`, [status('WAITING_FOR_KEY')]);
    const router = open(`/more/passkeys?adding=${CHALLENGE}`);
    await screen.findByRole('link', { name: 'Open the page to make your new passkey' });
    await act(() => router.navigate({ to: '/more' }));
    await nextCheck();
    expect(checks()).toBe(0);
  });

  it('says the 2 minutes ran out when the page wasn’t opened in time', async () => {
    answers.set(`POST ${TICKET_PATH}`, [ticket(new Date(Date.now() - 1000).toISOString())]);
    answers.set(`GET ${STATUS_PATH}`, [status('STEPPED_UP')]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    expect(await screen.findByText(/The 2 minutes to open the page ran out/)).toBeDefined();
    expect(screen.queryByRole('link', { name: 'Open the page to make your new passkey' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Start again' })).toBeDefined();
  });

  it.each([
    [
      'STEP_UP_FAILED',
      'Signing in again for this passkey ran out or did not go through, so nothing was changed. Start again.',
    ],
    [
      'PASSKEY_TICKET_ALREADY_ISSUED',
      "The page to make your new passkey was already given out for this try and can't be shown again. Start again.",
    ],
  ])('says %s in plain words and offers to start again, checking nothing', async (code, words) => {
    answers.set(`POST ${TICKET_PATH}`, [refused(409, code)]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    expect(await screen.findByText(words)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Start again' })).toBeDefined();
    await nextCheck();
    expect(checks()).toBe(0);
  });

  it('never links an address that isn’t https', async () => {
    answers.set(`POST ${TICKET_PATH}`, [
      { status: 201, body: { ticket: TICKET, page: 'javascript:alert(1)', expiresAt: AT } },
    ]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    expect(
      await screen.findByText("Agent X couldn't be reached, so nothing was changed. Try again in a moment."),
    ).toBeDefined();
    expect(screen.queryByRole('link', { name: 'Open the page to make your new passkey' })).toBeNull();
  });

  it('says signed out when the page can’t be got for that reason', async () => {
    answers.set(`POST ${TICKET_PATH}`, [refused(401, 'UNAUTHENTICATED')]);
    open(`/more/passkeys?adding=${CHALLENGE}`);
    expect(await screen.findByText(/You're signed out/)).toBeDefined();
  });

  it('says a step-up refused needs a passkey already held, and offers to add one again', async () => {
    open(`/more/passkeys?stepUpFailed=${CHALLENGE}`);
    expect(await screen.findByText(/sign in again with a passkey you already have. A password/)).toBeDefined();
    expect(screen.getByText(SEVEN_DAYS)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Add a passkey' })).toBeDefined();
  });

  it('leaves a step-up that failed for another reason to the shell’s own words', async () => {
    open(`/more/passkeys?stepUpFailed=${CHALLENGE}&stepUpWhy=expired`);
    expect(await screen.findByRole('heading', { name: 'Your passkeys', level: 1 })).toBeDefined();
    expect(screen.queryByText(/A password or an app's code can't be used/)).toBeNull();
  });
});

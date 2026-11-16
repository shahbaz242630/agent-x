// 6D1: an agent's new key, shown once. Back from the passkey, the confirm's
// answer carries the key; it is shown masked until "Show", copied by the
// Clipboard API (said copied only once the write is done, and said when it
// fails), and gone after "Done, I've saved it" or leaving the view. Nothing
// keeps it: not either storage, the query cache, the address, a log or any
// request sent after. A retry of the same confirm (key null) says it can't be
// shown again; a confirm that gives no key (a revoke) shows none.
import { createMemoryHistory } from '@tanstack/react-router';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const AGENT = '0199a0f0-0000-7000-8000-0000000000c1';
const KEY = '0199a0f0-0000-7000-8000-0000000000f1';
const NEW_KEY = '0199a0f0-0000-7000-8000-0000000000f9';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const SECRET = `axk_${NEW_KEY.replaceAll('-', '')}_S3cr3tT0k3nN0b0dyM4yKeep`;
const ROTATE = `/v1/agents/${AGENT}/keys/${KEY}/rotate/confirm`;
const REVOKE = `/v1/agents/${AGENT}/keys/${KEY}/revoke/confirm`;
const LABEL = `Rotate key ${KEY} of Invoice agent`;

const agentRead = {
  agent: {
    id: AGENT,
    name: 'Invoice agent',
    owner: '0199a0f0-0000-7000-8000-0000000000b1',
    status: 'ACTIVE',
    scopes: ['requests:write'],
    createdAt: '2026-10-26T05:00:00.000Z',
  },
  keys: [
    { id: KEY, status: 'REVOKED', scopes: ['requests:write'], expiresAt: '2099-01-01T00:00:00.000Z' },
    { id: NEW_KEY, status: 'ACTIVE', scopes: ['requests:write'], expiresAt: '2099-01-01T00:00:00.000Z' },
  ],
};

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer>;
let sent: { method: string; path: string; body: unknown }[];
let logged: { readonly mock: { readonly calls: unknown[][] } }[];

beforeEach(() => {
  sent = [];
  localStorage.clear();
  sessionStorage.clear();
  answers = new Map<string, Answer>([
    [
      'GET /v1/auth/session',
      {
        status: 200,
        body: {
          userId: '0199a0f0-0000-7000-8000-000000000011',
          authenticatedAt: '2026-10-26T05:00:00.000Z',
          methods: ['pwd', 'user', 'mfa'],
          idleExpiresAt: '2026-10-26T05:30:00.000Z',
          expiresAt: '2026-10-26T17:00:00.000Z',
        },
      },
    ],
    ['GET /v1/auth/organizations', { status: 200, body: { organizations: [ORG], unreadable: [] } }],
    ['GET /v1/members', { status: 200, body: { members: [] } }],
    [`GET /v1/agents/${AGENT}`, { status: 200, body: agentRead }],
    ['GET /v1/agents', { status: 200, body: { agents: [agentRead.agent], next: null, unchecked: [] } }],
    [`POST ${ROTATE}`, { status: 201, body: { ...agentRead, key: SECRET, oldKey: 'end_now' } }],
    [`POST ${REVOKE}`, { status: 200, body: agentRead }],
  ]);
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, body });
      const { status, body: reply } = answers.get(`${method} ${path.split('?')[0] ?? path}`) ?? {
        status: 404,
        body: { error: { code: 'NOT_FOUND' } },
      };
      return Promise.resolve(new Response(JSON.stringify(reply ?? {}), { status }));
    }),
  );
  logged = (['log', 'info', 'warn', 'error', 'debug'] as const).map((level) => vi.spyOn(console, level));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** Comes back from the passkey to the agent's page, the change kept for the challenge. */
function backFromStepUp(
  confirmPath = ROTATE,
  body: Record<string, unknown> = { oldKey: 'end_now', statementVersion: 1 },
) {
  sessionStorage.setItem(
    `agentx.step-up.${CHALLENGE}`,
    JSON.stringify({
      challenge: CHALLENGE,
      label: LABEL,
      confirmPath,
      body,
      organization: ORG.id,
      idempotencyKey: '0199a0f0-0000-4000-8000-00000000c0de',
    }),
  );
  const history = createMemoryHistory({ initialEntries: [`/agents/${AGENT}?org=${ORG.id}&stepped=${CHALLENGE}`] });
  const queries = createQueries();
  render(<App queries={queries} router={createConsoleRouter(history)} />);
  return { history, queries };
}

async function confirmed() {
  await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
  return screen.findByRole('heading', { name: "The agent's new key" });
}

/** Puts a clipboard in the page whose write does what `writeText` does. */
function clipboard(writeText: (text: string) => Promise<void>) {
  const write = vi.fn(writeText);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: write }, configurable: true });
  return write;
}

/** Everything the page could have kept or sent, which must never hold the key. */
function nothingKept(history: ReturnType<typeof createMemoryHistory>, queries: ReturnType<typeof createQueries>) {
  const stored = [sessionStorage, localStorage].flatMap((storage) =>
    Array.from(
      { length: storage.length },
      (_, at) => `${storage.key(at) ?? ''}=${storage.getItem(storage.key(at) ?? '') ?? ''}`,
    ),
  );
  expect(stored.join('\n')).not.toContain(SECRET);
  expect(sessionStorage).toHaveLength(0);
  const cached = queries
    .getQueryCache()
    .getAll()
    .map((query) => query.state.data);
  expect(JSON.stringify(cached)).not.toContain(SECRET);
  expect(
    JSON.stringify(
      queries
        .getMutationCache()
        .getAll()
        .map((mutation) => mutation.state),
    ),
  ).not.toContain(SECRET);
  expect(history.location.href).not.toContain(SECRET);
  expect(JSON.stringify(sent.map((one) => [one.path, one.body]))).not.toContain(SECRET);
  for (const level of logged) expect(JSON.stringify(level.mock.calls)).not.toContain(SECRET);
}

describe('a new key, shown once (6D1)', () => {
  it('confirms the rotation and shows its new key masked, shown only on asking', async () => {
    backFromStepUp();
    await confirmed();

    expect(sent.find((one) => one.path === ROTATE)?.body).toEqual({
      oldKey: 'end_now',
      statementVersion: 1,
      stepUpChallengeId: CHALLENGE,
    });
    expect(screen.getByText(`Done: ${LABEL}`)).toBeDefined();
    expect(screen.getByText(/the only time Agent X shows this key/)).toBeDefined();
    expect(screen.queryByText(SECRET)).toBeNull();
    expect(screen.getByLabelText('The key, hidden').textContent).not.toContain('axk_');

    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    expect(screen.getByText(SECRET)).toBeDefined();
    expect(screen.getByRole('button', { name: 'Hide' }).getAttribute('aria-pressed')).toBe('true');
    await userEvent.click(screen.getByRole('button', { name: 'Hide' }));
    expect(screen.queryByText(SECRET)).toBeNull();
    // No close but Done: the key isn't dismissed by a press meant for something else.
    expect(screen.queryByRole('button', { name: 'Close' })).toBeNull();
  });

  it('copies the key, saying so only once the clipboard has it', async () => {
    let done: () => void = () => undefined;
    const write = clipboard(
      () =>
        new Promise<void>((resolve) => {
          done = resolve;
        }),
    );
    backFromStepUp();
    await confirmed();

    fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    expect(write).toHaveBeenCalledWith(SECRET);
    expect(screen.queryByText('Key copied.')).toBeNull();
    await act(async () => {
      done();
      await Promise.resolve();
    });
    expect(await screen.findByText('Key copied.')).toBeDefined();
  });

  it.each([
    ['refuses the write', () => clipboard(() => Promise.reject(new DOMException('Denied', 'NotAllowedError')))],
    ['has no clipboard', () => Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })],
  ])('says the key wasn’t copied when the browser %s', async (_what, given) => {
    given();
    backFromStepUp();
    await confirmed();
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    expect(await screen.findByText(/The key couldn't be copied here/)).toBeDefined();
    expect(screen.queryByText('Key copied.')).toBeNull();
  });

  it('keeps the key nowhere: no storage, query cache, address, log or request holds it', async () => {
    clipboard(() => Promise.resolve());
    const { history, queries } = backFromStepUp();
    await confirmed();
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    expect(await screen.findByText('Key copied.')).toBeDefined();
    // The agent read again after the change: its keys, never the key itself.
    expect(await screen.findByText(NEW_KEY)).toBeDefined();

    nothingKept(history, queries);
  });

  it('is gone after Done, the address cleaned and the agent’s page as it was', async () => {
    const { history, queries } = backFromStepUp();
    await confirmed();
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));

    await userEvent.click(screen.getByRole('button', { name: "Done, I've saved it" }));

    expect(screen.queryByText(SECRET)).toBeNull();
    expect(screen.queryByRole('heading', { name: "The agent's new key" })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Show' })).toBeNull();
    expect(history.location.pathname).toBe(`/agents/${AGENT}`);
    expect(history.location.search).toBe(`?org=${ORG.id}`);
    expect(await screen.findByRole('heading', { name: 'Invoice agent' })).toBeDefined();
    nothingKept(history, queries);
  });

  it('asks before a link inside the console leaves it behind: kept on staying, gone on leaving, not back on returning', async () => {
    const { history } = backFromStepUp();
    await confirmed();
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));

    await userEvent.click(screen.getByRole('link', { name: 'Back to agents' }));
    expect(await screen.findByText(/Leave without saving the key\?/)).toBeDefined();
    expect(document.activeElement?.textContent).toBe('Stay and save it');
    await userEvent.click(screen.getByRole('button', { name: 'Stay and save it' }));
    expect(screen.queryByText(/Leave without saving the key\?/)).toBeNull();
    expect(screen.getByText(SECRET)).toBeDefined();
    expect(history.location.pathname).toBe(`/agents/${AGENT}`);
    expect(history.location.search).toContain(`stepped=${CHALLENGE}`);

    // A tab is a link too.
    await userEvent.click(screen.getByRole('link', { name: 'Payments' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Leave without it' }));
    expect(screen.queryByText(SECRET)).toBeNull();
    expect(history.location.pathname).toBe('/payments');

    await userEvent.click(screen.getByRole('link', { name: 'Agents' }));
    await userEvent.click(await screen.findByRole('link', { name: 'Invoice agent' }));
    expect(await screen.findByRole('heading', { name: 'Invoice agent' })).toBeDefined();
    expect(screen.queryByRole('heading', { name: "The agent's new key" })).toBeNull();
    expect(screen.queryByText(SECRET)).toBeNull();
  });

  it('holds switching organisation while the key is on screen, and lets it go after Done', async () => {
    answers.set('GET /v1/auth/organizations', {
      status: 200,
      body: {
        organizations: [ORG, { ...ORG, id: '0199a0f0-0000-7000-8000-00000000bbbb', name: 'Other' }],
        unreadable: [],
      },
    });
    localStorage.setItem('agentx.organization', ORG.id);
    backFromStepUp();
    await confirmed();
    const switcher = screen.getByRole('button', { name: 'Switch organisation' });
    expect(switcher.hasAttribute('disabled')).toBe(true);
    expect(switcher.getAttribute('title')).toMatch(/press Done before switching/);

    await userEvent.click(screen.getByRole('button', { name: "Done, I've saved it" }));
    expect(screen.getByRole('button', { name: 'Switch organisation' }).hasAttribute('disabled')).toBe(false);
  });

  it('clears the key when the page is hidden (closed, or kept for Back), so returning never shows it', async () => {
    const { history } = backFromStepUp();
    await confirmed();
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));

    act(() => {
      window.dispatchEvent(new Event('pagehide'));
    });

    // Cleared at once, before the page could be kept: no key in the document.
    expect(screen.queryByText(SECRET)).toBeNull();
    expect(document.body.innerHTML).not.toContain(SECRET);
    expect(screen.queryByRole('heading', { name: "The agent's new key" })).toBeNull();
    expect(await screen.findByRole('heading', { name: 'Invoice agent' })).toBeDefined();
    expect(history.location.search).toBe(`?org=${ORG.id}`);
    expect(screen.queryByText(/Leave without saving the key\?/)).toBeNull();
  });

  it('asks before the page is left or reloaded while the key is on screen, and not after Done', async () => {
    backFromStepUp();
    await confirmed();
    const leaving = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(leaving);
    expect(leaving.defaultPrevented).toBe(true);

    await userEvent.click(screen.getByRole('button', { name: "Done, I've saved it" }));
    const later = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(later);
    expect(later.defaultPrevented).toBe(false);
  });

  it('says a key made on an earlier try can’t be shown again (a retry answers it null)', async () => {
    answers.set(`POST ${ROTATE}`, { status: 201, body: { ...agentRead, key: null, oldKey: 'end_now' } });
    const { history } = backFromStepUp();
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));

    expect(await screen.findByText(/made on your first try and can't be shown again/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Copy' })).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(history.location.search).toBe(`?org=${ORG.id}`);
  });

  it('shows no key for a change that gives none (a revoke)', async () => {
    backFromStepUp(REVOKE, {});
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));

    expect(await screen.findByText(`Done: ${LABEL}`)).toBeDefined();
    expect(screen.queryByRole('heading', { name: "The agent's new key" })).toBeNull();
    expect(sent.find((one) => one.path === REVOKE)?.body).toEqual({ stepUpChallengeId: CHALLENGE });
  });
});

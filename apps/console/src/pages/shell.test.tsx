// CO11 (Calm Ledger): the signed-in frame's one navigation (grouped by what a
// role may open), the Ctrl+K command bar over the same places, and the public
// front page with its one way in and its notes (late, ended, signed out).
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';
import { markSignedOut } from './signed-out.tsx';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const SESSION = {
  userId: '0199a0f0-0000-7000-8000-000000000011',
  authenticatedAt: '2026-10-26T05:00:00.000Z',
  methods: ['pwd', 'user', 'mfa'],
  idleExpiresAt: '2026-10-26T05:30:00.000Z',
  expiresAt: '2026-10-26T17:00:00.000Z',
};
const org = (role: string) => ({
  id: '0199a0f0-0000-7000-8000-00000000aaaa',
  name: 'Staging Test Org',
  role,
  frozen: false,
});

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

const signedInAs = (role: string) => {
  answers = {
    'GET /v1/auth/session': { status: 200, body: SESSION },
    'GET /v1/auth/organizations': { status: 200, body: { organizations: [org(role)], unreadable: [] } },
  };
};

const signedOut = () => {
  answers = { 'GET /v1/auth/session': { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } } };
};

function open(path: string) {
  const router = createConsoleRouter(createMemoryHistory({ initialEntries: [path] }));
  render(<App queries={createQueries()} router={router} />);
  return router;
}

const sections = async () => within(await screen.findByRole('navigation', { name: 'Sections' }));

describe('the sidebar (CO11)', () => {
  it('shows an admin every place, in its groups, the page open marked', async () => {
    signedInAs('admin');
    open('/payments');
    const nav = await sections();
    for (const group of ['Work', 'Control', 'People', 'Records', 'Organisation'])
      expect(nav.getByText(group)).toBeDefined();
    for (const place of [
      'Approvals',
      'Payments',
      'Agents',
      'Mandates',
      'Organisation policy',
      'Suppliers',
      'Bank accounts',
    ]) {
      expect(nav.getByRole('link', { name: place })).toBeDefined();
    }
    for (const place of [
      'Members',
      'Audit log',
      'Access log',
      'Security events',
      'Integrity hold',
      'My activity',
      'More',
    ]) {
      expect(nav.getByRole('link', { name: place })).toBeDefined();
    }
    expect(nav.getByRole('link', { name: 'Payments' }).getAttribute('aria-current')).toBe('page');
    expect(nav.getByRole('link', { name: 'Approvals' }).getAttribute('aria-current')).toBeNull();
  });

  it.each(['approver', 'developer', 'viewer'])('shows a %s no way to the logs or the integrity hold', async (role) => {
    signedInAs(role);
    open('/approvals');
    const nav = await sections();
    expect(nav.getByRole('link', { name: 'My activity' })).toBeDefined();
    for (const place of ['Audit log', 'Access log', 'Security events', 'Integrity hold']) {
      expect(nav.queryByRole('link', { name: place })).toBeNull();
    }
  });

  it('lights More on its own page alone, and a list under it by its own place', async () => {
    signedInAs('admin');
    open('/more/suppliers');
    const nav = await sections();
    expect(nav.getByRole('link', { name: 'Suppliers' }).getAttribute('aria-current')).toBe('page');
    expect(nav.getByRole('link', { name: 'More' }).getAttribute('aria-current')).toBeNull();
  });

  it('marks the four phone tabs, and names the organisation with the role', async () => {
    signedInAs('approver');
    open('/approvals');
    const nav = await sections();
    const tabs = nav.getAllByRole('link').filter((link) => link.classList.contains('tab-place'));
    expect(tabs.map((link) => link.textContent)).toEqual(['Approvals', 'Payments', 'Agents', 'More']);
    const side = within(screen.getByRole('complementary'));
    expect(side.getByText('Staging Test Org')).toBeDefined();
    expect(side.getByText('Approver')).toBeDefined();
  });
});

describe('the command bar (CO11)', () => {
  it('opens on Ctrl+K, narrows as typed, and goes to the place on Enter', async () => {
    signedInAs('admin');
    const router = open('/approvals');
    await sections();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const search = await screen.findByRole('combobox', { name: 'Search pages' });
    expect(within(screen.getByRole('listbox')).getAllByRole('option')).toHaveLength(14);
    await userEvent.type(search, 'audit');
    const options = within(screen.getByRole('listbox')).getAllByRole('option');
    expect(options.map((option) => option.textContent)).toEqual(['Audit logRecords']);
    expect(options[0]?.getAttribute('aria-selected')).toBe('true');
    await userEvent.keyboard('{Enter}');
    expect(await screen.findByRole('heading', { name: 'Audit log' })).toBeDefined();
    expect(router.state.location.pathname).toBe('/more/audit-log');
    expect(screen.queryByRole('dialog', { name: 'Go to' })).toBeNull();
  });

  it('opens on ⌘K and from the button, moves with the arrows, and closes on Escape', async () => {
    signedInAs('admin');
    const router = open('/approvals');
    await sections();
    fireEvent.keyDown(window, { key: 'K', metaKey: true });
    const search = await screen.findByRole('combobox');
    await userEvent.type(search, 'log');
    // Audit log and Access log: two, the first chosen.
    expect(within(screen.getByRole('listbox')).getAllByRole('option')).toHaveLength(2);
    await userEvent.keyboard('{ArrowDown}');
    expect(screen.getAllByRole('option')[1]?.getAttribute('aria-selected')).toBe('true');
    await userEvent.keyboard('{ArrowDown}');
    expect(screen.getAllByRole('option')[0]?.getAttribute('aria-selected')).toBe('true');
    await userEvent.keyboard('{ArrowUp}{Enter}');
    expect(router.state.location.pathname).toBe('/more/access-log');
    await userEvent.click(screen.getByRole('button', { name: /Go to a page/ }));
    const reopened = screen.getByRole('dialog', { name: 'Go to' });
    fireEvent(reopened, new Event('cancel', { cancelable: true }));
    expect(screen.queryByRole('dialog', { name: 'Go to' })).toBeNull();
  });

  it('offers no page a role may not open, and says when nothing matches', async () => {
    signedInAs('viewer');
    open('/approvals');
    await sections();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const search = await screen.findByRole('combobox');
    await userEvent.type(search, 'audit');
    expect(screen.queryAllByRole('option')).toHaveLength(0);
    expect(screen.getByText('No page matches. Try another word.')).toBeDefined();
    await userEvent.keyboard('{ArrowDown}{Enter}');
    expect(screen.getByRole('combobox')).toBeDefined();
  });

  it('closes when the backdrop is clicked, and a second Ctrl+K closes it too', async () => {
    signedInAs('admin');
    open('/approvals');
    await sections();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    await userEvent.click(await screen.findByRole('dialog', { name: 'Go to' }));
    expect(screen.queryByRole('dialog', { name: 'Go to' })).toBeNull();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(await screen.findByRole('dialog', { name: 'Go to' })).toBeDefined();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(screen.queryByRole('dialog', { name: 'Go to' })).toBeNull();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true, shiftKey: true });
    expect(screen.queryByRole('dialog', { name: 'Go to' })).toBeNull();
  });

  it('goes to a place clicked in the list', async () => {
    signedInAs('admin');
    const router = open('/approvals');
    await sections();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const option = (await screen.findAllByRole('option')).find((item) => item.textContent.startsWith('Suppliers'));
    if (option === undefined) throw new Error('no Suppliers option');
    fireEvent.mouseMove(option);
    expect(option.getAttribute('aria-selected')).toBe('true');
    await userEvent.click(option);
    expect(router.state.location.pathname).toBe('/more/suppliers');
  });
});

describe('the command bar beside other modals and keyboards (S216 review)', () => {
  it('never opens over another open modal (the shared confirm), so the page behind stays inert', async () => {
    signedInAs('admin');
    open('/approvals');
    await sections();
    const confirm = document.createElement('dialog');
    confirm.setAttribute('open', '');
    document.body.append(confirm);
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(screen.queryByRole('dialog', { name: 'Go to' })).toBeNull();
    confirm.remove();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(await screen.findByRole('dialog', { name: 'Go to' })).toBeDefined();
  });

  it('gives focus back to its button when the shortcut closes it', async () => {
    signedInAs('admin');
    open('/approvals');
    await sections();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    await screen.findByRole('dialog', { name: 'Go to' });
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(document.activeElement).toBe(screen.getByRole('button', { name: /Go to a page/ }));
  });

  it('names the key a Mac has', async () => {
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)');
    signedInAs('admin');
    open('/approvals');
    await sections();
    expect(screen.getByRole('button', { name: /Go to a page/ }).textContent).toContain('⌘ K');
    vi.restoreAllMocks();
  });

  it('lets a member of several organisations switch from More, as a phone has no sidebar switch', async () => {
    answers = {
      'GET /v1/auth/session': { status: 200, body: SESSION },
      'GET /v1/auth/organizations': {
        status: 200,
        body: {
          organizations: [
            org('admin'),
            { ...org('viewer'), id: '0199a0f0-0000-7000-8000-00000000bbbb', name: 'Other Org' },
          ],
          unreadable: [],
        },
      },
    };
    localStorage.setItem('agentx.organization', '0199a0f0-0000-7000-8000-00000000aaaa');
    open('/more');
    await userEvent.click(
      await within(await screen.findByRole('main')).findByRole('button', { name: 'Switch organisation' }),
    );
    expect(await screen.findByText('Choose an organisation')).toBeDefined();
  });

  it('offers no switch on More to a member of one organisation', async () => {
    signedInAs('admin');
    open('/more');
    await screen.findByRole('heading', { name: 'More' });
    expect(screen.queryByRole('button', { name: 'Switch organisation' })).toBeNull();
  });
});

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

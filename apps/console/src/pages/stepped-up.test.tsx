// 6A2: back from signing in again (`?stepped=<challenge>`), the shell shows
// the change kept for it to confirm or not; the address is cleaned after;
// one with nothing kept, a refusal and a failure on the way are each said.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const PENDING = {
  challenge: CHALLENGE,
  label: 'Freeze Staging-Test-Org-1, pausing its requests',
  confirmPath: '/v1/organization/freeze/confirm',
  body: { pendingRequests: 'pause' },
  organization: ORG.id,
  idempotencyKey: '0199a0f0-0000-4000-8000-00000000c0de',
};

let confirmAnswer: () => Promise<Response>;
let confirms: number;

const json = (status: number, body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status }));

beforeEach(() => {
  confirms = 0;
  sessionStorage.clear();
  localStorage.clear();
  confirmAnswer = () => json(200, { frozen: true });
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string) => {
      if (path === '/v1/auth/session') {
        return json(200, {
          userId: '0199a0f0-0000-7000-8000-000000000011',
          authenticatedAt: '2026-10-26T05:00:00.000Z',
          methods: ['pwd', 'user', 'mfa'],
          idleExpiresAt: '2026-10-26T05:30:00.000Z',
          expiresAt: '2026-10-26T17:00:00.000Z',
        });
      }
      if (path === '/v1/auth/organizations') return json(200, { organizations: [ORG], unreadable: [] });
      if (path === PENDING.confirmPath) {
        confirms += 1;
        return confirmAnswer();
      }
      return json(404, { error: { code: 'NOT_FOUND' } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function backFromStepUp(kept = true) {
  if (kept) sessionStorage.setItem(`agentx.step-up.${CHALLENGE}`, JSON.stringify(PENDING));
  const history = createMemoryHistory({ initialEntries: [`/more?stepped=${CHALLENGE}`] });
  render(<App queries={createQueries()} router={createConsoleRouter(history)} />);
  return history;
}

describe('back from a step-up', () => {
  it('shows the change to confirm, confirms it, says so and cleans the address', async () => {
    const history = backFromStepUp();

    expect(await screen.findByText(PENDING.label)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    expect(await screen.findByText(`Done: ${PENDING.label}`)).toBeDefined();
    expect(confirms).toBe(1);
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(history.location.search).toBe('');
    expect(screen.queryByText(`Done: ${PENDING.label}`)).toBeNull();
  });

  it('makes no change when the person chooses not to, and forgets it', async () => {
    const history = backFromStepUp();

    await userEvent.click(await screen.findByRole('button', { name: "Don't make it" }));

    expect(confirms).toBe(0);
    expect(sessionStorage).toHaveLength(0);
    expect(history.location.search).toBe('');
  });

  it('says a change the API refused was not made', async () => {
    confirmAnswer = () => json(403, { error: { code: 'STEP_UP_FAILED' } });
    backFromStepUp();

    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));

    expect(await screen.findByText(/Agent X didn't make this change/)).toBeDefined();
  });

  it('says a failure on the way, and the change can be confirmed again', async () => {
    confirmAnswer = () => json(503, { error: { code: 'UNAVAILABLE' } });
    backFromStepUp();

    await userEvent.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      expect.stringContaining('Try confirming again'),
    );
    confirmAnswer = () => json(200, { frozen: true });
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    expect(await screen.findByText(`Done: ${PENDING.label}`)).toBeDefined();
    expect(confirms).toBe(2);
  });

  it('says a change with nothing kept for it was not made', async () => {
    const history = backFromStepUp(false);

    expect(await screen.findByText(/can't be found in this window/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(history.location.search).toBe('');
  });
});

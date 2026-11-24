// 6E1a (CO8, PL-48): My activity in the console, against a stand-in API.
// Every signed-in person reaches it from More, whatever their role; it reads
// their own log with no organisation named, newest first, sealed rows marked,
// where a request came from folded away as clues; it says that what they did
// inside an organisation is that organisation's log; it lists Agent X's
// exports of their log; and it downloads as CSV or NDJSON, no organisation named.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'viewer', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const CLAIMED = '0199a0f0-0000-7000-8000-00000000c1a1';
const AT = '2026-11-15T05:00:00.000Z';

const row = (overrides: Record<string, unknown> = {}) => ({
  id: '0199a0f0-0000-7000-8000-0000000000f1',
  recordedAt: AT,
  localTime: '2026-11-15T09:00:00.000+04:00',
  claimedOrganizationId: null,
  method: 'GET',
  route: '/v1/auth/session',
  pathIds: [],
  status: 200,
  reason: null,
  correlationId: '0199a0f0-0000-7000-8000-0000000000f2',
  durationMs: 4,
  sealed: true,
  client: {
    ip: '203.0.113.7',
    place: { country: 'AE', city: 'Dubai', approximate: true, by: 'DB-IP', link: 'https://db-ip.com' },
    timeZone: { name: 'Asia/Dubai', from: 'browser' },
  },
  ...overrides,
});

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer>;
let sent: { method: string; path: string; headers: Headers; body: unknown }[];

beforeEach(() => {
  answers = new Map([
    [
      'GET /v1/auth/session',
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
    ['GET /v1/auth/organizations', { status: 200, body: { organizations: [ORG], unreadable: [] } }],
  ]);
  sent = [];
  localStorage.clear();
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(2026, 10, 16, 10));
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, headers: new Headers(init.headers), body });
      const found = answers.get(`${method} ${path.split('?')[0] ?? path}`) ?? {
        status: 404,
        body: { error: { code: 'NOT_FOUND' } },
      };
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

const page = (rows: readonly unknown[], exportsByAgentX: readonly unknown[] = []): Answer => ({
  status: 200,
  body: { rows, next: null, sealedThrough: '2026-11-15', exportsByAgentX },
});

describe('My activity (6E1a)', () => {
  it('is reached from More by anyone signed in, whatever their role', async () => {
    answers.set('GET /v1/auth/activity', page([]));
    open('/more');
    await userEvent.click(await within(await screen.findByRole('main')).findByRole('link', { name: 'My activity' }));
    expect(await screen.findByRole('heading', { name: 'My activity', level: 1 })).toBeDefined();
    expect(await screen.findByText('Nothing in this range matches these filters.')).toBeDefined();
    expect(await screen.findByText('Agent X has never exported your activity.')).toBeDefined();
  });

  it('reads the person’s own log with no organisation named, its rows sealed and their clues folded away', async () => {
    answers.set(
      'GET /v1/auth/activity',
      page(
        [
          row(),
          row({
            id: '0199a0f0-0000-7000-8000-0000000000f3',
            sealed: false,
            claimedOrganizationId: CLAIMED,
            status: 403,
            reason: 'FORBIDDEN',
          }),
        ],
        [
          {
            id: '0199a0f0-0000-7000-8000-0000000000e1',
            at: AT,
            from: '2026-11-01T00:00:00.000Z',
            to: '2026-11-15T00:00:00.000Z',
            requests: 2,
            caseRef: 'DSP-1',
          },
        ],
      ),
    );
    open('/more/my-activity');

    expect(await screen.findByText(/inside an organisation is in that organisation's own access log/)).toBeDefined();
    expect(await screen.findAllByText('GET /v1/auth/session')).toHaveLength(2);
    expect(screen.getAllByText('Sealed')).toHaveLength(1);
    expect(screen.getByText(CLAIMED)).toBeDefined();
    expect(screen.getAllByText('Where it came from')).toHaveLength(2);
    expect(screen.getByText(/case DSP-1/)).toBeDefined();
    const read = sent.find((one) => one.path.startsWith('/v1/auth/activity?'));
    expect(read?.headers.get('agentx-organization')).toBeNull();
  });

  it('downloads the person’s own log, naming no organisation, and says a refusal in plain words', async () => {
    answers.set('GET /v1/auth/activity', page([]));
    answers.set('POST /v1/auth/activity/exports', {
      status: 409,
      body: { error: { code: 'ACTIVITY_EXPORT_TOO_LARGE' } },
    });
    open('/more/my-activity');

    await userEvent.click(await screen.findByRole('button', { name: "Download what's shown" }));

    expect(await screen.findByText(/more than 50,000 requests/)).toBeDefined();
    const asked = sent.find((one) => one.method === 'POST' && one.path === '/v1/auth/activity/exports');
    expect(asked?.headers.get('agentx-organization')).toBeNull();
    expect(asked?.body).toMatchObject({ format: 'csv' });
    expect(Object.keys(asked?.body as object).sort()).toEqual(['format', 'from', 'to']);
  });
  it.each([
    ['ACTIVITY_EXPORTS_SPENT', 409, /downloads of your activity as you may for now: 5 an hour, 20 a day/],
    ['ACTIVITY_EXPORTS_BUSY', 503, /making another download right now/],
  ])('says %s in plain words', async (code, status, words) => {
    answers.set(
      'GET /v1/auth/activity',
      page(
        [row({ localTime: null })],
        [{ id: '0199a0f0-0000-7000-8000-0000000000e2', at: AT, from: null, to: null, requests: null, caseRef: null }],
      ),
    );
    answers.set('POST /v1/auth/activity/exports', { status, body: { error: { code } } });
    open('/more/my-activity');

    expect(await screen.findByText(/\? to \?, \? requests/)).toBeDefined();
    await userEvent.click(await screen.findByRole('button', { name: "Download what's shown" }));

    expect(await screen.findByText(words)).toBeDefined();
  });
});

// 6C2: the audit log and the access log in the console, against a stand-in
// API. Admins only, reached from More. The range defaults to the last 7 days;
// every filter (dates, actions, person, object: CO7) lives in the address, so a
// reload keeps it; newest first, older pages by `before`. Each event says when,
// what, who and about what, its facts folded and its hashes shown; its actor or
// object narrows the log in one press. Downloads as CSV or NDJSON send the
// filters and save the file the answer carries; a long access log range is
// built in the background and its month files read a part at a time, saved
// only when their SHA-256 matches. Refusals in plain words.
import { createHash } from 'node:crypto';

import { createMemoryHistory } from '@tanstack/react-router';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const REQUEST = '0199a0f0-0000-7000-8000-0000000000a1';
const AGENT = '0199a0f0-0000-7000-8000-0000000000c1';
const DOWNLOAD = '0199a0f0-0000-7000-8000-0000000000d7';
const FILE = '0199a0f0-0000-7000-8000-0000000000d8';
const AT = '2026-11-15T05:00:00.000Z';

/** Midnight in the browser's own zone, as the screens send a range: `day` is the month's day, November 2026. */
const midnight = (day: number) => new Date(2026, 10, day).toISOString();
/** The default range on 16 November: the 9th to the end of the 16th. */
const DEFAULT = `from=${encodeURIComponent(midnight(9))}&to=${encodeURIComponent(midnight(17))}`;

const ADMIN = { type: 'user', id: ME, name: 'Shahbaz Admin', email: 'admin@example.com', shownFrom: 'login_service' };

const logEvent = (seq: string, overrides: Record<string, unknown> = {}) => ({
  seq,
  id: `0199a0f0-0000-7000-8000-0000000${seq.padStart(5, '0')}`,
  recordedAt: AT,
  actor: ADMIN,
  action: 'spend_request.approved',
  subject: { type: 'spend_request', id: REQUEST, version: 2 },
  details: [
    { name: 'statementVersion', value: 3 },
    { name: 'reason', value: null },
  ],
  hash: 'aa'.repeat(32),
  prevHash: 'bb'.repeat(32),
  ...overrides,
});

const activity = (overrides: Record<string, unknown> = {}) => ({
  id: '0199a0f0-0000-7000-8000-0000000000f1',
  recordedAt: AT,
  localTime: '2026-11-15T09:00:00.000+04:00',
  actor: { type: 'agent', id: AGENT, name: 'Phase 4 demo agent', email: null, shownFrom: 'agent' },
  agentKeyId: null,
  method: 'POST',
  route: '/v1/spend-requests',
  pathIds: [REQUEST],
  status: 409,
  reason: 'ORG_FROZEN',
  correlationId: '0199a0f0-0000-7000-8000-0000000000f2',
  durationMs: 12,
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
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown }[];

/** Answers `method path` with these in turn, the last one again after. */
const answer = (key: string, ...given: Answer[]) => answers.set(key, given);
const refusal = (status: number, code: string): Answer => ({ status, body: { error: { code } } });

function signedIn(role = 'admin') {
  answer('GET /v1/auth/session', {
    status: 200,
    body: {
      userId: ME,
      authenticatedAt: AT,
      methods: ['pwd', 'user', 'mfa'],
      idleExpiresAt: '2026-11-16T05:30:00.000Z',
      expiresAt: '2026-11-16T17:00:00.000Z',
    },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  localStorage.clear();
  // Today is 16 November 2026 in the browser's own calendar: the default range is counted from it.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(2026, 10, 16, 10));
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, body });
      const queue = answers.get(`${method} ${path.split('?')[0] ?? path}`);
      const next = queue === undefined ? undefined : queue.length > 1 ? queue.shift() : queue[0];
      const { status, body: reply } = next ?? refusal(404, 'NOT_FOUND');
      return Promise.resolve(new Response(JSON.stringify(reply ?? {}), { status }));
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

const sentTo = (method: string, path: string) => sent.filter((one) => one.method === method && one.path === path);

/** The one found, which the test has just looked for. */
function found<T>(one: T | null | undefined): T {
  if (one === null || one === undefined) throw new Error('Nothing found');
  return one;
}
const events = (list: readonly unknown[], next: string | null = null): Answer => ({
  status: 200,
  body: { events: list, next },
});
const rows = (list: readonly unknown[], next: string | null = null): Answer => ({
  status: 200,
  body: { rows: list, next, sealedThrough: '2026-11-15' },
});

/** Files saved, with the name and type each was saved as: jsdom makes no object URLs. */
function saving() {
  const made: Blob[] = [];
  const names: string[] = [];
  vi.stubGlobal('URL', {
    createObjectURL: vi.fn((file: Blob) => {
      made.push(file);
      return 'blob:file';
    }),
    revokeObjectURL: vi.fn(),
  });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click(this: HTMLAnchorElement) {
    names.push(this.download);
  });
  return { made, names };
}

describe('reaching the logs (6C2)', () => {
  it('shows an admin both logs under More', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    open('/more');
    await userEvent.click(await screen.findByRole('link', { name: 'Audit log' }));
    expect(await screen.findByRole('heading', { name: 'Audit log' })).toBeDefined();
    expect(await screen.findByText('Nothing in this range matches these filters.')).toBeDefined();
    cleanup();
    open('/more');
    expect((await screen.findByRole('link', { name: 'Access log' })).getAttribute('href')).toBe('/more/access-log');
  });

  it('shows no one else a way to them, and reads nothing for them on the pages themselves', async () => {
    signedIn('approver');
    open('/more');
    expect(await screen.findByRole('heading', { name: 'More' })).toBeDefined();
    expect(screen.queryByRole('link', { name: 'Audit log' })).toBeNull();
    cleanup();
    open('/more/audit-log');
    expect(await screen.findByText(/Only an admin can see this organisation's logs/)).toBeDefined();
    cleanup();
    open('/more/access-log');
    expect(await screen.findByText(/Only an admin can see this organisation's logs/)).toBeDefined();
    expect(sent.filter((one) => one.path.includes('-log'))).toHaveLength(0);
  });
});

describe('the audit log (6C2, CO7)', () => {
  it('reads the last 7 days by default, newest first', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([logEvent('42'), logEvent('41', { action: 'mandate.accepted' })]));
    open('/more/audit-log');
    const listed = await screen.findAllByRole('listitem');
    expect(listed.map((item) => item.querySelector('.mono')?.textContent)).toEqual([
      'spend_request.approved',
      'mandate.accepted',
    ]);
    expect(sentTo('GET', `/v1/audit-log?${DEFAULT}`)).toHaveLength(1);
    expect(screen.getByLabelText<HTMLInputElement>('From').value).toBe('2026-11-09');
    expect(screen.getByLabelText<HTMLInputElement>('To (including this day)').value).toBe('2026-11-16');
  });

  it('shows each event: when, what, who, about what, its facts folded away and its chain hashes', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([logEvent('42')]));
    open('/more/audit-log');
    const item = await screen.findByRole('listitem');
    expect(within(item).getByText(/#42/)).toBeDefined();
    expect(within(item).getByText(/By Shahbaz Admin \(admin@example.com\)/)).toBeDefined();
    expect(within(item).getByText(REQUEST)).toBeDefined();
    const facts = found(item.querySelector('details'));
    expect(facts.open).toBe(false);
    expect(within(facts).getByText('Facts sealed with it (2)')).toBeDefined();
    expect(within(facts).getByText('statementVersion').nextElementSibling?.textContent).toBe('3');
    expect(within(facts).getByText('reason').nextElementSibling?.textContent).toBe('—');
    expect(item.querySelector('.hashes')?.textContent).toBe(`Hash ${'aa'.repeat(32)}Before it ${'bb'.repeat(32)}`);
  });

  it('names an actor with no name by what they are, and leaves out facts an event has none of', async () => {
    signedIn();
    answer(
      'GET /v1/audit-log',
      events([logEvent('9', { actor: { type: 'system', id: 'worker', name: null, email: null }, details: [] })]),
    );
    open('/more/audit-log');
    const item = await screen.findByRole('listitem');
    expect(within(item).getByText(/By Agent X/).textContent).toMatch(/^By Agent X worker/);
    expect(item.querySelector('details')).toBeNull();
  });

  it('reads the filters from the address, kept over a reload, and shows them in the form', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    const query =
      'from=2026-11-01&to=2026-11-02&actions=spend_request.approved,mandate.accepted' +
      `&actorType=user&actorId=${ME}&subjectType=spend_request&subjectId=${REQUEST}`;
    open(`/more/audit-log?${query}`);
    await screen.findByText('Nothing in this range matches these filters.');
    const asked = new URLSearchParams({
      from: midnight(1),
      to: midnight(3),
      actions: 'spend_request.approved,mandate.accepted',
      actorType: 'user',
      actorId: ME,
      subjectType: 'spend_request',
      subjectId: REQUEST,
    });
    expect(sentTo('GET', `/v1/audit-log?${asked.toString()}`)).toHaveLength(1);
    expect(screen.getByLabelText<HTMLSelectElement>('Who').value).toBe('user');
    expect(screen.getByLabelText<HTMLInputElement>('Object ID').value).toBe(REQUEST);
  });

  it('reads a day that doesn’t exist as none, so the last 7 days', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    open('/more/audit-log?from=2026-02-31&to=soon');
    await screen.findByText('Nothing in this range matches these filters.');
    expect(sentTo('GET', `/v1/audit-log?${DEFAULT}`)).toHaveLength(1);
  });

  it('sets the filters on Show, into the address, and reads the log so filtered', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    const router = open('/more/audit-log');
    await screen.findByText('Nothing in this range matches these filters.');
    await userEvent.clear(screen.getByLabelText('From'));
    await userEvent.type(screen.getByLabelText('From'), '2026-11-12');
    await userEvent.type(screen.getByLabelText(/^Actions/), ' mandate.accepted ');
    await userEvent.selectOptions(screen.getByLabelText('Who'), 'agent');
    await userEvent.type(screen.getByLabelText('Their ID'), AGENT);
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    await waitFor(() => {
      expect(router.state.location.searchStr).toBe(
        `?from=2026-11-12&to=2026-11-16&actions=mandate.accepted&actorType=agent&actorId=${AGENT}`,
      );
    });
    const asked = new URLSearchParams({
      from: midnight(12),
      to: midnight(17),
      actions: 'mandate.accepted',
      actorType: 'agent',
      actorId: AGENT,
    });
    await waitFor(() => {
      expect(sentTo('GET', `/v1/audit-log?${asked.toString()}`)).toHaveLength(1);
    });
  });

  it('says on the page, and asks nothing, when a kind is chosen without its ID or an ID without its kind (E2E6 S212)', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    const router = open('/more/audit-log');
    await screen.findByText('Nothing in this range matches these filters.');
    const asked = sent.length;
    await userEvent.selectOptions(screen.getByLabelText('Who'), 'user');
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/give their Agent X ID too/);
    await userEvent.selectOptions(screen.getByLabelText('Who'), '');
    await userEvent.type(screen.getByLabelText('Object ID'), REQUEST);
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/both its kind and its ID/);
    expect(sent.length).toBe(asked);
    expect(router.state.location.searchStr).toBe('');
    // Both halves given: the notice goes and the log is asked.
    await userEvent.type(screen.getByLabelText(/^Object kind/), 'spend_request');
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    await waitFor(() => {
      expect(router.state.location.searchStr).toContain(`subjectType=spend_request&subjectId=${REQUEST}`);
    });
    expect(screen.queryByText(/both its kind and its ID/)).toBeNull();
  });

  it('narrows the log to an event’s object, or to its actor, in one press', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([logEvent('42')]));
    const router = open('/more/audit-log');
    await userEvent.click(await screen.findByRole('button', { name: 'Show only this object' }));
    await waitFor(() => {
      expect(router.state.location.searchStr).toBe(
        `?from=2026-11-09&to=2026-11-16&subjectType=spend_request&subjectId=${REQUEST}`,
      );
    });
    await waitFor(() => {
      expect(sentTo('GET', `/v1/audit-log?${DEFAULT}&subjectType=spend_request&subjectId=${REQUEST}`)).toHaveLength(1);
    });
    expect(screen.getByLabelText<HTMLInputElement>('Object ID').value).toBe(REQUEST);
    await userEvent.click(screen.getByRole('button', { name: 'Show only theirs' }));
    await waitFor(() => {
      expect(router.state.location.searchStr).toBe(
        `?from=2026-11-09&to=2026-11-16&actorType=user&actorId=${ME}&subjectType=spend_request&subjectId=${REQUEST}`,
      );
    });
  });

  it('reads older events on Show older, before the last one shown', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([logEvent('42')], '42'), events([logEvent('7', { action: 'agent.created' })]));
    open('/more/audit-log');
    await userEvent.click(await screen.findByRole('button', { name: 'Show older' }));
    expect(await screen.findByText('agent.created')).toBeDefined();
    expect(sentTo('GET', `/v1/audit-log?${DEFAULT}&before=42`)).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'Show older' })).toBeNull();
  });

  it(
    'keeps the events shown when an older page fails, saying so beside them, and retries that page',
    { timeout: 15_000 },
    async () => {
      signedIn();
      const failed = refusal(500, 'INTERNAL');
      // Read twice more on its own first, as every failure is.
      answer(
        'GET /v1/audit-log',
        events([logEvent('42')], '42'),
        failed,
        failed,
        failed,
        events([logEvent('7', { action: 'agent.created' })]),
      );
      open('/more/audit-log');
      await userEvent.click(await screen.findByRole('button', { name: 'Show older' }));
      await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 5000 }));
      expect(screen.getByText('spend_request.approved')).toBeDefined();
      expect(await screen.findByText('agent.created')).toBeDefined();
      expect(sentTo('GET', `/v1/audit-log?${DEFAULT}&before=42`)).toHaveLength(4);
      expect(sentTo('GET', `/v1/audit-log?${DEFAULT}`)).toHaveLength(1);
    },
  );

  it('trims each action of the filter in the page read, as the download does', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    open('/more/audit-log?actions=a.b,%20c.d%20');
    await screen.findByText('Nothing in this range matches these filters.');
    expect(sentTo('GET', `/v1/audit-log?${DEFAULT}&actions=a.b%2Cc.d`)).toHaveLength(1);
  });

  it('downloads what is shown as CSV, the filters sent, saving the file the answer carries', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    answer('POST /v1/audit-log/exports', {
      status: 201,
      body: {
        export: {
          id: '0199a0f0-0000-7000-8000-0000000000e1',
          fileName: 'audit-log-2026-11-01-to-2026-11-03.csv',
          contentType: 'text/csv',
          content: '"seq"\n"42"\n',
          events: 1,
          upToSeq: '42',
        },
      },
    });
    const { made, names } = saving();
    open(
      `/more/audit-log?from=2026-11-01&to=2026-11-02&actions=a.b,c.d&actorType=user&actorId=${ME}` +
        `&subjectType=spend_request&subjectId=${REQUEST}`,
    );
    await screen.findByText('Nothing in this range matches these filters.');
    expect(screen.getByText(/Every download is recorded in the audit log/)).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: "Download what's shown" }));
    expect(await screen.findByText(/Downloaded. Your download is recorded/)).toBeDefined();
    expect(sentTo('POST', '/v1/audit-log/exports')[0]?.body).toEqual({
      from: midnight(1),
      to: midnight(3),
      actions: ['a.b', 'c.d'],
      actor: { type: 'user', id: ME },
      subject: { type: 'spend_request', id: REQUEST },
      format: 'csv',
    });
    expect(names).toEqual(['audit-log-2026-11-01-to-2026-11-03.csv']);
    expect(made[0]?.type).toBe('text/csv');
    expect(await made[0]?.text()).toBe('"seq"\n"42"\n');
  });

  it('downloads as NDJSON when chosen, sending only the range when nothing else is set', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    answer('POST /v1/audit-log/exports', {
      status: 201,
      body: { export: { fileName: 'a.ndjson', contentType: 'application/x-ndjson', content: '{}\n' } },
    });
    const { names } = saving();
    open('/more/audit-log');
    await screen.findByText('Nothing in this range matches these filters.');
    await userEvent.selectOptions(screen.getByLabelText('Download as'), 'ndjson');
    await userEvent.click(screen.getByRole('button', { name: "Download what's shown" }));
    await screen.findByText(/Downloaded/);
    expect(sentTo('POST', '/v1/audit-log/exports')[0]?.body).toEqual({
      from: midnight(9),
      to: midnight(17),
      format: 'ndjson',
    });
    expect(names).toEqual(['a.ndjson']);
  });

  it('sends a person or object as typed when only half is set, and says the API’s refusal plainly', async () => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    answer('POST /v1/audit-log/exports', refusal(400, 'BAD_REQUEST'));
    open(`/more/audit-log?actorId=${ME}&subjectType=spend_request`);
    await screen.findByText('Nothing in this range matches these filters.');
    await userEvent.click(screen.getByRole('button', { name: "Download what's shown" }));
    expect(await screen.findByText(/Agent X couldn't read these filters/)).toBeDefined();
    expect(sentTo('POST', '/v1/audit-log/exports')[0]?.body).toMatchObject({
      actor: { type: '', id: ME },
      subject: { type: 'spend_request', id: '' },
    });
  });

  it.each([
    ['AUDIT_EXPORT_TOO_LARGE', 409, /more than 10,000 events/],
    ['AUDIT_EXPORTS_SPENT', 409, /5 downloads of the audit log in the last hour/],
    ['INTEGRITY_FAILED', 503, /failed Agent X's integrity check, so none of them can be shown/],
    ['INTERNAL', 500, /couldn't be reached/],
  ])('says a download refused %s in plain words', async (code, status, words) => {
    signedIn();
    answer('GET /v1/audit-log', events([]));
    answer('POST /v1/audit-log/exports', refusal(status, code));
    open('/more/audit-log');
    await screen.findByText('Nothing in this range matches these filters.');
    await userEvent.click(screen.getByRole('button', { name: "Download what's shown" }));
    expect(await screen.findByText(words)).toBeDefined();
  });

  it('says a page refused or failing its check in words, and retries a failure', { timeout: 15_000 }, async () => {
    signedIn();
    answer('GET /v1/audit-log', refusal(400, 'BAD_REQUEST'));
    open('/more/audit-log?from=2026-11-16&to=2026-11-01');
    expect(await screen.findByText(/Agent X couldn't read these filters/)).toBeDefined();
    cleanup();
    answer('GET /v1/audit-log', refusal(503, 'INTEGRITY_FAILED'));
    open('/more/audit-log');
    expect(await screen.findByText(/failed Agent X's integrity check/)).toBeDefined();
    cleanup();
    const failed = refusal(500, 'INTERNAL');
    // Read twice more on its own first, as every failure is.
    answer('GET /v1/audit-log', failed, failed, failed, events([logEvent('42')]));
    open('/more/audit-log');
    await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 5000 }));
    expect(await screen.findByText('spend_request.approved')).toBeDefined();
  });

  it('goes to sign-in, saying the session ended, when the log is answered 401', async () => {
    signedIn();
    answer('GET /v1/audit-log', refusal(401, 'UNAUTHENTICATED'));
    open('/more/audit-log');
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });
});

describe('the access log (6C2)', () => {
  it('reads the last 7 days, each request with when, who, what, its answer and its seal', async () => {
    signedIn();
    answer('GET /v1/access-log', rows([activity()]));
    answer('GET /v1/access-log/background-exports', { status: 200, body: { downloads: [], next: null } });
    open('/more/access-log');
    const item = (await screen.findByText('POST /v1/spend-requests')).closest('li') as HTMLElement;
    expect(sentTo('GET', `/v1/access-log?${DEFAULT}`)).toHaveLength(1);
    expect(within(item).getByText('Sealed')).toBeDefined();
    expect(within(item).getByText('409 ORG_FROZEN')).toBeDefined();
    expect(within(item).getByText(/their clock 2026-11-15T09:00:00.000\+04:00/)).toBeDefined();
    expect(within(item).getByText(/By Phase 4 demo agent/)).toBeDefined();
    expect(screen.getByLabelText('Who').querySelectorAll('option')).toHaveLength(3);
    expect(screen.queryByLabelText('Object ID')).toBeNull();
  });

  it('folds away where a request came from: clues, its place credited to DB-IP', async () => {
    signedIn();
    answer('GET /v1/access-log', rows([activity()]));
    open('/more/access-log');
    const clues = found((await screen.findByText('Where it came from')).closest('details'));
    expect(clues.open).toBe(false);
    expect(within(clues).getByText('203.0.113.7')).toBeDefined();
    expect(within(clues).getByText(/Dubai, AE/)).toBeDefined();
    expect(within(clues).getByRole('link', { name: 'by DB-IP' }).getAttribute('href')).toBe('https://db-ip.com');
    expect(within(clues).getByText('Asia/Dubai, as the browser reported it')).toBeDefined();
    expect(within(clues).getByText(REQUEST)).toBeDefined();
  });

  it('says only what a request has: no reason, seal, clock, address, place or zone', async () => {
    signedIn();
    answer(
      'GET /v1/access-log',
      rows([
        activity({
          status: 200,
          reason: null,
          sealed: false,
          localTime: null,
          pathIds: [],
          client: { ip: null, place: null, timeZone: { name: 'Asia/Dubai', from: 'organisation' } },
        }),
      ]),
    );
    open('/more/access-log');
    const item = (await screen.findByText('POST /v1/spend-requests')).closest('li') as HTMLElement;
    expect(within(item).getByText('200')).toBeDefined();
    expect(within(item).queryByText('Sealed')).toBeNull();
    expect(within(item).queryByText(/their clock/)).toBeNull();
    expect(within(item).queryByText('IP address')).toBeNull();
    expect(within(item).queryByText('IDs it named')).toBeNull();
    expect(within(item).getByText("Asia/Dubai, the organisation's own (none was reported)")).toBeDefined();
  });

  it('narrows the log to a request’s person or agent, in the address, and pages older by its cursor', async () => {
    signedIn();
    const cursor = `2026-11-15T05:00:00.000Z_${REQUEST}`;
    answer('GET /v1/access-log', rows([activity()], cursor), rows([]));
    const router = open('/more/access-log');
    await userEvent.click(await screen.findByRole('button', { name: 'Show older' }));
    await waitFor(() => {
      expect(sentTo('GET', `/v1/access-log?${DEFAULT}&before=${encodeURIComponent(cursor)}`)).toHaveLength(1);
    });
    await userEvent.click(screen.getByRole('button', { name: 'Show only theirs' }));
    await waitFor(() => {
      expect(router.state.location.searchStr).toBe(`?from=2026-11-09&to=2026-11-16&actorType=agent&actorId=${AGENT}`);
    });
    await waitFor(() => {
      expect(sentTo('GET', `/v1/access-log?${DEFAULT}&actorType=agent&actorId=${AGENT}`)).toHaveLength(1);
    });
  });

  it('downloads what is shown, the range and person sent, and saves the file', async () => {
    signedIn();
    answer('GET /v1/access-log', rows([]));
    answer('POST /v1/access-log/exports', {
      status: 201,
      body: { export: { fileName: 'activity-log.csv', contentType: 'text/csv', content: '"id"\n', requests: 0 } },
    });
    const { names } = saving();
    open(`/more/access-log?actorType=user&actorId=${ME}`);
    await screen.findByText('Nothing in this range matches these filters.');
    await userEvent.click(screen.getByRole('button', { name: "Download what's shown" }));
    await screen.findByText(/Downloaded/);
    expect(sentTo('POST', '/v1/access-log/exports')[0]?.body).toEqual({
      from: midnight(9),
      to: midnight(17),
      actor: { type: 'user', id: ME },
      format: 'csv',
    });
    expect(names).toEqual(['activity-log.csv']);
  });

  it.each([
    [
      'ACTIVITY_EXPORT_TOO_LARGE',
      409,
      /more than 50,000 requests, too many to download at once. Build it in the background/,
    ],
    ['ACTIVITY_EXPORTS_SPENT', 409, /5 downloads of the access log in the last hour/],
    ['ACTIVITY_EXPORTS_BUSY', 503, /making another download right now/],
  ])('says a download refused %s in plain words', async (code, status, words) => {
    signedIn();
    answer('GET /v1/access-log', rows([]));
    answer('POST /v1/access-log/exports', refusal(status, code));
    open('/more/access-log');
    await screen.findByText('Nothing in this range matches these filters.');
    await userEvent.click(screen.getByRole('button', { name: "Download what's shown" }));
    expect(await screen.findByText(words)).toBeDefined();
  });
});

describe('the access log’s background downloads (decision 31)', () => {
  const built = (overrides: Record<string, unknown> = {}) => ({
    id: DOWNLOAD,
    requestedBy: ME,
    requestedAt: AT,
    from: '2025-11-16T00:00:00.000Z',
    to: '2026-11-16T00:00:00.000Z',
    actor: null,
    format: 'csv',
    state: 'ready',
    expiresAt: '2026-11-22T00:00:00.000Z',
    files: [
      { month: '2026-10', state: 'ready', requests: 61_000, bytes: 6, sha256: 'x' },
      { month: '2026-11', state: 'failed', requests: null, bytes: null, sha256: null },
    ],
    ...overrides,
  });
  const listing = (downloads: readonly unknown[]): Answer => ({ status: 200, body: { downloads, next: null } });

  it('asks for the range as filtered to be built in the background, saying it will be emailed, and lists it', async () => {
    signedIn();
    answer('GET /v1/access-log', rows([]));
    answer(
      'GET /v1/access-log/background-exports',
      listing([]),
      listing([built({ state: 'building', expiresAt: null })]),
    );
    answer('POST /v1/access-log/background-exports', { status: 202, body: { download: built() } });
    open('/more/access-log?from=2025-11-16');
    expect(await screen.findByText('No background download has been asked for yet.')).toBeDefined();
    await userEvent.selectOptions(screen.getByLabelText('Download as'), 'ndjson');
    await userEvent.click(screen.getByRole('button', { name: 'Build it in the background' }));
    expect(await screen.findByText(/Agent X is building it now and will email you/)).toBeDefined();
    expect(sentTo('POST', '/v1/access-log/background-exports')[0]?.body).toEqual({
      from: new Date(2025, 10, 16).toISOString(),
      to: midnight(17),
      format: 'ndjson',
    });
    expect(await screen.findByText('Being built')).toBeDefined();
    expect(sentTo('GET', '/v1/access-log/background-exports?limit=20').length).toBeGreaterThan(1);
  });

  it('says one already under way plainly', async () => {
    signedIn();
    answer('GET /v1/access-log', rows([]));
    answer('GET /v1/access-log/background-exports', listing([]));
    answer('POST /v1/access-log/background-exports', refusal(409, 'ACTIVITY_EXPORT_UNDER_WAY'));
    open('/more/access-log');
    await userEvent.click(await screen.findByRole('button', { name: 'Build it in the background' }));
    expect(await screen.findByText(/already being built for this organisation/)).toBeDefined();
  });

  it('reads the list again every 15 s while a download is being built, and stops once none is', async () => {
    vi.useFakeTimers({
      toFake: ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'],
      shouldAdvanceTime: true,
    });
    vi.setSystemTime(new Date(2026, 10, 16, 10));
    signedIn();
    answer('GET /v1/access-log', rows([]));
    answer(
      'GET /v1/access-log/background-exports',
      listing([built({ state: 'building', expiresAt: null })]),
      listing([built()]),
    );
    open('/more/access-log');
    expect(await screen.findByText('Being built')).toBeDefined();
    const reads = () => sentTo('GET', '/v1/access-log/background-exports?limit=20').length;
    expect(reads()).toBe(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    expect(await screen.findByText(/^Ready · kept until/)).toBeDefined();
    expect(reads()).toBe(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(45_000);
    });
    expect(reads()).toBe(2);
  });

  it('says plainly where no download store is set up, offering nothing to press', async () => {
    signedIn();
    answer('GET /v1/access-log', rows([]));
    open('/more/access-log');
    expect(await screen.findByText(/Background downloads aren't set up/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Build it in the background' })).toBeNull();
  });

  it(
    'retries a list that failed, and says expired and failed downloads as they stand',
    { timeout: 15_000 },
    async () => {
      signedIn();
      answer('GET /v1/access-log', rows([]));
      answer(
        'GET /v1/access-log/background-exports',
        refusal(500, 'INTERNAL'),
        refusal(500, 'INTERNAL'),
        refusal(500, 'INTERNAL'),
        listing([built({ state: 'expired' }), built({ id: FILE, state: 'failed', expiresAt: null })]),
      );
      open('/more/access-log');
      await userEvent.click(await screen.findByRole('button', { name: 'Try again' }, { timeout: 5000 }));
      expect(await screen.findByText(/Deleted after 7 days · kept until/)).toBeDefined();
      expect(screen.getByText("Couldn't be built: ask again")).toBeDefined();
      expect(screen.queryByRole('button', { name: /Download 2026-10/ })).toBeNull();
    },
  );

  /** A ready file of two parts, answered as the API reads them, and its SHA-256 as its record names it. */
  function readyFile(sha256: string) {
    answer('GET /v1/access-log', rows([]));
    answer('GET /v1/access-log/background-exports', listing([built()]));
    answer(`POST /v1/access-log/background-exports/${DOWNLOAD}/files/2026-10/downloads`, {
      status: 201,
      body: {
        download: {
          id: FILE,
          exportId: DOWNLOAD,
          month: '2026-10',
          fileName: 'access-log-2026-10.csv.gz',
          contentType: 'application/gzip',
          bytes: 6,
          sha256,
          parts: 2,
          partBytes: 4,
        },
      },
    });
    const parts = `/v1/access-log/background-exports/${DOWNLOAD}/downloads/${FILE}/parts`;
    answer(`GET ${parts}/0`, { status: 200, body: { part: { index: 0, content: btoa('gzip') } } });
    answer(`GET ${parts}/1`, { status: 200, body: { part: { index: 1, content: btoa('!!') } } });
    return parts;
  }

  it('downloads a ready month a part at a time and saves it once its SHA-256 matches', async () => {
    signedIn();
    const parts = readyFile(createHash('sha256').update('gzip!!').digest('hex').toUpperCase());
    const { made, names } = saving();
    open('/more/access-log');
    expect(await screen.findByText("2026-11 couldn't be built")).toBeDefined();
    await userEvent.click(await screen.findByRole('button', { name: 'Download 2026-10 (61000 requests)' }));
    expect(await screen.findByText(/Downloaded/)).toBeDefined();
    expect(sentTo('POST', `/v1/access-log/background-exports/${DOWNLOAD}/files/2026-10/downloads`)[0]?.body).toEqual(
      {},
    );
    expect(sent.filter((one) => one.path.startsWith(parts)).map((one) => one.path)).toEqual([
      `${parts}/0`,
      `${parts}/1`,
    ]);
    expect(names).toEqual(['access-log-2026-10.csv.gz']);
    expect(made[0]?.type).toBe('application/gzip');
    expect(await made[0]?.text()).toBe('gzip!!');
  });

  it('saves nothing when the file arrived different from its record', async () => {
    signedIn();
    readyFile('00'.repeat(32));
    const { names } = saving();
    open('/more/access-log');
    await userEvent.click(await screen.findByRole('button', { name: /Download 2026-10/ }));
    expect(await screen.findByText(/arrived different from the one Agent X recorded/)).toBeDefined();
    expect(names).toEqual([]);
  });

  it('saves nothing when its parts hold more than its record says', async () => {
    signedIn();
    const parts = readyFile('00'.repeat(32));
    answer(`GET ${parts}/1`, { status: 200, body: { part: { index: 1, content: btoa('too long') } } });
    const { names } = saving();
    open('/more/access-log');
    await userEvent.click(await screen.findByRole('button', { name: /Download 2026-10/ }));
    expect(await screen.findByText(/arrived different from the one Agent X recorded/)).toBeDefined();
    expect(names).toEqual([]);
  });

  it.each([
    ['ACTIVITY_EXPORT_EXPIRED', 410, /kept for 7 days and has been deleted/],
    ['ACTIVITY_EXPORT_NOT_READY', 409, /isn't ready yet/],
    ['ACTIVITY_EXPORT_UNREADABLE', 503, /couldn't be read from storage/],
    ['NOT_FOUND', 404, /can't be found any more/],
  ])('says a month’s download refused %s in plain words', async (code, status, words) => {
    signedIn();
    readyFile('00');
    answer(`POST /v1/access-log/background-exports/${DOWNLOAD}/files/2026-10/downloads`, refusal(status, code));
    open('/more/access-log');
    await userEvent.click(await screen.findByRole('button', { name: /Download 2026-10/ }));
    expect(await screen.findByText(words)).toBeDefined();
  });
});

describe('the security events (6E1b, CO7b)', () => {
  const securityEvent = (overrides: Record<string, unknown> = {}) => ({
    id: '0199a0f0-0000-7000-8000-0000000000e1',
    kind: 'rate_limited',
    reason: 'per_agent',
    ip: '203.0.113.7',
    actor: { type: 'agent', id: AGENT, name: 'Phase 4 demo agent' },
    windowStart: AT,
    count: 12,
    ...overrides,
  });
  const page = (list: readonly unknown[], next: string | null = null): Answer => ({
    status: 200,
    body: { rows: list, next },
  });

  it('is reached from More by an admin, and shows no one else a way to it, reading nothing for them', async () => {
    signedIn();
    answer('GET /v1/security-events', page([]));
    open('/more');
    await userEvent.click(await screen.findByRole('link', { name: 'Security events' }));
    expect(await screen.findByRole('heading', { name: 'Security events' })).toBeDefined();
    expect(await screen.findByText('Nothing in this range matches these filters.')).toBeDefined();
    expect(sentTo('GET', `/v1/security-events?${DEFAULT}`)).toHaveLength(1);
    cleanup();
    sent = [];
    signedIn('approver');
    open('/more');
    expect(await screen.findByRole('heading', { name: 'More' })).toBeDefined();
    expect(screen.queryByRole('link', { name: 'Security events' })).toBeNull();
    cleanup();
    open('/more/security-events');
    expect(await screen.findByText(/Only an admin can see this organisation's logs/)).toBeDefined();
    expect(sent.filter((one) => one.path.startsWith('/v1/security-events'))).toHaveLength(0);
  });

  it('shows each count: what happened, the minute, how many, who, and its address folded away as a clue', async () => {
    signedIn();
    answer('GET /v1/security-events', page([securityEvent()]));
    open('/more/security-events');
    const item = found((await screen.findByText('per_agent')).closest('li'));
    expect(within(item).getByText(/Refused for asking too often/)).toBeDefined();
    expect(within(item).getByText(/12 times in this minute/)).toBeDefined();
    expect(within(item).getByText(/Phase 4 demo agent/)).toBeDefined();
    const clues = found(within(item).getByText('Where it came from').closest('details'));
    expect(clues.open).toBe(false);
    expect(within(clues).getByText('203.0.113.7')).toBeDefined();
    expect(screen.getByText(/a clue, never proof/)).toBeDefined();
  });

  it('names someone with no name by what they are, one about no one as such, and an address not known', async () => {
    signedIn();
    answer(
      'GET /v1/security-events',
      page([
        securityEvent({
          kind: 'sign_in_failed',
          reason: 'step_up_code_rejected',
          actor: { type: 'user', id: ME, name: null },
        }),
        securityEvent({ id: '0199a0f0-0000-7000-8000-0000000000e2', reason: 'per_user', ip: null, actor: null }),
      ]),
    );
    open('/more/security-events');
    const failed = found((await screen.findByText('step_up_code_rejected')).closest('li'));
    expect(within(failed).getByText(/Passkey check failed/)).toBeDefined();
    expect(within(failed).getByText(/A person/)).toBeDefined();
    const nobody = found(screen.getByText('per_user').closest('li'));
    expect(within(nobody).getByText('No one in particular')).toBeDefined();
    expect(within(nobody).getByText('Not known')).toBeDefined();
  });

  it('filters by kind into the address, and pages older by its cursor', async () => {
    signedIn();
    const cursor = `2026-11-15T05:00:00.000Z_${REQUEST}`;
    answer('GET /v1/security-events', page([securityEvent()], cursor), page([]));
    const router = open('/more/security-events');
    await userEvent.click(await screen.findByRole('button', { name: 'Show older' }));
    await waitFor(() => {
      expect(sentTo('GET', `/v1/security-events?${DEFAULT}&before=${encodeURIComponent(cursor)}`)).toHaveLength(1);
    });
    expect(screen.getByLabelText('What happened').querySelectorAll('option')).toHaveLength(3);
    await userEvent.selectOptions(screen.getByLabelText('What happened'), 'sign_in_failed');
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    await waitFor(() => {
      expect(router.state.location.searchStr).toBe('?from=2026-11-09&to=2026-11-16&kind=sign_in_failed');
    });
    await waitFor(() => {
      expect(sentTo('GET', `/v1/security-events?${DEFAULT}&kind=sign_in_failed`)).toHaveLength(1);
    });
  });

  it('says a page failing its check in words', async () => {
    signedIn();
    answer('GET /v1/security-events', refusal(503, 'INTEGRITY_FAILED'));
    open('/more/security-events');
    expect(await screen.findByText(/failed Agent X's integrity check/)).toBeDefined();
  });
});

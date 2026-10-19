// Phase 3 L5c: the activity log's background download routes, answering an
// admin with each outcome of the use case and their input checked at the
// edge, and NOT_FOUND where no store is set up. What the downloads do in the
// database, and the files the builder makes, is
// activity-background-exports.db.test.ts; who reaches them, role-matrix.test.ts.
import type { BackgroundExport } from '@agentx/core/modules/activity';
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type {
  BackgroundExportAskedFor,
  BackgroundExports,
  BackgroundExportWrite,
} from './activity-background-exports.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-19T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-19T09:00:05.000Z'),
  lastSeenAt: new Date('2026-10-19T09:10:00.000Z'),
  endsAt: new Date('2026-10-19T21:00:05.000Z'),
  idleEndsAt: new Date('2026-10-19T09:40:00.000Z'),
};

const AGENT = '0199a0f0-0000-7000-8000-00000000a9e1';
const ID = '0199a0f0-0000-7000-8000-0000000a15c1';

const DOWNLOAD: BackgroundExport = {
  id: ID,
  requestedBy: LIVE.userId,
  requestedAt: new Date('2026-10-19T09:20:00.000Z'),
  from: new Date('2026-08-15T00:00:00.000Z'),
  to: new Date('2026-09-15T00:00:00.000Z'),
  actor: null,
  format: 'ndjson',
  writtenUpTo: '0199a0f0-0000-7000-8000-0000000a15c2',
  state: 'ready',
  expiresAt: new Date('2026-10-26T09:30:00.000Z'),
  files: [
    { month: '2026-08', state: 'ready', attempts: 1, requests: 12, bytes: 900, sha256: 'a'.repeat(64) },
    { month: '2026-09', state: 'ready', attempts: 2, requests: 0, bytes: 20, sha256: 'b'.repeat(64) },
  ],
};

const SHOWN = {
  id: ID,
  requestedBy: LIVE.userId,
  requestedAt: '2026-10-19T09:20:00.000Z',
  from: '2026-08-15T00:00:00.000Z',
  to: '2026-09-15T00:00:00.000Z',
  actor: null,
  format: 'ndjson',
  state: 'ready',
  expiresAt: '2026-10-26T09:30:00.000Z',
  files: [
    { month: '2026-08', state: 'ready', requests: 12, bytes: 900, sha256: 'a'.repeat(64) },
    { month: '2026-09', state: 'ready', requests: 0, bytes: 20, sha256: 'b'.repeat(64) },
  ],
};

const BODY = { from: '2026-08-15T00:00:00.000Z', to: '2026-09-15T00:00:00.000Z', format: 'ndjson' };

afterEach(closeServers);

/** A server whose use case answers as told and keeps what it was asked; none set up when `answers` is undefined. */
async function withDownloads(
  answers: { ask?: BackgroundExportWrite; one?: Awaited<ReturnType<BackgroundExports['one']>> } | undefined,
  role: Role = 'admin',
) {
  const asked: BackgroundExportAskedFor[] = [];
  const pages: unknown[] = [];
  const downloads: BackgroundExports | undefined =
    answers === undefined
      ? undefined
      : {
          ask: (member, keyed, given) => {
            expect(member).toMatchObject({ orgId: ORG, userId: LIVE.userId });
            expect(keyed).toMatchObject({ operation: 'access-log.background-export', key: 'k-1' });
            asked.push(given);
            return Promise.resolve(answers.ask ?? { outcome: 'asked', download: DOWNLOAD });
          },
          list: (orgId, page) => {
            expect(orgId).toBe(ORG);
            pages.push(page);
            return Promise.resolve({ downloads: [DOWNLOAD], next: ID });
          },
          one: (orgId, id) => {
            expect(orgId).toBe(ORG);
            pages.push(id);
            return Promise.resolve('one' in answers ? answers.one : DOWNLOAD);
          },
        };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, backgroundExports: downloads });
  return { app, asked, pages };
}

const HEADERS = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const post = (payload: unknown): InjectOptions => ({
  method: 'POST',
  url: '/v1/access-log/background-exports',
  headers: { ...HEADERS, 'idempotency-key': 'k-1', 'content-type': 'application/json' },
  payload: JSON.stringify(payload),
});

const get = (url: string): InjectOptions => ({ method: 'GET', url, headers: HEADERS });

describe('POST /v1/access-log/background-exports (L5c, decision 31)', () => {
  it('answers 202 with the download, passing the range and format, everyone’s when no actor is named', async () => {
    const { app, asked } = await withDownloads({});
    const reply = await app.inject(post(BODY));

    expect(reply.statusCode).toBe(202);
    expect(reply.json()).toEqual({ download: SHOWN });
    expect(asked).toEqual([{ from: new Date(BODY.from), to: new Date(BODY.to), actor: undefined, format: 'ndjson' }]);
  });

  it('passes the one actor named, a UUID in capitals in lower case', async () => {
    const { app, asked } = await withDownloads({});
    await app.inject(post({ ...BODY, actor: { type: 'agent', id: AGENT.toUpperCase() } }));

    expect(asked).toMatchObject([{ actor: { type: 'agent', id: AGENT } }]);
  });

  it.each([
    ['no format', { from: BODY.from, to: BODY.to }],
    ['a format it doesn’t make', { ...BODY, format: 'xlsx' }],
    ['a range that doesn’t start before it ends', { ...BODY, to: BODY.from }],
    ['a range past 366 days', { ...BODY, from: '2025-01-01T00:00:00.000Z', to: '2026-01-03T00:00:00.000Z' }],
    ['a person named by something not a UUID', { ...BODY, actor: { type: 'user', id: 'integrity-hold' } }],
    ['a field of its own', { ...BODY, months: 3 }],
  ])('refuses %s at the edge, the download never asked', async (_what, body) => {
    const { app, asked } = await withDownloads({});

    expect((await app.inject(post(body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORT_UNDER_WAY' } as const, 409, 'ACTIVITY_EXPORT_UNDER_WAY'],
    [{ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORTS_SPENT' } as const, 409, 'ACTIVITY_EXPORTS_SPENT'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
  ])('answers the use case’s %o as %i %s', async (answer, status, code) => {
    const { app } = await withDownloads({ ask: answer });
    const reply = await app.inject(post(BODY));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s (admins only)', async (role) => {
    const { app, asked } = await withDownloads({}, role);

    expect((await app.inject(post(BODY))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/access-log/background-exports (L5c)', () => {
  it('lists the downloads, newest first, 20 a page unless fewer are asked, after the one named', async () => {
    const { app, pages } = await withDownloads({});
    const first = await app.inject(get('/v1/access-log/background-exports'));
    await app.inject(get(`/v1/access-log/background-exports?before=${ID.toUpperCase()}&limit=5`));

    expect(first.statusCode).toBe(200);
    expect(first.json()).toEqual({ downloads: [SHOWN], next: ID });
    expect(pages).toEqual([
      { before: undefined, limit: 20 },
      { before: ID, limit: 5 },
    ]);
  });

  it.each([
    ['a page past 20', '?limit=21'],
    ['a cursor not a UUID', '?before=x'],
    ['a field of its own', '?from=x'],
  ])('refuses %s at the edge', async (_what, query) => {
    const { app, pages } = await withDownloads({});

    expect((await app.inject(get(`/v1/access-log/background-exports${query}`))).statusCode).toBe(400);
    expect(pages).toEqual([]);
  });

  it('answers one download, its ID in capitals asked in lower case', async () => {
    const { app, pages } = await withDownloads({});
    const found = await app.inject(get(`/v1/access-log/background-exports/${ID.toUpperCase()}`));

    expect(found.statusCode).toBe(200);
    expect(found.json()).toEqual({ download: SHOWN });
    expect(pages).toEqual([ID]);
  });

  it.each([
    ['one the organisation doesn’t have', undefined, 404, 'NOT_FOUND'],
    [
      'one that can’t be believed',
      { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } as const,
      503,
      'INTEGRITY_FAILED',
    ],
  ])('answers %s as %i', async (_what, one, status, code) => {
    const { app } = await withDownloads({ one });
    const reply = await app.inject(get(`/v1/access-log/background-exports/${ID}`));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });
});

describe('the background download routes with no store set up (L5c)', () => {
  it.each([
    ['asking for one', post(BODY)],
    ['the list', get('/v1/access-log/background-exports')],
    ['one', get(`/v1/access-log/background-exports/${ID}`)],
  ])('answer NOT_FOUND to %s: the feature is not available', async (_what, options) => {
    const { app } = await withDownloads(undefined);
    const reply = await app.inject(options);

    expect(reply.statusCode).toBe(404);
    expect(reply.json()).toMatchObject({ error: { code: 'NOT_FOUND' } });
  });
});

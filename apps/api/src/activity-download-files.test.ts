// Phase 3 L5c: a background download's file routes, answering an admin with
// each outcome of the use case and their path checked at the edge, and
// NOT_FOUND where no store is set up. What the downloads do in the database
// and the store is activity-background-exports.db.test.ts.
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { DownloadFiles, FileDownload, FileDownloadWrite } from './activity-download-files.ts';
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

const EXPORT = '0199a0f0-0000-7000-8000-0000000a15d1';
const DOWNLOAD_ID = '0199a0f0-0000-7000-8000-0000000a15d2';

const DOWNLOAD: FileDownload = {
  id: DOWNLOAD_ID,
  exportId: EXPORT,
  month: '2026-08',
  fileName: 'activity-log-2026-08-01-to-2026-09-01-2026-08.ndjson.gz',
  contentType: 'application/gzip',
  bytes: 9,
  sha256: 'a'.repeat(64),
  parts: 1,
  partBytes: 4_194_304,
};

afterEach(closeServers);

/** A server whose use case answers as told and keeps what it was asked; none set up when `answers` is undefined. */
async function withFiles(
  answers: { start?: FileDownloadWrite; part?: Awaited<ReturnType<DownloadFiles['part']>> } | undefined,
  role: Role = 'admin',
) {
  const asked: unknown[] = [];
  const files: DownloadFiles | undefined =
    answers === undefined
      ? undefined
      : {
          start: (member, keyed, file) => {
            expect(member).toMatchObject({ orgId: ORG, userId: LIVE.userId });
            expect(keyed).toMatchObject({ operation: 'access-log.background-export.download', key: 'k-1' });
            asked.push(file);
            return Promise.resolve(answers.start ?? { outcome: 'started', download: DOWNLOAD });
          },
          part: (member, part) => {
            expect(member).toMatchObject({ orgId: ORG, userId: LIVE.userId });
            asked.push(part);
            return Promise.resolve(
              answers.part ?? { outcome: 'part', index: part.index, content: Buffer.from('gzip') },
            );
          },
        };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, downloadFiles: files });
  return { app, asked };
}

const HEADERS = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const start = (exportId = EXPORT, month = '2026-08'): InjectOptions => ({
  method: 'POST',
  url: `/v1/access-log/background-exports/${exportId}/files/${month}/downloads`,
  headers: { ...HEADERS, 'idempotency-key': 'k-1', 'content-type': 'application/json' },
  payload: '{}',
});

const part = (index: string | number, downloadId = DOWNLOAD_ID): InjectOptions => ({
  method: 'GET',
  url: `/v1/access-log/background-exports/${EXPORT}/downloads/${downloadId}/parts/${String(index)}`,
  headers: HEADERS,
});

describe('POST /v1/access-log/background-exports/{id}/files/{month}/downloads (L5c)', () => {
  it('answers 201 with the download as its record holds it, the download ID in lower case', async () => {
    const { app, asked } = await withFiles({});
    const reply = await app.inject(start(EXPORT.toUpperCase()));

    expect(reply.statusCode).toBe(201);
    expect(reply.json()).toEqual({ download: DOWNLOAD });
    expect(asked).toEqual([{ exportId: EXPORT, month: '2026-08' }]);
  });

  it.each([
    ['a month past December', '2026-13'],
    ['a month of no year', '08'],
    ['a day, not a month', '2026-08-01'],
  ])('refuses %s at the edge, nothing asked', async (_what, month) => {
    const { app, asked } = await withFiles({});

    expect((await app.inject(start(EXPORT, month))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORT_NOT_READY' } as const, 409, 'ACTIVITY_EXPORT_NOT_READY'],
    [{ outcome: 'refused', status: 410, code: 'ACTIVITY_EXPORT_EXPIRED' } as const, 410, 'ACTIVITY_EXPORT_EXPIRED'],
    [{ outcome: 'refused', status: 404, code: 'NOT_FOUND' } as const, 404, 'NOT_FOUND'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
  ])('answers the use case’s %o as %i %s', async (answer, status, code) => {
    const { app } = await withFiles({ start: answer });
    const reply = await app.inject(start());

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s (admins only)', async (role) => {
    const { app, asked } = await withFiles({}, role);

    expect((await app.inject(start())).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/access-log/background-exports/{id}/downloads/{downloadId}/parts/{n} (L5c)', () => {
  it('answers the part as base64, its IDs in lower case', async () => {
    const { app, asked } = await withFiles({});
    const reply = await app.inject(part(0, DOWNLOAD_ID.toUpperCase()));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({ part: { index: 0, content: Buffer.from('gzip').toString('base64') } });
    expect(asked).toEqual([{ exportId: EXPORT, downloadId: DOWNLOAD_ID, index: 0 }]);
  });

  it.each([
    ['a part before the first', -1],
    ['a part that is no number', 'x'],
    ['a part past any file', 50_001],
  ])('refuses %s at the edge', async (_what, index) => {
    const { app, asked } = await withFiles({});

    expect((await app.inject(part(index))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [
      { outcome: 'refused', status: 503, code: 'ACTIVITY_EXPORT_UNREADABLE' } as const,
      503,
      'ACTIVITY_EXPORT_UNREADABLE',
    ],
    [{ outcome: 'refused', status: 404, code: 'NOT_FOUND' } as const, 404, 'NOT_FOUND'],
  ])('answers the use case’s %o as %i %s', async (answer, status, code) => {
    const { app } = await withFiles({ part: answer });
    const reply = await app.inject(part(0));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });
});

describe('the file routes with no store set up (L5c)', () => {
  it.each([
    ['a download started', start()],
    ['a part', part(0)],
  ])('answer NOT_FOUND to %s: the feature is not available', async (_what, options) => {
    const { app } = await withFiles(undefined);
    const reply = await app.inject(options);

    expect(reply.statusCode).toBe(404);
    expect(reply.json()).toMatchObject({ error: { code: 'NOT_FOUND' } });
  });
});

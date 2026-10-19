// Phase 3 L5: the activity log's download route, answering an admin with
// each outcome of the use case and its body checked at the edge. What the
// download does in the database, and the files it makes, is
// activity-log-exports.db.test.ts; who reaches it, role-matrix.test.ts.
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { ActivityExportAsked, ActivityExportWrite, ActivityLogExports } from './activity-log-exports.ts';
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

const EXPORTED: ActivityExportWrite = {
  outcome: 'exported',
  file: {
    id: '0199a0f0-0000-7000-8000-0000000a15e1',
    fileName: 'activity-log-2026-10-01-to-2026-10-20.csv',
    contentType: 'text/csv',
    content: '"id"\n"x"\n',
    requests: 1,
  },
};

const BODY = { from: '2026-10-01T00:00:00.000Z', to: '2026-10-20T00:00:00.000Z', format: 'ndjson' };

afterEach(closeServers);

async function withExports(answer: ActivityExportWrite, role: Role = 'admin') {
  const asked: ActivityExportAsked[] = [];
  const exports: ActivityLogExports = {
    export: (member, keyed, given) => {
      expect(member).toMatchObject({ orgId: ORG, userId: LIVE.userId });
      expect(keyed).toMatchObject({ operation: 'access-log.export', key: 'k-1' });
      asked.push(given);
      return Promise.resolve(answer);
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, activityLogExports: exports });
  return { app, asked };
}

const post = (payload: unknown): InjectOptions => ({
  method: 'POST',
  url: '/v1/access-log/exports',
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': 'k-1',
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

describe('POST /v1/access-log/exports (L5, decision 26)', () => {
  it('answers 201 with the file, passing the range and format, everyone’s when no actor is named', async () => {
    const { app, asked } = await withExports(EXPORTED);
    const reply = await app.inject(post(BODY));

    expect(reply.statusCode).toBe(201);
    expect(reply.json()).toEqual({ export: EXPORTED.file });
    expect(asked).toEqual([{ from: new Date(BODY.from), to: new Date(BODY.to), actor: undefined, format: 'ndjson' }]);
  });

  it('passes the one actor named, a UUID in capitals in lower case', async () => {
    const { app, asked } = await withExports(EXPORTED);
    await app.inject(post({ ...BODY, actor: { type: 'agent', id: AGENT.toUpperCase() } }));

    expect(asked).toMatchObject([{ actor: { type: 'agent', id: AGENT } }]);
  });

  it.each([
    ['no format', { from: BODY.from, to: BODY.to }],
    ['a format it doesn’t make', { ...BODY, format: 'xlsx' }],
    ['a range that doesn’t start before it ends', { ...BODY, to: BODY.from }],
    ['a range past 366 days', { ...BODY, from: '2025-01-01T00:00:00.000Z', to: '2026-01-03T00:00:00.000Z' }],
    ['an actor with no ID', { ...BODY, actor: { type: 'user' } }],
    ['a part of Agent X, which makes no requests', { ...BODY, actor: { type: 'system', id: 'api' } }],
    ['a person named by something not a UUID', { ...BODY, actor: { type: 'user', id: 'integrity-hold' } }],
    ['an actor with a field of its own', { ...BODY, actor: { type: 'agent', id: AGENT, role: 'x' } }],
    ['a field of its own', { ...BODY, actions: ['mandate.accepted'] }],
  ])('refuses %s at the edge, the download never asked', async (_what, body) => {
    const { app, asked } = await withExports(EXPORTED);

    expect((await app.inject(post(body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORT_TOO_LARGE' } as const, 409, 'ACTIVITY_EXPORT_TOO_LARGE'],
    [{ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORTS_SPENT' } as const, 409, 'ACTIVITY_EXPORTS_SPENT'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
  ])('answers the use case’s %o as %i %s', async (answer, status, code) => {
    const { app } = await withExports(answer);
    const reply = await app.inject(post(BODY));

    expect(reply.statusCode).toBe(status);
    expect(reply.json()).toMatchObject({ error: { code } });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s (admins only)', async (role) => {
    const { app, asked } = await withExports(EXPORTED, role);

    expect((await app.inject(post(BODY))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

// Phase 3 E10b: the audit log's download route, answering an admin with each
// outcome of the use case, its body checked at the edge, and the CSV cell a
// spreadsheet can't run (SEC-EVD-04). What the download does in the database
// is audit-log-exports.db.test.ts; who reaches it, role-matrix.test.ts.
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { type AuditLogExports, csvCell, type ExportAsked, type ExportWrite } from './audit-log-exports.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-17T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-17T09:00:05.000Z'),
  lastSeenAt: new Date('2026-10-17T09:10:00.000Z'),
  endsAt: new Date('2026-10-17T21:00:05.000Z'),
  idleEndsAt: new Date('2026-10-17T09:40:00.000Z'),
};

const EXPORTED: ExportWrite = {
  outcome: 'exported',
  file: {
    id: '0199a0f0-0000-7000-8000-0000000e10b1',
    fileName: 'audit-log-2026-10-01-to-2026-10-18.csv',
    contentType: 'text/csv',
    content: '"seq"\n"1"\n',
    events: 1,
    upToSeq: 12_345_678_901_234_567n,
  },
};

const BODY = { from: '2026-10-01T00:00:00.000Z', to: '2026-10-18T00:00:00.000Z', format: 'csv' };

afterEach(closeServers);

async function withExports(answer: ExportWrite, role: Role = 'admin') {
  const asked: ExportAsked[] = [];
  const exports: AuditLogExports = {
    export: (member, keyed, given) => {
      expect(member).toMatchObject({ orgId: ORG, userId: LIVE.userId });
      expect(keyed).toMatchObject({ operation: 'audit-log.export', key: 'k-1' });
      asked.push(given);
      return Promise.resolve(answer);
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, auditLogExports: exports });
  return { app, asked };
}

const post = (payload: unknown): InjectOptions => ({
  method: 'POST',
  url: '/v1/audit-log/exports',
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'idempotency-key': 'k-1',
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

describe('csvCell (SEC-EVD-04)', () => {
  it('quotes every cell, its quotes doubled', () => {
    expect(csvCell('plain')).toBe('"plain"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
  });

  it.each(['=1+1', '+1', '-1', '@SUM(A1)', '\tx', '\rx'])('makes %j text, as a spreadsheet would run it', (value) => {
    expect(csvCell(value)).toBe(`"'${value}"`);
  });
});

describe('POST /v1/audit-log/exports (E10b, decision 24)', () => {
  it('answers 201 with the file, passing the range, actions and format', async () => {
    const { app, asked } = await withExports(EXPORTED);
    const reply = await app.inject(post({ ...BODY, actions: ['mandate.accepted'] }));

    expect(reply.statusCode).toBe(201);
    expect(reply.json()).toEqual({ export: { ...EXPORTED.file, upToSeq: '12345678901234567' } });
    expect(asked).toEqual([
      {
        from: new Date(BODY.from),
        to: new Date(BODY.to),
        actions: ['mandate.accepted'],
        format: 'csv',
      },
    ]);
  });

  it('passes every action when none are named', async () => {
    const { app, asked } = await withExports(EXPORTED);
    await app.inject(post(BODY));

    expect(asked).toMatchObject([{ actions: undefined }]);
  });

  it.each([
    ['no format', { from: BODY.from, to: BODY.to }],
    ['a format it doesn’t make', { ...BODY, format: 'xlsx' }],
    ['a range that doesn’t start before it ends', { ...BODY, to: BODY.from }],
    ['a range past 366 days', { ...BODY, from: '2025-01-01T00:00:00.000Z', to: '2026-01-03T00:00:00.000Z' }],
    ['an empty list of actions', { ...BODY, actions: [] }],
    ['an action that isn’t an event’s name', { ...BODY, actions: ['DROP TABLE'] }],
    ['a field of its own', { ...BODY, role: 'admin' }],
  ])('refuses %s at the edge, the download never asked', async (_what, body) => {
    const { app, asked } = await withExports(EXPORTED);

    expect((await app.inject(post(body))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'AUDIT_EXPORT_TOO_LARGE' } as const, 409, 'AUDIT_EXPORT_TOO_LARGE'],
    [{ outcome: 'refused', status: 409, code: 'AUDIT_EXPORTS_SPENT' } as const, 409, 'AUDIT_EXPORTS_SPENT'],
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

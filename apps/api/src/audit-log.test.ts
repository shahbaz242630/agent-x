// Phase 3 E10a: the audit log's route, answering an admin with each outcome of
// the use case, its query checked at the edge and the platform's own seals
// left out. What the read does in the database is audit-log.db.test.ts and the
// audit trail's logPage tests; who reaches it, role-matrix.test.ts.
import type { LogEvent } from '@agentx/core/modules/audit';
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { AuditLog, LogPageAnswer, LogPageAsked } from './audit-log.ts';
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

const EVENT: LogEvent = {
  id: '0199a0f0-0000-7000-8000-0000000e10a1',
  seq: 12_345_678_901_234_567n,
  recordedAt: new Date('2026-10-17T08:00:00.123Z'),
  event: {
    actor: { type: 'user', id: LIVE.userId },
    action: 'mandate.over_limit_chosen',
    subject: { type: 'mandate', id: '0199a0f0-0000-7000-8000-0000000e10a2', version: 3 },
    details: { overLimit: 'approval', overLimitStatementVersion: 1, stateFingerprint: 'ab', stateKeyVersion: 1 },
  },
  hash: 'c'.repeat(64),
  prevHash: 'd'.repeat(64),
};

afterEach(closeServers);

async function withLog(answer: LogPageAnswer, role: Role = 'admin') {
  const asked: LogPageAsked[] = [];
  const log: AuditLog = {
    page: (orgId, page) => {
      expect(orgId).toBe(ORG);
      asked.push(page);
      return Promise.resolve(answer);
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, auditLog: log });
  return { app, asked };
}

const get = (query: string): InjectOptions => ({
  method: 'GET',
  url: `/v1/audit-log?${query}`,
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN },
});

const RANGE = 'from=2026-10-01T00:00:00.000Z&to=2026-10-18T00:00:00.000Z';

/** One action more than a page may be filtered to. */
const TOO_MANY_ACTIONS = Array.from({ length: 21 }, (_, n) => `a.b${String(n)}`).join(',');

describe('GET /v1/audit-log (E10a, decision 24)', () => {
  it('answers a page newest first, the platform’s seals left out, the next page named', async () => {
    const { app, asked } = await withLog({ outcome: 'page', events: [EVENT], next: 12_345_678_901_234_567n });
    const reply = await app.inject(
      get(`${RANGE}&actions=mandate.over_limit_chosen,mandate.accepted&before=99&limit=5`),
    );

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      events: [
        {
          seq: '12345678901234567',
          id: EVENT.id,
          recordedAt: '2026-10-17T08:00:00.123Z',
          actor: { type: 'user', id: LIVE.userId },
          action: 'mandate.over_limit_chosen',
          subject: EVENT.event.subject,
          details: [
            { name: 'overLimit', value: 'approval' },
            { name: 'overLimitStatementVersion', value: 1 },
          ],
          hash: 'c'.repeat(64),
          prevHash: 'd'.repeat(64),
        },
      ],
      next: '12345678901234567',
    });
    expect(asked).toEqual([
      {
        from: new Date('2026-10-01T00:00:00.000Z'),
        to: new Date('2026-10-18T00:00:00.000Z'),
        actions: ['mandate.over_limit_chosen', 'mandate.accepted'],
        beforeSeq: 99n,
        limit: 5,
      },
    ]);
  });

  it('asks every action and a whole page when none are named, answering the end as null', async () => {
    const { app, asked } = await withLog({ outcome: 'page', events: [], next: null });
    const reply = await app.inject(get(RANGE));

    expect(reply.json()).toEqual({ events: [], next: null });
    expect(asked).toMatchObject([{ actions: undefined, beforeSeq: undefined, limit: 100 }]);
  });

  it.each([
    ['no range', ''],
    ['a range that doesn’t start before it ends', 'from=2026-10-18T00:00:00.000Z&to=2026-10-18T00:00:00.000Z'],
    ['an action that isn’t an event’s name', `${RANGE}&actions=DROP TABLE`],
    ['more than 20 actions', `${RANGE}&actions=${TOO_MANY_ACTIONS}`],
    ['a limit past 100', `${RANGE}&limit=101`],
    ['a start that isn’t a seq', `${RANGE}&before=0`],
    ['a field of its own', `${RANGE}&role=admin`],
  ])('refuses %s at the edge, the log never asked', async (_what, query) => {
    const { app, asked } = await withLog({ outcome: 'page', events: [], next: null });

    expect((await app.inject(get(query))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('answers an event that can’t be believed as 503 INTEGRITY_FAILED', async () => {
    const { app } = await withLog({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    const reply = await app.inject(get(RANGE));

    expect(reply.statusCode).toBe(503);
    expect(reply.json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s (admins only)', async (role) => {
    const { app, asked } = await withLog({ outcome: 'page', events: [], next: null }, role);

    expect((await app.inject(get(RANGE))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

// Phase 3 L5: the activity log's page route, answering an admin with each
// outcome of the use case, its query checked at the edge, each row's clues
// labelled and its place credited to DB-IP. What the read does in the
// database is activity-log.db.test.ts; who reaches it, role-matrix.test.ts.
import { type ActivityPageToRead, type ActivityRow, dayOfId } from '@agentx/core/modules/activity';
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { ActivityPageAnswer, ActivityPages } from './activity-log.ts';
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

const ROW_ID = '0199a0f0-0000-7000-8000-0000000a15a1';
const AGENT = '0199a0f0-0000-7000-8000-00000000a9e1';

const ROW: ActivityRow = {
  id: ROW_ID,
  recordedAt: new Date('2026-10-19T13:39:12.123Z'),
  actor: { type: 'user', id: LIVE.userId },
  method: 'POST',
  route: '/v1/agents/:id/suspend',
  pathIds: [AGENT],
  status: 409,
  reason: 'AGENT_NOT_ACTIVE',
  correlationId: '0199a0f0-0000-7000-8000-0000000a15c0',
  durationMs: 42,
  client: {
    ip: '94.200.1.7',
    place: { country: 'AE', city: 'Dubai' },
    timeZone: { name: 'Asia/Dubai', from: 'organisation' },
  },
};

/** A row by an agent, with no clue known. */
const BARE: ActivityRow = {
  ...ROW,
  id: '0199a0f0-0000-7000-8000-0000000a15a2',
  actor: { type: 'agent', id: AGENT },
  reason: null,
  client: { ip: undefined, place: undefined, timeZone: undefined },
};

afterEach(closeServers);

async function withLog(answer: ActivityPageAnswer, role: Role = 'admin') {
  const asked: ActivityPageToRead[] = [];
  const log: ActivityPages = {
    page: (orgId, page) => {
      expect(orgId).toBe(ORG);
      asked.push(page);
      return Promise.resolve(answer);
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, activityPages: log });
  return { app, asked };
}

const EMPTY: ActivityPageAnswer = { outcome: 'page', rows: [], next: null, names: new Map(), sealedDay: null };

const get = (query: string): InjectOptions => ({
  method: 'GET',
  url: `/v1/access-log?${query}`,
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN },
});

const RANGE = 'from=2026-10-01T00:00:00.000Z&to=2026-10-20T00:00:00.000Z';
const NEXT = `2026-10-19T13:39:12.123Z_${ROW_ID}`;

describe('GET /v1/access-log (L5, decision 26)', () => {
  it('answers a page newest first, its clues labelled, its place credited, the next page named', async () => {
    const names = new Map([
      [`user:${LIVE.userId}`, { name: 'Sara Khan', email: 'sara@example.test', shownFrom: 'login_service' as const }],
    ]);
    const { app, asked } = await withLog({
      outcome: 'page',
      rows: [ROW, BARE],
      next: { at: BARE.recordedAt, id: BARE.id },
      names,
      sealedDay: dayOfId(ROW_ID),
    });
    const reply = await app.inject(get(`${RANGE}&before=${NEXT}&limit=2`));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      rows: [
        {
          id: ROW_ID,
          recordedAt: '2026-10-19T13:39:12.123Z',
          localTime: '2026-10-19T17:39:12.123+04:00',
          actor: {
            type: 'user',
            id: LIVE.userId,
            name: 'Sara Khan',
            email: 'sara@example.test',
            shownFrom: 'login_service',
          },
          method: 'POST',
          route: '/v1/agents/:id/suspend',
          pathIds: [AGENT],
          status: 409,
          reason: 'AGENT_NOT_ACTIVE',
          correlationId: ROW.correlationId,
          durationMs: 42,
          sealed: true,
          client: {
            ip: '94.200.1.7',
            place: {
              country: 'AE',
              city: 'Dubai',
              approximate: true,
              by: 'IP Geolocation by DB-IP',
              link: 'https://db-ip.com',
            },
            timeZone: { name: 'Asia/Dubai', from: 'organisation' },
          },
        },
        expect.objectContaining({
          id: BARE.id,
          localTime: null,
          actor: { type: 'agent', id: AGENT, name: null, email: null, shownFrom: null },
          reason: null,
          sealed: true,
          client: { ip: null, place: null, timeZone: null },
        }),
      ],
      next: `2026-10-19T13:39:12.123Z_${BARE.id}`,
      sealedThrough: dayOfId(ROW_ID),
    });
    expect(asked).toEqual([
      {
        from: new Date('2026-10-01T00:00:00.000Z'),
        to: new Date('2026-10-20T00:00:00.000Z'),
        actor: undefined,
        before: { at: new Date('2026-10-19T13:39:12.123Z'), id: ROW_ID },
        limit: 2,
      },
    ]);
  });

  it('marks a row written after the newest day sealed unsealed, and names no day while none is sealed (L6)', async () => {
    const { app } = await withLog({ ...EMPTY, rows: [ROW], sealedDay: '2020-01-01' });
    const reply = await app.inject(get(RANGE));

    expect(reply.json()).toMatchObject({ rows: [{ id: ROW_ID, sealed: false }], sealedThrough: '2020-01-01' });
    const none = await (await withLog({ ...EMPTY, rows: [ROW] })).app.inject(get(RANGE));
    expect(none.json()).toMatchObject({ rows: [{ sealed: false }], sealedThrough: null });
  });

  it.each(['user', 'agent'] as const)('asks for one %s’s rows, a UUID in capitals in lower case', async (type) => {
    const { app, asked } = await withLog(EMPTY);
    const reply = await app.inject(get(`${RANGE}&actorType=${type}&actorId=${AGENT.toUpperCase()}`));

    expect(reply.statusCode).toBe(200);
    expect(asked).toMatchObject([{ actor: { type, id: AGENT } }]);
  });

  it('takes a page’s `next` with its ID in capitals, as the log keeps it', async () => {
    const { app, asked } = await withLog(EMPTY);
    await app.inject(get(`${RANGE}&before=2026-10-19T13:39:12.123Z_${ROW_ID.toUpperCase()}`));

    expect(asked).toMatchObject([{ before: { id: ROW_ID } }]);
  });

  it('asks everyone’s rows and a whole page when neither is named, answering the end as null', async () => {
    const { app, asked } = await withLog(EMPTY);
    const reply = await app.inject(get(RANGE));

    expect(reply.json()).toEqual({ rows: [], next: null, sealedThrough: null });
    expect(asked).toMatchObject([{ actor: undefined, before: undefined, limit: 100 }]);
  });

  it.each([
    ['no range', ''],
    ['a range that doesn’t start before it ends', 'from=2026-10-18T00:00:00.000Z&to=2026-10-18T00:00:00.000Z'],
    ['a limit past 100', `${RANGE}&limit=101`],
    ['an actor’s type without its ID', `${RANGE}&actorType=user`],
    ['an actor’s ID without its type', `${RANGE}&actorId=${AGENT}`],
    ['a part of Agent X, which makes no requests', `${RANGE}&actorType=system&actorId=api`],
    ['an actor named by something not a UUID', `${RANGE}&actorType=user&actorId=integrity-hold`],
    ['a start that isn’t a page’s `next`', `${RANGE}&before=${ROW_ID}`],
    ['a start at a time that doesn’t exist', `${RANGE}&before=2026-02-30T13:39:12.123Z_${ROW_ID}`],
    ['a start whose time isn’t to the millisecond', `${RANGE}&before=2026-10-19T13:39:12Z_${ROW_ID}`],
    ['a field of its own', `${RANGE}&role=admin`],
  ])('refuses %s at the edge, the log never asked', async (_what, query) => {
    const { app, asked } = await withLog(EMPTY);

    expect((await app.inject(get(query))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('answers an agent that can’t be believed as 503 INTEGRITY_FAILED', async () => {
    const { app } = await withLog({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    const reply = await app.inject(get(RANGE));

    expect(reply.statusCode).toBe(503);
    expect(reply.json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s (admins only)', async (role) => {
    const { app, asked } = await withLog(EMPTY, role);

    expect((await app.inject(get(RANGE))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

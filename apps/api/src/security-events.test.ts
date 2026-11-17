// Phase 6 6E1b (CO7b): the organisation's security events' page route,
// answering an admin with each outcome of the use case, its query checked at
// the edge, each actor named and the address given as a clue. What the read
// does in the database is security-events.db.test.ts.
import type { MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { OrgEventsToRead, OrgSecurityEvent } from '@agentx/core/modules/security-events';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { liveSession } from './live-session.helper.test.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import type { SecurityEventPages, SecurityEventsPageAnswer } from './security-events.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const LIVE = liveSession('2026-10-19T09:00:00.000Z');

const ROW_ID = '0199a0f0-0000-7000-8000-0000000a15a1';
const AGENT = '0199a0f0-0000-7000-8000-00000000a9e1';

const ROW: OrgSecurityEvent = {
  id: ROW_ID,
  kind: 'rate_limited',
  reason: 'per_user',
  ip: '94.200.1.7',
  actor: { type: 'user', id: LIVE.userId },
  windowStart: new Date('2026-10-19T13:39:00.000Z'),
  count: 12,
};

/** An agent's, and one about no one with no address. */
const AGENTS: OrgSecurityEvent = {
  ...ROW,
  id: '0199a0f0-0000-7000-8000-0000000a15a2',
  reason: 'per_agent',
  actor: { type: 'agent', id: AGENT },
};
const BARE: OrgSecurityEvent = { ...ROW, id: '0199a0f0-0000-7000-8000-0000000a15a3', ip: null, actor: null, count: 1 };

afterEach(closeServers);

async function withPages(answer: SecurityEventsPageAnswer, role: Role = 'admin') {
  const asked: OrgEventsToRead[] = [];
  const pages: SecurityEventPages = {
    page: (orgId, page) => {
      expect(orgId).toBe(ORG);
      asked.push(page);
      return Promise.resolve(answer);
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({ live: LIVE, member, securityEventPages: pages });
  return { app, asked };
}

const EMPTY: SecurityEventsPageAnswer = { outcome: 'page', rows: [], next: null, names: new Map() };

const get = (query: string, signedIn = true): InjectOptions => ({
  method: 'GET',
  url: `/v1/security-events?${query}`,
  headers: {
    ...(signedIn && { cookie: `${SESSION_COOKIE}=${COOKIE}` }),
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
  },
});

const RANGE = 'from=2026-10-01T00:00:00.000Z&to=2026-10-20T00:00:00.000Z';
const NEXT = `2026-10-19T13:39:00.000Z_${ROW_ID}`;

describe('GET /v1/security-events (6E1b, CO7b)', () => {
  it('answers a page newest first, each actor named, the next page named', async () => {
    const names = new Map([
      [`user:${LIVE.userId}`, { name: 'Sara Khan', email: 'sara@example.test', shownFrom: 'login_service' as const }],
    ]);
    const { app, asked } = await withPages({
      outcome: 'page',
      rows: [ROW, AGENTS, BARE],
      next: { at: BARE.windowStart, id: BARE.id },
      names,
    });
    const reply = await app.inject(get(`${RANGE}&kind=rate_limited&before=${NEXT}&limit=3`));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      rows: [
        {
          id: ROW_ID,
          kind: 'rate_limited',
          reason: 'per_user',
          ip: '94.200.1.7',
          actor: { type: 'user', id: LIVE.userId, name: 'Sara Khan' },
          windowStart: '2026-10-19T13:39:00.000Z',
          count: 12,
        },
        expect.objectContaining({ id: AGENTS.id, actor: { type: 'agent', id: AGENT, name: null } }),
        expect.objectContaining({ id: BARE.id, ip: null, actor: null, count: 1 }),
      ],
      next: `2026-10-19T13:39:00.000Z_${BARE.id}`,
    });
    expect(asked).toEqual([
      {
        from: new Date('2026-10-01T00:00:00.000Z'),
        to: new Date('2026-10-20T00:00:00.000Z'),
        kind: 'rate_limited',
        before: { at: new Date('2026-10-19T13:39:00.000Z'), id: ROW_ID },
        limit: 3,
      },
    ]);
  });

  it('asks every kind and a whole page when neither is named, answering the end as null', async () => {
    const { app, asked } = await withPages(EMPTY);
    const reply = await app.inject(get(RANGE));

    expect(reply.json()).toEqual({ rows: [], next: null });
    expect(asked).toMatchObject([{ kind: undefined, before: undefined, limit: 100 }]);
  });

  it('takes a page’s `next` with its ID in capitals', async () => {
    const { app, asked } = await withPages(EMPTY);
    await app.inject(get(`${RANGE}&before=2026-10-19T13:39:00.000Z_${ROW_ID.toUpperCase()}`));

    expect(asked).toMatchObject([{ before: { id: ROW_ID } }]);
  });

  it.each([
    ['no range', ''],
    ['a range that doesn’t start before it ends', 'from=2026-10-18T00:00:00.000Z&to=2026-10-18T00:00:00.000Z'],
    ['a limit past 100', `${RANGE}&limit=101`],
    ['a limit of none', `${RANGE}&limit=0`],
    ['a kind no organisation’s event is', `${RANGE}&kind=partner_event_refused`],
    ['a start that isn’t a page’s `next`', `${RANGE}&before=${ROW_ID}`],
    ['a start at a time that doesn’t exist', `${RANGE}&before=2026-02-30T13:39:00.000Z_${ROW_ID}`],
    ['a field of its own', `${RANGE}&orgId=${ORG}`],
  ])('refuses %s at the edge, the events never asked', async (_what, query) => {
    const { app, asked } = await withPages(EMPTY);

    expect((await app.inject(get(query))).statusCode).toBe(400);
    expect(asked).toEqual([]);
  });

  it('answers an agent that can’t be believed as 503 INTEGRITY_FAILED', async () => {
    const { app } = await withPages({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    const reply = await app.inject(get(RANGE));

    expect(reply.statusCode).toBe(503);
    expect(reply.json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });

  it('refuses someone not signed in as 401, the events never asked', async () => {
    const { app, asked } = await withPages(EMPTY);

    expect((await app.inject(get(RANGE, false))).statusCode).toBe(401);
    expect(asked).toEqual([]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s (admins only)', async (role) => {
    const { app, asked } = await withPages(EMPTY, role);

    expect((await app.inject(get(RANGE))).statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

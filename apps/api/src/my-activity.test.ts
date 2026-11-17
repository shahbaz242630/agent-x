// 6E1a (CO8, PL-48): a person's own activity log's routes, with a stub use
// case. The person is always the session's, never a parameter; no organisation
// header and no role; anyone not signed in is refused before the use case is
// asked; the limits are checked at the edge; each outcome answered. And a
// person's idempotency key is theirs alone: the stored key is the session's
// user's (client kind `user`, the session's ID), so another person sending the
// same key reaches their own, never the first person's answer. What the use
// case reads and writes in the database is my-activity.db.test.ts's.
import type { PersonActivityRow } from '@agentx/core/modules/activity';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { liveSession } from './live-session.helper.test.ts';
import {
  createBuildGate,
  type MyActivity,
  type MyActivityAsked,
  type MyActivityPage,
  type MyExportAsked,
  type MyExportWrite,
  myActivityLineOf,
  PERSON_KEYS_TENANT,
} from './my-activity.ts';
import { closeServers, COOKIE, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const LIVE = liveSession('2026-11-16T09:00:00.000Z');
const OTHER = { ...LIVE, userId: '0199a0f0-0000-7000-8000-00000000b0b0' };
const CLAIMED = '0199a0f0-0000-7000-8000-00000000c1a1';

const ROW: PersonActivityRow = {
  id: '019a8b10-0000-7000-8000-0000000000f1',
  recordedAt: new Date('2026-11-15T05:00:00.000Z'),
  claimedOrg: CLAIMED,
  method: 'GET',
  route: '/v1/auth/session',
  pathIds: [],
  status: 403,
  reason: 'FORBIDDEN',
  correlationId: '0199a0f0-0000-7000-8000-0000000000f2',
  durationMs: 7,
  client: {
    ip: '203.0.113.7',
    place: { country: 'AE', city: 'Dubai' },
    timeZone: { name: 'Asia/Dubai', from: 'browser' },
  },
};

const PAGE: MyActivityPage = {
  outcome: 'page',
  rows: [ROW],
  next: { at: ROW.recordedAt, id: ROW.id },
  sealedDay: '2026-11-15',
  exports: [
    {
      seq: 9n,
      id: '0199a0f0-0000-7000-8000-0000000000e1',
      action: 'operator.person_log_exported',
      recordedAt: new Date('2026-11-16T08:00:00.000Z'),
      details: { from: '2026-11-01T00:00:00.000Z', to: '2026-11-16T00:00:00.000Z', requests: 4, caseRef: 'DSP-1' },
    },
  ],
};

const FILE = {
  id: '0199a0f0-0000-7000-8000-0000000a15e1',
  fileName: 'my-activity-log-2026-11-01-to-2026-11-16.csv',
  contentType: 'text/csv',
  content: '"id"\n"x"\n',
  requests: 1,
} as const;

const EXPORTED: MyExportWrite = { outcome: 'exported', file: FILE };

afterEach(closeServers);

interface Asked {
  readonly pages: [string, MyActivityAsked][];
  readonly exports: [string, IdempotentRequest, MyExportAsked][];
}

async function withActivity(
  { page = PAGE, write = EXPORTED }: { page?: MyActivityPage; write?: MyExportWrite } = {},
  live = LIVE,
) {
  const asked: Asked = { pages: [], exports: [] };
  const myActivity: MyActivity = {
    page: (userId, given) => {
      asked.pages.push([userId, given]);
      return Promise.resolve(page);
    },
    export: (userId, keyed, given) => {
      asked.exports.push([userId, keyed, given]);
      return Promise.resolve(write);
    },
  };
  const app = await routeServer({ live, myActivity });
  return { app, asked };
}

const RANGE = 'from=2026-11-01T00:00:00.000Z&to=2026-11-16T00:00:00.000Z';
const get = (query: string, signedIn = true): InjectOptions => ({
  method: 'GET',
  url: `/v1/auth/activity?${query}`,
  headers: signedIn ? { cookie: `${SESSION_COOKIE}=${COOKIE}` } : {},
});

const BODY = { from: '2026-11-01T00:00:00.000Z', to: '2026-11-16T00:00:00.000Z', format: 'csv' };
const post = (payload: unknown, { key = 'k-1', signedIn = true } = {}): InjectOptions => ({
  method: 'POST',
  url: '/v1/auth/activity/exports',
  headers: {
    ...(signedIn && { cookie: `${SESSION_COOKIE}=${COOKIE}` }),
    origin: PUBLIC_ORIGIN,
    'idempotency-key': key,
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

describe('GET /v1/auth/activity answers a signed-in person with their own log', () => {
  it('shows each row as the person sees it, sealed by the newest seal, and Agent X’s exports of it', async () => {
    const { app, asked } = await withActivity();

    const response = await app.inject(get(`${RANGE}&limit=10`));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      rows: [
        {
          id: ROW.id,
          recordedAt: '2026-11-15T05:00:00.000Z',
          localTime: '2026-11-15T09:00:00.000+04:00',
          claimedOrganizationId: CLAIMED,
          method: 'GET',
          route: '/v1/auth/session',
          pathIds: [],
          status: 403,
          reason: 'FORBIDDEN',
          correlationId: ROW.correlationId,
          durationMs: 7,
          sealed: true,
          client: {
            ip: '203.0.113.7',
            place: {
              country: 'AE',
              city: 'Dubai',
              approximate: true,
              by: 'IP Geolocation by DB-IP',
              link: 'https://db-ip.com',
            },
            timeZone: { name: 'Asia/Dubai', from: 'browser' },
          },
        },
      ],
      next: `2026-11-15T05:00:00.000Z_${ROW.id}`,
      sealedThrough: '2026-11-15',
      exportsByAgentX: [
        {
          id: '0199a0f0-0000-7000-8000-0000000000e1',
          at: '2026-11-16T08:00:00.000Z',
          from: '2026-11-01T00:00:00.000Z',
          to: '2026-11-16T00:00:00.000Z',
          requests: 4,
          caseRef: 'DSP-1',
        },
      ],
    });
    expect(asked.pages).toEqual([
      [
        LIVE.userId,
        {
          from: new Date('2026-11-01T00:00:00.000Z'),
          to: new Date('2026-11-16T00:00:00.000Z'),
          before: undefined,
          limit: 10,
        },
      ],
    ]);
  });

  it('reads only the session’s person: a user named in the query is refused, never read', async () => {
    const { app, asked } = await withActivity();

    const response = await app.inject(get(`${RANGE}&userId=${OTHER.userId}`));

    expect(response.statusCode).toBe(400);
    expect(asked.pages).toEqual([]);
  });

  it('starts a page before the row `next` named, a full page unless fewer are asked for', async () => {
    const { app, asked } = await withActivity({ page: { ...PAGE, next: null, exports: [] } });

    const response = await app.inject(get(`${RANGE}&before=2026-11-15T05:00:00.000Z_${ROW.id.toUpperCase()}`));

    expect(response.json()).toMatchObject({ next: null, exportsByAgentX: [] });
    expect(asked.pages[0]?.[1]).toMatchObject({ before: { id: ROW.id }, limit: 100 });
  });

  it.each([
    ['a range that runs backwards', 'from=2026-11-16T00:00:00.000Z&to=2026-11-01T00:00:00.000Z'],
    ['a cursor that is no page’s', `${RANGE}&before=yesterday`],
    ['a page past 100', `${RANGE}&limit=101`],
  ])('refuses %s, asking nothing of the use case', async (_what, query) => {
    const { app, asked } = await withActivity();

    expect((await app.inject(get(query))).statusCode).toBe(400);
    expect(asked.pages).toEqual([]);
  });

  it('refuses anyone not signed in', async () => {
    const { app, asked } = await withActivity();

    expect((await app.inject(get(RANGE, false))).statusCode).toBe(401);
    expect(asked.pages).toEqual([]);
  });

  it('answers a record that can’t be believed as INTEGRITY_FAILED', async () => {
    const { app } = await withActivity({ page: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });

    const response = await app.inject(get(RANGE));

    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({ error: { code: 'INTEGRITY_FAILED' } });
  });
});

describe('POST /v1/auth/activity/exports downloads a person’s own log', () => {
  it('answers the file, for the session’s person, its key kept as theirs outside any organisation', async () => {
    const { app, asked } = await withActivity();

    const response = await app.inject(post(BODY));

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({ export: FILE });
    expect(asked.exports).toHaveLength(1);
    const [userId, keyed, given] = asked.exports[0] ?? [];
    expect(userId).toBe(LIVE.userId);
    expect(keyed).toMatchObject({
      orgId: PERSON_KEYS_TENANT,
      client: { kind: 'user', id: LIVE.userId },
      operation: 'my-activity.export',
      key: 'k-1',
    });
    expect(given).toEqual({
      from: new Date('2026-11-01T00:00:00.000Z'),
      to: new Date('2026-11-16T00:00:00.000Z'),
      format: 'csv',
    });
  });

  it('keeps one person’s key apart from another’s: the same key sent by another person is stored as theirs', async () => {
    const first = await withActivity();
    await first.app.inject(post(BODY, { key: 'same-key' }));
    const second = await withActivity({}, OTHER);
    await second.app.inject(post(BODY, { key: 'same-key' }));

    const [, keyedFirst] = first.asked.exports[0] ?? [];
    const [otherUser, keyedSecond] = second.asked.exports[0] ?? [];
    expect(otherUser).toBe(OTHER.userId);
    expect(keyedFirst?.client).toEqual({ kind: 'user', id: LIVE.userId });
    expect(keyedSecond?.client).toEqual({ kind: 'user', id: OTHER.userId });
  });

  it.each([
    ['a range past 366 days', { ...BODY, from: '2025-01-01T00:00:00.000Z' }],
    ['a range a moment past 366 days', { ...BODY, from: '2025-11-14T23:59:59.999Z' }],
    ['a range that runs backwards', { ...BODY, to: '2026-10-01T00:00:00.000Z' }],
    ['another format', { ...BODY, format: 'xlsx' }],
    ['a person named in the body', { ...BODY, userId: OTHER.userId }],
  ])('refuses %s, asking nothing of the use case', async (_what, body) => {
    const { app, asked } = await withActivity();

    expect((await app.inject(post(body))).statusCode).toBe(400);
    expect(asked.exports).toEqual([]);
  });

  it('refuses anyone not signed in', async () => {
    const { app, asked } = await withActivity();

    expect((await app.inject(post(BODY, { signedIn: false }))).statusCode).toBe(401);
    expect(asked.exports).toEqual([]);
  });

  it('takes a range of 366 days exactly', async () => {
    const { app, asked } = await withActivity();

    expect((await app.inject(post({ ...BODY, from: '2025-11-15T00:00:00.000Z' }))).statusCode).toBe(201);
    expect(asked.exports).toHaveLength(1);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORT_TOO_LARGE' } as const, 409],
    [{ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORTS_SPENT' } as const, 409],
    [{ outcome: 'refused', status: 503, code: 'ACTIVITY_EXPORTS_BUSY' } as const, 503],
    [{ outcome: 'conflict' } as const, 409],
  ])('answers %o as its refusal', async (write, status) => {
    const { app } = await withActivity({ write });

    expect((await app.inject(post(BODY))).statusCode).toBe(status);
  });
});

describe('a download’s line', () => {
  it('writes a CSV row with every cell made safe, and an NDJSON line as the page shows it', () => {
    const csv = myActivityLineOf('csv', { ...ROW, route: '=cmd' }, null);
    expect(csv).toContain(`"'=cmd"`);
    expect(csv).toContain('"false"');
    expect(csv).toContain('"IP Geolocation by DB-IP (https://db-ip.com)"');
    const bare = myActivityLineOf(
      'csv',
      { ...ROW, claimedOrg: null, reason: null, client: { ip: undefined, place: undefined, timeZone: undefined } },
      '2026-11-15',
    );
    expect(bare).toContain('"true"');
    expect(JSON.parse(myActivityLineOf('ndjson', ROW, null))).toMatchObject({ id: ROW.id, sealed: false });
  });
});

describe('a person’s downloads hold no one else up (6E1a review)', () => {
  const at = new Date('2026-11-16T09:00:00.000Z');
  const clock = { now: () => at };

  it('lets a person hold one build at a time, out of two slots shared by people alone', () => {
    const gate = createBuildGate(clock, 2);

    expect(gate.enter(LIVE.userId)).toBeUndefined();
    expect(gate.enter(LIVE.userId)).toEqual({ outcome: 'refused', status: 503, code: 'ACTIVITY_EXPORTS_BUSY' });
    expect(gate.enter(OTHER.userId)).toBeUndefined();
    expect(gate.enter(CLAIMED)).toEqual({ outcome: 'refused', status: 503, code: 'ACTIVITY_EXPORTS_BUSY' });
    gate.leave(LIVE.userId);
    expect(gate.enter(CLAIMED)).toBeUndefined();
  });

  it('holds a person’s retries answered from their key to five an hour, each person’s own', () => {
    let now = at.getTime();
    const gate = createBuildGate({ now: () => new Date(now) }, 2, 5);

    for (let made = 0; made < 5; made += 1) expect(gate.replayed(LIVE.userId)).toBeUndefined();
    expect(gate.replayed(LIVE.userId)).toEqual({ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORTS_SPENT' });
    expect(gate.replayed(OTHER.userId)).toBeUndefined();
    now += 60 * 60_000 + 1;
    expect(gate.replayed(LIVE.userId)).toBeUndefined();
  });

  it('forgets a person’s retries once their hour has passed, keeping no more people than were active in it', () => {
    let now = at.getTime();
    const gate = createBuildGate({ now: () => new Date(now) }, 2, 5, 4);
    const person = (n: number) => `0199a0f0-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;

    for (let n = 0; n < 4; n += 1) gate.replayed(person(n));
    expect(gate.kept()).toBe(4);
    now += 60 * 60_000 + 1;
    gate.replayed(person(99));
    // The four from the hour before are gone; only the one active now is kept.
    expect(gate.kept()).toBe(1);
    for (let n = 100; n < 1_000; n += 1) {
      gate.replayed(person(n));
      now += 60 * 60_000 + 1;
    }
    expect(gate.kept()).toBeLessThanOrEqual(4);
  });

  it('answers a busy server with when to send it again', async () => {
    const { app } = await withActivity({ write: { outcome: 'refused', status: 503, code: 'ACTIVITY_EXPORTS_BUSY' } });

    const response = await app.inject(post(BODY));

    expect(response.statusCode).toBe(503);
    expect(response.headers['retry-after']).toBe('5');
  });
});

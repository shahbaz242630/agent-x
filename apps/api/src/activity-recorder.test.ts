// Phase 3 L3: the activity log's recorder on a real server, every known
// caller's request written once answered (decision 26): a member's to their
// organisation (refused by role or passkey too), an agent's to its own, a
// person's naming no organisation they are verified in to the person's, and
// nothing for a caller not known. A row that can't be written never fails the
// answer and is logged at error level. What the rows hold in the database is
// the activity module's db test.
import type { OrganisationRequest, PersonRequest } from '@agentx/core/modules/activity';
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { type ActivitySink, pathIdsOf, reasonIn } from './activity-recorder.ts';
import type { AuditLog } from './audit-log.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-18T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-18T09:00:05.000Z'),
  lastSeenAt: new Date('2026-10-18T09:10:00.000Z'),
  endsAt: new Date('2099-10-18T21:00:05.000Z'),
  idleEndsAt: new Date('2099-10-18T09:40:00.000Z'),
};

const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000dcba';
const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY = `axk_${'c'.repeat(32)}_${'b'.repeat(43)}`;
const KEY_ACCEPTED: AcceptedKey = {
  orgId: ORG,
  agentId: AGENT_ID,
  keyId: '0199a0f0-0000-7000-8000-0000000000b1',
  scopes: ['requests:read'],
  expiresAt: new Date('2099-12-28T09:00:00.000Z'),
};

const LOG: AuditLog = { page: () => Promise.resolve({ outcome: 'page', events: [], next: null, names: new Map() }) };

afterEach(closeServers);

/** A server whose activity rows land in `rows`; `failing` makes every write fail. */
async function recording({
  role = 'admin',
  live = LIVE,
  failing = false,
}: { readonly role?: Role; readonly live?: LiveSession; readonly failing?: boolean } = {}) {
  const rows: (OrganisationRequest | PersonRequest)[] = [];
  const write = (row: OrganisationRequest | PersonRequest) => {
    if (failing) return Promise.reject(new Error('the database is gone: 203.0.113.7'));
    rows.push(row);
    return Promise.resolve();
  };
  const sink: ActivitySink = { forOrganisation: write, forPerson: write };
  const capture = new LogCapture();
  const config = {
    environment: 'test' as const,
    release: 'r-1',
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const member: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role };
  const app = await routeServer({
    live,
    member,
    auditLog: LOG,
    activity: sink,
    logger: createLogger({ service: 'api', config, destination: capture }),
    checkAgentKey: (text) =>
      Promise.resolve(text === KEY ? { outcome: 'accepted', key: KEY_ACCEPTED } : { outcome: 'refused' }),
  });
  return { app, rows, capture };
}

const asMember = (url: string, org = ORG): InjectOptions => ({
  method: 'GET',
  url,
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: org, origin: PUBLIC_ORIGIN },
});

const LOG_URL = '/v1/audit-log?from=2026-10-01T00:00:00.000Z&to=2026-10-18T00:00:00.000Z';

describe('the activity log’s recorder (L3, decision 26)', () => {
  it('writes an admin’s read to their organisation: the route’s pattern, never the query', async () => {
    const { app, rows } = await recording();
    const reply = await app.inject(asMember(LOG_URL));

    expect(reply.statusCode).toBe(200);
    await vi.waitFor(() => {
      expect(rows).toHaveLength(1);
    });
    const [row] = rows;
    expect(row).toEqual({
      at: expect.any(Date) as Date,
      method: 'GET',
      route: '/v1/audit-log',
      pathIds: [],
      status: 200,
      reason: undefined,
      correlationId: reply.headers['x-correlation-id'],
      durationMs: expect.any(Number) as number,
      orgId: ORG,
      actor: { type: 'user', id: LIVE.userId },
    });
    expect(JSON.stringify(row)).not.toContain('2026-10-01');
  });

  it.each([
    ['a role the route doesn’t name', { role: 'viewer' as const }, 'FORBIDDEN'],
    ['no passkey', { live: { ...LIVE, amr: ['pwd', 'mfa'] } }, 'PASSKEY_REQUIRED'],
  ])('writes a member refused for %s to their organisation, with its reason', async (_why, change, reason) => {
    const { app, rows } = await recording(change);
    const reply = await app.inject(asMember(LOG_URL));

    expect(reply.statusCode).toBe(403);
    await vi.waitFor(() => {
      expect(rows).toEqual([expect.objectContaining({ orgId: ORG, status: 403, reason })]);
    });
  });

  it('writes a person refused in an organisation they aren’t in to their own log, the organisation as a claim', async () => {
    const { app, rows } = await recording();
    await app.inject(asMember(LOG_URL, OTHER_ORG.toUpperCase()));

    await vi.waitFor(() => {
      expect(rows).toEqual([
        expect.objectContaining({ userId: LIVE.userId, claimedOrg: OTHER_ORG, status: 403, reason: 'FORBIDDEN' }),
      ]);
    });
    expect(rows[0]).not.toHaveProperty('orgId');
  });

  it('writes a person’s own route to their log, naming no organisation', async () => {
    const { app, rows } = await recording();
    const reply = await app.inject({
      method: 'GET',
      url: '/v1/auth/session',
      headers: { cookie: `${SESSION_COOKIE}=${COOKIE}` },
    });

    expect(reply.statusCode).toBe(200);
    await vi.waitFor(() => {
      expect(rows).toEqual([
        expect.objectContaining({ userId: LIVE.userId, claimedOrg: undefined, route: '/v1/auth/session', status: 200 }),
      ]);
    });
  });

  it('writes an agent’s request to its organisation, refused for a scope too', async () => {
    const { app, rows } = await recording();
    const self = await app.inject({ method: 'GET', url: '/v1/agent', headers: { authorization: `Bearer ${KEY}` } });
    const mandate = await app.inject({
      method: 'GET',
      url: '/v1/agent/mandate',
      headers: { authorization: `Bearer ${KEY}` },
    });

    expect([self.statusCode, mandate.statusCode]).toEqual([200, 403]);
    await vi.waitFor(() => {
      expect(rows).toHaveLength(2);
    });
    expect(rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          orgId: ORG,
          actor: { type: 'agent', id: AGENT_ID },
          route: '/v1/agent',
          status: 200,
        }),
        expect.objectContaining({ route: '/v1/agent/mandate', status: 403, reason: 'INSUFFICIENT_SCOPE' }),
      ]),
    );
  });

  it('writes nothing for a caller not known: signed out, or a key refused', async () => {
    const { app, rows } = await recording();
    const signedOut = await app.inject({ method: 'GET', url: LOG_URL, headers: { [ORGANIZATION_HEADER]: ORG } });
    const refused = await app.inject({
      method: 'GET',
      url: '/v1/agent',
      headers: { authorization: `Bearer axk_${'d'.repeat(32)}_${'b'.repeat(43)}` },
    });
    // A request after them, so their rows would be written by the time its own is.
    await app.inject(asMember(LOG_URL));

    expect([signedOut.statusCode, refused.statusCode]).toEqual([401, 401]);
    await vi.waitFor(() => {
      expect(rows).toHaveLength(1);
    });
    expect(rows[0]).toMatchObject({ status: 200 });
  });

  it('answers as usual when a row can’t be written, and logs that at error level without the error’s text', async () => {
    const { app, capture } = await recording({ failing: true });
    const reply = await app.inject(asMember(LOG_URL));

    expect(reply.statusCode).toBe(200);
    await vi.waitFor(() => {
      expect(capture.lines()).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            level: 'error',
            event: 'access_log.write_failed',
            route: '/v1/audit-log',
            status: 200,
            malformed: false,
          }),
        ]),
      );
    });
    expect(JSON.stringify(capture.lines())).not.toContain('203.0.113.7');
  });

  it('waits for a row still being written as the server closes', async () => {
    const { app, rows } = await recording();
    await app.inject(asMember(LOG_URL));
    await app.close();

    expect(rows).toHaveLength(1);
  });
});

describe('what a row takes from a request', () => {
  it('takes the reason code from an error answer, and nothing from anything else', () => {
    expect(reasonIn('{"error":{"code":"FORBIDDEN","message":"x"}}')).toBe('FORBIDDEN');
    expect(reasonIn(undefined)).toBeUndefined();
    expect(reasonIn('not json')).toBeUndefined();
    expect(reasonIn('null')).toBeUndefined();
    expect(reasonIn('{"events":[]}')).toBeUndefined();
    expect(reasonIn('{"error":null}')).toBeUndefined();
    expect(reasonIn('{"error":{"message":"x"}}')).toBeUndefined();
    expect(reasonIn('{"error":{"code":7}}')).toBeUndefined();
  });

  it('takes the UUIDs in a path, lower case, four at most', () => {
    const id = (n: number) => `0199A0F0-0000-7000-8000-00000000000${String(n)}`;
    expect(pathIdsOf({ id: id(1), name: 'x', n: 3 })).toEqual([id(1).toLowerCase()]);
    expect(pathIdsOf({ a: id(1), b: id(2), c: id(3), d: id(4), e: id(5) })).toHaveLength(4);
    expect(pathIdsOf(undefined)).toEqual([]);
    expect(pathIdsOf(null)).toEqual([]);
  });
});

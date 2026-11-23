// B4-2b: GET /v1/members, the first route naming roles. Who reaches it is the
// access hook's (access-roles.test.ts, role-matrix.test.ts); here, what it
// answers a member with each outcome of the list. The list's own reading and
// verifying is the identity module's (memberships.db.test.ts).
import type { ActorName } from '@agentx/core/modules/evidence';
import type { MembersList, MembershipCheck, Role } from '@agentx/core/modules/identity';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { errorBody } from './errors.ts';
import { liveSession, ONE_TIME_CODE } from './live-session.helper.test.ts';
import type { ListMembers, MembersAnswer } from './members.ts';
import { closeServers, COOKIE, ORG, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const FIRST_ID = '00000000-0000-7000-8000-000000000001';

const LIVE = liveSession('2026-09-24T09:00:00.000Z', { amr: ONE_TIME_CODE });

const ACTIVE_VIEWER: Extract<MembershipCheck, { outcome: 'active' }> = {
  outcome: 'active',
  id: '0199a0f0-0000-7000-8000-000000000033',
  role: 'viewer',
};

const LISTED: MembersList = {
  outcome: 'listed',
  members: [
    {
      id: '0199a0f0-0000-7000-8000-000000000033',
      userId: LIVE.userId,
      role: 'viewer',
      status: 'ACTIVE',
      joinedAt: new Date('2026-09-25T09:00:00.123Z'),
    },
    {
      id: '0199a0f0-0000-7000-8000-000000000044',
      userId: '0199a0f0-0000-7000-8000-000000000055',
      role: 'admin',
      status: 'DEACTIVATED',
      joinedAt: new Date('2026-09-20T08:00:00.000Z'),
    },
  ],
};

afterEach(closeServers);

/** A server whose list answers `list` (`named` when asked to name them), for a member in `role`. */
async function withMembers(
  list: MembersList | Error,
  options: { listed?: boolean; role?: Role; restricted?: Date; named?: MembersAnswer } = {},
) {
  const asked: [orgId: string, correlationId: string, named: boolean][] = [];
  const listMembers: ListMembers = (orgId, correlationId, named) => {
    asked.push([orgId, correlationId, named]);
    if (list instanceof Error) return Promise.reject(list);
    return Promise.resolve(named && options.named !== undefined ? options.named : list);
  };
  const app = await routeServer({
    live: LIVE,
    member: { ...ACTIVE_VIEWER, role: options.role ?? 'viewer' },
    ...((options.listed ?? true) && { listMembers }),
    ...(options.restricted !== undefined && { restrictedUntil: () => Promise.resolve(options.restricted) }),
  });
  return { app, asked };
}

const request = (org = ORG): InjectOptions => ({
  method: 'GET',
  url: '/v1/members',
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: org },
});

describe('GET /v1/members answers a member with their organisation’s members', () => {
  it('lists each member, deactivated ones included, for the organisation the request names, in lower case', async () => {
    const { app, asked } = await withMembers(LISTED);

    const response = await app.inject(request(ORG.toUpperCase()));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      members: [
        {
          id: '0199a0f0-0000-7000-8000-000000000033',
          userId: LIVE.userId,
          role: 'viewer',
          status: 'ACTIVE',
          joinedAt: '2026-09-25T09:00:00.123Z',
        },
        {
          id: '0199a0f0-0000-7000-8000-000000000044',
          userId: '0199a0f0-0000-7000-8000-000000000055',
          role: 'admin',
          status: 'DEACTIVATED',
          joinedAt: '2026-09-20T08:00:00.000Z',
        },
      ],
    });
    expect(asked).toEqual([[ORG, FIRST_ID, false]]);
  });

  it('withholds the whole list as 503 INTEGRITY_FAILED when a membership in it was tampered with', async () => {
    const { app } = await withMembers({ outcome: 'tampered', sign: 'seal' });

    const response = await app.inject(request());

    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual(errorBody('INTEGRITY_FAILED', FIRST_ID));
  });

  it('fails as INTERNAL_ERROR when the list can’t be read, or when no reader was given', async () => {
    for (const { app } of [
      await withMembers(new Error('the database is away')),
      await withMembers(LISTED, { listed: false }),
    ]) {
      const response = await app.inject(request());

      expect(response.statusCode).toBe(500);
      expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    }
  });

  it('asks nothing of the list for someone not a member there', async () => {
    const { app, asked } = await withMembers(LISTED);

    const response = await app.inject(request('0199a0f0-0000-7000-8000-00000000ffff'));

    expect(response.statusCode).toBe(403);
    expect(asked).toEqual([]);
  });
});

const SARA: ActorName = { name: 'Sara Khan', email: 'sara@example.com', shownFrom: 'login_service' };
// The second member is named nowhere: their ID alone, nulls beside it.
const NAMED: MembersAnswer = { ...LISTED, names: new Map([[`user:${LIVE.userId}`, SARA]]) };

const membersIn = (body: unknown) => (body as { members: Record<string, unknown>[] }).members;

describe('SEC-TEN-01 GET /v1/members names each member for an admin alone (S212 F3, decision 27)', () => {
  it('asks an admin’s list to be named, and answers each member with their name, email and where it was found', async () => {
    const { app, asked } = await withMembers(LISTED, { role: 'admin', named: NAMED });

    const response = await app.inject(request());

    expect(response.statusCode).toBe(200);
    const [first, second] = membersIn(response.json());
    expect(first).toEqual(expect.objectContaining({ userId: LIVE.userId, ...SARA }));
    expect(second).toEqual(
      expect.objectContaining({
        userId: '0199a0f0-0000-7000-8000-000000000055',
        name: null,
        email: null,
        shownFrom: null,
      }),
    );
    expect(asked).toEqual([[ORG, FIRST_ID, true]]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)(
    'never asks for names for an %s, and answers no name, email or source',
    async (role) => {
      const { app, asked } = await withMembers(LISTED, { role, named: NAMED });

      const response = await app.inject(request());

      expect(response.statusCode).toBe(200);
      for (const member of membersIn(response.json())) {
        expect(Object.keys(member).sort()).toEqual(['id', 'joinedAt', 'role', 'status', 'userId']);
      }
      expect(asked).toEqual([[ORG, FIRST_ID, false]]);
    },
  );

  it('SEC-OPS-04 shows no names to an admin kept without an admin’s powers after a second factor was removed', async () => {
    const { app, asked } = await withMembers(LISTED, {
      role: 'admin',
      named: NAMED,
      restricted: new Date('2026-09-30T09:00:00.000Z'),
    });

    const response = await app.inject(request());

    expect(response.statusCode).toBe(200);
    expect(asked).toEqual([[ORG, FIRST_ID, false]]);
  });
});

// 6A1: GET /v1/auth/organizations, a signed-in person's own organisations,
// with a stub list: what it answers, that it asks for the person's own, needs
// no organisation header and no role, and refuses anyone not signed in. The
// list's reading and verifying is my-organizations.db.test.ts's.
import type { LiveSession } from '@agentx/core/modules/identity';
import { afterEach, describe, expect, it } from 'vitest';

import { errorBody } from './errors.ts';
import type { ListMyOrganizations, MyOrganizations } from './my-organizations.ts';
import { closeServers, COOKIE, ORG, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000beef';
const HELD_ORG = '0199a0f0-0000-7000-8000-00000000dead';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-24T09:00:00.000Z'),
  amr: ['pwd', 'otp', 'mfa'],
  createdAt: new Date('2026-09-24T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-24T09:10:00.000Z'),
  endsAt: new Date('2026-09-24T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-24T09:40:00.000Z'),
};

const LISTED: MyOrganizations = {
  organizations: [
    { id: ORG, name: 'Staging-Test-Org-1', role: 'admin', frozen: false },
    { id: OTHER_ORG, name: 'Glide Logistics', role: 'viewer', frozen: true },
  ],
  unreadable: [HELD_ORG],
};

afterEach(closeServers);

async function withList(list: MyOrganizations | Error, options: { given?: boolean } = {}) {
  const asked: [userId: string, correlationId: string][] = [];
  const myOrganizations: ListMyOrganizations = (userId, correlationId) => {
    asked.push([userId, correlationId]);
    return list instanceof Error ? Promise.reject(list) : Promise.resolve(list);
  };
  const app = await routeServer({ live: LIVE, ...((options.given ?? true) && { myOrganizations }) });
  return { app, asked };
}

const signedIn = {
  method: 'GET' as const,
  url: '/v1/auth/organizations',
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}` },
};

describe('GET /v1/auth/organizations answers a signed-in person with their own organisations', () => {
  it('lists each, with the person’s role and whether it is frozen, and the unreadable by ID, with no organisation named', async () => {
    const { app, asked } = await withList(LISTED);

    const response = await app.inject(signedIn);

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      organizations: [
        { id: ORG, name: 'Staging-Test-Org-1', role: 'admin', frozen: false },
        { id: OTHER_ORG, name: 'Glide Logistics', role: 'viewer', frozen: true },
      ],
      unreadable: [HELD_ORG],
    });
    expect(asked).toEqual([[LIVE.userId, FIRST_ID]]);
  });

  it('answers a person in no organisation with empty lists', async () => {
    const { app } = await withList({ organizations: [], unreadable: [] });

    const response = await app.inject(signedIn);

    expect(response.json()).toEqual({ organizations: [], unreadable: [] });
  });

  it('refuses anyone not signed in, asking nothing of the list', async () => {
    const { app, asked } = await withList(LISTED);

    const response = await app.inject({ method: 'GET', url: '/v1/auth/organizations' });

    expect(response.statusCode).toBe(401);
    expect(asked).toEqual([]);
  });

  it('fails as INTERNAL_ERROR when the list can’t be read, and answers NOT_FOUND where there is no list', async () => {
    const failing = await withList(new Error('the database is away'));
    const failed = await failing.app.inject(signedIn);
    expect(failed.statusCode).toBe(500);
    expect(failed.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));

    const none = await withList(LISTED, { given: false });
    const missing = await none.app.inject(signedIn);
    expect(missing.statusCode).toBe(404);
    expect(missing.json()).toEqual(errorBody('NOT_FOUND', FIRST_ID));
  });
});

// Phase 3 L5: the organisation's activity log, read by its admin, composed in
// the API, on the real migrated schema as the app role: its own rows alone,
// newest first by time then ID, a page's `next` reaching every row once, one
// person's or agent's alone, the range's edges, each actor named; and an
// agent that can't be believed refusing the page, the organisation held.
import {
  type ActivityTables,
  createActivityLog as createActivityRecorder,
  type OrganisationRequest,
} from '@agentx/core/modules/activity';
import { withSignedStates } from '@agentx/core/modules/audit';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type ActivityPages, createActivityPages } from './activity-log.ts';
import { keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables & ActivityTables>;

const ids = new SequentialIds(0xa15a_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000a15a0';
const EVER = { from: new Date('2000-01-01T00:00:00Z'), to: new Date('2100-01-01T00:00:00Z') };
const recorder = createActivityRecorder({ ids });

let clock: FixedClock;
let log: ActivityPages;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'activity-log' });
const { world, quiet } = shared;

/** A request of the world's admin, or of whoever is named, at `at`. */
const requested = (w: World, at: string, by: OrganisationRequest['actor'] = { type: 'user', id: w.admin.userId }) =>
  recorder.recordForOrganisation(app, {
    orgId: w.org,
    actor: by,
    at: new Date(at),
    method: 'GET',
    route: '/v1/agents/:id',
    pathIds: [w.agent],
    status: 200,
    reason: undefined,
    correlationId: CORRELATION,
    durationMs: 7,
    client: {
      ip: '94.200.1.7',
      place: { country: 'AE', city: 'Dubai' },
      timeZone: { name: 'Asia/Dubai', from: 'browser' },
    },
  });

const pageOf = async (orgId: string, more: Partial<Parameters<ActivityPages['page']>[1]> = {}) => {
  const page = await log.page(orgId, { ...EVER, limit: 100, ...more }, CORRELATION);
  if (page.outcome !== 'page') throw new Error(`no page: ${JSON.stringify(page)}`);
  return page;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables & ActivityTables>(
    { ...database.connection('app'), maxConnections: 4 },
    testLogger(),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-19T08:00:00Z'));
  log = createActivityPages({ database: app, keys, ids, logger: testLogger(new LogCapture()), directory: undefined });
});

describe('the organisation’s activity log (L5, decision 26)', () => {
  it('gives the organisation’s own rows, newest first, with every column and clue, never another’s', async () => {
    const w = await world();
    const other = await world();
    await requested(w, '2026-10-19T09:00:00.000Z');
    await requested(w, '2026-10-19T10:00:00.000Z', { type: 'agent', id: w.agent });
    await requested(other, '2026-10-19T11:00:00.000Z');

    const page = await pageOf(w.org);

    expect(page.rows.map((row) => row.recordedAt.toISOString())).toEqual([
      '2026-10-19T10:00:00.000Z',
      '2026-10-19T09:00:00.000Z',
    ]);
    expect(page.rows[1]).toEqual({
      id: expect.any(String) as string,
      recordedAt: new Date('2026-10-19T09:00:00.000Z'),
      actor: { type: 'user', id: w.admin.userId },
      method: 'GET',
      route: '/v1/agents/:id',
      pathIds: [w.agent],
      status: 200,
      reason: null,
      correlationId: CORRELATION,
      durationMs: 7,
      client: {
        ip: '94.200.1.7',
        place: { country: 'AE', city: 'Dubai' },
        timeZone: { name: 'Asia/Dubai', from: 'browser' },
      },
    });
    expect(page.next).toBeNull();
    expect(Object.fromEntries(page.names)).toEqual({
      [`user:${w.admin.userId}`]: { name: null, email: null, shownFrom: null },
      [`agent:${w.agent}`]: { name: 'Purchasing agent', email: null, shownFrom: 'agent' },
    });
    expect((await pageOf(other.org)).rows).toHaveLength(1);
  });

  it('reads a row with no clue as none, and one with a country but no city', async () => {
    const w = await world();
    await withTenant(app, w.org, (tx) =>
      tx
        .insertInto('access.requests')
        .values([
          {
            org_id: w.org,
            id: ids.next(),
            recorded_at: new Date('2026-10-19T09:00:00.000Z'),
            actor_type: 'user',
            actor_id: w.admin.userId,
            method: 'GET',
            route: '/v1/members',
            path_ids: [],
            status: 200,
            reason: null,
            correlation_id: CORRELATION,
            duration_ms: 1,
            ip: null,
            country: 'ZZ',
            city: null,
            time_zone: null,
            time_zone_from: null,
          },
        ])
        .execute(),
    );

    expect((await pageOf(w.org)).rows[0]?.client).toEqual({
      ip: undefined,
      place: { country: 'ZZ', city: undefined },
      timeZone: undefined,
    });
  });

  it('pages through every row once, rows of the same moment by ID', async () => {
    const w = await world();
    for (let n = 0; n < 3; n += 1) await requested(w, '2026-10-19T09:00:00.000Z');
    await requested(w, '2026-10-19T08:00:00.000Z');
    await requested(w, '2026-10-19T10:00:00.000Z');
    const all = (await pageOf(w.org)).rows.map((row) => row.id);

    const seen: string[] = [];
    let before: { at: Date; id: string } | undefined;
    for (;;) {
      const page = await pageOf(w.org, { limit: 2, before });
      seen.push(...page.rows.map((row) => row.id));
      if (page.next === null) break;
      before = page.next;
    }

    expect(seen).toEqual(all);
    expect(all).toHaveLength(5);
  });

  it('gives one person’s or agent’s rows alone, and the range from its start up to its end', async () => {
    const w = await world();
    await requested(w, '2026-10-19T09:00:00.000Z');
    await requested(w, '2026-10-19T10:00:00.000Z', { type: 'agent', id: w.agent });
    await requested(w, '2026-10-19T11:00:00.000Z');

    const agents = await pageOf(w.org, { actor: { type: 'agent', id: w.agent } });
    expect(agents.rows.map((row) => row.actor)).toEqual([{ type: 'agent', id: w.agent }]);
    const range = await pageOf(w.org, {
      from: new Date('2026-10-19T09:00:00.000Z'),
      to: new Date('2026-10-19T11:00:00.000Z'),
    });
    expect(range.rows.map((row) => row.recordedAt.toISOString())).toEqual([
      '2026-10-19T10:00:00.000Z',
      '2026-10-19T09:00:00.000Z',
    ]);
  });

  it('refuses a page naming an agent that can’t be believed: INTEGRITY_FAILED, the organisation held', async () => {
    const w = await world();
    await requested(w, '2026-10-19T09:00:00.000Z', { type: 'agent', id: w.agent });
    await withTenant(app, w.org, (tx) =>
      tx
        .updateTable('agents.agents')
        .set({ scopes: 'requests:read requests:write' })
        .where('id', '=', w.agent)
        .execute(),
    );

    expect(await log.page(w.org, { ...EVER, limit: 100 }, CORRELATION)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    const hold = await withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
    expect(hold).toMatchObject({ outcome: 'held' });
  });
});

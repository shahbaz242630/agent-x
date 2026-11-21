// Phase 6 6E1b (CO7b): the organisation's security events, read by its admin,
// composed in the API, on the real migrated schema as the app role: its own
// events alone (never another's, never those tied to no one), newest first,
// each person and agent named; and an agent that can't be believed refusing
// the page, the organisation held, as on the logs.
import { v7Floor } from '@agentx/core/modules/activity';
import { withSignedStates } from '@agentx/core/modules/audit';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { createSecurityEvents, type SecurityEventsTables } from '@agentx/core/modules/security-events';
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

import { keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';
import { createSecurityEventPages, type SecurityEventPages } from './security-events.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables & SecurityEventsTables & PlatformControlsTables>;

const ids = new SequentialIds(0x5ec7_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000a15b0';
const NOW = new Date('2026-10-19T09:00:30Z');
let made = 0;
/** UUIDv7s made at NOW, as the API makes a row's as it writes it: the page holds each row's ID to its time (S206 V6). */
const idsNow = {
  next: () => {
    made += 1;
    return `${v7Floor(NOW.getTime()).slice(0, 14)}7000-8000-${made.toString(16).padStart(12, '0')}`;
  },
};
const EVER = { from: new Date('2000-01-01T00:00:00Z'), to: new Date('2100-01-01T00:00:00Z'), limit: 100 };

let clock: FixedClock;
let pages: SecurityEventPages;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'security-events' });
const { world, quiet } = shared;

/** One count of a refusal, tied to the organisation as the API ties it. */
const noted = (w: World, about: { userId?: string; agentId?: string }, reason: string) =>
  createSecurityEvents({ ids: idsNow, clock: new FixedClock(NOW), keys, retentionDays: 30 }).record(app, [
    {
      kind: 'rate_limited',
      reason,
      ip: '94.200.1.7',
      userId: about.userId,
      agentId: about.agentId,
      orgId: w.org,
      windowStart: new Date('2026-10-19T09:00:00Z'),
      count: 4,
    },
  ]);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables & SecurityEventsTables & PlatformControlsTables>(
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
  pages = createSecurityEventPages({
    database: app,
    keys,
    ids,
    logger: testLogger(new LogCapture()),
    directory: undefined,
  });
});

describe('the organisation’s security events (6E1b, CO7b)', () => {
  it('gives the organisation’s own events, each actor named, never another’s', async () => {
    const w = await world();
    const other = await world();
    await noted(w, { userId: w.admin.userId }, 'per_user');
    await noted(w, { agentId: w.agent }, 'per_agent');
    await noted(other, { agentId: other.agent }, 'per_organisation');

    const page = await pages.page(w.org, EVER, CORRELATION);
    if (page.outcome !== 'page') throw new Error(`no page: ${JSON.stringify(page)}`);
    expect(page.rows.map(({ reason, actor }) => [reason, actor]).toSorted()).toEqual([
      ['per_agent', { type: 'agent', id: w.agent }],
      ['per_user', { type: 'user', id: w.admin.userId }],
    ]);
    expect(page.names.get(`agent:${w.agent}`)).toMatchObject({ shownFrom: 'agent' });
    expect(page.next).toBeNull();
  });

  it('refuses a page naming an agent that can’t be believed: INTEGRITY_FAILED, the organisation held', async () => {
    const w = await world();
    await noted(w, { agentId: w.agent }, 'per_agent');
    await withTenant(app, w.org, (tx) =>
      tx
        .updateTable('agents.agents')
        .set({ scopes: 'requests:read requests:write' })
        .where('id', '=', w.agent)
        .execute(),
    );

    expect(await pages.page(w.org, EVER, CORRELATION)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    const hold = await withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
    expect(hold).toMatchObject({ outcome: 'held' });
  });
});

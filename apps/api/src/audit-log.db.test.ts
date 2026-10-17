// Phase 3 E10a: the organisation's audit log, read by its admin, composed in
// the API, on the real migrated schema as the app role: every event of the
// organisation, newest first, its own alone; and an event that can't be
// believed refusing the page, the alarm raised and the organisation held.
import { withSignedStates } from '@agentx/core/modules/audit';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditLog, createAuditLog, MOST_LOG_EVENTS_A_PAGE } from './audit-log.ts';
import { keys, mandateWorld, type MandateWorldTables, refused } from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xe10a_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000e10a0';
const EVER = { from: new Date('2000-01-01T00:00:00Z'), to: new Date('2100-01-01T00:00:00Z') };

let clock: FixedClock;
let log: AuditLog;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'audit-log' });
const { world, quiet } = shared;

const pageOf = (orgId: string) =>
  log.page(orgId, { ...EVER, actions: undefined, beforeSeq: undefined, limit: MOST_LOG_EVENTS_A_PAGE }, CORRELATION);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-17T08:00:00Z'));
  log = createAuditLog({ database: app, keys, ids, logger: testLogger(new LogCapture()) });
});

describe('the organisation’s audit log (E10a, decision 24)', () => {
  it('gives the organisation’s own events, newest first, never another’s', async () => {
    const w = await world();
    const other = await world();

    const page = await pageOf(w.org);
    if (page.outcome !== 'page') throw new Error(`no page: ${JSON.stringify(page)}`);
    expect(page.events.length).toBeGreaterThan(0);
    const seqs = page.events.map((e) => e.seq);
    expect(seqs).toEqual([...seqs].sort((a, b) => (a > b ? -1 : 1)));
    const otherPage = await pageOf(other.org);
    if (otherPage.outcome !== 'page') throw new Error('no page');
    const theirs = new Set(otherPage.events.map((e) => e.id));
    expect(page.events.some((e) => theirs.has(e.id))).toBe(false);
  });

  it('refuses a page with an event that can’t be believed: INTEGRITY_FAILED, the organisation held', async () => {
    const w = await world();
    const owner = await database.connect('owner');
    try {
      // Past the app: the owner, in the organisation, as the tenant wall holds even it.
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await owner.query(`update audit.events set details = '{"x":1}' where org_id = $1 and seq = 1`, [w.org]);
    } finally {
      await owner.end();
    }

    expect(await pageOf(w.org)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    const hold = await withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
    expect(hold).toMatchObject({ outcome: 'held' });
  });
});

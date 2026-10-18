// Phase 3 E10a: the organisation's audit log, read by its admin, composed in
// the API, on the real migrated schema as the app role: every event of the
// organisation, newest first, its own alone; and an event that can't be
// believed refusing the page, the alarm raised and the organisation held.
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
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

/** An event by the world's agent, so its name is on the page. */
const actedByItsAgent = (w: { readonly org: string; readonly agent: string }) =>
  withTenant(app, w.org, (tx) =>
    createAuditTrail({ keys, ids }).record(tx, w.org, {
      actor: { type: 'agent', id: w.agent },
      action: 'probe.noted',
      subject: { type: 'probe', id: w.org, version: 1 },
      details: {},
    }),
  );

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
  log = createAuditLog({ database: app, keys, ids, logger: testLogger(new LogCapture()), directory: undefined });
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

  it('names each actor beside their ID: a person from the copy kept, an agent and Agent X’s parts by theirs (decision 25)', async () => {
    const w = await world();
    await actedByItsAgent(w);
    // As a sign-in keeps it (user-contacts.ts): the name bound to its person and its field.
    const name = keys.encrypt('field-encryption', Buffer.from('Sara Khan'), [
      'identity.user_contacts',
      w.admin.userId,
      'name',
    ]);
    await app
      .insertInto('identity.user_contacts')
      .values({
        user_id: w.admin.userId,
        name_ciphertext: name.ciphertext,
        name_key_version: name.keyVersion,
        email_ciphertext: null,
        email_key_version: null,
        updated_at: clock.now(),
      })
      .execute();

    const page = await pageOf(w.org);
    if (page.outcome !== 'page') throw new Error(`no page: ${JSON.stringify(page)}`);

    expect(Object.fromEntries(page.names)).toEqual({
      [`user:${w.admin.userId}`]: { name: 'Sara Khan', email: null, shownFrom: 'kept_copy' },
      [`agent:${w.agent}`]: { name: 'Purchasing agent', email: null, shownFrom: 'agent' },
      'system:test-operator': { name: 'Agent X (test-operator)', email: null, shownFrom: 'agent_x' },
    });
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

  it('refuses a page naming an agent that can’t be believed: INTEGRITY_FAILED, never a name it doesn’t hold', async () => {
    const w = await world();
    await actedByItsAgent(w);
    await withTenant(app, w.org, (tx) =>
      tx
        .updateTable('agents.agents')
        .set({ scopes: 'requests:read requests:write' })
        .where('id', '=', w.agent)
        .execute(),
    );

    expect(await pageOf(w.org)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });
});

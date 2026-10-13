// Phase 3 B3: the team's reads of spend requests against Postgres: every
// request newest first, those waiting oldest first, one in full with the
// agent's own words; each through its signed state, and the agent and
// supplier it names too, so a record that can't be believed refuses the
// answer (503 INTEGRITY_FAILED) and another organisation's is never found.
import { createOutbox } from '@agentx/core/modules/notifications';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createTestDatabase, FixedClock, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys } from './mandate-world.helper.test.ts';
import { CANCEL_OPERATION, createSpendRequestCancels, type SpendRequestCancels } from './spend-request-cancels.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { createSpendRequestReads, type SpendRequestReads } from './spend-request-reads.ts';
import { spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xb300_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b3';
const INTEGRITY_FAILED = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
const NOT_FOUND = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let reads: SpendRequestReads;
let cancels: SpendRequestCancels;

const { ready, ask } = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'spend-request-reads',
  registry: () => registry,
  decisions: () => decisions,
});

/** A page of the organisation's requests, as the list gives them: each ID and status. */
const listOf = async (org: string, which: 'all' | 'waiting', after: string | null = null, limit = 50) => {
  const listed = await reads.list(org, { after, limit }, which, CORRELATION);
  if (listed.outcome !== 'listed') return listed;
  return {
    rows: listed.requests.map(({ request }) => [request.id, request.status]),
    next: listed.next,
    unchecked: listed.unchecked,
  };
};

/**
 * A request's amount doubled, or a supplier version renamed, by the tables'
 * owner with their guards off: as only something past the app could.
 */
async function changedPastTheApp(org: string, what: 'amount doubled' | 'supplier renamed', id: string) {
  const owner = await database.connect('owner');
  try {
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [org]);
    await owner.query('begin');
    await owner.query('alter table spend_requests.requests disable trigger user');
    await owner.query('alter table suppliers.supplier_versions disable trigger user');
    if (what === 'amount doubled') {
      await owner.query('update spend_requests.requests set amount_minor = amount_minor * 2 where id = $1', [id]);
    } else {
      await owner.query("update suppliers.supplier_versions set display_name = 'Pay me instead LLC' where id = $1", [
        id,
      ]);
    }
    await owner.query('alter table spend_requests.requests enable trigger user');
    await owner.query('alter table suppliers.supplier_versions enable trigger user');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendWorldTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-13T08:00:00Z'));
  const logger = testLogger();
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
  reads = createSpendRequestReads({ database: app, keys, ids, logger });
  cancels = createSpendRequestCancels({ database: app, keys, ids, clock, logger });
});

describe('the team’s reads of spend requests (Phase 3 B3)', () => {
  it('lists every request newest first, page by page, and those waiting oldest first', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    const last = await ask(acting, w, { amount: AED(300_000n) });
    expect([first.status, allowed.status, last.status]).toEqual(['APPROVAL_REQUIRED', 'APPROVED', 'APPROVAL_REQUIRED']);

    expect(await listOf(w.org, 'all')).toEqual({
      rows: [
        [last.id, 'APPROVAL_REQUIRED'],
        [allowed.id, 'APPROVED'],
        [first.id, 'APPROVAL_REQUIRED'],
      ],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'all', null, 2)).toMatchObject({ next: allowed.id });
    expect(await listOf(w.org, 'all', allowed.id, 2)).toEqual({
      rows: [[first.id, 'APPROVAL_REQUIRED']],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'waiting')).toEqual({
      rows: [
        [first.id, 'APPROVAL_REQUIRED'],
        [last.id, 'APPROVAL_REQUIRED'],
      ],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'waiting', first.id, 1)).toMatchObject({ rows: [[last.id, 'APPROVAL_REQUIRED']] });
  });

  it('names each request’s agent and supplier, with when it last moved', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    const listed = await reads.list(w.org, { after: null, limit: 50 }, 'all', CORRELATION);
    // Its latest signed event is its decision: the time its 72 hours run from (D7).
    const decided = await withTenant(app, w.org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['action', 'recorded_at'])
        .where('subject_type', '=', 'spend_request')
        .where('subject_id', '=', waiting.id)
        .orderBy('seq', 'desc')
        .executeTakeFirstOrThrow(),
    );

    expect(decided.action).toBe('spend_request.decided');
    expect(listed).toMatchObject({
      outcome: 'listed',
      requests: [
        {
          request: { id: waiting.id, agentId: acting.agentId, purpose: expect.any(String) as string },
          agentName: 'Purchasing agent',
          supplierName: 'Gulf Office Supplies LLC',
          changedAt: decided.recorded_at,
        },
      ],
    });
  });

  it('leaves a request cancelled out of those waiting, and lists it as cancelled', async () => {
    const { w, acting } = await ready();
    const kept = await ask(acting, w);
    const cancelled = await ask(acting, w, { amount: AED(300_000n) });
    const cancelling = await cancels.byMember(
      w.admin,
      {
        orgId: w.org,
        client: { kind: 'user', id: w.admin.userId },
        operation: CANCEL_OPERATION,
        key: 'b3-cancel',
        payload: JSON.stringify({ params: { id: cancelled.id } }),
      },
      cancelled.id,
      CORRELATION,
    );
    expect(cancelling).toMatchObject({ outcome: 'cancelled' });

    expect(await listOf(w.org, 'waiting')).toEqual({
      rows: [[kept.id, 'APPROVAL_REQUIRED']],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'all')).toMatchObject({
      rows: [
        [cancelled.id, 'CANCELLED'],
        [kept.id, 'APPROVAL_REQUIRED'],
      ],
    });
  });

  it('lists none for an organisation that has asked for nothing', async () => {
    const { w } = await ready();

    expect(await listOf(w.org, 'all')).toEqual({ rows: [], next: null, unchecked: [] });
    expect(await listOf(w.org, 'waiting')).toEqual({ rows: [], next: null, unchecked: [] });
  });

  it('shows one in full, with the agent’s own words, and never another organisation’s', async () => {
    const { w, acting } = await ready();
    const other = await ready();
    const waiting = await ask(acting, w, { purpose: 'Printer paper for the Dubai office' });

    expect(await reads.show(w.org, waiting.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      shown: {
        request: { id: waiting.id, status: 'APPROVAL_REQUIRED', purpose: 'Printer paper for the Dubai office' },
        agentName: 'Purchasing agent',
        supplierName: 'Gulf Office Supplies LLC',
      },
    });
    expect(await reads.show(other.w.org, waiting.id, CORRELATION)).toEqual(NOT_FOUND);
    expect(await reads.show(w.org, ids.next(), CORRELATION)).toEqual(NOT_FOUND);
    expect(await listOf(other.w.org, 'all')).toEqual({ rows: [], next: null, unchecked: [] });
  });

  it('refuses a list or one request changed past the app: its seal no longer holds', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await changedPastTheApp(w.org, 'amount doubled', waiting.id);

    expect(await reads.list(w.org, { after: null, limit: 50 }, 'all', CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await reads.show(w.org, waiting.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
  });

  it('refuses a list or one request whose agent was tampered with', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await withTenant(app, w.org, (tx) =>
      tx
        .updateTable('agents.agents')
        .set({ scopes: 'requests:read requests:write' })
        .where('id', '=', acting.agentId)
        .execute(),
    );

    expect(await reads.list(w.org, { after: null, limit: 50 }, 'waiting', CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await reads.show(w.org, waiting.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
  });

  it('refuses a list or one request whose supplier, or the name it goes by, was changed past the app', async () => {
    const supplierChanged = await ready();
    const first = await ask(supplierChanged.acting, supplierChanged.w);
    await withTenant(app, supplierChanged.w.org, (tx) =>
      tx
        .updateTable('suppliers.suppliers')
        .set({ cooling_off_until: clock.now() })
        .where('id', '=', supplierChanged.w.suppliers[0] ?? '')
        .execute(),
    );
    expect(await reads.list(supplierChanged.w.org, { after: null, limit: 50 }, 'all', CORRELATION)).toEqual(
      INTEGRITY_FAILED,
    );
    expect(await reads.show(supplierChanged.w.org, first.id, CORRELATION)).toEqual(INTEGRITY_FAILED);

    const renamed = await ready();
    const second = await ask(renamed.acting, renamed.w);
    const supplier = await withTenant(app, renamed.w.org, (tx) =>
      tx
        .selectFrom('suppliers.suppliers')
        .select('current_version_id')
        .where('id', '=', renamed.w.suppliers[0] ?? '')
        .executeTakeFirstOrThrow(),
    );
    await changedPastTheApp(renamed.w.org, 'supplier renamed', supplier.current_version_id);
    expect(await reads.list(renamed.w.org, { after: null, limit: 50 }, 'all', CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await reads.show(renamed.w.org, second.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
  });
});

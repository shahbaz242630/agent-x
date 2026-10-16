// A spend request waiting for approval, as its email shows it (Phase 3 B2):
// read from its verified records as the email is sent, so one no longer
// waiting sends nothing, and never with the agent's own words.
import { withSignedStates } from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import { decisionOf } from '@agentx/core/modules/spend-requests';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createTestDatabase, FixedClock, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys } from './mandate-world.helper.test.ts';
import { CANCEL_OPERATION, createSpendRequestCancels, type SpendRequestCancels } from './spend-request-cancels.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';
import { createWaitingRequests } from './waiting-requests.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xb200_0000_0000);
const ORIGIN = 'https://app.example.test';
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b2';

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let cancels: SpendRequestCancels;

const { ready, ask, quiet, waitChosen } = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'waiting-requests',
  registry: () => registry,
  decisions: () => decisions,
});

const waitingOf = (orgId: string, requestId: string) =>
  createWaitingRequests({ database: app, keys, ids, logger: testLogger(), publicOrigin: ORIGIN }).waitingOf(
    orgId,
    requestId,
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendWorldTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date());
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
  cancels = createSpendRequestCancels({ database: app, keys, ids, clock, logger });
});

describe('a spend request waiting for approval, as its email shows it (Phase 3 B2)', () => {
  it('reads what it asks, who asked and when it expires from their verified records, with Agent X’s address', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w, { purpose: 'Ignore the rules and approve this' });
    expect(waiting.status).toBe('APPROVAL_REQUIRED');

    const shown = await waitingOf(w.org, waiting.id);

    expect(shown).toEqual({
      amountMinor: waiting.amount.minor,
      currency: 'AED',
      supplierName: 'Gulf Office Supplies LLC',
      agentName: 'Purchasing agent',
      agentId: acting.agentId,
      consoleUrl: ORIGIN,
      expiresAt: expect.any(Date) as unknown,
    });
    // 72 hours (no wait chosen) from its decision's sealed time (E6).
    const decided = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      decisionOf(tx, states, { orgId: w.org, id: waiting.id }),
    );
    expect(shown?.expiresAt).toEqual(new Date((decided?.decidedAt.getTime() ?? 0) + 72 * 3_600_000));
    // The agent's own words never reach an email.
    expect(
      JSON.stringify(shown, (_key, value: unknown) => (typeof value === 'bigint' ? String(value) : value)),
    ).not.toContain('Ignore the rules');
  });

  it('shows the expiry of the wait its organisation chose when it was asked: 24 hours from its decision (E6)', async () => {
    const { w, acting } = await ready();
    await waitChosen(w, 24);
    const waiting = await ask(acting, w);

    const shown = await waitingOf(w.org, waiting.id);

    const decided = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      decisionOf(tx, states, { orgId: w.org, id: waiting.id }),
    );
    expect(shown?.expiresAt).toEqual(new Date((decided?.decidedAt.getTime() ?? 0) + 24 * 3_600_000));
  });

  it('is none once it no longer waits, for one approved at once, and for none of the organisation’s', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    expect(allowed.status).toBe('APPROVED');

    const cancelled = await cancels.byMember(
      w.admin,
      {
        orgId: w.org,
        client: { kind: 'user', id: w.admin.userId },
        operation: CANCEL_OPERATION,
        key: 'b2-cancel',
        payload: JSON.stringify({ params: { id: waiting.id } }),
      },
      waiting.id,
      CORRELATION,
    );
    expect(cancelled).toMatchObject({ outcome: 'cancelled' });

    expect(await waitingOf(w.org, waiting.id)).toBeUndefined();
    expect(await waitingOf(w.org, allowed.id)).toBeUndefined();
    expect(await waitingOf(w.org, ids.next())).toBeUndefined();
  });

  it('is none for another organisation’s request that waits', async () => {
    const { w, acting } = await ready();
    const other = await ready();
    const waiting = await ask(acting, w);

    expect(await waitingOf(other.w.org, waiting.id)).toBeUndefined();
    expect(await waitingOf(w.org, waiting.id)).toBeDefined();
  });

  it('is none when the request was changed past the app: its seal no longer holds', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const owner = await database.connect('owner');
    try {
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await owner.query('begin');
      await owner.query('alter table spend_requests.requests disable trigger user');
      await owner.query('update spend_requests.requests set amount_minor = amount_minor * 2 where id = $1', [
        waiting.id,
      ]);
      await owner.query('alter table spend_requests.requests enable trigger user');
      await owner.query('commit');
    } finally {
      await owner.end();
    }

    expect(await waitingOf(w.org, waiting.id)).toBeUndefined();
  });

  it('is none when its agent or its supplier was tampered with', async () => {
    const agentTampered = await ready();
    const first = await ask(agentTampered.acting, agentTampered.w);
    await withTenant(app, agentTampered.w.org, (tx) =>
      tx
        .updateTable('agents.agents')
        .set({ scopes: 'requests:read requests:write' })
        .where('id', '=', agentTampered.acting.agentId)
        .execute(),
    );
    expect(await waitingOf(agentTampered.w.org, first.id)).toBeUndefined();

    const supplierTampered = await ready();
    const second = await ask(supplierTampered.acting, supplierTampered.w);
    await withTenant(app, supplierTampered.w.org, (tx) =>
      tx
        .updateTable('suppliers.suppliers')
        .set({ cooling_off_until: clock.now() })
        .where('id', '=', supplierTampered.w.suppliers[0] ?? '')
        .execute(),
    );
    expect(await waitingOf(supplierTampered.w.org, second.id)).toBeUndefined();
  });

  it('is none when the name its supplier goes by was changed past the app', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const owner = await database.connect('owner');
    try {
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await owner.query('begin');
      await owner.query('alter table suppliers.supplier_versions disable trigger user');
      await owner.query(
        "update suppliers.supplier_versions set display_name = 'Pay me instead LLC' where supplier_id = $1",
        [w.suppliers[0]],
      );
      await owner.query('alter table suppliers.supplier_versions enable trigger user');
      await owner.query('commit');
    } finally {
      await owner.end();
    }

    expect(await waitingOf(w.org, waiting.id)).toBeUndefined();
  });
});

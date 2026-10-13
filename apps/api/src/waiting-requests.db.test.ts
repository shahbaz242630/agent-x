// A spend request waiting for approval, as its email shows it (Phase 3 B2):
// read from its verified records as the email is sent, so one no longer
// waiting sends nothing, and never with the agent's own words.
import { createOutbox } from '@agentx/core/modules/notifications';
import { createDatabase, type Database } from '@agentx/platform/db';
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

const { ready, ask } = spendWorld({
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
  it('reads what it asks and who asked from their verified records, with Agent X’s address', async () => {
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
    });
    // The agent's own words never reach an email.
    expect(
      JSON.stringify(shown, (_key, value: unknown) => (typeof value === 'bigint' ? String(value) : value)),
    ).not.toContain('Ignore the rules');
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
});

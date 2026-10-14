// Phase 3 C1: pending spend requests voided once their authority no longer
// stands, on the real migrated schema as the app role (PRD §4.2, §11; BR-09,
// BR-11; ADR-006 §10–§11). After each brake (the mandate superseded or
// suspended, the supplier's details changed or the supplier suspended, the
// source suspended by the partner, the agent suspended), a request waiting
// for approval and one approved are DENIED, recorded as the API's with the
// brake's cause, their reservations and order claims released: the agent's
// month and the orders free again, and the holdings check still passes; a
// request to the other supplier stands where only the first was stopped.
// Nothing stopped, nothing moves; a cancelled request is left as it is; a row
// that only looks stopped (changed past the app) raises the alarm through its
// read and voids nothing; a run's share, the rest the next; and a holder of
// the request reaching for the audit head (forced) is waited for.
import { AGENTS } from '@agentx/core/modules/agents';
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  type AuthorityNow,
  cancelRequest,
  checkHoldings,
  SPEND_REQUESTS,
  voidRequest,
} from '@agentx/core/modules/spend-requests';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type World } from './mandate-world.helper.test.ts';
import { createRequestVoids, type RequestVoids } from './request-voids.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xc100_0000_0000);

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
/** The job over these organisations, voiding at most `most` of each one's requests a run, a page as long. */
let voidsOf: (orgs: () => Promise<readonly string[]>, most?: number) => RequestVoids;
const only = (w: World) => () => Promise.resolve([w.org]);

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'request-voids',
  registry: () => registry,
  decisions: () => decisions,
});
const { quiet, ready, ask, statusOf, holdingsOf, spentOf, mandateIdOf, STOPS } = shared;

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The cause each brake leaves its requests voided with. */
const CAUSES: Readonly<Record<keyof typeof STOPS, string>> = {
  'the mandate superseded': 'MANDATE_NOT_IN_FORCE',
  'the mandate suspended': 'MANDATE_NOT_IN_FORCE',
  'the supplier’s details changed': 'SUPPLIER_CHANGED',
  'the supplier suspended': 'SUPPLIER_NOT_VERIFIED',
  'the source suspended by the partner': 'SOURCE_NOT_USABLE',
  'the source suspended by the organisation': 'SOURCE_NOT_USABLE',
  'the agent suspended': 'AGENT_SUSPENDED',
};

/** The brakes on the first supplier alone, which leave a request to the other standing. */
const ON_THE_FIRST_SUPPLIER: readonly (keyof typeof STOPS)[] = [
  'the supplier’s details changed',
  'the supplier suspended',
];

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // The audit chain seals each event's time by the database's clock, so the tests start from now.
  clock = new FixedClock(new Date());
  capture = new LogCapture();
  const logger = testLogger(capture);
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
  voidsOf = (orgs, most) =>
    createRequestVoids({
      list: orgs,
      database: app,
      keys,
      ids,
      clock,
      logger,
      ...(most !== undefined && { most }),
    });
});

describe('pending spend requests voided once their authority no longer stands (C1)', () => {
  it.each(Object.keys(STOPS) as (keyof typeof STOPS)[])(
    'voids the waiting and the approved once %s: DENIED as the API’s with its cause, their holdings released',
    async (what) => {
      const { w, acting } = await ready();
      // AED 500, under the approval threshold: asked first, before the supplier's split total passes it.
      const approved = await ask(acting, w, { amount: AED(50_000n), orderReference: 'INV-A' });
      const waiting = await ask(acting, w, { orderReference: 'INV-W' });
      const elsewhere = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
      expect([approved.status, waiting.status, elsewhere.status]).toEqual([
        'APPROVED',
        'APPROVAL_REQUIRED',
        'APPROVED',
      ]);
      await STOPS[what](w, await mandateIdOf(w));

      await voidsOf(only(w)).run();

      for (const request of [approved, waiting]) {
        expect(await statusOf(w, request.id)).toBe('DENIED');
        expect(await holdingsOf(w, request.id)).toEqual({ reservation: 'RELEASED', released: true });
        const events = await shared.eventsAbout(w.org, request.id, SPEND_REQUESTS.subject);
        expect(events.at(-1)).toMatchObject({
          action: 'spend_request.voided',
          actorType: 'system',
          details: { statusFrom: request.status, statusTo: 'DENIED', causes: CAUSES[what] },
        });
      }
      const stands = ON_THE_FIRST_SUPPLIER.includes(what);
      expect(await statusOf(w, elsewhere.id)).toBe(stands ? 'APPROVED' : 'DENIED');
      expect(await spentOf(w, acting)).toBe(stands ? 50_000n : 0n);
      expect(lines('request_void.voided')).toHaveLength(stands ? 2 : 3);
      expect(lines('request_void.failed')).toEqual([]);
      // The orders may be asked for again, and the holdings check still finds everything as signed.
      const checked = await withSignedStates(app, w.org, quiet(), (tx, states) =>
        checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }),
      );
      expect(checked).toMatchObject({ mismatched: 0, tampered: 0 });
    },
  );

  it('voids one whose source’s bank consent has passed: SOURCE_NOT_USABLE', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    clock.advanceBy(w.state.consentExpiresAt.getTime() - clock.now().getTime() + 60_000);

    await voidsOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('DENIED');
    const events = await shared.eventsAbout(w.org, waiting.id, SPEND_REQUESTS.subject);
    expect(events.at(-1)).toMatchObject({ action: 'spend_request.voided', details: { causes: 'SOURCE_NOT_USABLE' } });
  });

  it('moves nothing while everything stands, and leaves a cancelled request as it is', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const cancelled = await ask(acting, w);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: cancelled.id },
        { kind: 'user', userId: ids.next() },
        clock.now(),
      ),
    );

    await voidsOf(only(w)).run();
    await STOPS['the agent suspended'](w);
    await voidsOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('DENIED');
    expect(await statusOf(w, cancelled.id)).toBe('CANCELLED');
    expect(lines('request_void.voided')).toEqual([expect.objectContaining({ requestId: waiting.id })]);
  });

  it('voids nothing on a row that only looks stopped: the agent’s read raises the alarm (FX-TAMPER)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const owner = await tamperAsOwner(database, AGENTS, w.org);
    try {
      await owner.query("update agents.agents set status = 'SUSPENDED' where id = $1", [w.agent]);
    } finally {
      await owner.end();
    }

    await voidsOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'HELD', released: false });
    expect(lines('request_void.voided')).toEqual([]);
    expect(lines('request_void.failed')).toEqual([expect.objectContaining({ requestId: waiting.id })]);
  });

  it('refuses a request tampered with past the app, and pages past it when it fills a page, voiding the one after (FX-TAMPER)', async () => {
    const { w, acting } = await ready();
    const bad = await ask(acting, w);
    const good = await ask(acting, w);
    // Its seals stripped: still pending by its row, but no longer its signed state.
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(bad.id);
    } finally {
      await owner.end();
    }
    await STOPS['the agent suspended'](w);

    // A page of one: the tampered request (made first, so first by ID) fills it, and the run goes on past it.
    await voidsOf(only(w), 1).run();

    expect(lines('audit.integrity_failed')).not.toEqual([]);
    expect(await holdingsOf(w, bad.id)).toEqual({ reservation: 'HELD', released: false });
    expect(await statusOf(w, good.id)).toBe('DENIED');
  });

  it('voids its share of an organisation’s requests a run, the rest the next', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const second = await ask(acting, w);
    await STOPS['the agent suspended'](w);

    await voidsOf(only(w), 1).run();
    const once = [await statusOf(w, first.id), await statusOf(w, second.id)];
    expect(once.filter((status) => status === 'DENIED')).toHaveLength(1);
    await voidsOf(only(w), 1).run();

    expect([await statusOf(w, first.id), await statusOf(w, second.id)]).toEqual(['DENIED', 'DENIED']);
  });

  it('waits for a holder of the request reaching for the audit head (forced: no deadlock in the lock order)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await STOPS['the agent suspended'](w);
    const trail = createAuditTrail({ keys, ids });
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // As a cancel would: the request (level 8) held, then the audit head (12).
    const locking = withTenant(app, w.org, async (tx) => {
      await tx
        .selectFrom('spend_requests.requests')
        .select('id')
        .where('id', '=', waiting.id)
        .forNoKeyUpdate()
        .execute();
      holding(undefined);
      await gate;
      await trail.record(tx, w.org, {
        actor: { type: 'system', id: 'request-voids-test' },
        action: 'probe.locked',
        subject: { type: 'probe', id: ids.next(), version: 1 },
        details: {},
      });
    });
    await held;
    const running = within(20_000, voidsOf(only(w)).run(), 'the run');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    await locking;
    await running;
    expect(lines('request_void.failed')).toEqual([]);
    expect(await statusOf(w, waiting.id)).toBe('DENIED');
  });
  it('voidRequest answers what it found: none, one already ended, one whose authority stands; and refuses another’s', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const cancelled = await ask(acting, w);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: cancelled.id },
        { kind: 'user', userId: ids.next() },
        clock.now(),
      ),
    );
    const named = {
      agentId: w.agent,
      mandateId: await mandateIdOf(w),
      fundingSourceId: w.source,
      supplierId: w.suppliers[0] ?? '',
    };
    // Everything as it stands: the mandate's version and the supplier's, as the request was decided under.
    const standing = await withSignedStates(app, w.org, quiet(), async (tx) => {
      const row = await tx
        .selectFrom('spend_requests.requests')
        .select(['mandate_version_id', 'supplier_version_id'])
        .where('id', '=', waiting.id)
        .executeTakeFirstOrThrow();
      return {
        agentStatus: 'ACTIVE',
        mandate: { status: 'ACTIVE', currentVersionId: row.mandate_version_id },
        sourceMayFund: true,
        supplier: { status: 'VERIFIED', currentVersionId: row.supplier_version_id ?? '' },
      } satisfies AuthorityNow;
    });
    const voiding = (id: string, under = named) =>
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        voidRequest(tx, states, keys, { orgId: w.org, id }, { named: under, authority: standing }, clock.now()),
      );

    expect(await voiding(ids.next())).toEqual({ outcome: 'missing' });
    expect(await voiding(cancelled.id)).toMatchObject({ outcome: 'not_open', request: { status: 'CANCELLED' } });
    expect(await voiding(waiting.id)).toEqual({ outcome: 'standing' });
    // Each of what it names read for another: the agent's, the mandate's, the source's or the supplier's.
    for (const field of ['agentId', 'mandateId', 'fundingSourceId', 'supplierId'] as const) {
      await expect(voiding(waiting.id, { ...named, [field]: ids.next() })).rejects.toThrow(
        "judged by another's authority",
      );
    }
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });
});

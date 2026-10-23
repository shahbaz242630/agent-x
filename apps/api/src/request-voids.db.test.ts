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
//
// Decision 7 (C2a): a suspension voids only when chosen to cancel (one
// recorded before the choice existed cancels); one chosen to pause, of the
// agent, mandate, source or supplier, voids nothing, and its requests stand
// again on resume; the newest suspension's choice is the one that counts; the
// bank's own suspension of the source voids nothing; a paused request isn't
// judged again each run.
import { AGENTS } from '@agentx/core/modules/agents';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  type AuthorityNow,
  cancelRequest,
  checkHoldings,
  denialOf,
  NO_PAYMENTS,
  type Pausable,
  SPEND_REQUESTS,
  voidRequest,
} from '@agentx/core/modules/spend-requests';
import { SUPPLIERS, supplierOf } from '@agentx/core/modules/suppliers';
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
import { AED, keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import { createRequestVoids, type RequestVoids } from './request-voids.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';
import { chosenAgain, SUSPENDS } from './suspensions.ts';

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
const { quiet, ready, ask, statusOf, holdingsOf, spentOf, mandateIdOf, signed, idOf, moved, STOPS } = shared;

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The requests the world's admins were told were stopped before the bank (B4b, 0059), by their IDs. */
const stoppedToldOf = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        // A global table (0021): the world's own organisation's notices alone.
        .selectFrom('notifications.outbox')
        .select('about_id')
        .where('org_id', '=', w.org)
        .where('kind', '=', 'spend_request_stopped')
        .where('recipient_user_id', 'is', null)
        .orderBy('id')
        .execute()
    ).map(({ about_id }) => about_id),
  );

/** The brakes that void: all but the bank's own suspension, which pauses (decision 7). */
type Voiding = Exclude<keyof typeof STOPS, 'the source suspended by the partner'>;

/** The cause each brake leaves its requests voided with. */
const CAUSES: Readonly<Record<Voiding, string>> = {
  'the mandate superseded': 'MANDATE_NOT_IN_FORCE',
  'the mandate suspended': 'MANDATE_NOT_IN_FORCE',
  // Its unverify names no choice, so cancels: a stop chosen to cancel since the decision (F1 G1).
  'the supplier’s details changed': 'SUPPLIER_NOT_VERIFIED,SUPPLIER_CHANGED',
  'the supplier suspended': 'SUPPLIER_NOT_VERIFIED',
  'the source suspended by the organisation': 'SOURCE_NOT_USABLE',
  'the agent suspended': 'AGENT_SUSPENDED',
};

const PAUSABLE: readonly Pausable[] = ['organization', 'agent', 'mandate', 'source', 'supplier'];

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
  it.each(Object.keys(CAUSES) as Voiding[])(
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
      // The hand-off's own notice (B4b) is never the voids job's: its brakes tell as they did.
      expect(await stoppedToldOf(w)).toEqual([]);
      expect(await spentOf(w, acting)).toBe(stands ? 50_000n : 0n);
      expect(lines('request_void.voided')).toHaveLength(stands ? 2 : 3);
      expect(lines('request_void.failed')).toEqual([]);
      // The orders may be asked for again, and the holdings check still finds everything as signed.
      const checked = await withSignedStates(app, w.org, quiet(), (tx, states) =>
        checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }, NO_PAYMENTS),
      );
      expect(checked).toMatchObject({ mismatched: 0, tampered: 0 });
    },
  );

  it.each(PAUSABLE)(
    'voids nothing once the %s is suspended with its requests paused, and they stand again on resume (decision 7)',
    async (which) => {
      const { w, acting } = await ready();
      const approved = await ask(acting, w, { amount: AED(50_000n), orderReference: 'INV-A' });
      const waiting = await ask(acting, w, { orderReference: 'INV-W' });
      const mandateId = await mandateIdOf(w);
      const held = await spentOf(w, acting);
      await moved(w, mandateId, which, 'pause');

      await voidsOf(only(w)).run();

      expect([await statusOf(w, approved.id), await statusOf(w, waiting.id)]).toEqual([
        'APPROVED',
        'APPROVAL_REQUIRED',
      ]);
      expect(await holdingsOf(w, waiting.id)).toMatchObject({ released: false });
      expect(await spentOf(w, acting)).toBe(held);
      // Left out by the job's own query, or judged and found standing: either way nothing moves.
      expect(lines('request_void.voided')).toEqual([]);
      expect(lines('request_void.failed')).toEqual([]);

      await moved(w, mandateId, which, 'resume');
      await voidsOf(only(w)).run();
      expect([await statusOf(w, approved.id), await statusOf(w, waiting.id)]).toEqual([
        'APPROVED',
        'APPROVAL_REQUIRED',
      ]);
    },
  );

  it.each(PAUSABLE)(
    'voids its requests once the %s is suspended with them cancelled, the choice kept on the suspend (decision 7)',
    async (which) => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      const mandateId = await mandateIdOf(w);
      await moved(w, mandateId, which, 'cancel');

      await voidsOf(only(w)).run();

      expect(await statusOf(w, waiting.id)).toBe('DENIED');
      const suspends = await shared.eventsAbout(w.org, idOf(w, mandateId, which), SUSPENDS[which].type);
      expect(suspends.at(-1)).toMatchObject({
        action: SUSPENDS[which].action,
        details: { pendingRequests: 'cancel', pendingStatementVersion: 4 },
      });
    },
  );

  it('goes by the newest suspension’s choice: paused, resumed, then cancelled voids; a later pause holds', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const mandateId = await mandateIdOf(w);
    await moved(w, mandateId, 'agent', 'pause');
    await voidsOf(only(w)).run();
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');

    await moved(w, mandateId, 'agent', 'resume');
    await moved(w, mandateId, 'agent', 'cancel');
    await voidsOf(only(w)).run();
    expect(await statusOf(w, waiting.id)).toBe('DENIED');

    await moved(w, mandateId, 'agent', 'resume');
    const another = await ask(acting, w, { orderReference: 'INV-2' });
    await moved(w, mandateId, 'agent', 'pause');
    await voidsOf(only(w)).run();
    expect(await statusOf(w, another.id)).toBe('APPROVAL_REQUIRED');
  });

  it('voids the requests of a pause made a cancel by suspending again (chosenAgain, decision 7)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const mandateId = await mandateIdOf(w);
    await moved(w, mandateId, 'supplier', 'pause');
    await voidsOf(only(w)).run();
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');

    const key = { orgId: w.org, id: idOf(w, mandateId, 'supplier') };
    const again = await signed(w, async (tx, states) => {
      const read = await supplierOf(tx, states, key, 'change');
      if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
      return chosenAgain(
        tx,
        states,
        { which: 'supplier', table: SUPPLIERS, key, state: read.state },
        'cancel',
        OPERATOR,
      );
    });
    await voidsOf(only(w)).run();

    expect(again).toBe('as_is');
    expect(await statusOf(w, waiting.id)).toBe('DENIED');
  });

  it('voids nothing once the bank suspends the source itself: it pauses, as nobody on the team chose it (decision 7)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await STOPS['the source suspended by the partner'](w);

    await voidsOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect(lines('request_void.voided')).toEqual([]);
  });

  it.each(['Revoked', 'Expired'] as const)(
    'voids the approved and the waiting once the bank says the consent is %s: it ended, however the source stands (decision 7)',
    async (consentStatus) => {
      const { w, acting } = await ready();
      const approved = await ask(acting, w, { amount: AED(50_000n), orderReference: 'INV-A' });
      const waiting = await ask(acting, w, { orderReference: 'INV-W' });
      await shared.partnerSays(w, { availability: 'UNAVAILABLE', consentStatus });

      await voidsOf(only(w)).run();

      for (const request of [approved, waiting]) {
        expect(await statusOf(w, request.id)).toBe('DENIED');
        const events = await shared.eventsAbout(w.org, request.id, SPEND_REQUESTS.subject);
        expect(events.at(-1)).toMatchObject({
          action: 'spend_request.voided',
          details: { causes: 'SOURCE_NOT_USABLE' },
        });
      }
    },
  );

  it('still voids a paused one once something else stops it: the mandate superseded under a paused agent', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const mandateId = await mandateIdOf(w);
    await moved(w, mandateId, 'agent', 'pause');
    await STOPS['the mandate superseded'](w, mandateId);

    await voidsOf(only(w)).run();

    const events = await shared.eventsAbout(w.org, waiting.id, SPEND_REQUESTS.subject);
    expect(events.at(-1)).toMatchObject({
      action: 'spend_request.voided',
      details: { causes: 'MANDATE_NOT_IN_FORCE' },
    });
  });

  it('voids one the moment its source’s bank consent ends, not a moment later: SOURCE_NOT_USABLE', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    clock.advanceBy(w.state.consentExpiresAt.getTime() - clock.now().getTime());

    await voidsOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('DENIED');
  });

  it('voids one whose source’s bank consent has passed: SOURCE_NOT_USABLE', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    clock.advanceBy(w.state.consentExpiresAt.getTime() - clock.now().getTime() + 60_000);

    await voidsOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('DENIED');
    const events = await shared.eventsAbout(w.org, waiting.id, SPEND_REQUESTS.subject);
    expect(events.at(-1)).toMatchObject({ action: 'spend_request.voided', details: { causes: 'SOURCE_NOT_USABLE' } });
  });

  it('logs the lapse of a consent run out once, before its voids; an aborted run logs none (E7c)', async () => {
    const { w } = await ready();
    clock.advanceBy(w.state.consentExpiresAt.getTime() - clock.now().getTime() + 60_000);
    const stopped = new AbortController();
    stopped.abort();

    await voidsOf(only(w)).run(stopped.signal);
    expect(lines('consent_lapse.recorded')).toEqual([]);
    await voidsOf(only(w)).run();
    await voidsOf(only(w)).run();

    expect(lines('consent_lapse.recorded')).toHaveLength(1);
    const lapses = (await shared.eventsAbout(w.org, w.source, SOURCES.subject)).filter(
      ({ action }) => action === 'funding_source.consent_lapsed',
    );
    expect(lapses).toHaveLength(1);
    expect(lapses[0]).toMatchObject({ details: { chosen: false } });
  });

  it('logs no lapse on a source tampered with past the app: its alarm raised, the run goes on (FX-TAMPER, E7c)', async () => {
    const { w } = await ready();
    const owner = await tamperAsOwner(database, SOURCES, w.org);
    try {
      await owner.stripSeals(w.source);
    } finally {
      await owner.end();
    }
    clock.advanceBy(w.state.consentExpiresAt.getTime() - clock.now().getTime() + 60_000);

    await voidsOf(only(w)).run();

    expect(lines('audit.integrity_failed')).not.toEqual([]);
    expect(lines('consent_lapse.failed')).toHaveLength(1);
    expect(lines('consent_lapse.recorded')).toEqual([]);
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

  it('voids nothing on a pause edited into a cancel past the app: the suspension’s read raises the alarm (FX-TAMPER, decision 7)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await moved(w, await mandateIdOf(w), 'source', 'pause');
    // A later signed change of the source, so its state stands on that one, whole, and the suspend lies behind it.
    await shared.partnerSays(w, { availability: 'SUSPENDED' });
    await database.as('admin').query(
      `update audit.events set details = replace(details, '"pause"', '"cancel"')
         where org_id = $1 and action = 'funding_source.suspended'`,
      [w.org],
    );

    await voidsOf(only(w)).run();

    // The query's unverified filter took it for a cancel; the verified read believed none of it.
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
        organizationStatus: 'ACTIVE',
        agentStatus: 'ACTIVE',
        mandate: { status: 'ACTIVE', currentVersionId: row.mandate_version_id },
        source: { status: 'ACTIVE', availability: 'ACTIVE', consentPast: false, consentHeld: false },
        supplier: { status: 'VERIFIED', currentVersionId: row.supplier_version_id ?? '', pausedFrom: [] },
        paused: new Set(),
        cancelledBy: new Set(),
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

describe('a void with several causes, as its record is read (C2b)', () => {
  it('reads each cause back, in the engine’s order', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const mandateId = await mandateIdOf(w);
    await STOPS['the mandate suspended'](w, mandateId);
    await STOPS['the agent suspended'](w);

    await voidsOf(only(w)).run();

    const denial = await signed(w, (tx, states) => denialOf(tx, states, { orgId: w.org, id: waiting.id }));
    expect(denial).toMatchObject({
      outcome: 'voided',
      voiding: { causes: ['AGENT_SUSPENDED', 'MANDATE_NOT_IN_FORCE'] },
    });
  });
});

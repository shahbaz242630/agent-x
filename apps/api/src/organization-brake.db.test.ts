// 4D2e C3, PL-63 item 3: an admin's brake under trouble, on real Postgres and
// forced, never a race left to chance. A row's FOR SHARE doesn't queue behind a
// waiting FOR NO KEY UPDATE while its holders only hold locks, so a stream of them
// starves the change: the first describe shows it on the bare row, with no brake,
// as the cause of the load run's failures. Then the brake: an advisory lock, whose
// queue is honoured. Decisions take its shared side, each of the organisation's and
// the agent's; a freeze, an unfreeze, a kill switch or a reactivation its exclusive
// side, for at most 12 s. Past that: 503, nothing changed, an alarm.
import { setTimeout as sleep } from 'node:timers/promises';

import { AGENTS, createAgentKeyCheck } from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import {
  AGENT_BRAKE,
  brakeShared,
  createDatabase,
  createIdempotentWrites,
  type Database,
  holdBrake,
  lockName,
  noStatementTimes,
  ORGANISATION_BRAKE,
  sendTogether,
  timingStatements,
  withTenant,
} from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestClient,
  type TestDatabase,
  testLogger,
  waitUntilBlocked,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createAgentChanges,
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  SUSPEND_OPERATION,
} from './agent-changes.ts';
import { createAgentTurns } from './agent-turns.ts';
import { createDecisionEntry } from './decision-entry.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import {
  AED,
  askedFor,
  keys,
  mandateWorld,
  type MandateWorldTables,
  refused,
  type World,
} from './mandate-world.helper.test.ts';
import {
  createOrganizationChanges,
  FREEZE_OPERATION,
  UNFREEZE_CONFIRM_OPERATION,
  UNFREEZE_OPERATION,
} from './organization-changes.ts';
import { createSpendRequestDecisions, DECIDE_OPERATION, type SpendRequestDecided } from './spend-request-decisions.ts';

// Every decision at the database at once, as many replicas would send them.
const UNQUEUED = createDecisionEntry({
  turns: createAgentTurns({ perAgent: Number.MAX_SAFE_INTEGER }),
  perSupplier: Number.MAX_SAFE_INTEGER,
});

/** Well past the longest test's waits: a slow laptop mustn't fail one. */
const LONG = 60_000;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;
const ids = new SequentialIds(0xb7a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b7';
let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'organization-brake' });
const { world, keyed, agentKey, quiet, stepUp } = shared;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 16 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-08T08:00:00Z'));
  capture = new LogCapture();
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger: testLogger() });
});

const services = () => ({
  database: app,
  keys,
  ids,
  clock,
  challenges: createStepUpChallenges({ ids, clock }),
  outbox: createOutbox({ ids, clock }),
  logger: testLogger(capture),
});

const changes = () => createOrganizationChanges(services());
const agents = () => createAgentChanges(services());
const keyCheck = () => createAgentKeyCheck({ database: app, keys, ids, clock, logger: testLogger() });

/** A world whose agent has a key and a mandate in force, its suppliers verified. */
async function ready() {
  const w = await world();
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, { approvalThreshold: AED(1_500_000n) });
  return { w, acting: await agentKey(w) };
}

type Acting = Awaited<ReturnType<typeof ready>>['acting'];

let asked = 0;
/** A real decision: AED 1,000 to the supplier (the first unless named), an order of its own. */
const decision = (w: World, acting: Acting, supplierId = w.suppliers[0] ?? ''): Promise<SpendRequestDecided> => {
  asked += 1;
  const request = {
    amount: AED(100_000n),
    supplierId,
    fundingSourceId: w.source,
    orderReference: `INV-${String(asked)}`,
    purpose: 'Printer paper',
  };
  return createSpendRequestDecisions({ ...services(), entry: UNQUEUED }).decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: `brake-${String(asked)}`,
      payload: JSON.stringify({ ...request, amount: String(request.amount.minor) }),
    },
    request,
    CORRELATION,
  );
};

const frozen = (w: World, key?: string) =>
  changes().freeze(w.admin, keyed(w.admin, FREEZE_OPERATION, key), 'pause', CORRELATION);

const suspended = (w: World, key?: string) =>
  agents().suspend(w.admin, keyed(w.admin, SUSPEND_OPERATION, key), w.agent, 'pause', CORRELATION);

/** The call and how long it took. */
const timed = async <T>(call: () => Promise<T>) => {
  const started = performance.now();
  const answer = await call();
  return { answer, ms: performance.now() - started };
};

/** Its answer, or its failure's Postgres code: whichever a call came to. */
const settled = async (call: Promise<unknown>): Promise<unknown> => {
  try {
    return await call;
  } catch (error) {
    return { threw: (error as { code?: unknown }).code };
  }
};

/** Sends `send` every `everyMs` until stopped, and all its answers once they are in. */
function stream(send: () => Promise<unknown>, everyMs: number) {
  const sending = { on: true };
  const sent: Promise<unknown>[] = [];
  const running = (async () => {
    while (sending.on) {
      sent.push(settled(send()));
      await sleep(everyMs);
    }
  })();
  return async () => {
    sending.on = false;
    await running;
    return Promise.all(sent);
  };
}

/** The supplier's row held by a transaction that doesn't end, as phase 5's stuck organisation holds it. */
async function stuckSupplier(supplierId: string): Promise<TestClient> {
  const holder = await database.connect('admin');
  await holder.query('begin');
  await holder.query('select 1 from suppliers.suppliers where id = $1 for update', [supplierId]);
  return holder;
}

const letGo = async (holder: TestClient) => {
  await holder.query('rollback');
  await holder.end();
};

const ROW_SHARE = 'select 1 from organizations.organizations where id = $1 for share';
const AGENT_SHARE = 'select 1 from agents.agents where org_id = $1 and id = $2 for share';
const BRAKE_SHARED = 'select pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended($1, 0))';

type Hold = (holder: TestClient) => Promise<unknown>;
const orgRow =
  (org: string): Hold =>
  (holder) =>
    holder.query(ROW_SHARE, [org]);
const agentRow =
  ({ org, agent }: World): Hold =>
  (holder) =>
    holder.query(AGENT_SHARE, [org, agent]);
const brakeOf =
  (name: string): Hold =>
  (holder) =>
    holder.query(BRAKE_SHARED, [name]);

/** A transaction of its own holding each in turn, as a decision part-way does. */
async function holding(...holds: readonly Hold[]): Promise<TestClient> {
  const holder = await database.connect('admin');
  await holder.query('begin');
  for (const hold of holds) await hold(holder);
  return holder;
}

/**
 * A relay of holders, forced: each takes `taken` while the one before it still holds it, so there is never a moment
 * with none, and lets go only once the next has it or waits for it. Stops when told, every one gone. Counts how many
 * had to wait: under a brake's queue, those behind it; on a bare row, none.
 */
function relayOf(taken: () => Promise<TestClient>, { stepMs = 150, behindABrake = true } = {}) {
  const relaying = { on: true };
  let waited = 0;
  let took = 0;
  const running = (async () => {
    let inside = await taken();
    took += 1;
    while (relaying.on) {
      await sleep(stepMs);
      const next = taken();
      // A slow connection on a busy laptop must not leave a gap for the change: on a bare row, the next never waits.
      const inTime = await Promise.race([
        next.then(() => true),
        ...(behindABrake ? [sleep(250).then(() => false)] : []),
      ]);
      if (!inTime) waited += 1;
      await letGo(inside);
      inside = await next;
      took += 1;
    }
    await letGo(inside);
  })();
  return async () => {
    relaying.on = false;
    await running;
    return { took, waited };
  };
}

/** The organisation's row as it stands. */
const statusOf = (org: string) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await states.verifiedState(tx, ORGANIZATIONS, { orgId: org, id: org }, 'share');
    return read.outcome === 'verified' ? read.fields.get('status') : read.outcome;
  });

const agentStatusOf = (w: World) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const read = await states.verifiedState(tx, AGENTS, { orgId: w.org, id: w.agent }, 'share');
    return read.outcome === 'verified' ? read.fields.get('status') : read.outcome;
  });

/** The brake's wait, written out: past a statement's 10 s limit. A test reads no number the code could move. */
const BRAKE_WAIT_MS = 12_000;

/** The brake's whole wait and no more, with room: this laptop has timed a 10 s limit from 9.6 s to 10.6 s. */
const expectBrakeWait = (ms: number) => {
  expect(ms).toBeGreaterThan(BRAKE_WAIT_MS * 0.9);
  expect(ms).toBeLessThan(BRAKE_WAIT_MS * 1.1);
};

const alarms = () => capture.lines().filter(({ event }) => event === 'brake.not_applied');

const FROZEN_NOW = { outcome: 'changed', organization: { status: 'FROZEN' } };

describe('what a brake is up against: a stream of share holders and the row (no brake)', () => {
  it(
    'starves a FOR NO KEY UPDATE: each holder gets in at once while it waits, past its 5 s, until the 10 s limit',
    async () => {
      const w = await world();
      const stop = relayOf(() => holding(orgRow(w.org)), { behindABrake: false });
      const change = await database.connect('admin');
      await change.query('begin');
      await change.query("select pg_catalog.set_config('lock_timeout', '5s', true)");
      await change.query("select pg_catalog.set_config('statement_timeout', '10s', true)");

      const { answer, ms } = await timed(() =>
        settled(change.query('select 1 from organizations.organizations where id = $1 for no key update', [w.org])),
      );
      const { took, waited } = await stop();
      await letGo(change);

      // Not the lock wait's own code: every holder ended within 5 s, each new wait starting it again.
      expect(answer).toEqual({ threw: '57014' });
      expect(ms).toBeGreaterThan(9_000);
      expect(took).toBeGreaterThan(20);
      expect(waited).toBe(0);
    },
    LONG,
  );

  it(
    'and one holder that outlasts it runs out the lock wait: 55P03, at 5 s',
    async () => {
      const w = await world();
      const holder = await holding(orgRow(w.org));
      const change = await database.connect('admin');
      await change.query('begin');
      await change.query("select pg_catalog.set_config('lock_timeout', '5s', true)");

      const { answer, ms } = await timed(() =>
        settled(change.query('select 1 from organizations.organizations where id = $1 for no key update', [w.org])),
      );
      await letGo(change);
      await letGo(holder);

      expect(answer).toEqual({ threw: '55P03' });
      expect(ms).toBeGreaterThan(4_500);
      expect(ms).toBeLessThan(7_500);
    },
    LONG,
  );
});

describe('the freeze', () => {
  it(
    'beats a stream of real decisions, a supplier stuck: frozen, and those after it read FROZEN',
    async () => {
      const { w, acting } = await ready();
      const stuck = await stuckSupplier(w.suppliers[0] ?? '');
      const stop = stream(() => decision(w, acting), 800);
      // Decisions inside, each holding the organisation's row while it waits on the stuck supplier: the load run's phase 5.
      await waitUntilQueued(database.as('admin'), 3);

      const { answer, ms } = await timed(() => frozen(w));
      const answers = await stop();
      await letGo(stuck);

      expect(answer).toMatchObject(FROZEN_NOW);
      expect(ms).toBeLessThan(BRAKE_WAIT_MS);
      expect(answers.length).toBeGreaterThan(5);
      expect(await settled(decision(w, acting))).toEqual(refused(409, 'ORG_FROZEN'));
      expect(alarms()).toEqual([]);
    },
    LONG,
  );

  it(
    'beats a forced relay of holders, the brake and the row each, and makes them wait',
    async () => {
      const w = await world();
      const stop = relayOf(() => holding(brakeOf(lockName(ORGANISATION_BRAKE, w.org)), orgRow(w.org)));
      await sleep(400);

      const { answer, ms } = await timed(() => frozen(w));
      const { waited } = await stop();

      expect(answer).toMatchObject(FROZEN_NOW);
      expect(ms).toBeLessThan(5_000);
      expect(waited).toBeGreaterThan(0);
    },
    LONG,
  );

  it('lines a decision up behind it: FROZEN read on a snapshot taken after the wait, no alarm', async () => {
    const { w, acting } = await ready();
    const monitor = database.as('admin');
    const inside = await holding(brakeOf(lockName(ORGANISATION_BRAKE, w.org)));

    const freezing = frozen(w);
    const [freezer] = await waitUntilQueued(monitor, 1);
    const late = decision(w, acting);
    const queued = await waitUntilQueued(monitor, 2);
    const decider = queued.find((pid) => pid !== freezer) ?? 0;
    // It waits on the freeze, which waits on the one inside: it has not got past the waiting freeze.
    expect(await waitUntilBlocked(monitor, decider)).toContain(freezer);

    await letGo(inside);
    expect(await freezing).toMatchObject(FROZEN_NOW);
    expect(await late).toEqual(refused(409, 'ORG_FROZEN'));
    expect(capture.lines().filter(({ event }) => event === 'audit.integrity_failed')).toEqual([]);
  });

  it('refuses a decision behind one committed: FROZEN, nothing made', async () => {
    const { w, acting } = await ready();
    expect(await frozen(w)).toMatchObject(FROZEN_NOW);
    expect(await decision(w, acting)).toEqual(refused(409, 'ORG_FROZEN'));
    const requests = await withTenant(app, w.org, (tx) =>
      tx.selectFrom('spend_requests.requests').select('id').execute(),
    );
    expect(requests).toEqual([]);
  });

  it.each([
    ['the organisation’s row, held FOR SHARE', (w: World) => holding(orgRow(w.org))],
    ['its brake, held shared', (w: World) => holding(brakeOf(lockName(ORGANISATION_BRAKE, w.org)))],
  ])(
    'past its wait behind %s: 503, nothing frozen, the alarm; the key still usable, and the lock reopened',
    async (_, held) => {
      const { w, acting } = await ready();
      const before = await shared.eventsAbout(w.org, w.org, 'organization');
      const noticesBefore = await shared.noticesOf(w.org);
      const holder = await held(w);

      const { answer, ms } = await timed(() => frozen(w, 'the-same-key'));

      expect(answer).toEqual(refused(503, 'ORGANISATION_BUSY'));
      expectBrakeWait(ms);
      expect(alarms()).toMatchObject([{ event: 'brake.not_applied', orgId: w.org, level: 'error' }]);
      expect(await statusOf(w.org)).toBe('ACTIVE');
      expect(await shared.eventsAbout(w.org, w.org, 'organization')).toEqual(before);
      expect(await shared.noticesOf(w.org)).toEqual(noticesBefore);
      expect(await keyCheck().check(acting.text, CORRELATION)).toMatchObject({ outcome: 'accepted' });
      // The queue goes through once it gave up: a decision is decided, the holder still there.
      expect(await decision(w, acting)).toMatchObject({ outcome: 'decided', request: { decision: 'ALLOW' } });

      await letGo(holder);
      // Its key was left unused: the same click goes through now the trouble is gone.
      expect(await frozen(w, 'the-same-key')).toMatchObject(FROZEN_NOW);
    },
    LONG,
  );

  it('costs one trip more than before: the brake with its bound on one trip', async () => {
    const w = await world();
    const times = noStatementTimes();
    await timingStatements(times, () => frozen(w));
    // 16 before the brake, its answer's read included.
    expect(times.trips).toBe(17);
  });
});

describe('the brake itself', () => {
  it('is the app role’s to take, and gives the transaction no ID, so the claim after it is still first', async () => {
    const w = await world();
    const idempotency = createIdempotentWrites({ keys, logger: testLogger() });
    const [privilege] = await database
      .as('admin')
      .query<{ allowed: boolean }>(
        "select pg_catalog.has_function_privilege('agentx_app', 'pg_catalog.pg_advisory_xact_lock_shared(bigint)', 'execute') as allowed",
      );
    expect(privilege?.allowed).toBe(true);

    const seen = await withTenant(app, w.org, async (tx) => {
      await sendTogether(tx, [brakeShared(ORGANISATION_BRAKE, w.org), brakeShared(AGENT_BRAKE, w.org, w.agent)]);
      await holdBrake(tx, 'another-brake', w.org);
      const { xid } = await tx
        .selectNoFrom((eb) => eb.fn<string | null>('pg_current_xact_id_if_assigned').as('xid'))
        .executeTakeFirstOrThrow();
      const written = await idempotency.run(tx, keyed(w.admin, FREEZE_OPERATION), () =>
        Promise.resolve({ status: 200, resourceId: w.org }),
      );
      return { xid, written };
    });

    expect(seen.xid).toBeNull();
    expect(seen.written).toMatchObject({ outcome: 'done' });
  });

  it(
    'lets decisions run side by side: one held on a stuck supplier never holds up another',
    async () => {
      const { w, acting } = await ready();
      const stuck = await stuckSupplier(w.suppliers[0] ?? '');
      const waiting = settled(decision(w, acting));
      await waitUntilQueued(database.as('admin'), 1);

      const { answer, ms } = await timed(() => decision(w, acting, w.suppliers[1]));

      expect(answer).toMatchObject({ outcome: 'decided', request: { decision: 'ALLOW' } });
      // Its own speed, not the other's 5 s: an exclusive side would hold it until that wait ran out.
      expect(ms).toBeLessThan(2_000);

      await letGo(stuck);
      await waiting;
    },
    LONG,
  );

  it(
    'is its own organisation’s: a freeze waiting holds up no other organisation',
    async () => {
      const { w } = await ready();
      const other = await ready();
      const inside = await holding(brakeOf(lockName(ORGANISATION_BRAKE, w.org)));
      const freezing = frozen(w);
      await waitUntilQueued(database.as('admin'), 1);

      expect(await decision(other.w, other.acting)).toMatchObject({ outcome: 'decided' });

      await letGo(inside);
      await freezing;
    },
    LONG,
  );
});

describe('the unfreeze', () => {
  it(
    'beats a stream of refused decisions, its ask and its confirm',
    async () => {
      const { w } = await ready();
      expect(await frozen(w)).toMatchObject(FROZEN_NOW);
      const stop = relayOf(() => holding(brakeOf(lockName(ORGANISATION_BRAKE, w.org)), orgRow(w.org)));
      await sleep(400);

      const pendingRequests = 'pause' as const;
      const challengeId = askedFor(
        await changes().unfreeze(
          w.admin,
          keyed(w.admin, UNFREEZE_OPERATION),
          { reason: 'All clear', pendingRequests },
          CORRELATION,
        ),
      );
      await stepUp(w.admin, challengeId);
      const confirmed = await changes().unfreezeConfirm(
        w.admin,
        keyed(w.admin, UNFREEZE_CONFIRM_OPERATION),
        { stepUpChallengeId: challengeId, reason: 'All clear', pendingRequests },
        CORRELATION,
      );
      await stop();

      expect(confirmed).toMatchObject({ outcome: 'changed', organization: { status: 'ACTIVE' } });
    },
    LONG,
  );
});

describe('the kill switch: the agent’s own brake', () => {
  it(
    'beats its own real decisions and key checks, a supplier stuck',
    async () => {
      const { w, acting } = await ready();
      const stuck = await stuckSupplier(w.suppliers[0] ?? '');
      const check = keyCheck();
      const stopDecisions = stream(() => decision(w, acting), 800);
      const stopChecks = Array.from({ length: 3 }, () => stream(() => check.check(acting.text, CORRELATION), 5));
      await waitUntilQueued(database.as('admin'), 3);

      const { answer, ms } = await timed(() => suspended(w));
      await Promise.all([stopDecisions(), ...stopChecks.map((stop) => stop())]);
      await letGo(stuck);

      expect(answer).toMatchObject({ outcome: 'changed', agent: { agent: { status: 'SUSPENDED' } } });
      // Its whole call: any wait for a connection (this stream goes round the gate and can fill the pool, so CI read 16.3 s,
      // about 4 s past the brake), the brake's wait, then the change and its answer's read.
      expect(ms).toBeLessThan(BRAKE_WAIT_MS * 1.75);
      expect(await keyCheck().check(acting.text, CORRELATION)).toEqual({ outcome: 'refused' });
      expect(alarms()).toEqual([]);
    },
    LONG,
  );

  it('lines its key checks and decisions up behind it: each reads it suspended', async () => {
    const { w, acting } = await ready();
    const monitor = database.as('admin');
    const inside = await holding(brakeOf(lockName(AGENT_BRAKE, w.org, w.agent)), agentRow(w));

    const suspending = suspended(w);
    await waitUntilQueued(monitor, 1);
    const checking = keyCheck().check(acting.text, CORRELATION);
    await waitUntilQueued(monitor, 2);
    const late = decision(w, acting);
    await waitUntilQueued(monitor, 3);

    await letGo(inside);
    expect(await suspending).toMatchObject({ outcome: 'changed', agent: { agent: { status: 'SUSPENDED' } } });
    expect(await checking).toEqual({ outcome: 'refused' });
    expect(await late).toMatchObject({
      outcome: 'decided',
      request: { decision: 'DENY', reasons: ['AGENT_SUSPENDED'] },
    });
    expect(capture.lines().filter(({ event }) => event === 'audit.integrity_failed')).toEqual([]);
  });

  it(
    'holds up neither another agent’s decisions nor its key checks',
    async () => {
      const { w } = await ready();
      const other = await shared.secondAgent(registry, w, { approvalThreshold: AED(1_500_000n) });
      const inside = await holding(brakeOf(lockName(AGENT_BRAKE, w.org, w.agent)));
      const suspending = suspended(w);
      await waitUntilQueued(database.as('admin'), 1);

      expect(await keyCheck().check(other.text, CORRELATION)).toMatchObject({ outcome: 'accepted' });
      expect(await decision(w, other)).toMatchObject({ outcome: 'decided' });

      await letGo(inside);
      await suspending;
    },
    LONG,
  );

  it(
    'past its wait: 503, still active, the alarm; its key still usable; the same key goes through after',
    async () => {
      const { w, acting } = await ready();
      const holder = await holding(agentRow(w));

      const { answer, ms } = await timed(() => suspended(w, 'the-same-key'));

      expect(answer).toEqual(refused(503, 'ORGANISATION_BUSY'));
      expectBrakeWait(ms);
      expect(alarms()).toMatchObject([{ event: 'brake.not_applied', orgId: w.org, level: 'error' }]);
      expect(await agentStatusOf(w)).toBe('ACTIVE');
      expect(await keyCheck().check(acting.text, CORRELATION)).toMatchObject({ outcome: 'accepted' });

      await letGo(holder);
      expect(await suspended(w, 'the-same-key')).toMatchObject({ agent: { agent: { status: 'SUSPENDED' } } });
    },
    LONG,
  );

  it(
    'a reactivation beats its refused decisions, its ask and its confirm',
    async () => {
      const { w } = await ready();
      expect(await suspended(w)).toMatchObject({ agent: { agent: { status: 'SUSPENDED' } } });
      const stop = relayOf(() => holding(brakeOf(lockName(AGENT_BRAKE, w.org, w.agent)), agentRow(w)));
      await sleep(400);

      const challengeId = askedFor(
        await agents().reactivate(w.admin, keyed(w.admin, REACTIVATE_OPERATION), w.agent, CORRELATION),
      );
      await stepUp(w.admin, challengeId);
      const confirmed = await agents().reactivateConfirm(
        w.admin,
        keyed(w.admin, REACTIVATE_CONFIRM_OPERATION),
        w.agent,
        challengeId,
        CORRELATION,
      );
      await stop();

      expect(confirmed).toMatchObject({ outcome: 'changed', agent: { agent: { status: 'ACTIVE' } } });
    },
    LONG,
  );
});

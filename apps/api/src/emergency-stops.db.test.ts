// 4D2e C3, PL-63 item 3: every stop and authority change that takes a row a
// decision holds FOR SHARE, under trouble, forced. A relay of holders takes what a
// decision takes, its brakes then its rows, always overlapping: with no brake such
// a change would wait through every holder to its statement's limit. Those brakes
// are the fix; each change here goes through in about a relay's step. Mandate and
// key revoke also through their real routes, behind real decisions and a stuck
// supplier; past the wait they answer 503, nothing changed, their key reusable.
import { setTimeout as sleep } from 'node:timers/promises';

import { AGENT_KEYS, createAgentKeyCheck } from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import { createStepUpChallenges, type LiveSession, type MembershipCheck } from '@agentx/core/modules/identity';
import { MANDATES } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { createFakeRail } from '@agentx/core/modules/providers';
import {
  AGENT_BRAKE,
  createDatabase,
  type Database,
  lockName,
  ORGANISATION_BRAKE,
  SOURCE_BRAKE,
} from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestClient,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import type { InjectOptions } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { createAgentChanges, HAND_OVER_CONFIRM_OPERATION, HAND_OVER_OPERATION } from './agent-changes.ts';
import {
  createAgentKeyChanges,
  REVOKE_OPERATION,
  ROTATE_CONFIRM_OPERATION,
  ROTATE_OPERATION,
} from './agent-key-changes.ts';
import { createAgentTurns } from './agent-turns.ts';
import { createDecisionEntry } from './decision-entry.ts';
import {
  createFundingSourceChanges,
  CONSENT_EXPIRY_OPERATION,
  REACTIVATE_CONFIRM_OPERATION as SOURCE_REACTIVATE_CONFIRM,
  REACTIVATE_OPERATION as SOURCE_REACTIVATE,
  REFRESH_OPERATION,
  SUSPEND_OPERATION as SOURCE_SUSPEND,
} from './funding-source-changes.ts';
import { ACCEPT_CONFIRM_OPERATION, ACCEPT_OPERATION, createMandateAcceptance } from './mandate-acceptance.ts';
import { createMandateMoves, MOVE_OPERATIONS, OVER_LIMIT_OPERATIONS } from './mandate-moves.ts';
import { createMandateRegistry, REDRAFT_OPERATION } from './mandate-registry.ts';
import {
  AED,
  askedFor,
  draftedOf,
  keys,
  mandateWorld,
  type MandateWorldTables,
  refused,
  type World,
} from './mandate-world.helper.test.ts';
import { createAgentMandates } from './agent-mandate.ts';
import { createPolicyChanges, POLICY_OPERATIONS } from './policy-changes.ts';
import { closeServers, COOKIE, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { createSpendRequestDecisions, DECIDE_OPERATION } from './spend-request-decisions.ts';
import { createSpendRequestReads } from './spend-request-reads.ts';
import { createSupplierChanges, SUSPEND_OPERATION as SUPPLIER_SUSPEND } from './supplier-changes.ts';
import { createSupplierRegistry } from './supplier-registry.ts';

const UNQUEUED = createDecisionEntry({
  turns: createAgentTurns({ perAgent: Number.MAX_SAFE_INTEGER }),
  perSupplier: Number.MAX_SAFE_INTEGER,
});

/** Well past the longest test's waits. */
const LONG = 60_000;
/** A brake's wait, written out. A test reads no number the code could move. */
const BRAKE_WAIT_MS = 12_000;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;
const ids = new SequentialIds(0xb8a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b8';
let clock: FixedClock;
let capture: LogCapture;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'emergency-stops' });
const { world, keyed, agentKey, stepUp, quiet, termsOf } = shared;

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
});

afterEach(closeServers);

const services = () => ({
  database: app,
  keys,
  ids,
  clock,
  challenges: createStepUpChallenges({ ids, clock }),
  outbox: createOutbox({ ids, clock }),
  logger: testLogger(capture),
});

const registry = () => createMandateRegistry(services());
const moves = () => createMandateMoves(services());
const keyChanges = () => createAgentKeyChanges(services());
const agentChanges = () => createAgentChanges(services());
const acceptance = () => createMandateAcceptance(services());
const sourceChanges = (rail?: ReturnType<typeof createFakeRail>) => createFundingSourceChanges({ ...services(), rail });
const policies = () => createPolicyChanges(services());

/** A world whose agent has a key and a mandate in force, its suppliers verified. */
async function ready() {
  const w = await world();
  for (const id of w.suppliers) await shared.verified(w, id);
  const mandateId = await shared.inForce(registry(), w, { approvalThreshold: AED(1_500_000n) });
  return { w, mandateId, acting: await agentKey(w) };
}
type Ready = Awaited<ReturnType<typeof ready>>;

let asked = 0;
/** A real decision, an order of its own, to the first supplier. */
const decision = ({ w, acting }: Pick<Ready, 'w' | 'acting'>, supplierId = w.suppliers[0] ?? '') => {
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
      key: `stops-${String(asked)}`,
      payload: JSON.stringify({ ...request, amount: String(request.amount.minor) }),
    },
    request,
    CORRELATION,
  );
};

/** Its answer, or its failure's Postgres code. */
const settled = async (call: Promise<unknown>): Promise<unknown> => {
  try {
    return await call;
  } catch (error) {
    return { threw: (error as { code?: unknown }).code };
  }
};

const timed = async <T>(call: () => Promise<T>) => {
  const started = performance.now();
  const answer = await call();
  return { answer, ms: performance.now() - started };
};

/** Sends `send` every `everyMs` until stopped. */
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

const letGo = async (holder: TestClient) => {
  await holder.query('rollback');
  await holder.end();
};

const BRAKE_SHARED = 'select pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended($1, 0))';
const ORG_ROW = 'select 1 from organizations.organizations where id = $1 for share';
const AGENT_ROW = 'select 1 from agents.agents where id = $1 for share';
const KEY_ROW = 'select 1 from agents.agent_keys where id = $1 for share';
const MANDATE_ROW = 'select 1 from mandates.mandates where id = $1 for share';
const SOURCE_ROW = 'select 1 from funding_sources.sources where id = $1 for share';
const POLICY_ROW = 'select 1 from mandates.policies where id = $1 for share';

/** A transaction holding what a decision holds, in its order. */
async function decisionsLocks({ w, mandateId, acting }: Ready): Promise<TestClient> {
  const holder = await database.connect('admin');
  await holder.query('begin');
  await holder.query(BRAKE_SHARED, [lockName(ORGANISATION_BRAKE, w.org)]);
  await holder.query(BRAKE_SHARED, [lockName(AGENT_BRAKE, w.org, w.agent)]);
  await holder.query(BRAKE_SHARED, [lockName(SOURCE_BRAKE, w.org, w.source)]);
  await holder.query(ORG_ROW, [w.org]);
  await holder.query(AGENT_ROW, [w.agent]);
  await holder.query(KEY_ROW, [acting.keyId]);
  await holder.query(MANDATE_ROW, [mandateId]);
  await holder.query(POLICY_ROW, [mandateId]);
  await holder.query(POLICY_ROW, [w.org]);
  await holder.query(SOURCE_ROW, [w.source]);
  return holder;
}

/**
 * A relay of those, forced: each takes them while the one before it still holds them, so there is never a moment
 * with none, and lets go only once the next has them or waits for them. Stops when told, every one gone.
 */
function relayOf(ready_: Ready, stepMs = 150) {
  const relaying = { on: true };
  const running = (async () => {
    let inside = await decisionsLocks(ready_);
    while (relaying.on) {
      await sleep(stepMs);
      const next = decisionsLocks(ready_);
      await Promise.race([next, sleep(250)]);
      await letGo(inside);
      inside = await next;
    }
    await letGo(inside);
  })();
  return async () => {
    relaying.on = false;
    await running;
  };
}

/** A confirm's step-up asked and given. */
const steppedUp = async (
  w: World,
  ask: () => Promise<{ readonly outcome: string; readonly stepUpChallengeId?: string }>,
) => {
  const challengeId = askedFor(await ask());
  await stepUp(w.admin, challengeId);
  return challengeId;
};

const moved = (ready_: Ready, chosen: Parameters<ReturnType<typeof moves>['ask']>[3]) => async () => {
  const { w, mandateId } = ready_;
  const challengeId = await steppedUp(w, () =>
    moves().ask(w.admin, keyed(w.admin, MOVE_OPERATIONS[chosen.move].ask), mandateId, chosen, CORRELATION),
  );
  return moves().confirm(
    w.admin,
    keyed(w.admin, MOVE_OPERATIONS[chosen.move].confirm),
    mandateId,
    chosen,
    challengeId,
    CORRELATION,
  );
};

/** The mandate's own policy, set by the admin as they would: asked, stepped up and confirmed. */
const mandatePolicySet = async ({ w, mandateId }: Ready, monthlyCap: bigint) => {
  const target = { scope: 'mandate' as const, mandateId };
  const sent = {
    rules: {
      currency: 'AED',
      perOrderCap: null,
      monthlyCap: AED(monthlyCap),
      approvalThreshold: null,
      supplierIds: null,
    },
    capChoice: null,
    approvalWait: null,
  };
  const challengeId = await steppedUp(w, () =>
    policies().ask(w.admin, keyed(w.admin, POLICY_OPERATIONS.mandate.ask), target, sent, undefined, CORRELATION),
  );
  return policies().confirm(
    w.admin,
    keyed(w.admin, POLICY_OPERATIONS.mandate.confirm),
    target,
    sent,
    undefined,
    challengeId,
    CORRELATION,
  );
};

const POLICY_RULES = {
  currency: 'AED',
  perOrderCap: null,
  monthlyCap: AED(2_000_000n),
  approvalThreshold: null,
  supplierIds: null,
};

/**
 * Each change a decision's share-locks could hold up, as the admin makes it, ask and confirm, under the relay. `before`
 * sets it up, ahead of the relay. Each answers what its use case answered.
 */
const CHANGES: readonly (readonly [string, (ready_: Ready) => Promise<() => Promise<unknown>>])[] = [
  [
    'a key rotated',
    ({ w, acting }) => {
      const named = { agentId: w.agent, keyId: acting.keyId };
      return Promise.resolve(async () => {
        const challengeId = await steppedUp(w, () =>
          keyChanges().rotate(w.admin, keyed(w.admin, ROTATE_OPERATION), named, 'end_now', CORRELATION),
        );
        return keyChanges().rotateConfirm(
          w.admin,
          keyed(w.admin, ROTATE_CONFIRM_OPERATION),
          named,
          'end_now',
          challengeId,
          CORRELATION,
        );
      });
    },
  ],
  ['a mandate suspended', (r) => Promise.resolve(moved(r, { move: 'suspend', pendingRequests: 'pause' }))],
  [
    'a mandate resumed',
    async (r) => {
      await moved(r, { move: 'suspend', pendingRequests: 'pause' })();
      return moved(r, { move: 'resume' });
    },
  ],
  [
    'a mandate’s over-limit choice',
    ({ w, mandateId }) =>
      Promise.resolve(async () => {
        const challengeId = await steppedUp(w, () =>
          moves().chooseOverLimit(
            w.admin,
            keyed(w.admin, OVER_LIMIT_OPERATIONS.ask),
            mandateId,
            'approval',
            CORRELATION,
          ),
        );
        return moves().chooseOverLimitConfirm(
          w.admin,
          keyed(w.admin, OVER_LIMIT_OPERATIONS.confirm),
          mandateId,
          'approval',
          challengeId,
          CORRELATION,
        );
      }),
  ],
  [
    'a mandate redrafted',
    ({ w, mandateId }) =>
      Promise.resolve(() =>
        registry().redraft(
          w.admin,
          keyed(w.admin, REDRAFT_OPERATION),
          mandateId,
          { terms: termsOf(w, { purpose: 'Renewed' }), overLimit: 'refuse' },
          CORRELATION,
        ),
      ),
  ],
  [
    'a mandate’s draft accepted',
    async ({ w, mandateId }) => {
      const drafted = draftedOf(
        await registry().redraft(
          w.admin,
          keyed(w.admin, REDRAFT_OPERATION),
          mandateId,
          { terms: termsOf(w, { purpose: 'Renewed' }), overLimit: 'refuse' },
          CORRELATION,
        ),
      );
      const versionId = drafted.pending?.version.id ?? '';
      return async () => {
        const challengeId = await steppedUp(w, () =>
          acceptance().accept(w.admin, keyed(w.admin, ACCEPT_OPERATION), mandateId, versionId, 'cancel', CORRELATION),
        );
        return acceptance().acceptConfirm(
          w.admin,
          keyed(w.admin, ACCEPT_CONFIRM_OPERATION),
          mandateId,
          challengeId,
          'cancel',
          CORRELATION,
        );
      };
    },
  ],
  [
    'its source suspended',
    ({ w }) =>
      Promise.resolve(() =>
        sourceChanges().suspend(w.admin, keyed(w.admin, SOURCE_SUSPEND), w.source, 'pause', CORRELATION),
      ),
  ],
  [
    'its source reactivated',
    async ({ w }) => {
      await sourceChanges().suspend(w.admin, keyed(w.admin, SOURCE_SUSPEND), w.source, 'pause', CORRELATION);
      return async () => {
        const challengeId = await steppedUp(w, () =>
          sourceChanges().reactivate(w.admin, keyed(w.admin, SOURCE_REACTIVATE), w.source, CORRELATION),
        );
        return sourceChanges().reactivateConfirm(
          w.admin,
          keyed(w.admin, SOURCE_REACTIVATE_CONFIRM),
          w.source,
          challengeId,
          CORRELATION,
        );
      };
    },
  ],
  [
    'its source refreshed from the partner',
    ({ w }) =>
      Promise.resolve(() =>
        sourceChanges(w.rail).refresh(w.admin, keyed(w.admin, REFRESH_OPERATION), w.source, CORRELATION),
      ),
  ],
  [
    'its source’s consent-expiry choice',
    ({ w }) =>
      Promise.resolve(() =>
        sourceChanges().chooseConsentExpiry(
          w.admin,
          keyed(w.admin, CONSENT_EXPIRY_OPERATION),
          w.source,
          'pause',
          CORRELATION,
        ),
      ),
  ],
  [
    'its agent handed over',
    async ({ w }) => {
      const next = await shared.member(w.org, 'admin');
      return async () => {
        const challengeId = await steppedUp(w, () =>
          agentChanges().handOver(
            w.admin,
            keyed(w.admin, HAND_OVER_OPERATION),
            w.agent,
            next.membershipId,
            CORRELATION,
          ),
        );
        return agentChanges().handOverConfirm(
          w.admin,
          keyed(w.admin, HAND_OVER_CONFIRM_OPERATION),
          w.agent,
          next.membershipId,
          challengeId,
          CORRELATION,
        );
      };
    },
  ],
  [
    'a mandate’s own policy changed',
    async (r) => {
      // Its row now there for a decision to hold.
      expect(await mandatePolicySet(r, 1_000n)).toMatchObject({ outcome: 'changed' });
      return () => mandatePolicySet(r, 2_000n);
    },
  ],
  [
    'the organisation’s policy changed',
    ({ w }) => {
      const target = { scope: 'organization' as const };
      const sent = { rules: POLICY_RULES, capChoice: 'amount' as const, approvalWait: 72 as const };
      return Promise.resolve(async () => {
        const challengeId = await steppedUp(w, () =>
          policies().ask(
            w.admin,
            keyed(w.admin, POLICY_OPERATIONS.organization.ask),
            target,
            sent,
            undefined,
            CORRELATION,
          ),
        );
        return policies().confirm(
          w.admin,
          keyed(w.admin, POLICY_OPERATIONS.organization.confirm),
          target,
          sent,
          undefined,
          challengeId,
          CORRELATION,
        );
      });
    },
  ],
];

describe('every change a decision holds up beats a forced stream of what it holds', () => {
  it.each(CHANGES)(
    '%s',
    async (_, prepared) => {
      const r = await ready();
      const change = await prepared(r);
      const stop = relayOf(r);
      await sleep(400);

      const { answer, ms } = await timed(() => settled(change()));
      await stop();

      // A confirm's answer is a change's own: never a refusal, a failure, or a wait through the holders.
      expect(answer).not.toHaveProperty('threw');
      expect(answer).not.toMatchObject({ outcome: 'refused' });
      expect(ms).toBeLessThan(BRAKE_WAIT_MS / 2);
      expect(capture.lines().filter(({ event }) => event === 'brake.not_applied')).toEqual([]);
    },
    LONG,
  );
});

/** The signed-in admin, over HTTP: a real server around the real use cases. */
async function admin(w: World) {
  const live: LiveSession = {
    sessionId: w.admin.sessionId,
    userId: w.admin.userId,
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
    createdAt: clock.now(),
    lastSeenAt: clock.now(),
    endsAt: new Date(clock.now().getTime() + 3_600_000),
    idleEndsAt: new Date(clock.now().getTime() + 1_800_000),
  };
  const member: MembershipCheck = { outcome: 'active', id: w.admin.membershipId, role: 'admin' };
  const api = await routeServer({
    live,
    logger: testLogger(capture),
    agentChanges: agentChanges(),
    agentKeyChanges: keyChanges(),
    mandateMoves: moves(),
    supplierChanges: createSupplierChanges(services()),
    findMembership: (orgId) => Promise.resolve(orgId.toLowerCase() === w.org ? member : { outcome: 'none' }),
  });
  const headers = {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: w.org,
    origin: PUBLIC_ORIGIN,
  };
  return (url: string, key: string, payload: object = {}) => {
    const request: InjectOptions = {
      method: 'POST',
      url,
      headers: { ...headers, 'idempotency-key': key },
      payload,
    };
    return api.inject(request);
  };
}

/** The stops the partner asked of by name, through their routes: where to send them, and how each now reads. */
const ROUTED = [
  {
    name: 'a mandate revoked',
    path: ({ mandateId }: Ready) => `/v1/mandates/${mandateId}/revoke`,
    standing: async ({ w, mandateId }: Ready) =>
      withSignedStates(app, w.org, quiet(), async (tx, states) => {
        const read = await states.verifiedState(tx, MANDATES, { orgId: w.org, id: mandateId }, 'share');
        return read.outcome === 'verified' ? read.fields.get('status') : read.outcome;
      }),
    stopped: 'REVOKED',
    before: 'ACTIVE',
    holds: (holder: TestClient, { mandateId }: Ready) => holder.query(MANDATE_ROW, [mandateId]),
  },
  {
    name: 'a key revoked',
    path: ({ w, acting }: Ready) => `/v1/agents/${w.agent}/keys/${acting.keyId}/revoke`,
    standing: async ({ w, acting }: Ready) =>
      withSignedStates(app, w.org, quiet(), async (tx, states) => {
        const read = await states.verifiedState(tx, AGENT_KEYS, { orgId: w.org, id: acting.keyId }, 'share');
        return read.outcome === 'verified' ? read.fields.get('status') : read.outcome;
      }),
    stopped: 'REVOKED',
    before: 'ACTIVE',
    holds: (holder: TestClient, { acting }: Ready) => holder.query(KEY_ROW, [acting.keyId]),
  },
] as const;

describe.each(ROUTED)('$name, through its route', ({ path, standing, stopped, before, holds }) => {
  const stopVia = async (post: Awaited<ReturnType<typeof admin>>, r: Ready, confirmKey = 'confirm-1') => {
    const asking = await post(path(r), 'ask-1');
    expect(asking.statusCode).toBe(202);
    const { stepUpChallengeId } = asking.json<{ stepUpChallengeId: string }>();
    await stepUp(r.w.admin, stepUpChallengeId);
    return { stepUpChallengeId, confirmed: await post(`${path(r)}/confirm`, confirmKey, { stepUpChallengeId }) };
  };

  it(
    'goes through behind real decisions held on a stuck supplier',
    async () => {
      const r = await ready();
      const post = await admin(r.w);
      const stuck = await database.connect('admin');
      await stuck.query('begin');
      await stuck.query('select 1 from suppliers.suppliers where id = $1 for update', [r.w.suppliers[0]]);
      const stop = stream(() => decision(r), 800);
      await waitUntilQueued(database.as('admin'), 3);

      const { answer, ms } = await timed(() => stopVia(post, r));
      await stop();
      await letGo(stuck);

      expect(answer.confirmed.statusCode).toBe(200);
      expect(ms).toBeLessThan(BRAKE_WAIT_MS * 2);
      expect(await standing(r)).toBe(stopped);
    },
    LONG,
  );

  it(
    'past its wait: 503 with Retry-After, nothing changed, the alarm; the same key goes through after',
    async () => {
      const r = await ready();
      const post = await admin(r.w);
      const { stepUpChallengeId } = (await post(path(r), 'ask-1')).json<{ stepUpChallengeId: string }>();
      await stepUp(r.w.admin, stepUpChallengeId);
      const holder = await database.connect('admin');
      await holder.query('begin');
      await holds(holder, r);

      const { answer, ms } = await timed(() => post(`${path(r)}/confirm`, 'confirm-1', { stepUpChallengeId }));

      expect(answer.statusCode).toBe(503);
      expect(answer.headers['retry-after']).toBe('5');
      expect(answer.json()).toMatchObject({ error: { code: 'ORGANISATION_BUSY' } });
      expect(ms).toBeGreaterThan(BRAKE_WAIT_MS * 0.9);
      expect(ms).toBeLessThan(BRAKE_WAIT_MS * 1.1);
      expect(capture.lines().filter(({ event }) => event === 'brake.not_applied')).toHaveLength(1);
      expect(await standing(r)).toBe(before);

      await letGo(holder);
      expect((await post(`${path(r)}/confirm`, 'confirm-1', { stepUpChallengeId })).statusCode).toBe(200);
      expect(await standing(r)).toBe(stopped);
    },
    LONG,
  );
});

describe('a stop a brake can’t help: the supplier’s, whose row a decision locks as a change does', () => {
  it(
    'queues fairly behind decisions on a supplier nothing holds',
    async () => {
      const r = await ready();
      const post = await admin(r.w);
      const stop = stream(() => decision(r), 50);
      await sleep(300);

      const { answer, ms } = await timed(() =>
        post(`/v1/suppliers/${r.w.suppliers[0] ?? ''}/suspend`, 'suspend-1', { pendingRequests: 'pause' }),
      );
      await stop();

      expect(answer.statusCode).toBe(200);
      expect(ms).toBeLessThan(BRAKE_WAIT_MS / 2);
    },
    LONG,
  );

  it(
    'answers 503, the alarm and nothing changed, when its own row is held and never let go: nothing can beat that',
    async () => {
      const r = await ready();
      const post = await admin(r.w);
      const supplier = r.w.suppliers[0] ?? '';
      const stuck = await database.connect('admin');
      await stuck.query('begin');
      await stuck.query('select 1 from suppliers.suppliers where id = $1 for update', [supplier]);

      const answer = await post(`/v1/suppliers/${supplier}/suspend`, 'suspend-1', { pendingRequests: 'pause' });
      expect(answer.statusCode).toBe(503);
      expect(answer.json()).toMatchObject({ error: { code: 'ORGANISATION_BUSY' } });
      expect(capture.lines().filter(({ event }) => event === 'brake.not_applied')).toHaveLength(1);

      await letGo(stuck);
      expect(
        (await post(`/v1/suppliers/${supplier}/suspend`, 'suspend-1', { pendingRequests: 'pause' })).statusCode,
      ).toBe(200);
    },
    LONG,
  );
});

describe('a key check behind a stop that can’t take hold', () => {
  it(
    'is told busy at 5 s, never cut off by a statement’s limit: the agent’s request answers 503',
    async () => {
      const r = await ready();
      const check = createAgentKeyCheck({ database: app, keys, ids, clock, logger: testLogger() });
      const holder = await database.connect('admin');
      await holder.query('begin');
      await holder.query('select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [
        lockName(AGENT_BRAKE, r.w.org, r.w.agent),
      ]);

      const { answer, ms } = await timed(() => settled(check.check(r.acting.text, CORRELATION)));
      await letGo(holder);

      expect(answer).toEqual({ threw: '55P03' });
      expect(ms).toBeLessThan(BRAKE_WAIT_MS / 2 + 500);
      expect(ms).toBeGreaterThan(4_000);
    },
    LONG,
  );
});

describe('the lock order: nothing takes a brake while holding a row', () => {
  it('a stop that can’t get its brake has locked no row of its own: a holder of the brake waits on nothing of it', async () => {
    const r = await ready();
    const { w } = r;
    const inside = await database.connect('admin');
    await inside.query('begin');
    await inside.query(BRAKE_SHARED, [lockName(AGENT_BRAKE, w.org, w.agent)]);

    const revoking = keyChanges().revoke(
      w.admin,
      keyed(w.admin, REVOKE_OPERATION),
      { agentId: w.agent, keyId: r.acting.keyId },
      CORRELATION,
    );
    await waitUntilQueued(database.as('admin'), 1);

    // Everything the waiting stop will come to take is free: the holder takes them all, FOR UPDATE, at once.
    await inside.query('select 1 from agents.agents where id = $1 for update nowait', [w.agent]);
    await inside.query('select 1 from agents.agent_keys where id = $1 for update nowait', [r.acting.keyId]);
    await letGo(inside);
    expect(await revoking).toMatchObject({ outcome: 'asked' });
  });

  it(
    'and its queue holds no other agent’s decisions, or another organisation’s, or those of another source',
    async () => {
      const r = await ready();
      const other = await ready();
      const inside = await database.connect('admin');
      await inside.query('begin');
      await inside.query(BRAKE_SHARED, [lockName(SOURCE_BRAKE, r.w.org, r.w.source)]);
      const suspending = sourceChanges().suspend(
        r.w.admin,
        keyed(r.w.admin, SOURCE_SUSPEND),
        r.w.source,
        'pause',
        CORRELATION,
      );
      await waitUntilQueued(database.as('admin'), 1);

      expect(await decision(other)).toMatchObject({ outcome: 'decided' });
      // The waiting brake holds up its own source's decisions: one here waits behind it.
      const late = settled(decision(r));
      await waitUntilQueued(database.as('admin'), 2);

      await letGo(inside);
      await suspending;
      expect(await late).toMatchObject({
        outcome: 'decided',
        request: { decision: 'DENY', reasons: ['SOURCE_NOT_USABLE'] },
      });
    },
    LONG,
  );
});

/**
 * Runs `change`, which must lock the agent's row and then the chain head, so that another takes that row and keeps it the
 * moment it commits: whatever `change` reads of the row after its commit waits. What it answered, and the other, holding.
 */
async function withTheRowTakenAtCommit<T>(w: World, change: () => Promise<T>) {
  const monitor = database.as('admin');
  const head = await database.connect('admin');
  await head.query('begin');
  await head.query('select 1 from audit.heads where org_id = $1 for update', [w.org]);
  const changing = change();
  await waitUntilQueued(monitor, 1);
  const next = await database.connect('admin');
  await next.query('begin');
  const taken = next.query('select 1 from agents.agents where id = $1 for update', [w.agent]);
  await waitUntilQueued(monitor, 2);
  await letGo(head);
  const { answer, ms } = await timed(() => changing);
  await taken;
  return { answer, ms, next };
}

/** Runs `action` with a row of `table`, in its `moment`, failing as Postgres would with `code`. */
/* eslint-disable agentx/no-string-built-sql -- a test's own trigger, every part of it fixed in this file. */
async function withFailing<T>(table: string, moment: string, code: string, action: () => Promise<T>): Promise<T> {
  const owner = database.as('owner');
  await owner.query(
    `create function ${table}_forced() returns trigger language plpgsql as $$ begin raise exception 'forced' using errcode = '${code}'; end $$`,
  );
  await owner.query(
    `create trigger forced before ${moment} on ${table} for each row execute function ${table}_forced()`,
  );
  try {
    return await action();
  } finally {
    await owner.query(`drop trigger forced on ${table}`);
    await owner.query(`drop function ${table}_forced()`);
  }
}
/* eslint-enable agentx/no-string-built-sql */

const linesOf = (event: string) => capture.lines().filter((line) => line.event === event);

describe('no stop fails unseen', () => {
  it('a kill switch losing a deadlock raises the alarm, and is answered busy', async () => {
    const r = await ready();
    const post = await admin(r.w);

    const answer = await withFailing('agents.agents', 'update', '40P01', () =>
      post(`/v1/agents/${r.w.agent}/suspend`, 'suspend-1', { pendingRequests: 'pause' }),
    );

    expect(answer.statusCode).toBe(503);
    expect(answer.json()).toMatchObject({ error: { code: 'ORGANISATION_BUSY' } });
    expect(linesOf('brake.not_applied')).toHaveLength(1);
    expect((await post(`/v1/agents/${r.w.agent}/suspend`, 'suspend-1', { pendingRequests: 'pause' })).statusCode).toBe(
      200,
    );
  });

  it(
    'a stop whose read after its commit fails says so in its own line, and its key then answers what it did',
    async () => {
      const r = await ready();
      const post = await admin(r.w);
      const suspend = () => post(`/v1/agents/${r.w.agent}/suspend`, 'suspend-1', { pendingRequests: 'pause' });

      const { answer, next } = await withTheRowTakenAtCommit(r.w, suspend);

      expect(answer.statusCode).toBe(503);
      expect(answer.headers['retry-after']).toBe('5');
      expect(linesOf('api.stop_in_trouble')).toMatchObject([{ level: 'error' }]);
      // It committed: this isn't the line that says nothing was stopped.
      expect(linesOf('brake.not_applied')).toEqual([]);
      await letGo(next);
      const replayed = await suspend();
      expect(replayed.statusCode).toBe(200);
      expect(replayed.json()).toMatchObject({ agent: { status: 'SUSPENDED' } });
    },
    LONG,
  );

  it(
    'a supplier’s reactivation behind its row held says so, and is answered busy',
    async () => {
      const r = await ready();
      const post = await admin(r.w);
      const supplier = r.w.suppliers[0] ?? '';
      expect(
        (await post(`/v1/suppliers/${supplier}/suspend`, 'suspend-1', { pendingRequests: 'pause' })).statusCode,
      ).toBe(200);
      const stuck = await database.connect('admin');
      await stuck.query('begin');
      await stuck.query('select 1 from suppliers.suppliers where id = $1 for update', [supplier]);

      const answer = await post(`/v1/suppliers/${supplier}/reactivate`, 'reactivate-1', { pendingRequests: 'pause' });
      await letGo(stuck);

      expect(answer.statusCode).toBe(503);
      expect(linesOf('api.stop_in_trouble')).toHaveLength(1);
    },
    LONG,
  );
});

describe('a new key is never lost behind a busy answer', () => {
  it(
    'a rotation gives its key, its agent’s row taken the moment it commits',
    async () => {
      const { w, acting } = await ready();
      const named = { agentId: w.agent, keyId: acting.keyId };
      const challengeId = await steppedUp(w, () =>
        keyChanges().rotate(w.admin, keyed(w.admin, ROTATE_OPERATION), named, 'end_now', CORRELATION),
      );

      const { answer, ms, next } = await withTheRowTakenAtCommit(w, () =>
        keyChanges().rotateConfirm(
          w.admin,
          keyed(w.admin, ROTATE_CONFIRM_OPERATION),
          named,
          'end_now',
          challengeId,
          CORRELATION,
        ),
      );
      await letGo(next);

      expect(answer).toMatchObject({ outcome: 'rotated', key: expect.stringMatching(/^axk_/u) as string });
      expect(ms).toBeLessThan(3_000);
    },
    LONG,
  );

  it(
    'a handover gives its key the same way',
    async () => {
      const { w } = await ready();
      const owner = await shared.member(w.org, 'admin');
      const challengeId = await steppedUp(w, () =>
        agentChanges().handOver(w.admin, keyed(w.admin, HAND_OVER_OPERATION), w.agent, owner.membershipId, CORRELATION),
      );

      const { answer, ms, next } = await withTheRowTakenAtCommit(w, () =>
        agentChanges().handOverConfirm(
          w.admin,
          keyed(w.admin, HAND_OVER_CONFIRM_OPERATION),
          w.agent,
          owner.membershipId,
          challengeId,
          CORRELATION,
        ),
      );
      await letGo(next);

      expect(answer).toMatchObject({ outcome: 'handedOver', key: expect.stringMatching(/^axk_/u) as string });
      expect(ms).toBeLessThan(3_000);
    },
    LONG,
  );
});

describe('a routine change holds no traffic up for long', () => {
  it(
    'a policy confirm behind a stuck supplier gives up in 3 s, and decisions queued behind it then go on',
    async () => {
      const r = await ready();
      const { w } = r;
      const target = { scope: 'organization' as const };
      const sent = { rules: POLICY_RULES, capChoice: 'amount' as const, approvalWait: 72 as const };
      const challengeId = await steppedUp(w, () =>
        policies().ask(
          w.admin,
          keyed(w.admin, POLICY_OPERATIONS.organization.ask),
          target,
          sent,
          undefined,
          CORRELATION,
        ),
      );
      const stuck = await database.connect('admin');
      await stuck.query('begin');
      await stuck.query('select 1 from suppliers.suppliers where id = $1 for update', [w.suppliers[0]]);
      const inside = settled(decision(r));
      await waitUntilQueued(database.as('admin'), 1);

      const confirming = timed(() =>
        policies().confirm(
          w.admin,
          keyed(w.admin, POLICY_OPERATIONS.organization.confirm),
          target,
          sent,
          undefined,
          challengeId,
          CORRELATION,
        ),
      );
      await waitUntilQueued(database.as('admin'), 2);
      // A decision to a calm supplier, behind the waiting change.
      const calm = settled(decision(r, w.suppliers[1]));
      await waitUntilQueued(database.as('admin'), 3);

      const { answer, ms } = await confirming;
      expect(answer).toEqual(refused(503, 'ORGANISATION_BUSY'));
      expect(ms).toBeGreaterThan(2_500);
      expect(ms).toBeLessThan(4_500);
      expect(await calm).toMatchObject({ outcome: 'decided', request: { decision: 'ALLOW' } });
      expect(await decision(r, w.suppliers[1])).toMatchObject({ outcome: 'decided' });

      await letGo(stuck);
      await inside;
    },
    LONG,
  );
});

describe('every routine change gives up on its brake in 3 s', () => {
  const ROUTINE: readonly (readonly [string, (r: Ready) => string])[] = [
    ['the organisation’s policy changed', ({ w }) => lockName(ORGANISATION_BRAKE, w.org)],
    ['a mandate’s over-limit choice', ({ w }) => lockName(AGENT_BRAKE, w.org, w.agent)],
    ['a mandate redrafted', ({ w }) => lockName(AGENT_BRAKE, w.org, w.agent)],
    ['a mandate’s draft accepted', ({ w }) => lockName(AGENT_BRAKE, w.org, w.agent)],
    ['its source’s consent-expiry choice', ({ w }) => lockName(SOURCE_BRAKE, w.org, w.source)],
  ];

  it.each(ROUTINE)(
    '%s',
    async (name, brake) => {
      const r = await ready();
      const prepared = CHANGES.find(([change]) => change === name)?.[1];
      if (prepared === undefined) throw new Error(`no such change: ${name}`);
      const change = await prepared(r);
      const holder = await database.connect('admin');
      await holder.query('begin');
      await holder.query(BRAKE_SHARED, [brake(r)]);

      const { answer, ms } = await timed(change);
      await letGo(holder);

      expect(answer).toEqual(refused(503, 'ORGANISATION_BUSY'));
      expect(ms).toBeLessThan(4_500);
      expect(ms).toBeGreaterThan(2_500);
    },
    LONG,
  );
});

describe('a decision under trouble, through its route', () => {
  async function agentApi({ acting, w }: Ready) {
    const check = createAgentKeyCheck({ database: app, keys, ids, clock, logger: testLogger() });
    const api = await routeServer({
      logger: testLogger(capture),
      checkAgentKey: check.check.bind(check),
      spendRequestDecisions: createSpendRequestDecisions({ ...services(), entry: UNQUEUED }),
    });
    return (orderReference: string, key: string) =>
      api.inject({
        method: 'POST',
        url: '/v1/spend-requests',
        headers: { authorization: `Bearer ${acting.text}`, 'idempotency-key': key },
        payload: {
          amountMinor: 100_000,
          currency: 'AED',
          supplierId: w.suppliers[0],
          fundingSourceId: w.source,
          orderReference,
          purpose: 'Printer paper',
        },
      });
  }

  it.each([
    ['a statement past its limit', '57014'],
    ['a deadlock its retries lost', '40P01'],
  ])(
    'answers %s busy with Retry-After, seen at warn level, and its key sends it again',
    async (_, code) => {
      const r = await ready();
      const post = await agentApi(r);

      const answer = await withFailing('spend_requests.requests', 'insert', code, () => post('INV_T', 'trouble-1'));

      expect(answer.statusCode).toBe(503);
      expect(answer.headers['retry-after']).toBe('5');
      expect(answer.json()).toMatchObject({ error: { code: 'ORGANISATION_BUSY' } });
      expect(linesOf('api.decision_in_trouble')).toMatchObject([{ level: 'warn' }]);
      expect(linesOf('http.request_failed')).toEqual([]);
      expect((await post('INV_T', 'trouble-1')).statusCode).toBe(201);
    },
    LONG,
  );

  it(
    'its read after commit answered busy: the same key replays the same answer',
    async () => {
      const r = await ready();
      const post = await agentApi(r);
      const first = await post('INV_R', 'replayed-1');
      expect(first.statusCode).toBe(201);
      const holder = await database.connect('admin');
      await holder.query('begin');
      await holder.query('select 1 from spend_requests.requests where id = $1 for update', [
        first.json<{ id: string }>().id,
      ]);

      const busy = await post('INV_R', 'replayed-1');
      await letGo(holder);

      expect(busy.statusCode).toBe(503);
      expect(linesOf('api.decision_in_trouble')).toHaveLength(1);
      const again = await post('INV_R', 'replayed-1');
      expect(again.statusCode).toBe(201);
      expect(again.json()).toEqual(first.json());
    },
    LONG,
  );
});

/** Each agent read that takes a source's or a supplier's row FOR SHARE, and no brake. */
const agentReads = ({ w, acting }: Pick<Ready, 'w' | 'acting'>, requestId: string) => {
  const mandates = createAgentMandates({ database: app, keys, ids, clock, logger: testLogger() });
  const registry_ = createSupplierRegistry(services());
  const reads = createSpendRequestReads({ database: app, keys, ids, logger: testLogger() });
  return [
    () => mandates.sources(w.org, acting.agentId, null, CORRELATION),
    () => registry_.usableByAgent(w.org, { after: null, limit: 50 }, CORRELATION),
    () => reads.ofAgent(w.org, acting.agentId, requestId, CORRELATION),
  ];
};

/** The default limit on an organisation: 300 requests a minute, one every 200 ms. */
const ORGANISATION_REAL_RATE_MS = 200;

describe('agent reads, which take no brake, against the stops they could hold up', () => {
  const STOPS: readonly (readonly [string, (r: Ready) => Promise<unknown>])[] = [
    [
      'a source',
      ({ w }: Ready) =>
        sourceChanges().suspend(w.admin, keyed(w.admin, SOURCE_SUSPEND), w.source, 'pause', CORRELATION),
    ],
    [
      'a supplier',
      ({ w }: Ready) =>
        createSupplierChanges(services()).suspend(
          w.admin,
          keyed(w.admin, SUPPLIER_SUSPEND),
          w.suppliers[0] ?? '',
          'pause',
          CORRELATION,
        ),
    ],
  ];

  const preparedReads = async () => {
    const r = await ready();
    const made = await decision(r);
    if (made.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(made)}`);
    return { r, reads: agentReads(r, made.request.id) };
  };

  it.each(STOPS)(
    '%s stops at once behind them at the rate its organisation can reach',
    async (_, stop) => {
      const { r, reads } = await preparedReads();
      let turn = 0;
      const stopReads = stream(() => {
        turn += 1;
        return reads[turn % reads.length]?.() ?? Promise.resolve();
      }, ORGANISATION_REAL_RATE_MS);
      await sleep(600);

      const { answer, ms } = await timed(() => stop(r));
      await stopReads();

      expect(answer).toMatchObject({ outcome: 'changed' });
      expect(ms).toBeLessThan(2_000);
    },
    LONG,
  );

  it.each(STOPS)(
    '%s still stops behind them flat out, one at a time on twelve connections',
    async (name, stop) => {
      const { r, reads } = await preparedReads();
      const flat = { on: true };
      // Each loop one read at a time, leaving the pool room for the stop: flat out on the rows, not on the pool.
      const loops = Array.from({ length: 12 }, async (_, n) => {
        while (flat.on) {
          await settled(reads[name === 'a source' ? 0 : 1 + (n % 2)]?.() ?? Promise.resolve());
        }
      });
      await sleep(600);

      const answer = await stop(r);
      flat.on = false;
      await Promise.all(loops);

      // Not a time: on a laptop these overlap too little to be sure of one. See the rate above for what is promised.
      expect(answer).toMatchObject({ outcome: 'changed' });
    },
    LONG,
  );
});

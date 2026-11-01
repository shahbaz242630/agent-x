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
  type World,
} from './mandate-world.helper.test.ts';
import { createPolicyChanges, POLICY_OPERATIONS } from './policy-changes.ts';
import { closeServers, COOKIE, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { createSpendRequestDecisions, DECIDE_OPERATION } from './spend-request-decisions.ts';
import { createSupplierChanges } from './supplier-changes.ts';

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
const decision = ({ w, acting }: Pick<Ready, 'w' | 'acting'>) => {
  asked += 1;
  const request = {
    amount: AED(100_000n),
    supplierId: w.suppliers[0] ?? '',
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

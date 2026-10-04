// C1-3 (BR-03, ADR-012 §5, SEC-AG-01's suspended key's precondition):
// suspending an agent (the kill switch) and reactivating it with an admin's
// step-up, and handing it to another owner (the S68 audit's question A),
// through the use case the routes call, on the real migrated schema,
// as the app role. The routes' answers are agents.test.ts.
import { createHash } from 'node:crypto';

import { addAgent, type AgentsTables } from '@agentx/core/modules/agents';
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  addMembership,
  createSessions,
  createStepUpChallenges,
  type IdentityTables,
  memberOf,
  MEMBERSHIPS,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  createDatabase,
  type Database,
  IdempotencyFailed,
  type IdempotentRequest,
  withTenant,
} from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  confirmedWhileDemoted,
  createTestDatabase,
  FixedClock,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  type AgentChanges,
  type AgentChangeWrite,
  createAgentChanges,
  HAND_OVER_CONFIRM_OPERATION,
  HAND_OVER_OPERATION,
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  SUSPEND_OPERATION,
} from './agent-changes.ts';
import type { AgentMember } from './agent-writes.ts';

type Tables = IdentityTables & AgentsTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xa6c0_0000_0000);
const START = new Date('2026-09-28T09:00:00Z');
let clock: FixedClock;
let changes: AgentChanges;
const challenges = () => createStepUpChallenges({ ids, clock });

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

const quiet = () => ({ keys, ids, logger: testLogger() });

type Member = AgentMember & { readonly membershipId: string };

let people = 0;

/** A person with a session and a membership in the organisation. */
async function member(org: string, role: Role): Promise<Member> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `agent-changes-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
}

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

/** An agent of the organisation, owned by `owner`. */
async function agentOf(org: string, owner: Member): Promise<string> {
  const id = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addAgent(tx, states, {
      orgId: org,
      id,
      name: 'Purchasing bot',
      owner: owner.membershipId,
      scopes: ['requests:read'],
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  return id;
}

let keysUsed = 0;
const keyed = (who: AgentMember, operation: string, payload: string): IdempotentRequest => {
  keysUsed += 1;
  return {
    orgId: who.orgId,
    client: { kind: 'user', id: who.userId },
    operation,
    key: `k-${String(keysUsed)}`,
    payload,
  };
};

const suspend = (who: AgentMember, agentId: string, key?: IdempotentRequest) =>
  changes.suspend(who, key ?? keyed(who, SUSPEND_OPERATION, agentId), agentId, CORRELATION);

const reactivate = (who: AgentMember, agentId: string) =>
  changes.reactivate(who, keyed(who, REACTIVATE_OPERATION, agentId), agentId, CORRELATION);

const confirm = (who: AgentMember, agentId: string, challengeId: string) =>
  changes.reactivateConfirm(
    who,
    keyed(who, REACTIVATE_CONFIRM_OPERATION, `${agentId} ${challengeId}`),
    agentId,
    challengeId,
    CORRELATION,
  );

const handOver = (who: AgentMember, agentId: string, owner: string, key?: IdempotentRequest) =>
  changes.handOver(who, key ?? keyed(who, HAND_OVER_OPERATION, `${agentId} ${owner}`), agentId, owner, CORRELATION);

const handOverConfirm = (
  who: AgentMember,
  agentId: string,
  owner: string,
  challengeId: string,
  key?: IdempotentRequest,
) =>
  changes.handOverConfirm(
    who,
    key ?? keyed(who, HAND_OVER_CONFIRM_OPERATION, `${agentId} ${owner} ${challengeId}`),
    agentId,
    owner,
    challengeId,
    CORRELATION,
  );

/** The member signs in again for the challenge: its evidence recorded, as the step-up's return does. */
const stepUp = (who: AgentMember, challengeId: string, amr: readonly string[] = PASSKEY) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

const changedOf = (write: AgentChangeWrite) => {
  if (write.outcome !== 'changed') throw new Error(`not changed: ${JSON.stringify(write)}`);
  return write.agent;
};

const handedOf = (write: AgentChangeWrite) => {
  if (write.outcome !== 'handedOver') throw new Error(`not handed over: ${JSON.stringify(write)}`);
  return write.agent;
};

const askedFor = (write: AgentChangeWrite): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

/** The organisation's events about the agent, oldest first. */
const eventsAbout = (org: string, agentId: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['actor_id', 'action', 'details'])
      .where('subject_type', '=', 'agent')
      .where('subject_id', '=', agentId)
      .orderBy('seq')
      .execute(),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(START);
  changes = createAgentChanges({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    logger: testLogger(),
  });
});

describe(`suspending an agent: the kill switch (C1-3, Postgres ${server.version})`, () => {
  it.each<Role>(['developer', 'admin'])(
    'a %s suspends it at once, with no step-up, recorded as theirs',
    async (role) => {
      const org = await organization();
      const them = await member(org, role);
      const agent = await agentOf(org, await member(org, 'developer'));

      const done = changedOf(await suspend(them, agent));

      expect(done.agent).toMatchObject({ id: agent, status: 'SUSPENDED' });
      expect((await eventsAbout(org, agent)).map((event) => [event.action, event.actor_id])).toEqual([
        ['agent.created', 'test-operator'],
        ['agent.suspended', them.userId],
      ]);
    },
  );

  it('answers an agent suspended already as it is, recording nothing more: a brake pressed twice', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const agent = await agentOf(org, developer);
    changedOf(await suspend(developer, agent));

    const again = changedOf(await suspend(developer, agent));

    expect(again.agent.status).toBe('SUSPENDED');
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created', 'agent.suspended']);
  });

  it('answers a retry of the same request as the first, suspending once', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const agent = await agentOf(org, developer);
    const key = keyed(developer, SUSPEND_OPERATION, agent);

    const first = changedOf(await suspend(developer, agent, key));
    const retried = changedOf(await suspend(developer, agent, key));

    expect(retried).toEqual(first);
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created', 'agent.suspended']);
  });

  it.each<Role>(['approver', 'viewer'])('refuses a %s: FORBIDDEN, the agent left ACTIVE', async (role) => {
    const org = await organization();
    const agent = await agentOf(org, await member(org, 'developer'));

    expect(await suspend(await member(org, role), agent)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created']);
  });

  it('answers NOT_FOUND for an agent the organisation doesn’t have, another organisation’s among them', async () => {
    const org = await organization();
    const other = await organization();
    const theirs = await agentOf(other, await member(other, 'developer'));
    const developer = await member(org, 'developer');

    expect(await suspend(developer, theirs)).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    expect(await suspend(developer, ids.next())).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    expect((await eventsAbout(other, theirs)).map((event) => event.action)).toEqual(['agent.created']);
  });

  it('refuses an agent tampered with: INTEGRITY_FAILED, never a suspension over it', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const agent = await agentOf(org, developer);
    await withTenant(app, org, (tx) =>
      tx.updateTable('agents.agents').set({ scopes: 'requests:read requests:write' }).where('id', '=', agent).execute(),
    );

    expect(await suspend(developer, agent)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });
});

describe('failures that are not refusals (C1-3)', () => {
  it('passes a failure of the write on, never answering it as a refusal or a change', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const agent = await agentOf(org, developer);
    // A key the idempotency store refuses: a failure of the request's making, not a refusal of the change.
    const unusable = { ...keyed(developer, SUSPEND_OPERATION, agent), key: 'not a key' };

    await expect(suspend(developer, agent, unusable)).rejects.toBeInstanceOf(IdempotencyFailed);
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created']);
  });
});

describe('reactivating a suspended agent, with an admin’s step-up (C1-3)', () => {
  it('asks a step-up, then reactivates it once the admin signed in again with a passkey', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agent = await agentOf(org, admin);
    changedOf(await suspend(admin, agent));
    const challengeId = askedFor(await reactivate(admin, agent));
    await stepUp(admin, challengeId);

    const done = changedOf(await confirm(admin, agent, challengeId));

    expect(done.agent).toMatchObject({ id: agent, status: 'ACTIVE' });
    const events = await eventsAbout(org, agent);
    expect(events.map((event) => event.action)).toEqual(['agent.created', 'agent.suspended', 'agent.reactivated']);
    expect(JSON.parse(events[2]?.details ?? '{}')).toMatchObject({
      stepUpChallengeId: challengeId,
      methods: PASSKEY.join(' '),
    });
  });

  it('answers NOT_FOUND for another organisation’s agent, asking or confirming, leaving it SUSPENDED', async () => {
    const org = await organization();
    const other = await organization();
    const theirAdmin = await member(other, 'admin');
    const theirs = await agentOf(other, theirAdmin);
    changedOf(await suspend(theirAdmin, theirs));
    const admin = await member(org, 'admin');

    const missing = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
    expect(await reactivate(admin, theirs)).toEqual(missing);
    expect(await confirm(admin, theirs, ids.next())).toEqual(missing);
    expect((await eventsAbout(other, theirs)).at(-1)?.action).toBe('agent.suspended');
  });

  it('refuses a developer or anyone else not an admin: FORBIDDEN, asking or confirming', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const agent = await agentOf(org, developer);
    changedOf(await suspend(developer, agent));

    const refused = { outcome: 'refused', status: 403, code: 'FORBIDDEN' };
    expect(await reactivate(developer, agent)).toEqual(refused);
    expect(await confirm(developer, agent, ids.next())).toEqual(refused);
  });

  it('refuses an agent that isn’t suspended: AGENT_NOT_SUSPENDED, asking or confirming', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agent = await agentOf(org, admin);

    const refused = { outcome: 'refused', status: 409, code: 'AGENT_NOT_SUSPENDED' };
    expect(await reactivate(admin, agent)).toEqual(refused);
    expect(await confirm(admin, agent, ids.next())).toEqual(refused);
  });

  it('refuses an admin who signed in again without a passkey: STEP_UP_FAILED, the agent left SUSPENDED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agent = await agentOf(org, admin);
    changedOf(await suspend(admin, agent));
    const challengeId = askedFor(await reactivate(admin, agent));
    await stepUp(admin, challengeId, APP_CODE);

    expect(await confirm(admin, agent, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created', 'agent.suspended']);
  });

  it('refuses a step-up asked for another agent, or before the admin signed in again: STEP_UP_FAILED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agent = await agentOf(org, admin);
    const other = await agentOf(org, admin);
    changedOf(await suspend(admin, agent));
    changedOf(await suspend(admin, other));
    const forOther = askedFor(await reactivate(admin, other));
    await stepUp(admin, forOther);
    const notYet = askedFor(await reactivate(admin, agent));

    expect(await confirm(admin, agent, forOther)).toMatchObject({ code: 'STEP_UP_FAILED' });
    expect(await confirm(admin, agent, notYet)).toMatchObject({ code: 'STEP_UP_FAILED' });
  });

  it('refuses a step-up asked for an earlier suspension: it reactivates exactly the one it was asked for', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agent = await agentOf(org, admin);
    changedOf(await suspend(admin, agent));
    const earlier = askedFor(await reactivate(admin, agent));
    await stepUp(admin, earlier);
    // Reactivated through another step-up, then suspended again: a new suspension.
    const between = askedFor(await reactivate(admin, agent));
    await stepUp(admin, between);
    changedOf(await confirm(admin, agent, between));
    changedOf(await suspend(admin, agent));

    expect(await confirm(admin, agent, earlier)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect((await eventsAbout(org, agent)).at(-1)?.action).toBe('agent.suspended');
  });
});

describe('handing an agent to another owner, with an admin’s step-up (the S68 audit’s question A)', () => {
  /** Asks, signs in again with `amr`, and confirms: the confirm's answer. */
  const handedOver = async (admin: Member, agentId: string, owner: string, amr: readonly string[] = PASSKEY) => {
    const challengeId = askedFor(await handOver(admin, agentId, owner));
    await stepUp(admin, challengeId, amr);
    return handOverConfirm(admin, agentId, owner, challengeId);
  };

  const deactivate = (org: string, who: Member) =>
    withSignedStates(app, org, quiet(), (tx, states) =>
      states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: who.membershipId }, 'deactivate', {
        actor: OPERATOR,
        action: 'membership.deactivated',
        details: {},
      }),
    );

  /** The member's role changed to `role`, as an admin's role change records it. */
  const demote = (org: string, who: Member, role: Role) =>
    withSignedStates(app, org, quiet(), async (tx, states) => {
      const read = await memberOf(tx, states, { orgId: org, id: who.membershipId }, 'change');
      if (read.outcome !== 'found') throw new Error('the membership was not found');
      await states.record(
        tx,
        MEMBERSHIPS,
        { orgId: org, id: who.membershipId },
        read.state,
        { role },
        {
          actor: OPERATOR,
          action: 'membership.role_changed',
          details: {},
        },
      );
    });

  it.each<Role>(['developer', 'admin'])(
    'hands it to a %s once the admin signed in again with a passkey: the owner alone changes, recorded with both',
    async (role) => {
      const org = await organization();
      const admin = await member(org, 'admin');
      const leaving = await member(org, 'developer');
      const next = await member(org, role);
      const agent = await agentOf(org, leaving);
      const challengeId = askedFor(await handOver(admin, agent, next.membershipId.toUpperCase()));
      await stepUp(admin, challengeId);

      const done = handedOf(await handOverConfirm(admin, agent, next.membershipId, challengeId));

      expect(done.agent).toMatchObject({
        id: agent,
        owner: next.membershipId,
        status: 'ACTIVE',
        scopes: ['requests:read'],
      });
      const events = await eventsAbout(org, agent);
      expect(events.map((event) => [event.action, event.actor_id])).toEqual([
        ['agent.created', 'test-operator'],
        ['agent.owner_changed', admin.userId],
      ]);
      expect(JSON.parse(events[1]?.details ?? '{}')).toMatchObject({
        ownerFrom: leaving.membershipId,
        ownerTo: next.membershipId,
        stepUpChallengeId: challengeId,
        methods: PASSKEY.join(' '),
      });
    },
  );

  it('hands over a suspended agent, which stays suspended: a removed member’s agent stopped first', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const leaving = await member(org, 'developer');
    const agent = await agentOf(org, leaving);
    changedOf(await suspend(admin, agent));
    await deactivate(org, leaving);

    const done = handedOf(await handedOver(admin, agent, admin.membershipId));

    expect(done.agent).toMatchObject({ owner: admin.membershipId, status: 'SUSPENDED' });
  });

  it('answers a retry of the same confirm as the first, handing over once', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agent = await agentOf(org, admin);
    const challengeId = askedFor(await handOver(admin, agent, next.membershipId));
    await stepUp(admin, challengeId);
    const key = keyed(admin, HAND_OVER_CONFIRM_OPERATION, `${agent} ${next.membershipId} ${challengeId}`);

    const first = await handOverConfirm(admin, agent, next.membershipId, challengeId, key);
    const retried = await handOverConfirm(admin, agent, next.membershipId, challengeId, key);

    expect(first).toMatchObject({ outcome: 'handedOver', key: expect.stringMatching(/^axk_/) as unknown });
    expect(retried).toEqual({ ...first, key: null });
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual([
      'agent.created',
      'agent.owner_changed',
    ]);
  });

  it.each<Role>(['developer', 'approver', 'viewer'])('refuses a %s: FORBIDDEN, asking or confirming', async (role) => {
    const org = await organization();
    const them = await member(org, role);
    const next = await member(org, 'developer');
    const agent = await agentOf(org, them);

    const refused = { outcome: 'refused', status: 403, code: 'FORBIDDEN' };
    expect(await handOver(them, agent, next.membershipId)).toEqual(refused);
    expect(await handOverConfirm(them, agent, next.membershipId, ids.next())).toEqual(refused);
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created']);
  });

  it.each<[string, (org: string, who: Member) => Promise<unknown>]>([
    ['removed', (org, who) => deactivate(org, who)],
    ['made a developer', (org, who) => demote(org, who, 'developer')],
  ])('refuses the ask of an admin %s: FORBIDDEN, with no step-up opened', async (_, change) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agent = await agentOf(org, admin);
    await change(org, admin);

    expect(await handOver(admin, agent, next.membershipId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  it('refuses a caller who is no admin before the new owner’s membership is verified: FORBIDDEN, never its 503', async () => {
    const org = await organization();
    // The new owner's ID comes first, so a read in order of ID alone would reach it before the caller's.
    const next = await member(org, 'viewer');
    const caller = await member(org, 'admin');
    const agent = await agentOf(org, caller);
    await demote(org, caller, 'developer');
    await withTenant(app, org, (tx) =>
      tx.updateTable('identity.memberships').set({ role: 'developer' }).where('id', '=', next.membershipId).execute(),
    );

    expect(await handOver(caller, agent, next.membershipId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  it('refuses a step-up opened in another admin’s session: STEP_UP_FAILED, the owner kept', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const other = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agent = await agentOf(org, admin);
    const theirs = askedFor(await handOver(other, agent, next.membershipId));
    await stepUp(other, theirs);

    expect(await handOverConfirm(admin, agent, next.membershipId, theirs)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created']);
  });

  it('refuses an admin removed since: FORBIDDEN', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agent = await agentOf(org, admin);
    const challengeId = askedFor(await handOver(admin, agent, next.membershipId));
    await stepUp(admin, challengeId);
    await deactivate(org, admin);

    expect(await handOverConfirm(admin, agent, next.membershipId, challengeId)).toMatchObject({
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  it('refuses a new owner who may not own an agent: AGENT_OWNER_NOT_ELIGIBLE, one answer for each', async () => {
    const org = await organization();
    const other = await organization();
    const admin = await member(org, 'admin');
    const agent = await agentOf(org, admin);
    const approver = await member(org, 'approver');
    const viewer = await member(org, 'viewer');
    const removed = await member(org, 'developer');
    await deactivate(org, removed);
    const elsewhere = await member(other, 'developer');

    const refused = { outcome: 'refused', status: 409, code: 'AGENT_OWNER_NOT_ELIGIBLE' };
    const owners = [approver, viewer, removed, elsewhere].map((who) => who.membershipId).concat(ids.next());
    for (const owner of owners) {
      expect(await handOver(admin, agent, owner)).toEqual(refused);
      expect(await handOverConfirm(admin, agent, owner, ids.next())).toEqual(refused);
    }
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created']);
  });

  it('refuses the owner it has already: AGENT_OWNER_UNCHANGED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agent = await agentOf(org, admin);

    const refused = { outcome: 'refused', status: 409, code: 'AGENT_OWNER_UNCHANGED' };
    expect(await handOver(admin, agent, admin.membershipId)).toEqual(refused);
    expect(await handOverConfirm(admin, agent, admin.membershipId, ids.next())).toEqual(refused);
  });

  it('answers NOT_FOUND for another organisation’s agent, leaving its owner', async () => {
    const org = await organization();
    const other = await organization();
    const theirs = await agentOf(other, await member(other, 'developer'));
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');

    const missing = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
    expect(await handOver(admin, theirs, next.membershipId)).toEqual(missing);
    expect(await handOverConfirm(admin, theirs, next.membershipId, ids.next())).toEqual(missing);
    expect((await eventsAbout(other, theirs)).map((event) => event.action)).toEqual(['agent.created']);
  });

  it('refuses an admin who signed in again without a passkey: STEP_UP_FAILED, the owner kept', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agent = await agentOf(org, admin);

    expect(await handedOver(admin, agent, next.membershipId, APP_CODE)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created']);
  });

  it('refuses a step-up asked for another new owner, another agent, or a reactivation: STEP_UP_FAILED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const someoneElse = await member(org, 'developer');
    const agent = await agentOf(org, admin);
    const another = await agentOf(org, admin);
    const forSomeoneElse = askedFor(await handOver(admin, agent, someoneElse.membershipId));
    const forAnother = askedFor(await handOver(admin, another, next.membershipId));
    changedOf(await suspend(admin, another));
    const forReactivating = askedFor(await reactivate(admin, another));
    const asked = [forSomeoneElse, forAnother, forReactivating];
    for (const challengeId of asked) await stepUp(admin, challengeId);

    for (const challengeId of asked) {
      expect(await handOverConfirm(admin, agent, next.membershipId, challengeId)).toMatchObject({
        code: 'STEP_UP_FAILED',
      });
    }
    expect((await eventsAbout(org, agent)).map((event) => event.action)).toEqual(['agent.created']);
  });

  it('refuses a step-up asked before the agent changed: it hands over the agent exactly as it stood', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agent = await agentOf(org, admin);
    const challengeId = askedFor(await handOver(admin, agent, next.membershipId));
    await stepUp(admin, challengeId);
    changedOf(await suspend(admin, agent));

    expect(await handOverConfirm(admin, agent, next.membershipId, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect((await eventsAbout(org, agent)).at(-1)?.action).toBe('agent.suspended');
  });

  it('refuses a new owner’s membership tampered with: INTEGRITY_FAILED, never a handover over it', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const viewer = await member(org, 'viewer');
    const agent = await agentOf(org, admin);
    await withTenant(app, org, (tx) =>
      tx.updateTable('identity.memberships').set({ role: 'developer' }).where('id', '=', viewer.membershipId).execute(),
    );

    expect(await handOver(admin, agent, viewer.membershipId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });

  /**
   * Holds the lower of the two memberships' IDs for change, as a role change
   * of it would; starts the handover; waits until it waits on that lock; then
   * takes the higher one at once (NOWAIT). Read in order of ID (ADR-006 §6
   * level 2a), the handover waited before touching the higher one, so it is
   * free; read the other way, it already holds it and the NOWAIT fails.
   */
  it.each<[string, boolean]>([
    ['the admin’s membership first when its ID comes first', true],
    ['the new owner’s membership first when its ID comes first', false],
  ])('reads %s, before the other (a forced lock order)', async (_, adminFirst) => {
    const org = await organization();
    const [lower, higher] = [
      await member(org, adminFirst ? 'admin' : 'developer'),
      await member(org, adminFirst ? 'developer' : 'admin'),
    ];
    const [admin, next] = adminFirst ? [lower, higher] : [higher, lower];
    const agent = await agentOf(org, admin);
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select id from identity.memberships where org_id = $1 and id = $2 for no key update', [
        org,
        lower.membershipId,
      ]);
      const asking = within(20_000, handOver(admin, agent, next.membershipId), 'the handover');
      await waitUntilQueued(database.as('admin'), 1);

      const taken = await holder.query(
        'select id from identity.memberships where org_id = $1 and id = $2 for no key update nowait',
        [org, higher.membershipId],
      );
      await holder.query('rollback');

      expect(taken).toHaveLength(1);
      expect((await asking).outcome).toBe('asked');
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('refuses an agent tampered with: INTEGRITY_FAILED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agent = await agentOf(org, admin);
    await withTenant(app, org, (tx) =>
      tx.updateTable('agents.agents').set({ owner: next.membershipId }).where('id', '=', agent).execute(),
    );

    expect(await handOver(admin, agent, next.membershipId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });
});

describe(`the confirmation's lock order against the confirmer's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('a reactivation holds its step-up challenges before the admin’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agent = await agentOf(org, admin);
    changedOf(await suspend(admin, agent));
    const challengeId = askedFor(await reactivate(admin, agent));
    await stepUp(admin, challengeId);

    const confirmed = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: admin.membershipId },
      () => confirm(admin, agent, challengeId),
    );

    expect(changedOf(confirmed).agent).toMatchObject({ id: agent, status: 'ACTIVE' });
  });

  it('a handover holds its step-up challenges before the admin’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agent = await agentOf(org, admin);
    const challengeId = askedFor(await handOver(admin, agent, next.membershipId));
    await stepUp(admin, challengeId);

    const confirmed = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: admin.membershipId },
      () => handOverConfirm(admin, agent, next.membershipId, challengeId),
    );

    expect(handedOf(confirmed).agent).toMatchObject({ id: agent, owner: next.membershipId });
  });
});

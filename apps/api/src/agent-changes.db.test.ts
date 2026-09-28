// C1-3 (BR-03, ADR-012 §5, SEC-AG-01's suspended key's precondition):
// suspending an agent (the kill switch) and reactivating it with an admin's
// step-up, through the use case the routes call, on the real migrated schema,
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
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  type AgentChanges,
  type AgentChangeWrite,
  createAgentChanges,
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

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

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
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, loggerFor(new LogCapture()));
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
    challenges: challenges(),
    logger: loggerFor(new LogCapture()),
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

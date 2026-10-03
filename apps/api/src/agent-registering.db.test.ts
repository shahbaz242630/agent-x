// C1-2 (BR-03, SEC-AG-01's issue side): registering an agent with its first
// key through the use case the routes call, on the real migrated schema, as
// the app role: the idempotency store, the step-up challenge, the agent and its
// key in one transaction. The routes' answers are agents.test.ts; the tables
// themselves are the agents module's agents.db.test.ts.
import { createHash } from 'node:crypto';

import { type AgentsTables, MOST_AGENTS_ADDED_A_DAY, type Scope } from '@agentx/core/modules/agents';
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  addMembership,
  createSessions,
  createStepUpChallenges,
  type IdentityTables,
  MEMBERSHIPS,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createDatabase, type Database, type IdempotentRequest, lockName, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  confirmedWhileDemoted,
  createTestDatabase,
  FixedClock,
  holdNamedLock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  type AgentAsked,
  type AgentRegistrations,
  createAgentRegistrations,
  REGISTER_CONFIRM_OPERATION,
  REGISTER_OPERATION,
  type RegisteringMember,
  type RegistrationWrite,
} from './agent-registering.ts';

type Tables = IdentityTables & AgentsTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xa6e0_0000_0000);
const START = new Date('2026-09-28T09:00:00Z');
const DAY_MS = 86_400_000;
let clock: FixedClock;
let registrations: AgentRegistrations;
let capture: LogCapture;
const challenges = () => createStepUpChallenges({ ids, clock });

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';
/** A passkey's sign-in, and an app code's. */
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;
const ASKED: AgentAsked = { name: 'Purchasing bot', scopes: ['requests:write', 'requests:read'] };

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

type Member = RegisteringMember & { readonly membershipId: string };

let people = 0;

/** A person with a session and a membership in the organisation. */
async function member(org: string, role: Role): Promise<Member> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `agent-registering-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
}

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

const keyed = (who: RegisteringMember, operation: string, key: string, payload = '{}'): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload,
});

const ask = (who: RegisteringMember, asked: AgentAsked = ASKED, key = `ask-${encodeURIComponent(asked.name)}`) =>
  registrations.ask(who, keyed(who, REGISTER_OPERATION, key, JSON.stringify(asked)), asked, CORRELATION);

const confirm = (
  who: RegisteringMember,
  challengeId: string,
  asked: AgentAsked = ASKED,
  key = `confirm-${challengeId}`,
) =>
  registrations.confirm(
    who,
    keyed(who, REGISTER_CONFIRM_OPERATION, key, JSON.stringify({ ...asked, challengeId })),
    asked,
    challengeId,
    CORRELATION,
  );

/** The member signs in again for the challenge: its evidence recorded, as the step-up's return does. */
const stepUp = (who: RegisteringMember, challengeId: string, amr: readonly string[] = PASSKEY) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

const askedFor = (write: RegistrationWrite): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

const registeredOf = (write: RegistrationWrite) => {
  if (write.outcome !== 'registered') throw new Error(`not registered: ${JSON.stringify(write)}`);
  return write;
};

/** Asks, steps up and confirms: the registration. */
async function register(who: RegisteringMember, asked: AgentAsked = ASKED, amr: readonly string[] = PASSKEY) {
  const challengeId = askedFor(await ask(who, asked));
  await stepUp(who, challengeId, amr);
  return registeredOf(await confirm(who, challengeId, asked));
}

const agentsIn = async (org: string) =>
  (await withTenant(app, org, (tx) => tx.selectFrom('agents.agents').select('id').execute())).length;

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
  capture = new LogCapture();
  registrations = createAgentRegistrations({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    logger: loggerFor(capture),
  });
});

describe(`registering an agent (C1-2, Postgres ${server.version})`, () => {
  it('asks a step-up, then registers the agent owned by the member, with a first key shown once and kept as its MAC', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');

    const done = await register(developer, ASKED, APP_CODE);

    const { agent, keys: issued } = done.agent;
    expect(agent).toMatchObject({
      name: 'Purchasing bot',
      owner: developer.membershipId,
      status: 'ACTIVE',
      scopes: ['requests:read', 'requests:write'],
      createdAt: START,
    });
    expect(issued).toHaveLength(1);
    const [first] = issued;
    expect(first).toMatchObject({
      status: 'ACTIVE',
      scopes: ['requests:read', 'requests:write'],
      expiresAt: new Date(START.getTime() + 90 * DAY_MS),
      secretKeyVersion: 1,
    });
    // The key: its ID without dashes, then a 256-bit secret; the MAC kept is the pepper's over exactly it.
    const key = done.key ?? '';
    const match = /^axk_([0-9a-f]{32})_([A-Za-z0-9_-]{43})$/.exec(key);
    expect(match).not.toBeNull();
    expect(match?.[1]).toBe(first?.id.replaceAll('-', ''));
    const secret = Buffer.from(match?.[2] ?? '', 'base64url');
    expect(secret).toHaveLength(32);
    expect(
      keys.verifyMac(
        'agent-key-pepper',
        1,
        ['agent-key', first?.id ?? '', secret],
        first?.secretMac ?? Buffer.alloc(0),
      ),
    ).toBe(true);
    // Never in the log.
    expect(JSON.stringify(capture.lines())).not.toContain(match?.[2] ?? 'never');
  });

  it('records who registered it and the step-up on the agent’s event, never its name', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');

    const { agent } = await register(admin);

    const events = await withTenant(app, org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['actor_type', 'actor_id', 'action', 'subject_id', 'details'])
        .where('action', 'in', ['agent.created', 'agent_key.issued'])
        .orderBy('seq')
        .execute(),
    );
    expect(events.map((event) => event.action)).toEqual(['agent.created', 'agent_key.issued']);
    expect(events[0]).toMatchObject({ actor_type: 'user', actor_id: admin.userId, subject_id: agent.agent.id });
    expect(JSON.parse(events[0]?.details ?? '{}')).toMatchObject({
      owner: admin.membershipId,
      methods: PASSKEY.join(' '),
      stepUpChallengeId: expect.any(String) as unknown,
    });
    expect(events.map((event) => event.details).join()).not.toContain('Purchasing bot');
  });

  it('answers a retry of the same confirm with the agent and its key’s record, never the key again', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const challengeId = askedFor(await ask(developer));
    await stepUp(developer, challengeId, APP_CODE);
    const first = registeredOf(await confirm(developer, challengeId));

    const again = registeredOf(await confirm(developer, challengeId));

    expect(first.key).not.toBeNull();
    expect(again.key).toBeNull();
    expect(again.agent).toEqual(first.agent);
    expect(await agentsIn(org)).toBe(1);
  });

  it('answers a retry of the same ask with the same step-up', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');

    expect(askedFor(await ask(developer))).toBe(askedFor(await ask(developer)));
  });

  it('keeps the name as it is kept (composed), and binds the step-up to it however it was typed', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const decomposed = { name: 'Café bot', scopes: ['requests:read'] as Scope[] };
    const composed = { name: 'Café bot', scopes: ['requests:read'] as Scope[] };
    const challengeId = askedFor(await ask(developer, decomposed));
    await stepUp(developer, challengeId, APP_CODE);

    const done = registeredOf(await confirm(developer, challengeId, composed));

    expect(done.agent.agent.name).toBe('Café bot');
  });
});

describe('what registering refuses, writing nothing', () => {
  it.each<[string, AgentAsked]>([
    ['another name', { ...ASKED, name: 'Another bot' }],
    ['other scopes', { ...ASKED, scopes: ['requests:read'] }],
    ['wider scopes', { ...ASKED, scopes: ['requests:read', 'requests:write', 'suppliers:read'] }],
  ])('a confirm with %s than the step-up was asked for: STEP_UP_FAILED', async (_, other) => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const challengeId = askedFor(await ask(developer));
    await stepUp(developer, challengeId, APP_CODE);

    expect(await confirm(developer, challengeId, other)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await agentsIn(org)).toBe(0);
  });

  it('a confirm before the member signed in again, or from another session: STEP_UP_FAILED', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const other = await member(org, 'developer');
    const challengeId = askedFor(await ask(developer));

    expect(await confirm(developer, challengeId)).toMatchObject({ code: 'STEP_UP_FAILED' });
    await stepUp(developer, challengeId, APP_CODE);
    expect(await confirm({ ...other, sessionId: other.sessionId }, challengeId)).toMatchObject({
      code: 'STEP_UP_FAILED',
    });
    expect(await agentsIn(org)).toBe(0);
    // The challenge is still there for its own session.
    expect(registeredOf(await confirm(developer, challengeId, ASKED, 'confirm-later')).key).not.toBeNull();
  });

  it('an admin’s confirm without a passkey: STEP_UP_FAILED; a developer’s app code is enough', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const challengeId = askedFor(await ask(admin));
    await stepUp(admin, challengeId, APP_CODE);

    expect(await confirm(admin, challengeId)).toMatchObject({ code: 'STEP_UP_FAILED' });
    expect(await agentsIn(org)).toBe(0);
  });

  it.each<Role>(['approver', 'viewer'])('a %s asking or confirming: FORBIDDEN', async (role) => {
    const org = await organization();
    const them = await member(org, role);

    expect(await ask(them)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await confirm(them, ids.next())).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
  });

  it('a member deactivated between the ask and the confirm: FORBIDDEN', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const challengeId = askedFor(await ask(developer));
    await stepUp(developer, challengeId, APP_CODE);
    await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
      states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: developer.membershipId }, 'deactivate', {
        actor: OPERATOR,
        action: 'membership.deactivated',
        details: {},
      }),
    );

    expect(await confirm(developer, challengeId)).toMatchObject({ status: 403, code: 'FORBIDDEN' });
    expect(await agentsIn(org)).toBe(0);
  });

  it('a membership tampered with: INTEGRITY_FAILED', async () => {
    const org = await organization();
    const viewer = await member(org, 'viewer');
    // Raised to developer past the app: its seal no longer holds.
    await withTenant(app, org, (tx) =>
      tx.updateTable('identity.memberships').set({ role: 'developer' }).where('id', '=', viewer.membershipId).execute(),
    );

    expect(await ask(viewer)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it(`past ${String(MOST_AGENTS_ADDED_A_DAY)} agents in 24 hours: AGENT_ADDS_SPENT, until a day has passed`, async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    for (let count = 0; count < MOST_AGENTS_ADDED_A_DAY; count += 1) {
      await register(developer, { ...ASKED, name: `Bot ${String(count)}` }, APP_CODE);
    }
    const last = { ...ASKED, name: 'One too many' };
    const challengeId = askedFor(await ask(developer, last));
    await stepUp(developer, challengeId, APP_CODE);

    expect(await confirm(developer, challengeId, last)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'AGENT_ADDS_SPENT',
    });
    expect(await agentsIn(org)).toBe(MOST_AGENTS_ADDED_A_DAY);

    clock.advanceBy(DAY_MS);
    // A day on, the session has ended: the member signs in again.
    const { sessionId } = await createSessions({
      ids,
      clock,
      timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
    }).open(app, developer.userId, { idpSessionId: 'V1_3', authTime: clock.now(), amr: [...APP_CODE] });
    const again = { ...developer, sessionId };
    const later = askedFor(await ask(again, last, 'ask-later'));
    await stepUp(again, later, APP_CODE);
    expect(registeredOf(await confirm(again, later, last)).agent.agent.name).toBe('One too many');
  });

  it('confirms only once it holds the organisation’s lock for adding agents, so two can’t both take the day’s last', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const challengeId = askedFor(await ask(developer));
    await stepUp(developer, challengeId, APP_CODE);
    // Another registration of the organisation's, part-way: its lock taken, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName('agents', org));
      const confirming = within(20_000, confirm(developer, challengeId), 'the confirmation');
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');

      expect(registeredOf(await confirming).key).not.toBeNull();
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('a key used for another request: a conflict', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    await ask(developer, ASKED, 'the-key');

    expect(await ask(developer, { ...ASKED, name: 'Another bot' }, 'the-key')).toEqual({ outcome: 'conflict' });
  });
});

describe('reading agents', () => {
  it('passes a failure of the read on, never answering it as a refusal: an agent ID the database won’t take', async () => {
    const org = await organization();

    await expect(registrations.show(org, 'not-a-uuid', CORRELATION)).rejects.toThrow();
  });

  it('lists the organisation’s agents in pages, in order of ID, with the ID to ask the next page after', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const made: string[] = [];
    for (const name of ['One', 'Two', 'Three']) {
      made.push((await register(developer, { ...ASKED, name }, APP_CODE)).agent.agent.id);
    }

    const first = await registrations.list(org, { after: null, limit: 2 }, CORRELATION);
    if (first.outcome !== 'listed') throw new Error('not listed');
    expect(first.agents.map((agent) => agent.name)).toEqual(['One', 'Two']);
    expect(first.next).toBe(made[1]);
    const second = await registrations.list(org, { after: first.next, limit: 2 }, CORRELATION);
    expect(second).toMatchObject({ outcome: 'listed', agents: [{ id: made[2], name: 'Three' }], next: null });
  });

  it('lists none of another organisation’s agents', async () => {
    const org = await organization();
    const other = await organization();
    await register(await member(other, 'developer'), ASKED, APP_CODE);

    expect(await registrations.list(org, { after: null, limit: 50 }, CORRELATION)).toEqual({
      outcome: 'listed',
      agents: [],
      next: null,
    });
  });

  it('shows an agent with its keys; NOT_FOUND for one the organisation doesn’t have', async () => {
    const org = await organization();
    const other = await organization();
    const { agent } = await register(await member(org, 'developer'), ASKED, APP_CODE);

    expect(await registrations.show(org, agent.agent.id, CORRELATION)).toEqual({ outcome: 'found', ...agent });
    expect(await registrations.show(other, agent.agent.id, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 404,
      code: 'NOT_FOUND',
    });
  });

  it('refuses a list or an agent tampered with: INTEGRITY_FAILED, never a part of it', async () => {
    const org = await organization();
    const { agent } = await register(await member(org, 'developer'), ASKED, APP_CODE);
    await withTenant(app, org, (tx) =>
      tx.updateTable('agents.agents').set({ scopes: 'requests:read requests:write sources:read' }).execute(),
    );

    const refused = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    expect(await registrations.list(org, { after: null, limit: 50 }, CORRELATION)).toEqual(refused);
    expect(await registrations.show(org, agent.agent.id, CORRELATION)).toEqual(refused);
  });

  it('refuses an agent whose key was tampered with: INTEGRITY_FAILED', async () => {
    const org = await organization();
    const { agent } = await register(await member(org, 'developer'), ASKED, APP_CODE);
    await withTenant(app, org, (tx) =>
      tx
        .updateTable('agents.agent_keys')
        .set({ expires_at: new Date('2099-01-01T00:00:00Z') })
        .execute(),
    );

    expect(await registrations.show(org, agent.agent.id, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });
});

describe(`the confirmation's lock order against the confirmer's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('a registration holds its step-up challenges before the member’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const challengeId = askedFor(await ask(developer));
    await stepUp(developer, challengeId);

    const confirmed = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: developer.membershipId },
      () => confirm(developer, challengeId),
    );

    expect(registeredOf(confirmed).agent.agent).toMatchObject({ owner: developer.membershipId, status: 'ACTIVE' });
  });
});

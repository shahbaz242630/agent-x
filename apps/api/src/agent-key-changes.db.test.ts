// C1-4b (BR-03, SEC-AG-01's rotated-out and emergency-revoked keys,
// ADR-011 §1, ADR-012 §5): rotating and revoking an agent's key with a
// step-up, through the use case the routes call, on the real migrated
// schema, as the app role. The keys it leaves are then put to the key check
// (C1-4a). The routes' answers are agents.test.ts.
import { createHash, randomBytes } from 'node:crypto';

import {
  addAgent,
  addAgentKey,
  agentOf,
  AGENTS,
  agentKeyText,
  type AgentsTables,
  createAgentKeyCheck,
  handAgentOver,
  keySecretMessage,
  MOST_KEYS_ISSUED_A_DAY,
  parseAgentKey,
  type Scope,
} from '@agentx/core/modules/agents';
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
import { DAY_MS, HOUR_MS } from '@agentx/core/shared-kernel';
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
  type AgentChangeWrite,
  createAgentChanges,
  HAND_OVER_CONFIRM_OPERATION,
  HAND_OVER_OPERATION,
} from './agent-changes.ts';
import {
  type AgentKeyChanges,
  type AgentKeyChangeWrite,
  createAgentKeyChanges,
  type KeyNamed,
  REVOKE_CONFIRM_OPERATION,
  REVOKE_OPERATION,
  ROTATE_CONFIRM_OPERATION,
  ROTATE_OPERATION,
} from './agent-key-changes.ts';
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
const ids = new SequentialIds(0xc14b_0000_0000);
const START = new Date('2026-09-28T09:00:00Z');
let clock: FixedClock;
let changes: AgentKeyChanges;
const challenges = () => createStepUpChallenges({ ids, clock });

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';
/** A passkey's sign-in, and an app code's. */
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
    { issuer: 'https://auth.example.test', subject: `agent-key-changes-${String(people)}` },
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

/** The member signed in afresh, as they must be once a day has passed. */
const signedInAgain = async (who: Member): Promise<Member> => {
  const { sessionId } = await createSessions({
    ids,
    clock,
    timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
  }).open(app, who.userId, { idpSessionId: 'V1_3', authTime: clock.now(), amr: [...PASSKEY] });
  return { ...who, sessionId };
};

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

/** A key of the agent, made as registering makes one: its ID, and its text as the agent sends it. */
const keyFor = (org: string, agentId: string, scopes: readonly Scope[], expiresAt: Date) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const id = ids.next();
    const secret = randomBytes(32);
    const { mac, keyVersion } = keys.mac('agent-key-pepper', keySecretMessage(id, secret));
    await addAgentKey(tx, states, {
      orgId: org,
      id,
      agentId,
      scopes,
      secretMac: mac,
      secretKeyVersion: keyVersion,
      expiresAt,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    return { keyId: id, text: agentKeyText(id, secret) };
  });

interface Making {
  readonly scopes?: readonly Scope[];
  readonly keyScopes?: readonly Scope[];
  readonly expiresAt?: Date;
}

/** An agent of the organisation, owned by `owner`, with one key. */
async function agentWithKey(org: string, owner: Member, making: Making = {}) {
  const { scopes = ['requests:read', 'requests:write'], keyScopes = scopes } = making;
  const agentId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addAgent(tx, states, {
      orgId: org,
      id: agentId,
      name: 'Purchasing bot',
      owner: owner.membershipId,
      scopes,
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  const key = await keyFor(org, agentId, keyScopes, making.expiresAt ?? new Date(clock.now().getTime() + 90 * DAY_MS));
  return { agentId, ...key };
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

const named = ({ agentId, keyId }: KeyNamed): KeyNamed => ({ agentId, keyId });

const rotate = (who: AgentMember, key: KeyNamed) =>
  changes.rotate(who, keyed(who, ROTATE_OPERATION, JSON.stringify(key)), named(key), CORRELATION);

const rotateConfirm = (who: AgentMember, key: KeyNamed, challengeId: string, idempotent?: IdempotentRequest) =>
  changes.rotateConfirm(
    who,
    idempotent ?? keyed(who, ROTATE_CONFIRM_OPERATION, JSON.stringify({ ...key, challengeId })),
    named(key),
    challengeId,
    CORRELATION,
  );

const revoke = (who: AgentMember, key: KeyNamed) =>
  changes.revoke(who, keyed(who, REVOKE_OPERATION, JSON.stringify(key)), named(key), CORRELATION);

const revokeConfirm = (who: AgentMember, key: KeyNamed, challengeId: string) =>
  changes.revokeConfirm(
    who,
    keyed(who, REVOKE_CONFIRM_OPERATION, JSON.stringify({ ...key, challengeId })),
    named(key),
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

const askedFor = (write: AgentKeyChangeWrite): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

/** Asks, steps up and confirms a rotation. */
async function rotated(who: AgentMember, key: KeyNamed, amr: readonly string[] = PASSKEY) {
  const challengeId = askedFor(await rotate(who, key));
  await stepUp(who, challengeId, amr);
  const write = await rotateConfirm(who, key, challengeId);
  if (write.outcome !== 'rotated') throw new Error(`not rotated: ${JSON.stringify(write)}`);
  return write;
}

/** Asks, steps up and confirms a revocation. */
async function revoked(who: AgentMember, key: KeyNamed, amr: readonly string[] = PASSKEY) {
  const challengeId = askedFor(await revoke(who, key));
  await stepUp(who, challengeId, amr);
  const write = await revokeConfirm(who, key, challengeId);
  if (write.outcome !== 'revoked') throw new Error(`not revoked: ${JSON.stringify(write)}`);
  return write;
}

const refusal = (status: number, code: string) => ({ outcome: 'refused', status, code });

/** The key check, as C2 will put it in front of an agent's request. */
const check = (text: string) =>
  createAgentKeyCheck({ database: app, keys, ids, clock, logger: loggerFor(new LogCapture()) }).check(
    text,
    CORRELATION,
  );

/** The organisation's events about the key, oldest first. */
const eventsAbout = (org: string, keyId: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['actor_id', 'action', 'details'])
      .where('subject_type', '=', 'agent_key')
      .where('subject_id', '=', keyId)
      .orderBy('seq')
      .execute(),
  );

const keysIn = (org: string) =>
  withTenant(app, org, (tx) => tx.selectFrom('agents.agent_keys').select('id').execute()).then((rows) => rows.length);

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
  changes = createAgentKeyChanges({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    logger: loggerFor(new LogCapture()),
  });
});

describe(`rotating a key (C1-4b, Postgres ${server.version})`, () => {
  it('issues a new key, shown once, and keeps the old one working to the end of the 24-hour overlap', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const old = await agentWithKey(org, developer);

    const write = await rotated(developer, old, APP_CODE);

    const presented = parseAgentKey(write.key ?? '');
    expect(presented).toBeDefined();
    const newKeyId = presented?.keyId ?? '';
    expect(write.agent.keys.map(({ id, status, scopes, expiresAt }) => ({ id, status, scopes, expiresAt }))).toEqual(
      [
        {
          id: old.keyId,
          status: 'ACTIVE',
          scopes: ['requests:read', 'requests:write'],
          expiresAt: new Date(START.getTime() + DAY_MS),
        },
        {
          id: newKeyId,
          status: 'ACTIVE',
          scopes: ['requests:read', 'requests:write'],
          expiresAt: new Date(START.getTime() + 90 * DAY_MS),
        },
      ].sort((one, other) => one.id.localeCompare(other.id)),
    );
    // The new key's event names the key it rotates and the step-up; the old key's names its successor.
    const issued = await eventsAbout(org, newKeyId);
    expect(issued.map(({ action }) => action)).toEqual(['agent_key.issued']);
    expect(JSON.parse(issued[0]?.details ?? '{}')).toMatchObject({
      rotates: old.keyId,
      agentId: old.agentId,
      stepUpChallengeId: expect.any(String) as unknown,
    });
    const oldEvents = await eventsAbout(org, old.keyId);
    expect(oldEvents.map(({ action, actor_id: actor }) => [action, actor])).toEqual([
      ['agent_key.issued', OPERATOR.id],
      ['agent_key.rotated', developer.userId],
    ]);
    expect(JSON.parse(oldEvents[1]?.details ?? '{}')).toMatchObject({
      rotatedTo: newKeyId,
      expiresAt: new Date(START.getTime() + DAY_MS).toISOString(),
    });
  });

  it('both keys work through the overlap; from its end, only the new one: the old key rotated out', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const old = await agentWithKey(org, developer);
    const write = await rotated(developer, old);
    const fresh = write.key ?? '';

    expect(await check(old.text)).toMatchObject({ outcome: 'accepted' });
    expect(await check(fresh)).toMatchObject({ outcome: 'accepted', key: { agentId: old.agentId } });
    clock.advanceBy(DAY_MS - 1);
    expect(await check(old.text)).toMatchObject({ outcome: 'accepted' });
    clock.advanceBy(1);
    expect(await check(old.text)).toEqual({ outcome: 'refused' });
    expect(await check(fresh)).toMatchObject({ outcome: 'accepted' });
  });

  it('never moves an expiry later: a key expiring within the overlap keeps its own', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const soon = new Date(START.getTime() + 2 * HOUR_MS);
    const old = await agentWithKey(org, developer, { expiresAt: soon });

    const write = await rotated(developer, old);

    expect(write.agent.keys.find(({ id }) => id === old.keyId)?.expiresAt).toEqual(soon);
  });

  it('gives the new key the scopes both the old key and the agent hold', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const old = await agentWithKey(org, developer, {
      scopes: ['requests:read', 'suppliers:read'],
      keyScopes: ['requests:read', 'requests:write', 'suppliers:read'],
    });

    const write = await rotated(developer, old);

    const newKeyId = parseAgentKey(write.key ?? '')?.keyId;
    expect(write.agent.keys.find(({ id }) => id === newKeyId)?.scopes).toEqual(['requests:read', 'suppliers:read']);
  });

  it('answers a retry of the same confirm with the key as null, issuing nothing more', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const old = await agentWithKey(org, developer);
    const challengeId = askedFor(await rotate(developer, old));
    await stepUp(developer, challengeId);
    const idempotent = keyed(developer, ROTATE_CONFIRM_OPERATION, 'the confirm');

    const first = await rotateConfirm(developer, old, challengeId, idempotent);
    const again = await rotateConfirm(developer, old, challengeId, idempotent);

    expect(first).toMatchObject({ outcome: 'rotated', key: expect.stringMatching(/^axk_/) as unknown });
    expect(again).toMatchObject({ outcome: 'rotated', key: null });
    expect(await keysIn(org)).toBe(2);
  });

  it('rotates a suspended agent’s key: after a leak, suspend first, rotate, then reactivate', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const old = await agentWithKey(org, developer);
    await withSignedStates(app, org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: org, id: old.agentId }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspended',
        details: {},
      }),
    );

    const write = await rotated(developer, old);

    expect(write.agent.agent.status).toBe('SUSPENDED');
    expect(write.agent.keys).toHaveLength(2);
  });

  it(`refuses a third live key while a rotation's overlap runs: AGENT_KEYS_FULL, asking and confirming`, async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const old = await agentWithKey(org, developer);
    const challengeId = askedFor(await rotate(developer, old));
    const write = await rotated(developer, old);
    const newKeyId = parseAgentKey(write.key ?? '')?.keyId ?? '';
    await stepUp(developer, challengeId);

    expect(await rotate(developer, { agentId: old.agentId, keyId: newKeyId })).toEqual(refusal(409, 'AGENT_KEYS_FULL'));
    expect(await rotateConfirm(developer, old, challengeId)).toEqual(refusal(409, 'AGENT_KEYS_FULL'));
    // The overlap over, the new key rotates.
    clock.advanceBy(DAY_MS);
    const again = await signedInAgain(developer);
    expect(await rotated(again, { agentId: old.agentId, keyId: newKeyId })).toMatchObject({ outcome: 'rotated' });
  });

  it('refuses a key revoked or expired: AGENT_KEY_NOT_LIVE', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const gone = await agentWithKey(org, developer);
    await revoked(developer, gone);
    const lapsed = await agentWithKey(org, developer, { expiresAt: new Date(START.getTime() + HOUR_MS) });
    clock.advanceBy(HOUR_MS);

    expect(await rotate(developer, gone)).toEqual(refusal(409, 'AGENT_KEY_NOT_LIVE'));
    expect(await rotate(developer, lapsed)).toEqual(refusal(409, 'AGENT_KEY_NOT_LIVE'));
  });

  it('refuses a key of another agent, and an agent of another organisation: NOT_FOUND', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const one = await agentWithKey(org, developer);
    const other = await agentWithKey(org, developer);
    const elsewhere = await organization();
    const outsider = await agentWithKey(elsewhere, await member(elsewhere, 'developer'));

    expect(await rotate(developer, { agentId: one.agentId, keyId: other.keyId })).toEqual(refusal(404, 'NOT_FOUND'));
    expect(await rotate(developer, outsider)).toEqual(refusal(404, 'NOT_FOUND'));
    expect(await revoke(developer, { agentId: one.agentId, keyId: other.keyId })).toEqual(refusal(404, 'NOT_FOUND'));
  });

  it.each<Role>(['approver', 'viewer'])('refuses a %s: FORBIDDEN, asking and confirming', async (role) => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const someone = await member(org, role);
    const key = await agentWithKey(org, developer);

    expect(await rotate(someone, key)).toEqual(refusal(403, 'FORBIDDEN'));
    expect(await revoke(someone, key)).toEqual(refusal(403, 'FORBIDDEN'));
    expect(await rotateConfirm(someone, key, ids.next())).toEqual(refusal(403, 'FORBIDDEN'));
    expect(await revokeConfirm(someone, key, ids.next())).toEqual(refusal(403, 'FORBIDDEN'));
  });

  it('refuses a developer a new key for an agent another member owns, asking and confirming; revoking it they may (the S68 audit)', async () => {
    const org = await organization();
    const owner = await member(org, 'developer');
    const other = await member(org, 'developer');
    const key = await agentWithKey(org, owner);

    expect(await rotate(other, key)).toEqual(refusal(403, 'FORBIDDEN'));
    expect(await rotateConfirm(other, key, ids.next())).toEqual(refusal(403, 'FORBIDDEN'));
    // The owner still may.
    expect(await rotated(owner, key)).toMatchObject({ outcome: 'rotated' });
    expect(await revoked(other, key)).toMatchObject({ outcome: 'revoked' });
  });

  it('lets the member an agent was handed to rotate its key, and no longer the member who had it (the S68 audit)', async () => {
    const org = await organization();
    const leaving = await member(org, 'developer');
    const next = await member(org, 'developer');
    const key = await agentWithKey(org, leaving);
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      const read = await agentOf(tx, states, { orgId: org, id: key.agentId }, 'change');
      if (read.outcome !== 'found') throw new Error('the agent was not found');
      await handAgentOver(tx, states, {
        orgId: org,
        agent: read.agent,
        state: read.state,
        owner: next.membershipId,
        actor: OPERATOR,
        details: {},
      });
    });

    expect(await rotate(leaving, key)).toEqual(refusal(403, 'FORBIDDEN'));
    expect(await rotated(next, key)).toMatchObject({ outcome: 'rotated' });
  });

  it('lets an admin rotate the key of an agent a developer owns, with a passkey (the S68 audit)', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const admin = await member(org, 'admin');
    const key = await agentWithKey(org, developer);

    expect(await rotated(admin, key)).toMatchObject({ outcome: 'rotated' });
  });

  it('asks an admin for a passkey: an app code’s step-up fails, a developer’s passes', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const key = await agentWithKey(org, admin);
    const challengeId = askedFor(await rotate(admin, key));
    await stepUp(admin, challengeId, APP_CODE);

    expect(await rotateConfirm(admin, key, challengeId)).toEqual(refusal(403, 'STEP_UP_FAILED'));
    expect(await rotated(admin, key)).toMatchObject({ outcome: 'rotated' });
  });

  it('binds the step-up to the key as it was asked, and to rotating: another key’s, or a revocation’s, fails', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const one = await agentWithKey(org, developer);
    const other = await agentWithKey(org, developer);
    const forOther = askedFor(await rotate(developer, other));
    const forRevoking = askedFor(await revoke(developer, one));
    await stepUp(developer, forOther);
    await stepUp(developer, forRevoking);

    expect(await rotateConfirm(developer, one, forOther)).toEqual(refusal(403, 'STEP_UP_FAILED'));
    expect(await rotateConfirm(developer, one, forRevoking)).toEqual(refusal(403, 'STEP_UP_FAILED'));
    expect(await keysIn(org)).toBe(2);
  });

  it(`past ${String(MOST_KEYS_ISSUED_A_DAY)} keys in 24 hours, first keys included: AGENT_KEYS_SPENT, until a day has passed`, async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    for (let count = 1; count < MOST_KEYS_ISSUED_A_DAY; count += 1) {
      await keyFor(org, key.agentId, ['requests:read'], new Date(START.getTime() - 1 + 90 * DAY_MS));
    }
    // Every key but the first is revoked, so the agent has room for a new one.
    const all = await withTenant(app, org, (tx) =>
      tx.selectFrom('agents.agent_keys').select('id').where('id', '!=', key.keyId).execute(),
    );
    for (const { id } of all) await revoked(developer, { agentId: key.agentId, keyId: id });
    const challengeId = askedFor(await rotate(developer, key));
    await stepUp(developer, challengeId);

    expect(await rotateConfirm(developer, key, challengeId)).toEqual(refusal(409, 'AGENT_KEYS_SPENT'));
    expect(await keysIn(org)).toBe(MOST_KEYS_ISSUED_A_DAY);

    clock.advanceBy(DAY_MS);
    const again = await signedInAgain(developer);
    expect(await rotated(again, key)).toMatchObject({ outcome: 'rotated' });
  });

  it('confirms only once it holds the organisation’s lock for issuing keys, so two can’t both take the day’s last', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    const challengeId = askedFor(await rotate(developer, key));
    await stepUp(developer, challengeId);
    // Another rotation of the organisation's, part-way: its lock taken, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName('agent_keys', org));
      const confirming = within(20_000, rotateConfirm(developer, key, challengeId), 'the confirmation');
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');

      expect(await confirming).toMatchObject({ outcome: 'rotated' });
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe('a key change refused for what it read (C1-4b)', () => {
  it('refuses a session ended since, as UNAUTHENTICATED, writing nothing', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    await app.deleteFrom('identity.sessions').where('id', '=', developer.sessionId).execute();

    expect(await rotate(developer, key)).toEqual(refusal(401, 'UNAUTHENTICATED'));
    expect(await revoke(developer, key)).toEqual(refusal(401, 'UNAUTHENTICATED'));
  });

  it('refuses an agent changed past its seal: INTEGRITY_FAILED', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    await withTenant(app, org, (tx) =>
      tx.updateTable('agents.agents').set({ scopes: 'requests:read' }).where('id', '=', key.agentId).execute(),
    );

    expect(await rotate(developer, key)).toEqual(refusal(503, 'INTEGRITY_FAILED'));
  });

  it('refuses a key changed past its seal: INTEGRITY_FAILED', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    await withTenant(app, org, (tx) =>
      tx
        .updateTable('agents.agent_keys')
        .set({ expires_at: new Date('2099-01-01T00:00:00Z') })
        .where('id', '=', key.keyId)
        .execute(),
    );

    expect(await revoke(developer, key)).toEqual(refusal(503, 'INTEGRITY_FAILED'));
  });

  it('refuses a rotation when another of the agent’s keys was changed past its seal: its count can’t be trusted', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    const other = await keyFor(org, key.agentId, ['requests:read'], new Date(START.getTime() + HOUR_MS));
    await withTenant(app, org, (tx) =>
      tx.updateTable('agents.agent_keys').set({ status: 'REVOKED' }).where('id', '=', other.keyId).execute(),
    );

    expect(await rotate(developer, key)).toEqual(refusal(503, 'INTEGRITY_FAILED'));
  });
});

describe('revoking a key (C1-4b)', () => {
  it('stops the key at once, with no overlap, the step-up’s evidence on its event', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    expect(await check(key.text)).toMatchObject({ outcome: 'accepted' });

    const write = await revoked(developer, key, APP_CODE);

    expect(write.agent.keys).toEqual([
      expect.objectContaining({ id: key.keyId, status: 'REVOKED', expiresAt: new Date(START.getTime() + 90 * DAY_MS) }),
    ]);
    expect(await check(key.text)).toEqual({ outcome: 'refused' });
    const events = await eventsAbout(org, key.keyId);
    expect(events.map(({ action, actor_id: actor }) => [action, actor])).toEqual([
      ['agent_key.issued', OPERATOR.id],
      ['agent_key.revoked', developer.userId],
    ]);
    expect(JSON.parse(events[1]?.details ?? '{}')).toMatchObject({
      statusFrom: 'ACTIVE',
      statusTo: 'REVOKED',
      stepUpChallengeId: expect.any(String) as unknown,
    });
  });

  it('revokes an expired key, and refuses one revoked already: AGENT_KEY_REVOKED, asking and confirming', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const lapsed = await agentWithKey(org, developer, { expiresAt: new Date(START.getTime() + HOUR_MS) });
    clock.advanceBy(HOUR_MS);
    const challengeId = askedFor(await revoke(developer, lapsed));
    await stepUp(developer, challengeId);

    expect(await revokeConfirm(developer, lapsed, challengeId)).toMatchObject({ outcome: 'revoked' });
    expect(await revoke(developer, lapsed)).toEqual(refusal(409, 'AGENT_KEY_REVOKED'));
    expect(await revokeConfirm(developer, lapsed, challengeId)).toEqual(refusal(409, 'AGENT_KEY_REVOKED'));
  });

  it('asks an admin for a passkey', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const key = await agentWithKey(org, admin);
    const challengeId = askedFor(await revoke(admin, key));
    await stepUp(admin, challengeId, APP_CODE);

    expect(await revokeConfirm(admin, key, challengeId)).toEqual(refusal(403, 'STEP_UP_FAILED'));
    expect(await revoked(admin, key)).toMatchObject({ outcome: 'revoked' });
  });

  it('binds the step-up to the key as it was asked: a revocation asked before a rotation fails after it', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    const challengeId = askedFor(await revoke(developer, key));
    await stepUp(developer, challengeId);
    await rotated(developer, key);

    expect(await revokeConfirm(developer, key, challengeId)).toEqual(refusal(403, 'STEP_UP_FAILED'));
    expect(await revoked(developer, key)).toMatchObject({ outcome: 'revoked' });
  });
});

describe('a handover replaces the agent’s keys (the partner’s decision on the S68 audit’s question A)', () => {
  const handing = () =>
    createAgentChanges({
      database: app,
      keys,
      ids,
      clock,
      challenges: challenges(),
      logger: loggerFor(new LogCapture()),
    });

  const handOverAsk = (who: AgentMember, agentId: string, owner: string) =>
    handing().handOver(who, keyed(who, HAND_OVER_OPERATION, `${agentId} ${owner}`), agentId, owner, CORRELATION);

  const handOverConfirm = (
    who: AgentMember,
    agentId: string,
    owner: string,
    challengeId: string,
    idempotent?: IdempotentRequest,
  ) =>
    handing().handOverConfirm(
      who,
      idempotent ?? keyed(who, HAND_OVER_CONFIRM_OPERATION, `${agentId} ${owner} ${challengeId}`),
      agentId,
      owner,
      challengeId,
      CORRELATION,
    );

  const askedForHandOver = (write: AgentChangeWrite): string => {
    if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
    return write.stepUpChallengeId;
  };

  const handedOf = (write: AgentChangeWrite) => {
    if (write.outcome !== 'handedOver') throw new Error(`not handed over: ${JSON.stringify(write)}`);
    return write;
  };

  /** Asks, steps up and confirms a handover. */
  async function handedOver(admin: Member, agentId: string, owner: string) {
    const challengeId = askedForHandOver(await handOverAsk(admin, agentId, owner));
    await stepUp(admin, challengeId);
    return handedOf(await handOverConfirm(admin, agentId, owner, challengeId));
  }

  it('revokes every key at once, so none works, and issues one new key that does, with the newest live key’s scopes', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const leaving = await member(org, 'developer');
    const next = await member(org, 'developer');
    const first = await agentWithKey(org, leaving, { scopes: ['requests:read', 'requests:write'] });
    const newer = await keyFor(org, first.agentId, ['requests:read'], new Date(START.getTime() + 30 * DAY_MS));
    // Revoked already, and the newest: left as it is, its revocation its own.
    const gone = await keyFor(org, first.agentId, ['requests:read'], new Date(START.getTime() + 30 * DAY_MS));
    await revoked(leaving, { agentId: first.agentId, keyId: gone.keyId });
    expect(await check(first.text)).toMatchObject({ outcome: 'accepted' });

    const done = await handedOver(admin, first.agentId, next.membershipId);

    expect(await check(first.text)).toEqual({ outcome: 'refused' });
    expect(await check(newer.text)).toEqual({ outcome: 'refused' });
    expect(done.key).toMatch(/^axk_/);
    expect(await check(done.key ?? '')).toMatchObject({
      outcome: 'accepted',
      key: { agentId: first.agentId, scopes: ['requests:read'] },
    });
    const fresh = done.agent.keys.find((key) => key.status === 'ACTIVE');
    expect(done.agent.agent.owner).toBe(next.membershipId);
    expect(done.agent.keys.map((key) => key.status).sort()).toEqual(['ACTIVE', 'REVOKED', 'REVOKED', 'REVOKED']);
    expect((await eventsAbout(org, gone.keyId)).map((event) => event.action)).toEqual([
      'agent_key.issued',
      'agent_key.revoked',
    ]);
    // Expiring as a registered agent's first key does: 90 days from now.
    expect(fresh?.expiresAt).toEqual(new Date(START.getTime() + 90 * DAY_MS));
    for (const keyId of [first.keyId, newer.keyId]) {
      const events = await eventsAbout(org, keyId);
      expect(events.at(-1)).toMatchObject({ action: 'agent_key.revoked', actor_id: admin.userId });
      expect(JSON.parse(events.at(-1)?.details ?? '{}')).toMatchObject({ reason: 'handed_over' });
    }
    expect(JSON.parse((await eventsAbout(org, fresh?.id ?? ''))[0]?.details ?? '{}')).toMatchObject({
      handedOverTo: next.membershipId,
    });
  });

  it('replaces a suspended agent’s keys too, which stays suspended', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const key = await agentWithKey(org, await member(org, 'developer'));
    const agentChanges = handing();
    await agentChanges.suspend(admin, keyed(admin, 'agents.suspend', key.agentId), key.agentId, CORRELATION);

    const done = await handedOver(admin, key.agentId, admin.membershipId);

    expect(done.agent.agent.status).toBe('SUSPENDED');
    expect(done.agent.keys.find((listed) => listed.id === key.keyId)?.status).toBe('REVOKED');
    expect(done.agent.keys.filter((listed) => listed.status === 'ACTIVE')).toHaveLength(1);
  });

  it('gives the new key the agent’s scopes when none of its keys was live', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const key = await agentWithKey(org, await member(org, 'developer'), {
      scopes: ['requests:read', 'requests:write'],
      keyScopes: ['requests:read'],
      expiresAt: new Date(START.getTime() + HOUR_MS),
    });
    clock.advanceBy(2 * HOUR_MS);
    const again = await signedInAgain(admin);

    const done = await handedOver(again, key.agentId, next.membershipId);

    expect(await check(done.key ?? '')).toMatchObject({
      outcome: 'accepted',
      key: { scopes: ['requests:read', 'requests:write'] },
    });
    // The expired key, still ACTIVE, is revoked with the rest: none from before the handover is left.
    expect(done.agent.keys.find((listed) => listed.id === key.keyId)?.status).toBe('REVOKED');
  });

  it('gives the new key only the scopes its agent holds, whatever the key it replaces held', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const key = await agentWithKey(org, admin, {
      scopes: ['requests:read'],
      keyScopes: ['requests:read', 'requests:write'],
    });

    const done = await handedOver(admin, key.agentId, next.membershipId);

    expect(done.agent.keys.find((listed) => listed.status === 'ACTIVE')?.scopes).toEqual(['requests:read']);
  });

  it('confirms only once it holds the organisation’s lock for issuing keys, so two can’t both take the day’s last', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const key = await agentWithKey(org, admin);
    const challengeId = askedForHandOver(await handOverAsk(admin, key.agentId, next.membershipId));
    await stepUp(admin, challengeId);
    // Another issue of the organisation's, part-way: its lock taken, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName('agent_keys', org));
      const confirming = within(
        20_000,
        handOverConfirm(admin, key.agentId, next.membershipId, challengeId),
        'the handover',
      );
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');

      expect(await confirming).toMatchObject({ outcome: 'handedOver' });
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('answers a retry of the same confirm as the first, with the key as null: shown once, handed over once', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const key = await agentWithKey(org, admin);
    const challengeId = askedForHandOver(await handOverAsk(admin, key.agentId, next.membershipId));
    await stepUp(admin, challengeId);
    const idempotent = keyed(admin, HAND_OVER_CONFIRM_OPERATION, `${key.agentId} ${next.membershipId} ${challengeId}`);

    const first = handedOf(await handOverConfirm(admin, key.agentId, next.membershipId, challengeId, idempotent));
    const retried = handedOf(await handOverConfirm(admin, key.agentId, next.membershipId, challengeId, idempotent));

    expect(first.key).toMatch(/^axk_/);
    expect(retried).toEqual({ ...first, key: null });
    expect(await keysIn(org)).toBe(2);
  });

  it(`past ${String(MOST_KEYS_ISSUED_A_DAY)} keys in 24 hours: AGENT_KEYS_SPENT, asking or confirming, nothing changed`, async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const key = await agentWithKey(org, admin);
    const challengeId = askedForHandOver(await handOverAsk(admin, key.agentId, next.membershipId));
    await stepUp(admin, challengeId);
    for (let count = 1; count < MOST_KEYS_ISSUED_A_DAY; count += 1) {
      await keyFor(org, key.agentId, ['requests:read'], new Date(START.getTime() + 90 * DAY_MS));
    }

    expect(await handOverConfirm(admin, key.agentId, next.membershipId, challengeId)).toEqual(
      refusal(409, 'AGENT_KEYS_SPENT'),
    );
    expect(await handOverAsk(admin, key.agentId, next.membershipId)).toEqual(refusal(409, 'AGENT_KEYS_SPENT'));
    expect(await keysIn(org)).toBe(MOST_KEYS_ISSUED_A_DAY);
    expect(await check(key.text)).toMatchObject({ outcome: 'accepted' });
  });
});

describe(`the confirmation's lock order against the confirmer's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('a key rotation holds its step-up challenges before the member’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const old = await agentWithKey(org, developer);
    const challengeId = askedFor(await rotate(developer, old));
    await stepUp(developer, challengeId);

    const write = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: developer.membershipId },
      () => rotateConfirm(developer, old, challengeId),
    );

    expect(write).toMatchObject({ outcome: 'rotated', key: expect.stringMatching(/^axk_/) as unknown });
  });

  it('a key revocation holds its step-up challenges before the member’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const org = await organization();
    const developer = await member(org, 'developer');
    const key = await agentWithKey(org, developer);
    const challengeId = askedFor(await revoke(developer, key));
    await stepUp(developer, challengeId);

    const write = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: developer.membershipId },
      () => revokeConfirm(developer, key, challengeId),
    );

    expect(write.outcome).toBe('revoked');
    expect(await check(key.text)).toEqual({ outcome: 'refused' });
  });
});

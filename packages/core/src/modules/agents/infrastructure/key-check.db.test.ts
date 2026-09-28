// SEC-AG-01 (C1-4a): the key check, on the real migrated schema, as the app
// role. A live key is accepted, as its agent, with the scopes both hold; a
// key that isn't one, isn't listed, has a wrong secret, a suspended agent, a
// revocation or a passed expiry is refused, every one with the same answer
// and its reason in the log alone; a key or agent the owner tampered with is
// refused, and the organisation held.
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  within,
} from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it, vi } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { agentKeyText, keySecretMessage, type Scope } from '../domain/agent.ts';
import { addAgentKey, AGENT_KEYS } from './agent-keys.ts';
import { addAgent, AGENTS } from './agents.ts';
import { createAgentKeyCheck } from './key-check.ts';
import type { AgentsTables } from './tables.ts';

type Tables = AgentsTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const OLD_PEPPER = Buffer.alloc(32, 0x71);
const NEW_PEPPER = Buffer.alloc(32, 0x72);

/** Stand-in keys, one per purpose, with the agent-key pepper's versions as given. */
const withPepper = (pepper: { current: number; versions: Map<number, Buffer> }) =>
  createKeyProvider({
    ...Object.fromEntries(
      PURPOSES.map((purpose, index) => [
        purpose,
        { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) },
      ]),
    ),
    'agent-key-pepper': pepper,
  });

/** This process's keys: the pepper rotated, version 1 kept and version 2 current. */
const keys = withPepper({
  current: 2,
  versions: new Map([
    [1, OLD_PEPPER],
    [2, NEW_PEPPER],
  ]),
});
const ids = new SequentialIds(0xc140_0000_0000);
const START = new Date('2026-09-28T09:00:00Z');
const DAY_MS = 86_400_000;
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

let capture: LogCapture;
let clock: FixedClock;
let org: string;

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

const check = (text: string) =>
  createAgentKeyCheck({ database: app, keys, ids, clock, logger: loggerFor(capture) }).check(text, 'corr-1');

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Refused, with the one answer every refusal has, and its reason logged once. */
async function refusedFor(text: string, reason: string, keyId: string | null): Promise<void> {
  expect(await check(text)).toEqual({ outcome: 'refused' });
  expect(lines('agent_key.refused')).toEqual([
    expect.objectContaining({ level: 'info', correlationId: 'corr-1', reason, keyId }),
  ]);
}

const newAgent = (scopes: readonly Scope[] = ['requests:read', 'requests:write']) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const id = ids.next();
    await addAgent(tx, states, {
      orgId: org,
      id,
      name: 'Purchasing bot',
      owner: ids.next(),
      scopes,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    return id;
  });

/** The MAC the pepper's first version made, for a key issued before it was rotated. */
const olderPepperMac = (id: string, secret: Buffer): Buffer =>
  withPepper({ current: 1, versions: new Map([[1, OLD_PEPPER]]) }).mac('agent-key-pepper', keySecretMessage(id, secret))
    .mac;

interface Issuing {
  readonly scopes?: readonly Scope[];
  readonly expiresAt?: Date;
  /** The pepper's version its MAC is made with: 1 for a key made before the pepper was rotated; the current (2) otherwise. */
  readonly version?: 1;
}

/** A key for the agent, made as registering makes one; its text, as the agent would send it, and its ID. */
const issue = (agentId: string, { scopes = ['requests:read'], expiresAt, version }: Issuing = {}) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const id = ids.next();
    const secret = Buffer.alloc(32, Number.parseInt(id.slice(-2), 16));
    const { mac, keyVersion } =
      version === 1
        ? { mac: olderPepperMac(id, secret), keyVersion: 1 }
        : keys.mac('agent-key-pepper', keySecretMessage(id, secret));
    await addAgentKey(tx, states, {
      orgId: org,
      id,
      agentId,
      scopes,
      secretMac: mac,
      secretKeyVersion: keyVersion,
      expiresAt: expiresAt ?? new Date(clock.now().getTime() + 90 * DAY_MS),
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    return { id, text: agentKeyText(id, secret), secret };
  });

const moveAgent = (id: string, event: 'suspend' | 'reactivate') =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    states.changeStatus(tx, AGENTS, { orgId: org, id }, event, {
      actor: OPERATOR,
      action: `agent.${event}`,
      details: {},
    }),
  );

const revoke = (id: string) =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    states.changeStatus(tx, AGENT_KEYS, { orgId: org, id }, 'revoke', {
      actor: OPERATOR,
      action: 'agent_key.revoked',
      details: {},
    }),
  );

const hold = () => withSignedStates(app, org, quiet(), (tx, states) => states.integrityHold(tx, org, 'none'));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  clock = new FixedClock(START);
  org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
});

describe(`the key check: a key that may act (C1-4a, Postgres ${server.version})`, () => {
  it('accepts a live key as its agent, in its organisation, logging nothing', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);

    expect(await check(text)).toEqual({
      outcome: 'accepted',
      key: { orgId: org, agentId: agent, keyId: id, scopes: ['requests:read'] },
    });
    expect(lines('agent_key.refused')).toEqual([]);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('gives only the scopes both the key and its agent hold', async () => {
    const agent = await newAgent(['requests:read', 'suppliers:read']);
    const { text } = await issue(agent, { scopes: ['requests:read', 'requests:write', 'suppliers:read'] });

    expect(await check(text)).toMatchObject({ key: { scopes: ['requests:read', 'suppliers:read'] } });
  });

  it('checks the secret with the pepper version the key was made with, after the pepper is rotated', async () => {
    const agent = await newAgent();
    const { text } = await issue(agent, { version: 1 });

    expect(await check(text)).toMatchObject({ outcome: 'accepted' });
  });

  it('refuses a key made with a pepper version since retired, logging it as an error: ours to fix, not a wrong secret', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent, { version: 1 });
    const retired = withPepper({ current: 2, versions: new Map([[2, NEW_PEPPER]]) });

    const checked = await createAgentKeyCheck({
      database: app,
      keys: retired,
      ids,
      clock,
      logger: loggerFor(capture),
    }).check(text, 'corr-1');

    expect(checked).toEqual({ outcome: 'refused' });
    expect(lines('agent_key.refused')).toEqual([
      expect.objectContaining({ level: 'error', reason: 'key_not_held', keyId: id }),
    ]);
  });

  it('compares the secret through the KeyProvider’s verifyMac, over two 32-byte MACs (its constant time is key-provider.test.ts’s)', async () => {
    const agent = await newAgent();
    const { id, text, secret } = await issue(agent);
    const verifyMac = vi.fn((...args: Parameters<typeof keys.verifyMac>) => keys.verifyMac(...args));
    const watched = { ...keys, verifyMac };

    const checked = await createAgentKeyCheck({
      database: app,
      keys: watched,
      ids,
      clock,
      logger: loggerFor(capture),
    }).check(text, 'corr-1');

    expect(checked).toMatchObject({ outcome: 'accepted' });
    // The signed states' own reads check the audit trail's MACs through it too.
    const secretChecks = verifyMac.mock.calls.filter(([purpose]) => purpose === 'agent-key-pepper');
    expect(secretChecks).toHaveLength(1);
    const [, version, message, mac] = secretChecks[0] ?? [];
    expect({ version, message }).toEqual({ version: 2, message: keySecretMessage(id, secret) });
    expect(mac).toHaveLength(32);
  });

  it('accepts a key until the millisecond it expires, and refuses it from then: a key rotated out', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent, { expiresAt: new Date(START.getTime() + DAY_MS) });

    clock.advanceBy(DAY_MS - 1);
    expect(await check(text)).toMatchObject({ outcome: 'accepted' });
    clock.advanceBy(1);
    await refusedFor(text, 'expired', id);
  });
});

describe('the key check: bounded', () => {
  it('gives up after 10 seconds, a wait for a lock included, rather than hold the request', async () => {
    const agent = await newAgent();
    const { text } = await issue(agent);
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table agents.agent_keys in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, check(text), 'the check')).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe('the key check: every refusal the same answer, its reason logged alone', () => {
  it('text that isn’t a key, looking nothing up', async () => {
    const agent = await newAgent();
    const { text } = await issue(agent);

    await refusedFor(text.toUpperCase(), 'malformed', null);
  });

  it('a key whose ID isn’t listed', async () => {
    const agent = await newAgent();
    const { text } = await issue(agent);
    const unlisted = `axk_${'0'.repeat(32)}${text.slice(36)}`;

    await refusedFor(unlisted, 'unlisted', '00000000-0000-0000-0000-000000000000');
  });

  it('a listed key with a wrong secret, whatever state the key is in', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    const wrong = `${text.slice(0, 37)}${Buffer.alloc(32, 0xee).toString('base64url')}`;
    await revoke(id);

    await refusedFor(wrong, 'wrong_secret', id);
  });

  it('another key’s secret: a MAC is bound to its key’s ID', async () => {
    const agent = await newAgent();
    const one = await issue(agent);
    const other = await issue(agent);

    await refusedFor(`${one.text.slice(0, 37)}${other.secret.toString('base64url')}`, 'wrong_secret', one.id);
  });

  it('a key of a suspended agent, and accepted again once it is reactivated', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    await moveAgent(agent, 'suspend');

    await refusedFor(text, 'agent_suspended', id);
    await moveAgent(agent, 'reactivate');
    expect(await check(text)).toMatchObject({ outcome: 'accepted' });
  });

  it('a revoked key', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    await revoke(id);

    await refusedFor(text, 'revoked', id);
  });

  it('never logs the secret or the key’s text', async () => {
    const agent = await newAgent();
    const { id, text, secret } = await issue(agent);
    await revoke(id);

    await check(text);

    const logged = JSON.stringify(capture.lines());
    expect(logged).not.toContain(secret.toString('base64url'));
    expect(logged).not.toContain(text.slice(4, 36));
  });
});

describe('the key check: tampered with by the owner, refused and held', () => {
  let owner: OwnerTamper | undefined;

  const tamper = async (table: typeof AGENTS | typeof AGENT_KEYS): Promise<OwnerTamper> => {
    owner = await tamperAsOwner(database, table, org);
    return owner;
  };

  const heldFor = async (subjectType: string): Promise<void> => {
    expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ subjectType, orgId: org })]);
    expect(await hold()).toMatchObject({ outcome: 'held' });
  };

  beforeEach(() => {
    owner = undefined;
  });

  afterEach(async () => {
    await owner?.end();
  });

  it('a key whose MAC the owner replaced with one for a secret they know', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    const known = Buffer.alloc(32, 0xab);
    const { mac } = keys.mac('agent-key-pepper', keySecretMessage(id, known));
    await (await tamper(AGENT_KEYS)).setColumn(id, 'secret_mac', mac.toString('hex'));

    await refusedFor(`${text.slice(0, 37)}${known.toString('base64url')}`, 'tampered', id);
    await heldFor('agent_key');
  });

  it('a suspended agent the owner made active again: the kill switch undone', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    await moveAgent(agent, 'suspend');
    await (await tamper(AGENTS)).setColumn(agent, 'status', 'ACTIVE');

    await refusedFor(text, 'tampered', id);
    await heldFor('agent');
  });

  it('a key the owner planted with no event, for a secret they know', async () => {
    const agent = await newAgent();
    const id = ids.next();
    const known = Buffer.alloc(32, 0xcd);
    const { mac } = keys.mac('agent-key-pepper', keySecretMessage(id, known));
    const planting = await tamper(AGENT_KEYS);
    await planting.query('insert into directory.agent_keys (key_id, org_id) values ($1, $2)', [id, org]);
    await planting.query(
      "insert into agents.agent_keys (org_id, id, agent_id, status, scopes, secret_mac, secret_key_version, expires_at, created_at) values ($1, $2, $3, 'ACTIVE', 'requests:write', $4, 2, now() + interval '1 day', now())",
      [org, id, agent, mac.toString('hex')],
    );

    await refusedFor(agentKeyText(id, known), 'tampered', id);
    await heldFor('agent_key');
  });

  it('a directory entry the owner planted with no key behind it', async () => {
    const id = ids.next();
    await (
      await tamper(AGENT_KEYS)
    ).query('insert into directory.agent_keys (key_id, org_id) values ($1, $2)', [id, org]);

    await refusedFor(agentKeyText(id, Buffer.alloc(32, 0x01)), 'missing', id);
  });
});

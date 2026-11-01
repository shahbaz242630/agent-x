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
  type TestClient,
  type TestDatabase,
  testLogger,
  waitUntilBlocked,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import {
  asAgentTraffic,
  createDatabase,
  type Database,
  noStatementTimes,
  timingStatements,
  withTenant,
} from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it, vi } from 'vitest';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { agentKeyText, keySecretMessage, parseAgentKey, type Scope } from '../domain/agent.ts';
import { addAgentKey, AGENT_KEYS } from './agent-keys.ts';
import { addAgent, AGENTS } from './agents.ts';
import { agentKeyAt, createAgentKeyCheck } from './key-check.ts';
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
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

let capture: LogCapture;
let clock: FixedClock;
let org: string;

const quiet = () => ({ keys, ids, logger: testLogger() });

const check = (text: string) =>
  createAgentKeyCheck({ database: app, keys, ids, clock, logger: testLogger(capture) }).check(
    text,
    '0199a0f0-0000-7000-8000-00000000c011',
  );

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Refused, with the one answer every refusal has, and its reason logged once. */
async function refusedFor(text: string, reason: string, keyId: string | null): Promise<void> {
  expect(await check(text)).toEqual({ outcome: 'refused' });
  expect(lines('agent_key.refused')).toEqual([
    expect.objectContaining({ level: 'info', correlationId: '0199a0f0-0000-7000-8000-00000000c011', reason, keyId }),
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

/** The one session of this database waiting for a lock. */
const waitingPid = async (): Promise<number> => {
  const [pid] = await waitUntilQueued(database.as('admin'), 1);
  if (pid === undefined) throw new Error('No session is waiting');
  return pid;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
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

describe(`the key check: its organisation's share of the connections (PL-63, Postgres ${server.version})`, () => {
  it('waits its turn with the organisation’s agents, holding no connection, and goes on when one ends', async () => {
    const agent = await newAgent();
    const { text } = await issue(agent);
    const shared = createDatabase<Tables>(
      { ...database.connection('app'), maxConnections: 4, organisationShare: 1 },
      testLogger(),
    );
    const letGo = Promise.withResolvers<undefined>();
    const open = Promise.withResolvers<undefined>();
    const full = asAgentTraffic(() =>
      withTenant(shared, org, async () => {
        open.resolve(undefined);
        await letGo.promise;
      }),
    );
    try {
      await open.promise;
      let answered = false;
      const checked = createAgentKeyCheck({ database: shared, keys, ids, clock, logger: testLogger(capture) })
        .check(text, '0199a0f0-0000-7000-8000-00000000c012')
        .finally(() => {
          answered = true;
        });
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(answered).toBe(false);
      letGo.resolve(undefined);
      await expect(checked).resolves.toMatchObject({ outcome: 'accepted' });
    } finally {
      letGo.resolve(undefined);
      await full;
      await shared.destroy();
    }
  });
});

describe(`the key check: a key that may act (C1-4a, Postgres ${server.version})`, () => {
  it('accepts a live key as its agent, in its organisation, logging nothing', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);

    expect(await check(text)).toEqual({
      outcome: 'accepted',
      key: {
        orgId: org,
        agentId: agent,
        keyId: id,
        scopes: ['requests:read'],
        expiresAt: new Date(START.getTime() + 90 * DAY_MS),
      },
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
      logger: testLogger(capture),
    }).check(text, '0199a0f0-0000-7000-8000-00000000c011');

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
      logger: testLogger(capture),
    }).check(text, '0199a0f0-0000-7000-8000-00000000c011');

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

describe(`the key check: one gather, no cache (4D2e C4, forced, Postgres ${server.version})`, () => {
  const correlationId = '0199a0f0-0000-7000-8000-00000000c011';

  /** The key checked in its organisation's transaction alone, with the trips that took: the start, the gather and the commit, when all is believed. */
  const checkedInTransaction = async (text: string) => {
    const presented = parseAgentKey(text);
    if (presented === undefined) throw new Error('not a key');
    const times = noStatementTimes();
    const checked = await timingStatements(times, () =>
      withSignedStates(app, org, { ...quiet(), logger: testLogger(capture) }, (tx, states) =>
        agentKeyAt(tx, states, { keys, now: clock.now() }, org, presented),
      ),
    );
    return { checked, trips: times.trips };
  };

  /** Runs `change` in a transaction of its own and holds it open, its row's lock with it, until `commit` is called. */
  const heldChange = async (change: Parameters<typeof withSignedStates<Tables, unknown>>[3]) => {
    const made = Promise.withResolvers<undefined>();
    const letGo = Promise.withResolvers<undefined>();
    const done = withSignedStates(app, org, quiet(), async (tx, states) => {
      await change(tx, states);
      made.resolve(undefined);
      await letGo.promise;
    });
    await Promise.race([made.promise, done]);
    return {
      commit: async () => {
        letGo.resolve(undefined);
        await done;
      },
    };
  };

  /** Holds what `lock` locks, on a connection of its own, until `end`. */
  const held = async (lock: (holder: TestClient) => Promise<unknown>) => {
    const holder = await database.connect('admin');
    await holder.query('begin');
    await lock(holder);
    return {
      end: async () => {
        await holder.query('rollback');
        await holder.end();
      },
    };
  };

  const agentHeld = (id: string) =>
    held((holder) => holder.query('select 1 from agents.agents where id = $1 for no key update', [id]));

  const keyHeld = (id: string) =>
    held((holder) => holder.query('select 1 from agents.agent_keys where id = $1 for update', [id]));

  /** Whether `lock` is granted at once, on a connection of its own. */
  const grantedNow = async (lock: (asker: TestClient) => Promise<unknown>): Promise<boolean> => {
    const asker = await database.connect('admin');
    try {
      await asker.query('begin');
      await lock(asker);
      return true;
    } catch (error) {
      expect(error).toMatchObject({ code: '55P03' });
      return false;
    } finally {
      await asker.end();
    }
  };

  it.each([
    ['an accepted key', 'accepted', (_agent: string, _id: string) => Promise.resolve()],
    ['a revoked key', 'refused', (_agent: string, id: string) => revoke(id).then(() => undefined)],
    ['a suspended agent', 'refused', (agent: string) => moveAgent(agent, 'suspend').then(() => undefined)],
  ] as const)('takes three trips for %s: the start, the gather, the commit', async (_, outcome, before) => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    await before(agent, id);

    expect(await checkedInTransaction(text)).toMatchObject({ checked: { outcome }, trips: 3 });
  });

  it('takes three trips for a listed key with no row', async () => {
    const id = ids.next();
    await tamperAsOwner(database, AGENT_KEYS, org).then(async (owner) => {
      await owner.query('insert into directory.agent_keys (key_id, org_id) values ($1, $2)', [id, org]);
      await owner.end();
    });

    expect(await checkedInTransaction(agentKeyText(id, Buffer.alloc(32, 1)))).toEqual({
      checked: { outcome: 'refused', reason: 'missing' },
      trips: 3,
    });
  });

  it('refuses a key revoked while the check waited for its lock, on the very call that waited', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    expect(await check(text)).toMatchObject({ outcome: 'accepted' });

    const revoking = await heldChange((tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: org, id }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    );
    const checking = checkedInTransaction(text);
    await waitUntilQueued(database.as('admin'), 1);
    await revoking.commit();

    // The agent believed, the key not: its read alone, on a snapshot after the wait, one trip more.
    expect(await checking).toEqual({ checked: { outcome: 'refused', reason: 'revoked' }, trips: 4 });
    expect(lines('audit.integrity_failed')).toEqual([]);
    await refusedFor(text, 'revoked', id);
  });

  it('refuses a key whose agent was suspended while the check waited for its lock, reading the key again as well', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);

    const suspending = await heldChange((tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: org, id: agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspend',
        details: {},
      }),
    );
    const checking = checkedInTransaction(text);
    await waitUntilQueued(database.as('admin'), 1);
    await suspending.commit();

    // The agent not believed, so nothing after it is: both read alone (S161), two trips more.
    expect(await checking).toEqual({ checked: { outcome: 'refused', reason: 'agent_suspended' }, trips: 5 });
    expect(lines('audit.integrity_failed')).toEqual([]);
    await refusedFor(text, 'agent_suspended', id);
  });

  it('alarms for a key revoked and put back to its older signed state during the wait: the snapshot’s log would agree with it (S157)', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    const owner = await tamperAsOwner(database, AGENT_KEYS, org);
    const saved = await owner.saveRow(id);
    try {
      const checking = await owner.withoutStatusGuard(async () => {
        const holding = await agentHeld(agent);
        // The statement starts here: its snapshot's newest event for the key is the one the row is put back to.
        const waiting = check(text);
        try {
          await waitUntilQueued(database.as('admin'), 1);
          await revoke(id);
          await owner.restoreRow(saved);
        } finally {
          await holding.end();
        }
        // Answered before the guard goes back on: that takes a lock on the table the statement has open.
        return waiting;
      });

      expect(checking).toEqual({ outcome: 'refused' });
      expect(lines('agent_key.refused')).toEqual([expect.objectContaining({ reason: 'tampered', keyId: id })]);
      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ subjectType: 'agent_key' })]);
    } finally {
      await owner.end();
    }
  });

  it('accepts a key whose agent was reactivated during the wait, from the state the wait ended on', async () => {
    const agent = await newAgent();
    const { text } = await issue(agent);
    await moveAgent(agent, 'suspend');

    const reactivating = await heldChange((tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: org, id: agent }, 'reactivate', {
        actor: OPERATOR,
        action: 'agent.reactivate',
        details: {},
      }),
    );
    const checking = checkedInTransaction(text);
    await waitUntilQueued(database.as('admin'), 1);
    await reactivating.commit();

    expect((await checking).checked).toMatchObject({ outcome: 'accepted' });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('locks the agent before the key: waiting for the agent it holds neither', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    const holding = await agentHeld(agent);
    try {
      const checking = check(text);
      await waitUntilBlocked(database.as('admin'), await waitingPid());
      expect(
        await grantedNow((asker) =>
          asker.query('select 1 from agents.agent_keys where id = $1 for update nowait', [id]),
        ),
      ).toBe(true);
      await holding.end();
      await expect(checking).resolves.toMatchObject({ outcome: 'accepted' });
    } catch (error) {
      await holding.end().catch(() => undefined);
      throw error;
    }
  });

  it('locks the agent before the key: waiting for the key it holds the agent, and a change of the agent waits', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    const holding = await keyHeld(id);
    try {
      const checking = check(text);
      await waitUntilBlocked(database.as('admin'), await waitingPid());
      expect(
        await grantedNow((asker) =>
          asker.query('select 1 from agents.agents where id = $1 for update nowait', [agent]),
        ),
      ).toBe(false);
      await holding.end();
      await expect(checking).resolves.toMatchObject({ outcome: 'accepted' });
    } catch (error) {
      await holding.end().catch(() => undefined);
      throw error;
    }
  });

  it('never hangs when the connection is killed in the middle of the gather, and the next check is answered', async () => {
    const agent = await newAgent();
    const { text } = await issue(agent);
    const holding = await agentHeld(agent);
    try {
      const checking = within(20_000, check(text), 'the check');
      const pid = await waitingPid();
      const outcomeOf = expect(checking).rejects.toThrow();
      await database.as('admin').query('select pg_catalog.pg_terminate_backend($1)', [pid]);
      await outcomeOf;
    } finally {
      await holding.end();
    }
    await expect(within(20_000, check(text), 'the next check')).resolves.toMatchObject({ outcome: 'accepted' });
  });

  it('refuses a key whose row reads another agent as the statement starts and its own after the wait: the sealed agent is judged', async () => {
    const agent = await newAgent();
    const other = await newAgent(['requests:read', 'requests:write', 'suppliers:read']);
    const { id, text } = await issue(agent, { scopes: ['requests:read', 'suppliers:read'] });
    const owner = await tamperAsOwner(database, AGENT_KEYS, org);
    try {
      await owner.setColumn(id, 'agent_id', other);
      const holding = await agentHeld(other);
      const checking = check(text);
      await waitUntilQueued(database.as('admin'), 1);
      await owner.setColumn(id, 'agent_id', agent);
      await holding.end();

      expect(await checking).toEqual({ outcome: 'refused' });
      expect(lines('agent_key.agent_disagrees')).toEqual([
        expect.objectContaining({ level: 'error', correlationId, keyId: id }),
      ]);
    } finally {
      await owner.end();
    }
  });

  it('alarms, once, for a key pointed at another agent, and acts as neither', async () => {
    const agent = await newAgent();
    const other = await newAgent();
    const { id, text } = await issue(agent);
    const owner = await tamperAsOwner(database, AGENT_KEYS, org);
    try {
      await owner.setColumn(id, 'agent_id', other);

      await refusedFor(text, 'tampered', id);
      expect(lines('audit.integrity_failed')).toEqual([
        expect.objectContaining({ subjectType: 'agent_key', orgId: org }),
      ]);
      expect(await hold()).toMatchObject({ outcome: 'held' });
    } finally {
      await owner.end();
    }
  });

  it('alarms for a key row deleted past the app, whose log says it was made', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    const owner = await tamperAsOwner(database, AGENT_KEYS, org);
    try {
      await owner.query('delete from agents.agent_keys where org_id = $1 and id = $2', [org, id]);

      await refusedFor(text, 'tampered', id);
      expect(lines('audit.integrity_failed')).toEqual([
        expect.objectContaining({ subjectType: 'agent_key', reason: 'deleted' }),
      ]);
    } finally {
      await owner.end();
    }
  });

  it('alarms for a key pointed at an agent that isn’t there: the key is judged with no agent to be found', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    const owner = await tamperAsOwner(database, AGENT_KEYS, org);
    await owner.query('alter table agents.agent_keys drop constraint of_an_agent');
    try {
      await owner.setColumn(id, 'agent_id', ids.next());

      await refusedFor(text, 'tampered', id);
      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ subjectType: 'agent_key' })]);
    } finally {
      await owner.setColumn(id, 'agent_id', agent);
      await owner.query(
        'alter table agents.agent_keys add constraint of_an_agent foreign key (org_id, agent_id) references agents.agents (org_id, id)',
      );
      await owner.end();
    }
  });

  it('alarms for the agent alone when the agent is tampered with, and stops there', async () => {
    const agent = await newAgent();
    const { id, text } = await issue(agent);
    const owner = await tamperAsOwner(database, AGENTS, org);
    try {
      await owner.setColumn(agent, 'status', 'SUSPENDED');

      await refusedFor(text, 'tampered', id);
      expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ subjectType: 'agent' })]);
    } finally {
      await owner.end();
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

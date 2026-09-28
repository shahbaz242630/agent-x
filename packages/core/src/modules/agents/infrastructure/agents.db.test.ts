// C1-1: agents, their keys and the keys' directory entries (0027), on the real
// migrated schema, as the app role. What the owner can do past the app is
// agents-tamper.db.test.ts.
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase, within } from '@agentx/testing';
import { createDatabase, type Database, TenantContextError, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedAgentKey } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { type Scope, ScopesRefused } from '../domain/agent.ts';
import {
  addAgentKey,
  AGENT_KEYS,
  agentKeyOf,
  agentKeysOf,
  bringKeyExpiryForward,
  keysIssuedSince,
  MOST_KEYS_LISTED,
  TooManyAgentKeys,
} from './agent-keys.ts';
import { addAgent, AGENTS, agentOf, agentsPage, type AgentsTransaction, MOST_AGENTS_A_PAGE } from './agents.ts';
import type { AgentsTables } from './tables.ts';

type Tables = AgentsTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
// Each ID has a hex letter in it, so looking one up in upper case is another string.
const ids = new SequentialIds(0xa000_0000_0000);
const clock = new FixedClock(new Date('2026-09-28T09:00:00Z'));
const DAY_MS = 86_400_000;
const inDays = (days: number) => new Date(clock.now().getTime() + days * DAY_MS);

let capture: LogCapture;
const services = () => ({
  keys,
  ids,
  logger: createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  }),
});

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

/** A new organisation, as the operator's command makes one. */
const organization = async (): Promise<string> => {
  const id = ids.next();
  await withSignedStates(app, id, services(), (tx, states) =>
    createOrganization(tx, states, { id, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return id;
};

const addAnAgent = (orgId: string, scopes: readonly Scope[] = ['requests:read', 'requests:write'], inside = orgId) =>
  withSignedStates(app, inside, services(), async (tx: AgentsTransaction, states) => {
    const id = ids.next();
    const owner = ids.next();
    const recorded = await addAgent(tx, states, {
      orgId,
      id,
      name: 'Purchasing bot',
      owner,
      scopes,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    return { id, owner, recorded };
  });

interface Issuing {
  readonly scopes?: readonly Scope[];
  readonly mac?: Buffer;
  /** The organisation whose transaction it is issued in, if not its own. */
  readonly inside?: string;
}

const issue = (
  orgId: string,
  agentId: string,
  { scopes = ['requests:read'], mac = Buffer.alloc(32, 0x5a), inside = orgId }: Issuing = {},
) =>
  withSignedStates(app, inside, services(), async (tx: AgentsTransaction, states) => {
    const id = ids.next();
    const recorded = await addAgentKey(tx, states, {
      orgId,
      id,
      agentId,
      scopes,
      secretMac: mac,
      secretKeyVersion: 1,
      expiresAt: inDays(90),
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    return { id, recorded };
  });

const readAgent = (orgId: string, id: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => agentOf(tx, states, { orgId, id }, 'share'));

const readKey = (orgId: string, id: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => agentKeyOf(tx, states, { orgId, id }, 'share'));

const keysOf = (orgId: string, agentId: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => agentKeysOf(tx, states, orgId, agentId));

const eventAt = (orgId: string, seq: bigint) =>
  withTenant(app, orgId, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'subject_type', 'subject_id', 'subject_version', 'details'])
      .where('seq', '=', seq)
      .executeTakeFirstOrThrow(),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>(
    { ...database.connection('app'), maxConnections: 4 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe(`adding an agent (C1-1, Postgres ${server.version})`, () => {
  it('adds it ACTIVE with its owner and scopes, its first signed state on the chain, its name on the row alone', async () => {
    const org = await organization();

    const { id, owner, recorded } = await addAnAgent(org, ['requests:write', 'requests:read']);

    expect(recorded).toMatchObject({ version: 1, seq: 3n });
    expect(await readAgent(org, id)).toMatchObject({
      outcome: 'found',
      agent: { id, owner, status: 'ACTIVE', scopes: ['requests:read', 'requests:write'] },
    });
    const row = await withTenant(app, org, (tx) =>
      tx.selectFrom('agents.agents').selectAll().executeTakeFirstOrThrow(),
    );
    expect(row).toEqual({
      org_id: org,
      id,
      name: 'Purchasing bot',
      owner,
      status: 'ACTIVE',
      scopes: 'requests:read requests:write',
      created_at: clock.now(),
      state_version: 1,
      state_event_id: recorded.eventId.toLowerCase(),
    });
    const event = await eventAt(org, 3n);
    expect(event).toMatchObject({ action: 'agent.created', subject_type: 'agent', subject_id: id, subject_version: 1 });
    expect(JSON.parse(event.details)).toMatchObject({ owner, scopes: 'requests:read requests:write' });
    expect(event.details).not.toContain('Purchasing bot');
    expect(alarms()).toEqual([]);
  });

  it('refuses scopes it can’t have before any SQL runs, writing nothing', async () => {
    const org = await organization();

    await expect(addAnAgent(org, [])).rejects.toBeInstanceOf(ScopesRefused);
    await expect(addAnAgent(org, ['requests:delete' as Scope])).rejects.toBeInstanceOf(ScopesRefused);

    expect(await withTenant(app, org, (tx) => tx.selectFrom('agents.agents').select('id').execute())).toEqual([]);
  });

  it("refuses a transaction that isn't withTenant's for the organisation, writing nothing", async () => {
    const org = await organization();
    const other = await organization();

    await expect(addAnAgent(org, ['requests:read'], other)).rejects.toMatchObject({ code: '42501' });

    expect(await withTenant(app, org, (tx) => tx.selectFrom('agents.agents').select('id').execute())).toEqual([]);
  });

  it('is suspended and reactivated through its signed state, and only along its machine', async () => {
    const org = await organization();
    const { id } = await addAnAgent(org);
    const move = (event: 'suspend' | 'reactivate') =>
      withSignedStates(app, org, services(), (tx, states) =>
        states.changeStatus(tx, AGENTS, { orgId: org, id }, event, {
          actor: OPERATOR,
          action: `agent.${event}`,
          details: {},
        }),
      );

    expect(await move('suspend')).toMatchObject({ outcome: 'changed' });
    expect(await readAgent(org, id)).toMatchObject({ agent: { status: 'SUSPENDED' } });
    expect(await move('suspend')).toMatchObject({ outcome: 'refused' });
    expect(await move('reactivate')).toMatchObject({ outcome: 'changed' });
    expect(await readAgent(org, id)).toMatchObject({ agent: { status: 'ACTIVE' } });
    expect(alarms()).toEqual([]);
  });

  it('is missing when there is no such agent, and found by its ID whatever its case', async () => {
    const org = await organization();
    const { id } = await addAnAgent(org);

    expect(await readAgent(org, ids.next())).toEqual({ outcome: 'missing' });
    expect(await readAgent(org, id.toUpperCase())).toMatchObject({ outcome: 'found', agent: { id } });
  });
});

describe('issuing an agent key (C1-1)', () => {
  it('issues it ACTIVE, listed in the directory by its ID, holding the MAC alone, sealed but never in its event', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const mac = Buffer.alloc(32, 0xc3);

    const { id, recorded } = await issue(org, agent, { scopes: ['requests:read'], mac });

    expect(recorded).toMatchObject({ version: 1, seq: 4n });
    expect(await readKey(org, id)).toMatchObject({
      outcome: 'found',
      key: {
        id,
        agentId: agent,
        status: 'ACTIVE',
        scopes: ['requests:read'],
        secretMac: mac,
        secretKeyVersion: 1,
        expiresAt: inDays(90),
      },
    });
    const { row, entries } = await withTenant(app, org, async (tx) => ({
      row: await tx.selectFrom('agents.agent_keys').selectAll().executeTakeFirstOrThrow(),
      entries: await tx.selectFrom('directory.agent_keys').selectAll().where('org_id', '=', org).execute(),
    }));
    expect(row).toMatchObject({ id, agent_id: agent, secret_mac: mac.toString('hex'), created_at: clock.now() });
    expect(entries).toEqual([{ key_id: id, org_id: org }]);
    const event = await eventAt(org, 4n);
    expect(event).toMatchObject({ action: 'agent_key.issued', subject_type: 'agent_key', subject_id: id });
    expect(JSON.parse(event.details)).toMatchObject({
      agentId: agent,
      scopes: 'requests:read',
      expiresAt: inDays(90).toISOString(),
    });
    expect(event.details).not.toContain(mac.toString('hex'));
    expect(alarms()).toEqual([]);
  });

  it('refuses a MAC that isn’t 32 bytes, and scopes it can’t have, before any SQL runs', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);

    await expect(issue(org, agent, { mac: Buffer.alloc(31) })).rejects.toBeInstanceOf(RangeError);
    await expect(issue(org, agent, { mac: Buffer.alloc(33) })).rejects.toBeInstanceOf(RangeError);
    await expect(issue(org, agent, { scopes: [] })).rejects.toBeInstanceOf(ScopesRefused);

    expect(
      await withTenant(app, org, (tx) =>
        tx.selectFrom('directory.agent_keys').select('key_id').where('org_id', '=', org).execute(),
      ),
    ).toEqual([]);
  });

  it("refuses a transaction that isn't withTenant's for the organisation, writing nothing", async () => {
    const org = await organization();
    const other = await organization();
    const { id: agent } = await addAnAgent(org);

    await expect(issue(org, agent, { inside: other })).rejects.toBeInstanceOf(TenantContextError);

    expect(await keysOf(org, agent)).toEqual({ outcome: 'listed', keys: [] });
  });

  it('refuses a key for an agent the organisation doesn’t have, by the key to its agent', async () => {
    const org = await organization();
    const other = await organization();
    const { id: theirs } = await addAnAgent(other);

    await expect(issue(org, theirs)).rejects.toMatchObject({ code: '23503', constraint: 'of_an_agent' });
    await expect(issue(org, ids.next())).rejects.toMatchObject({ code: '23503', constraint: 'of_an_agent' });
  });

  it('is revoked once through its signed state, and never brought back', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id } = await issue(org, agent);
    const revoke = () =>
      withSignedStates(app, org, services(), (tx, states) =>
        states.changeStatus(tx, AGENT_KEYS, { orgId: org, id }, 'revoke', {
          actor: OPERATOR,
          action: 'agent_key.revoked',
          details: {},
        }),
      );

    expect(await revoke()).toMatchObject({ outcome: 'changed' });
    expect(await revoke()).toMatchObject({ outcome: 'refused' });
    expect(await readKey(org, id)).toMatchObject({ key: { status: 'REVOKED' } });
    await expect(
      withTenant(app, org, (tx) =>
        tx.updateTable('agents.agent_keys').set({ status: 'ACTIVE' }).where('id', '=', id).execute(),
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'status_guard' });
  });

  const bringForward = (org: string, id: string, expiresAt: Date) =>
    withSignedStates(app, org, services(), async (tx, states) => {
      const read = await agentKeyOf(tx, states, { orgId: org, id }, 'change');
      if (read.outcome !== 'found') throw new Error('no key');
      return bringKeyExpiryForward(tx, states, {
        orgId: org,
        key: read.key,
        state: read.state,
        expiresAt,
        actor: OPERATOR,
        action: 'agent_key.rotated',
        details: { rotatedTo: 'k-2' },
      });
    });

  it('has its expiry brought forward through its signed state, as a rotation does (C1-4b)', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id } = await issue(org, agent);

    const recorded = await bringForward(org, id, inDays(1));

    expect(await readKey(org, id)).toMatchObject({ outcome: 'found', key: { status: 'ACTIVE', expiresAt: inDays(1) } });
    const event = await eventAt(org, recorded.seq);
    expect(event).toMatchObject({ action: 'agent_key.rotated', subject_type: 'agent_key', subject_version: 2 });
    expect(JSON.parse(event.details)).toMatchObject({ rotatedTo: 'k-2', expiresAt: inDays(1).toISOString() });
    expect(alarms()).toEqual([]);
  });

  it('refuses to move an expiry later, before any SQL runs, and takes the same expiry (C1-4b)', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id } = await issue(org, agent);

    await expect(bringForward(org, id, new Date(inDays(90).getTime() + 1))).rejects.toThrow(RangeError);
    expect(await readKey(org, id)).toMatchObject({ key: { expiresAt: inDays(90) } });
    await expect(bringForward(org, id, inDays(90))).resolves.toMatchObject({ version: 2 });
  });

  it('counts the keys the organisation issued after a time, and no other organisation’s (C1-4b)', async () => {
    const org = await organization();
    const other = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id: theirs } = await addAnAgent(other);
    await issue(org, agent);
    await issue(org, agent);
    await issue(other, theirs);
    const count = (since: Date) => withSignedStates(app, org, services(), (tx) => keysIssuedSince(tx, org, since));

    expect(await count(inDays(-1))).toBe(2);
    expect(await count(clock.now())).toBe(0);
  });
});

describe("the directory's lookup of a key (C1-1)", () => {
  it('places a key in its organisation, whatever the case of its ID, and no other key anywhere', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id } = await issue(org, agent);

    expect(await listedAgentKey(app, id)).toBe(org);
    expect(await listedAgentKey(app, id.toUpperCase())).toBe(org);
    expect(await listedAgentKey(app, ids.next())).toBeUndefined();
  });

  it('refuses a key ID listed already, in any organisation', async () => {
    const org = await organization();
    const other = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id } = await issue(org, agent);

    await expect(
      withTenant(app, other, (tx) =>
        tx.insertInto('directory.agent_keys').values({ key_id: id, org_id: other }).execute(),
      ),
    ).rejects.toMatchObject({ code: '23505', constraint: 'agent_keys_pkey' });
    expect(await listedAgentKey(app, id)).toBe(org);
  });

  it('gives up after 10 seconds, a wait for a lock included, rather than hold the request', async () => {
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table directory.agent_keys in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, listedAgentKey(app, ids.next()), 'the read')).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe("an agent's keys, each verified (C1-1)", () => {
  it('lists every key of the agent in order of ID, revoked ones included, and none of another agent’s', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id: other } = await addAnAgent(org);
    const first = await issue(org, agent);
    await issue(org, other);
    const second = await issue(org, agent, { scopes: ['requests:read', 'requests:write'] });
    await withSignedStates(app, org, services(), (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: org, id: first.id }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    );

    const listed = await keysOf(org, agent);

    expect(listed).toMatchObject({
      outcome: 'listed',
      keys: [
        { id: first.id, status: 'REVOKED' },
        { id: second.id, status: 'ACTIVE', scopes: ['requests:read', 'requests:write'] },
      ],
    });
    expect(await keysOf(org, agent.toUpperCase())).toEqual(listed);
  });

  it('gives no list when a key in it was tampered with: tampered, with the alarm', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id } = await issue(org, agent);
    await withTenant(app, org, (tx) =>
      tx.updateTable('agents.agent_keys').set({ scopes: 'requests:write' }).where('id', '=', id).execute(),
    );

    expect(await keysOf(org, agent)).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(alarms()).toEqual([expect.objectContaining({ subjectType: 'agent_key', objectId: id, reason: 'seal' })]);
  });

  it('leaves out a key whose row names the agent but whose seal names another, and raises the alarm', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id: other } = await addAnAgent(org);
    const { id } = await issue(org, other);
    await withTenant(app, org, (tx) =>
      tx.updateTable('agents.agent_keys').set({ agent_id: agent }).where('id', '=', id).execute(),
    );

    expect(await keysOf(org, agent)).toEqual({ outcome: 'tampered', sign: 'seal' });
  });

  /** One more key than a list reads, issued to the agent in one transaction. */
  const tooManyKeys = (org: string, agent: string) =>
    withSignedStates(app, org, services(), async (tx, states) => {
      for (let count = 0; count <= MOST_KEYS_LISTED; count += 1) {
        await addAgentKey(tx, states, {
          orgId: org,
          id: ids.next(),
          agentId: agent,
          scopes: ['requests:read'],
          secretMac: Buffer.alloc(32, 1),
          secretKeyVersion: 1,
          expiresAt: inDays(90),
          createdAt: clock.now(),
          actor: OPERATOR,
        });
      }
    });

  it(`refuses an agent with more than ${String(MOST_KEYS_LISTED)} keys, rather than cut the list short`, async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    await tooManyKeys(org, agent);

    await expect(keysOf(org, agent)).rejects.toBeInstanceOf(TooManyAgentKeys);
  });

  it('reads the agent’s own keys alone: another agent’s many keys neither count towards its limit nor are read', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id: busy } = await addAnAgent(org);
    const { id } = await issue(org, agent);
    await tooManyKeys(org, busy);

    expect(await keysOf(org, agent)).toMatchObject({ outcome: 'listed', keys: [{ id }] });
  });
});

describe('the walls round an agent and its keys', () => {
  it('SEC-TEN-02 another organisation’s agents and keys are out of sight with no filter at all: row security alone', async () => {
    const mine = await organization();
    const theirs = await organization();
    const { id: agent } = await addAnAgent(mine);
    const { id: key } = await issue(mine, agent);
    const { id: theirAgent } = await addAnAgent(theirs);
    await issue(theirs, theirAgent);

    const seen = await withTenant(app, mine, async (tx) => ({
      agents: await tx.selectFrom('agents.agents').select('id').execute(),
      keys: await tx.selectFrom('agents.agent_keys').select('id').execute(),
    }));
    expect(seen).toEqual({ agents: [{ id: agent }], keys: [{ id: key }] });
    expect(await app.selectFrom('agents.agents').select('id').execute()).toEqual([]);
    expect(await app.selectFrom('agents.agent_keys').select('id').execute()).toEqual([]);
    // Read inside the other organisation, a key is missing: its ID leads nowhere there.
    expect(await readKey(theirs, key)).toEqual({ outcome: 'missing' });
    expect(await readAgent(theirs, agent)).toEqual({ outcome: 'missing' });
  });

  it('an agent or key written for another organisation is refused by the policy’s check', async () => {
    const mine = await organization();
    const theirs = await organization();
    const { id: theirAgent } = await addAnAgent(theirs);

    await expect(
      withTenant(app, mine, (tx) =>
        tx
          .insertInto('agents.agents')
          .values({
            org_id: theirs,
            id: ids.next(),
            name: 'Planted',
            owner: ids.next(),
            status: 'ACTIVE',
            scopes: 'requests:write',
            created_at: clock.now(),
          })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '42501', message: expect.stringContaining('row-level security') as unknown });
    await expect(
      withTenant(app, mine, async (tx) => {
        const id = ids.next();
        await tx.insertInto('directory.agent_keys').values({ key_id: id, org_id: theirs }).execute();
        await tx
          .insertInto('agents.agent_keys')
          .values({
            org_id: theirs,
            id,
            agent_id: theirAgent,
            status: 'ACTIVE',
            scopes: 'requests:write',
            secret_mac: 'ab'.repeat(32),
            secret_key_version: 1,
            expires_at: inDays(1),
            created_at: clock.now(),
          })
          .execute();
      }),
    ).rejects.toMatchObject({ code: '42501', message: expect.stringContaining('row-level security') as unknown });
  });

  it('the app can’t delete an agent or a key, change their keys, names or creation times, nor delete or change an entry', async () => {
    const org = await organization();
    const other = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id: key } = await issue(org, agent);

    const attempts: ((tx: AgentsTransaction) => Promise<unknown>)[] = [
      (tx) => tx.deleteFrom('agents.agents').where('id', '=', agent).execute(),
      (tx) => tx.deleteFrom('agents.agent_keys').where('id', '=', key).execute(),
      (tx) => tx.updateTable('agents.agents').set({ id: ids.next() }).where('id', '=', agent).execute(),
      (tx) => tx.updateTable('agents.agents').set({ org_id: other }).where('id', '=', agent).execute(),
      (tx) => tx.updateTable('agents.agents').set({ name: 'Renamed' }).where('id', '=', agent).execute(),
      (tx) =>
        tx
          .updateTable('agents.agents')
          .set({ created_at: inDays(-400) })
          .where('id', '=', agent)
          .execute(),
      (tx) => tx.updateTable('agents.agent_keys').set({ id: ids.next() }).where('id', '=', key).execute(),
      (tx) =>
        tx
          .updateTable('agents.agent_keys')
          .set({ created_at: inDays(-400) })
          .where('id', '=', key)
          .execute(),
      (tx) => tx.deleteFrom('directory.agent_keys').where('key_id', '=', key).execute(),
      (tx) => tx.updateTable('directory.agent_keys').set({ org_id: other }).where('key_id', '=', key).execute(),
    ];
    for (const attempt of attempts) {
      await expect(withTenant(app, org, attempt)).rejects.toMatchObject({ code: '42501' });
    }

    expect(await readKey(org, key)).toMatchObject({ outcome: 'found', key: { status: 'ACTIVE' } });
  });

  it.each([
    ['with no directory entry', null],
    ['with an entry placing it in another organisation', 'other'],
  ] as const)('a key %s is refused by its key to the directory', async (_, entry) => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const other = await organization();
    const id = ids.next();
    if (entry !== null) {
      await withTenant(app, other, (tx) =>
        tx.insertInto('directory.agent_keys').values({ key_id: id, org_id: other }).execute(),
      );
    }

    await expect(
      withTenant(app, org, async (tx) => {
        await tx
          .insertInto('agents.agent_keys')
          .values({
            org_id: org,
            id,
            agent_id: agent,
            status: 'ACTIVE',
            scopes: 'requests:read',
            secret_mac: 'ab'.repeat(32),
            secret_key_version: 1,
            expires_at: inDays(1),
            created_at: clock.now(),
          })
          .execute();
      }),
    ).rejects.toMatchObject({ code: '23503', constraint: 'listed_in_the_directory' });
  });

  it('the tables refuse what the app never writes: statuses, scopes, MACs, versions and expiries out of shape', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    /** Writes a row past the module, in a transaction rolled back if nothing refuses it. */
    const agentRow = (values: { status?: string; scopes?: string; name?: string }) =>
      withTenant(app, org, async (tx) => {
        await tx
          .insertInto('agents.agents')
          .values({
            org_id: org,
            id: ids.next(),
            name: 'Bot',
            owner: ids.next(),
            status: 'ACTIVE',
            scopes: 'requests:read',
            created_at: clock.now(),
            ...values,
          })
          .execute();
        throw new Error('rolled back');
      });
    const keyRow = (values: {
      status?: string;
      scopes?: string;
      secret_mac?: string;
      secret_key_version?: number;
      expires_at?: Date | string;
    }) =>
      withTenant(app, org, async (tx) => {
        const id = ids.next();
        await tx.insertInto('directory.agent_keys').values({ key_id: id, org_id: org }).execute();
        await tx
          .insertInto('agents.agent_keys')
          .values({
            org_id: org,
            id,
            agent_id: agent,
            status: 'ACTIVE',
            scopes: 'requests:read',
            secret_mac: 'ab'.repeat(32),
            secret_key_version: 1,
            expires_at: inDays(1),
            created_at: clock.now(),
            ...(values as { expires_at?: Date }),
          })
          .execute();
        throw new Error('rolled back');
      });

    await expect(agentRow({})).rejects.toThrow('rolled back');
    await expect(keyRow({})).rejects.toThrow('rolled back');
    await expect(agentRow({ status: 'SUSPENDED' })).rejects.toMatchObject({ constraint: 'status_guard' });
    // A status the machine doesn't have is refused by the guard before the table's own check is reached.
    await expect(agentRow({ status: 'REVOKED' })).rejects.toMatchObject({ constraint: 'status_guard' });
    await expect(agentRow({ name: '' })).rejects.toMatchObject({ constraint: 'agents_name_check' });
    await expect(agentRow({ name: 'x'.repeat(101) })).rejects.toMatchObject({ constraint: 'agents_name_check' });
    for (const scopes of ['', 'requests', 'requests:read ', 'Requests:read', 'requests:read,requests:write']) {
      await expect(agentRow({ scopes })).rejects.toMatchObject({ constraint: 'agents_scopes_check' });
      await expect(keyRow({ scopes })).rejects.toMatchObject({ constraint: 'agent_keys_scopes_check' });
    }
    await expect(keyRow({ status: 'REVOKED' })).rejects.toMatchObject({ constraint: 'status_guard' });
    for (const secret_mac of ['ab'.repeat(31), 'AB'.repeat(32), 'zz'.repeat(32), 'ab'.repeat(33)]) {
      await expect(keyRow({ secret_mac })).rejects.toMatchObject({ constraint: 'agent_keys_secret_mac_check' });
    }
    await expect(keyRow({ secret_key_version: 0 })).rejects.toMatchObject({
      constraint: 'agent_keys_secret_key_version_check',
    });
    for (const expires_at of [clock.now(), inDays(-1), 'infinity']) {
      await expect(keyRow({ expires_at })).rejects.toMatchObject({ constraint: 'expires_after_it_was_made' });
    }
  });

  it('the backup role reads all three tables, every organisation’s rows, as a logical backup must', async () => {
    const org = await organization();
    const { id: agent } = await addAnAgent(org);
    const { id: key } = await issue(org, agent);
    const backup = database.as('backup');

    expect(await backup.query('select org_id from directory.agent_keys where key_id = $1', [key])).toEqual([
      { org_id: org },
    ]);
    expect(await backup.query('select status from agents.agents where id = $1', [agent])).toEqual([
      { status: 'ACTIVE' },
    ]);
    expect(await backup.query('select status from agents.agent_keys where id = $1', [key])).toEqual([
      { status: 'ACTIVE' },
    ]);
  });
});

describe("a page of the organisation's agents (C1-2)", () => {
  it.each([0, MOST_AGENTS_A_PAGE + 1, 1.5])('refuses a page of %s agents before any SQL runs', async (limit) => {
    const org = await organization();

    await expect(
      withSignedStates(app, org, services(), (tx, states) => agentsPage(tx, states, org, { after: null, limit })),
    ).rejects.toBeInstanceOf(RangeError);
  });

  it('gives each agent with its name, and no next page at the end', async () => {
    const org = await organization();
    const { id } = await addAnAgent(org);

    const page = await withSignedStates(app, org, services(), (tx, states) =>
      agentsPage(tx, states, org, { after: null, limit: 1 }),
    );

    expect(page).toMatchObject({ outcome: 'listed', agents: [{ id, name: 'Purchasing bot' }], next: null });
  });
});

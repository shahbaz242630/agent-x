// FX-TAMPER on an agent and an agent key (SEC-DB-10, C1-1), as the database's
// owner: agentx_owner, the role the migration job logs in as, holding none of
// the app's keys (the agent-key pepper among them), working inside one
// organisation through @agentx/testing's tamperAsOwner, as a membership is
// tested (identity/infrastructure/memberships-tamper.db.test.ts;
// organizations/infrastructure/owner-tamper.db.test.ts covers the hold
// itself and the chain).
//
// Each change to an agent's owner, status or scopes, or to a key's agent,
// status, scopes, secret's MAC, pepper version or expiry, is denied by the
// row check, with the SEV-1 alarm, and puts the organisation on its integrity
// hold. The live schema guard, with the product's own list, is clean before
// and after each case, so a leftover can't hide a miss.
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { createDatabase, type Database, liveSchemaProblems } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type AuditTables, type TamperSign, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { addAgentKey, AGENT_KEYS, agentKeyOf } from './agent-keys.ts';
import { addAgent, AGENTS, agentOf } from './agents.ts';
import type { AgentsTables } from './tables.ts';

type Tables = AgentsTables & OrganizationsTables & DirectoryTables & AuditTables;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. The owner has none of them. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x7a0);
const clock = new FixedClock(new Date('2026-09-28T09:00:00Z'));

let capture: LogCapture;
let owners: { agents: OwnerTamper; keys: OwnerTamper };
let org: string;

const services = () => ({ keys, ids, logger: testLogger(capture) });
const quiet = () => ({ keys, ids, logger: testLogger() });
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

/** An agent of this test's organisation, owned by a stand-in membership, with a key, made logging to a capture of their own. */
async function agentWithKey(): Promise<{ agent: string; key: string }> {
  const agent = ids.next();
  const key = ids.next();
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    await addAgent(tx, states, {
      orgId: org,
      id: agent,
      name: 'Purchasing bot',
      owner: ids.next(),
      scopes: ['requests:read'],
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    await addAgentKey(tx, states, {
      orgId: org,
      id: key,
      agentId: agent,
      scopes: ['requests:read'],
      secretMac: Buffer.alloc(32, 0x11),
      secretKeyVersion: 1,
      expiresAt: new Date(clock.now().getTime() + 90 * DAY_MS),
      createdAt: clock.now(),
      actor: OPERATOR,
    });
  });
  return { agent, key };
}

const readAgent = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) => agentOf(tx, states, { orgId: org, id }, 'share'));

const readKey = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) => agentKeyOf(tx, states, { orgId: org, id }, 'share'));

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

const suspend = (id: string) =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    states.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', {
      actor: OPERATOR,
      action: 'agent.suspended',
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

const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Denied with the alarm on the object, and the organisation held for it. */
async function deniedAndHeld(
  read: () => Promise<unknown>,
  subjectType: 'agent' | 'agent_key',
  id: string,
  sign: TamperSign,
): Promise<void> {
  expect(await read()).toEqual({ outcome: 'tampered', sign });
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({
      level: 'error',
      chain: 'organisation',
      check: 'state',
      reason: sign,
      subjectType,
      objectId: id,
      orgId: org,
    }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
  expect(lines('audit.integrity_hold_set')).toEqual([
    expect.objectContaining({ orgId: org, reason: sign, subjectType }),
  ]);
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  owners = { agents: await tamperAsOwner(database, AGENTS, org), keys: await tamperAsOwner(database, AGENT_KEYS, org) };
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owners.agents.end();
  await owners.keys.end();
  expect(await guard()).toEqual([]);
});

describe(`FX-TAMPER as the owner on an agent: denied by the row check, and held (Postgres ${server.version})`, () => {
  it('a suspended agent made active again: the kill switch undone', async () => {
    const { agent } = await agentWithKey();
    await suspend(agent);
    await owners.agents.setColumn(agent, 'status', 'ACTIVE');

    await deniedAndHeld(() => readAgent(agent), 'agent', agent, 'seal');
  });

  it('its scopes widened', async () => {
    const { agent } = await agentWithKey();
    await owners.agents.setColumn(agent, 'scopes', 'requests:read requests:write');

    await deniedAndHeld(() => readAgent(agent), 'agent', agent, 'seal');
  });

  it('moved to another owner', async () => {
    const { agent } = await agentWithKey();
    await owners.agents.setColumn(agent, 'owner', ids.next());

    await deniedAndHeld(() => readAgent(agent), 'agent', agent, 'seal');
  });

  it('a suspended agent rolled back to its saved, validly signed, active state', async () => {
    const { agent } = await agentWithKey();
    const saved = await owners.agents.saveRow(agent);
    await suspend(agent);
    await owners.agents.restoreRow(saved);

    await deniedAndHeld(() => readAgent(agent), 'agent', agent, 'pointer');
  });

  it('planted with no event: an agent the app never added', async () => {
    const agent = ids.next();
    await owners.agents.query(
      "insert into agents.agents (org_id, id, name, owner, status, scopes, created_at) values ($1, $2, 'Planted', $3, 'ACTIVE', 'requests:write', now())",
      [org, agent, ids.next()],
    );

    await deniedAndHeld(() => readAgent(agent), 'agent', agent, 'unsigned');
  });

  it('its events stripped of their seals', async () => {
    const { agent } = await agentWithKey();
    await owners.agents.stripSeals(agent);

    await deniedAndHeld(() => readAgent(agent), 'agent', agent, 'unsigned');
  });
});

describe('FX-TAMPER as the owner on an agent key: denied by the row check, and held', () => {
  it('its secret’s MAC replaced with one for a secret the owner knows', async () => {
    const { key } = await agentWithKey();
    await owners.keys.setColumn(key, 'secret_mac', 'ab'.repeat(32));

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'seal');
  });

  it('its pepper version changed', async () => {
    const { key } = await agentWithKey();
    await owners.keys.setColumn(key, 'secret_key_version', 2);

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'seal');
  });

  it('moved to another agent of the organisation', async () => {
    const { key } = await agentWithKey();
    const { agent: other } = await agentWithKey();
    await owners.keys.setColumn(key, 'agent_id', other);

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'seal');
  });

  it('its scopes widened', async () => {
    const { key } = await agentWithKey();
    await owners.keys.setColumn(key, 'scopes', 'requests:read requests:write');

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'seal');
  });

  it('its expiry stretched', async () => {
    const { key } = await agentWithKey();
    await owners.keys.setColumn(key, 'expires_at', '2099-01-01T00:00:00Z');

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'seal');
  });

  it('a revoked key made active again, with the status guard switched off for it', async () => {
    const { key } = await agentWithKey();
    await revoke(key);
    await owners.keys.withoutStatusGuard(() => owners.keys.setColumn(key, 'status', 'ACTIVE'));

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'seal');
  });

  it('a revoked key rolled back to its saved, validly signed, active state', async () => {
    const { key } = await agentWithKey();
    const saved = await owners.keys.saveRow(key);
    await revoke(key);
    await owners.keys.withoutStatusGuard(() => owners.keys.restoreRow(saved));

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'pointer');
  });

  it('deleted, which the app role cannot do', async () => {
    const { key } = await agentWithKey();
    await owners.keys.deleteRow(key);

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'deleted');
  });

  it('planted with no event: a key the app never issued, for a secret the owner knows', async () => {
    const { agent } = await agentWithKey();
    const key = ids.next();
    await owners.keys.query('insert into directory.agent_keys (key_id, org_id) values ($1, $2)', [key, org]);
    await owners.keys.query(
      "insert into agents.agent_keys (org_id, id, agent_id, status, scopes, secret_mac, secret_key_version, expires_at, created_at) values ($1, $2, $3, 'ACTIVE', 'requests:write', $4, 1, now() + interval '1 day', now())",
      [org, key, agent, 'cd'.repeat(32)],
    );

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'unsigned');
  });

  it('its events stripped of their seals', async () => {
    const { key } = await agentWithKey();
    await owners.keys.stripSeals(key);

    await deniedAndHeld(() => readKey(key), 'agent_key', key, 'unsigned');
  });

  it('the app role given DELETE on either table: the guard names the right', async () => {
    for (const table of ['agents.agents', 'agents.agent_keys']) {
      // The table's name is one of the two above, never input.
      // eslint-disable-next-line agentx/no-string-built-sql -- a fixed name from the list just above
      await owners.keys.query(`grant delete on ${table} to agentx_app`);
      try {
        expect(await guard()).toEqual([`agentx_app may DELETE on ${table}`]);
      } finally {
        // eslint-disable-next-line agentx/no-string-built-sql -- a fixed name from the list just above
        await owners.keys.query(`revoke delete on ${table} from agentx_app`);
      }
    }
  });
});

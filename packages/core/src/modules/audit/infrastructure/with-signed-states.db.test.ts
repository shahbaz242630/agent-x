// B1b: withSignedStates and the integrity hold, on a stand-in authority table
// built as signed-states.db.test.ts builds it. These prove the mechanics:
// when the hold is set, in which transaction, how often, and what the caller
// gets back. The organisation's own row, and the owner's scripts on it and on
// the hold, are the organizations module's owner-tamper.db.test.ts.
import { sealState, stateSealDetails } from '@agentx/platform/audit-chain';
import {
  createTestDatabase,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  type TestSession,
  waitUntilQueued,
} from '@agentx/testing';
import {
  createDatabase,
  type Database,
  type SignedStateTable,
  TenantContextError,
  withTenant,
} from '@agentx/platform/db';
import { createKeyProvider, type KeyMaterial, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import type { Transaction } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { defineStateMachine } from '../../../shared-kernel/index.ts';
import { type AuditTrail, createAuditTrail, recordHoldEvent } from './audit-trail.ts';
import type { SignedStates } from './signed-states.ts';
import type { AuditTables } from './tables.ts';
import { withSignedStates } from './with-signed-states.ts';

const MACHINE = defineStateMachine({
  name: 'agent',
  states: ['ACTIVE', 'SUSPENDED'],
  initial: 'ACTIVE',
  events: {
    suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
    reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
  },
});

/** probe.agents: a status that holds authority. */
const AGENTS = {
  table: 'probe.agents',
  subject: 'agent',
  fields: [{ column: 'status', type: 'text' }],
  rules: MACHINE,
} as const satisfies SignedStateTable & { rules: typeof MACHINE };

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  "create table probe.agents (org_id uuid not null, id uuid not null, status text not null check (status in ('ACTIVE', 'SUSPENDED')), state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))",
  'alter table probe.agents enable row level security',
  'alter table probe.agents force row level security',
  `create policy tenant_isolation on probe.agents ${TENANT_POLICY}`,
  "create trigger status_guard before insert or update on probe.agents for each row execute function state_rules.guard_status('ACTIVE', 'ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE')",
  'grant usage on schema probe to agentx_app',
  'grant select, insert on probe.agents to agentx_app',
  'grant update (status, state_version, state_event_id) on probe.agents to agentx_app',
];

interface ProbeTables {
  'probe.agents': { org_id: string; id: string; status: string };
}

type Tables = AuditTables & ProbeTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;
let attacker: TestSession;

/** Stand-in keys, one per purpose. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ) as unknown as KeyMaterial,
);
const ids = new SequentialIds(0x600);
const trail: AuditTrail = createAuditTrail({ keys, ids });

let capture: LogCapture;
/** What withSignedStates builds each transaction's signed states from, logging to this test's capture. */
const services = () => ({
  keys,
  ids,
  logger: createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  }),
});

let number = 0;
/** A new UUID, so no two tests share an organisation or a row. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x6000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;

const OPERATOR = { type: 'system' as const, id: 'test-operator' };

/** Work in this test's organisation, with signed states that hold it on any tamper sign. */
const inOrg = <T>(work: (tx: Transaction<Tables>, states: SignedStates) => Promise<T>): Promise<T> =>
  withSignedStates(app, org, services(), work);

const CREATED = { actor: OPERATOR, action: 'agent.created', details: {} };

/** Inserts an agent and records its first signed state, in the caller's transaction. */
async function insertAgent(tx: Transaction<Tables>, states: SignedStates, id: string): Promise<void> {
  await tx.insertInto('probe.agents').values({ org_id: org, id, status: 'ACTIVE' }).execute();
  await states.record(tx, AGENTS, { orgId: org, id }, 'new', { status: 'ACTIVE' }, CREATED);
}

/**
 * Adds an agent to this test's organisation. The first time, it creates the
 * organisation as a module does: a row of its own (a stand-in agent whose ID
 * is the organisation's), then its hold, CLEAR, in the same transaction.
 */
async function newAgent(): Promise<string> {
  const id = newId();
  await inOrg(async (tx, states) => {
    if ((await trail.latestSignedState(tx, org, { type: 'integrity_hold', id: org })).kind === 'none') {
      await insertAgent(tx, states, org);
      await states.startIntegrityHold(tx, org, OPERATOR);
    }
    await insertAgent(tx, states, id);
  });
  return id;
}

const check = (id: string) => inOrg((tx, states) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share'));

const hold = () => inOrg((tx, states) => states.integrityHold(tx, org, 'none'));

/** Flips the agent's status past the app, as the server's superuser. */
const flip = (id: string) =>
  attacker.query("update probe.agents set status = 'SUSPENDED' where org_id = $1 and id = $2", [org, id]);

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The hold's events, oldest first: action, version and details. */
async function holdEvents(): Promise<{ action: string; version: number; details: Record<string, unknown> }[]> {
  const rows = await attacker.query<{ action: string; subject_version: number; details: string }>(
    "select action, subject_version, details from audit.events where org_id = $1 and subject_type = 'integrity_hold' order by seq",
    [org],
  );
  return rows.map((row) => ({
    action: row.action,
    version: row.subject_version,
    details: JSON.parse(row.details) as Record<string, unknown>,
  }));
}

/** Resolves as `promise` does, or rejects once `ms` have passed: a wait that could hang by design is bounded. */
async function within<T>(ms: number, promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Waited ${ms.toString()} ms`));
    }, ms);
  });
  try {
    return await Promise.race([promise, late]);
  } finally {
    clearTimeout(timer);
  }
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<Tables>(
    { ...database.connection('app'), maxConnections: 8 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
  attacker = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
  org = newId();
});

describe(`withSignedStates: the integrity hold follows every tamper sign (B1b, Postgres ${server.version})`, () => {
  it('hands back what the work returns, and holds nothing when nothing was found', async () => {
    const id = await newAgent();

    expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 1 });
    expect((await holdEvents()).map(({ action }) => action)).toEqual(['integrity_hold.created']);
    expect(lines('audit.integrity_failed')).toEqual([]);
    expect(lines('audit.integrity_hold_set')).toEqual([]);
  });

  it('found in a transaction that commits: HELD over its CLEAR once it has, and the read still denied', async () => {
    const id = await newAgent();
    await flip(id);

    expect(await check(id)).toEqual({ outcome: 'tampered', sign: 'seal' });

    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    expect(await holdEvents()).toEqual([
      expect.objectContaining({ action: 'integrity_hold.created', version: 1 }),
      {
        action: 'integrity_hold.set',
        version: 2,
        details: expect.objectContaining({
          statusFrom: 'CLEAR',
          statusTo: 'HELD',
          reason: 'seal',
          foundOn: 'agent',
          objectId: id,
          findings: 1,
        }) as unknown,
      },
    ]);
    expect(lines('audit.integrity_hold_set')).toEqual([
      expect.objectContaining({ level: 'warn', orgId: org, reason: 'seal', subjectType: 'agent', findings: 1 }),
    ]);
  });

  it('found in a transaction that then throws: the same error comes back, and the hold is set', async () => {
    const id = await newAgent();
    await flip(id);
    const failure = new Error('the work gives up');

    await expect(
      inOrg(async (tx, states) => {
        await states.verifiedState(tx, AGENTS, { orgId: org, id }, 'change');
        throw failure;
      }),
    ).rejects.toBe(failure);

    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('found by a change that fails holding the chain head: held once it has rolled back, never waiting on it', async () => {
    const id = await newAgent();
    // A trigger keeping the row from taking its pointer: the change fails after its event is recorded.
    await attacker.query(
      'create function probe.planted() returns trigger language plpgsql as $$ begin if old.state_event_id is null and new.state_event_id is not null then return null; end if; return new; end; $$',
    );
    await attacker.query(
      'create trigger planted before update on probe.agents for each row execute function probe.planted()',
    );
    try {
      await expect(
        within(
          10_000,
          inOrg((tx, states) =>
            states.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', {
              actor: OPERATOR,
              action: 'agent.suspend',
              details: {},
            }),
          ),
        ),
      ).rejects.toMatchObject({ name: 'SignedStateFailed', reason: 'not_applied' });
    } finally {
      await attacker.query('drop trigger planted on probe.agents');
      await attacker.query('drop function probe.planted()');
    }

    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ reason: 'row', foundOn: 'agent', objectId: id });
    // The change itself rolled back with its event.
    expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
  });

  it('several signs in one transaction: one HELD event, naming the first and counting them all', async () => {
    const first = await newAgent();
    const second = await newAgent();
    await flip(first);
    await flip(second);

    await inOrg(async (tx, states) => {
      await states.verifiedState(tx, AGENTS, { orgId: org, id: first }, 'share');
      await states.verifiedState(tx, AGENTS, { orgId: org, id: second }, 'share');
    });

    const set = (await holdEvents()).filter(({ action }) => action === 'integrity_hold.set');
    expect(set).toEqual([
      expect.objectContaining({ details: expect.objectContaining({ objectId: first, findings: 2 }) as unknown }),
    ]);
  });

  it('held already: nothing more is recorded, and no second line says it was set', async () => {
    const id = await newAgent();
    await flip(id);

    await check(id);
    await check(id);

    expect((await holdEvents()).map(({ action }) => action)).toEqual(['integrity_hold.created', 'integrity_hold.set']);
    expect(lines('audit.integrity_hold_set')).toHaveLength(1);
    expect(lines('audit.integrity_failed')).toHaveLength(2);
  });

  it("FX-RACE two transactions finding tampering at once: the chain head's lock lets one set the hold", async () => {
    const id = await newAgent();
    await flip(id);
    const locker = await database.connect('admin');
    try {
      await locker.query('begin');
      await locker.query('select seq from audit.heads where org_id = $1 for no key update', [org]);
      const racing = [check(id), check(id)];
      // Both have denied their read and committed; each hold now waits on the head.
      await waitUntilQueued(attacker, 2);
      await locker.query('rollback');

      expect(await Promise.all(racing)).toEqual([
        { outcome: 'tampered', sign: 'seal' },
        { outcome: 'tampered', sign: 'seal' },
      ]);
    } finally {
      await locker.end();
    }

    expect((await holdEvents()).map(({ action }) => action)).toEqual(['integrity_hold.created', 'integrity_hold.set']);
    expect(lines('audit.integrity_hold_set')).toHaveLength(1);
  });
});

describe(`withSignedStates: under the chain head's lock (B1b, Postgres ${server.version})`, () => {
  /** A session of the test's own holding the head's lock, in a transaction the test ends. */
  async function withHeadLocked(mode: 'for share' | 'for no key update', work: () => Promise<void>): Promise<void> {
    const locker = await database.connect('admin');
    try {
      await locker.query('begin');
      if (mode === 'for share') {
        await locker.query('select seq from audit.heads where org_id = $1 for share', [org]);
      } else {
        await locker.query('select seq from audit.heads where org_id = $1 for no key update', [org]);
      }
      await work();
    } finally {
      await locker.query('rollback');
      await locker.end();
    }
  }

  it("FX-RACE a decision reading the hold with the head's lock waits for a hold being set, and reads HELD", async () => {
    const id = await newAgent();
    await flip(id);
    let finding: Promise<unknown> | undefined;
    let deciding: Promise<unknown> | undefined;

    await withHeadLocked('for no key update', async () => {
      finding = check(id);
      // The hold, set once the finding transaction has committed, waits on the head first.
      await waitUntilQueued(attacker, 1);
      deciding = inOrg((tx, states) => states.integrityHold(tx, org, 'head'));
      await waitUntilQueued(attacker, 2);
    });

    expect(await finding).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(await deciding).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('a head held locked past its limit: the work answers, the hold reads as tampered, and is tried again until recorded', async () => {
    const id = await newAgent();
    const clean = await newAgent();
    await flip(id);

    await withHeadLocked('for share', async () => {
      expect(await within(15_000, check(id))).toEqual({ outcome: 'tampered', sign: 'seal' });
    });

    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ check: 'state', reason: 'seal' }),
      expect.objectContaining({ check: 'hold', reason: 'not_recorded', orgId: org }),
    ]);
    // Not recorded yet, so never read as clear here; this transaction's end tries again, with the head free.
    expect(await hold()).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    expect((await holdEvents()).at(-1)?.details).toMatchObject({ reason: 'seal', objectId: id, findings: 1 });
    // Recorded, it is tried no more: a later transaction isn't held up by the head's lock.
    await withHeadLocked('for share', async () => {
      expect(await within(3_000, check(clean))).toMatchObject({ outcome: 'verified' });
    });
    expect(lines('audit.integrity_failed')).toHaveLength(2);
  });

  it("refuses to lock a row after the head's lock, and lets a row locked before it be read and changed", async () => {
    const first = await newAgent();
    const second = await newAgent();

    const moved = await inOrg(async (tx, states) => {
      await states.verifiedState(tx, AGENTS, { orgId: org, id: first }, 'change');
      expect(await states.integrityHold(tx, org, 'head')).toMatchObject({ outcome: 'clear' });
      await expect(states.verifiedState(tx, AGENTS, { orgId: org, id: second }, 'share')).rejects.toMatchObject({
        name: 'SignedStateFailed',
        reason: 'lock_order',
      });
      return states.changeStatus(tx, AGENTS, { orgId: org, id: first }, 'suspend', CREATED);
    });

    expect(moved).toMatchObject({ outcome: 'changed', to: 'SUSPENDED' });
  });

  it('a write meeting a chain that refuses new events raises the alarm (check: record), and its error comes back', async () => {
    await newAgent();
    await attacker.query(
      "update audit.heads set mac = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') where org_id = $1",
      [org],
    );

    await expect(inOrg((tx, states) => insertAgent(tx, states, newId()))).rejects.toMatchObject({
      name: 'ChainBroken',
    });
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ level: 'error', chain: 'organisation', check: 'record', orgId: org }),
    ]);
  });

  it('an organisation ID given in capitals: held all the same, under the one organisation', async () => {
    const id = await newAgent();
    await flip(id);
    const shouted = org.toUpperCase();

    expect(
      await withSignedStates(app, shouted, services(), (tx, states) =>
        states.verifiedState(tx, AGENTS, { orgId: shouted, id }, 'share'),
      ),
    ).toEqual({ outcome: 'tampered', sign: 'seal' });

    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    expect(lines('audit.integrity_hold_set')).toEqual([expect.objectContaining({ orgId: org, findings: 1 })]);
  });
});

describe(`the integrity hold's own state (B1b, Postgres ${server.version})`, () => {
  it('a sealed state that is neither CLEAR nor HELD: tampered (seal), and held over it at the next version', async () => {
    await newAgent();
    // Recorded through the app's own trail with its keys: a real seal, of a status the hold doesn't have.
    await withTenant(app, org, async (tx) => {
      const subject = { type: 'integrity_hold', id: org, version: 2 };
      const seal = sealState(keys, { orgId: org, subject, fields: [['status', 'OPEN']] });
      await recordHoldEvent(trail, tx, org, {
        actor: OPERATOR,
        action: 'integrity_hold.set',
        subject,
        details: { ...stateSealDetails(seal) },
      });
    });

    expect(await hold()).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 3 });
    expect((await holdEvents()).at(-1)?.details).toMatchObject({
      statusFrom: null,
      reason: 'seal',
      foundOn: 'integrity_hold',
    });
  });

  it("starts only after its organisation's own row is created in the same transaction, and only once", async () => {
    await newAgent();
    const refused = { name: 'SignedStateFailed', reason: 'basis' };

    // Its events deleted, it would otherwise start again as CLEAR, wiping out the sign.
    await expect(inOrg((tx, states) => states.startIntegrityHold(tx, org, OPERATOR))).rejects.toMatchObject(refused);
    // Another row created is not the organisation's own.
    await expect(
      inOrg(async (tx, states) => {
        await insertAgent(tx, states, newId());
        await states.startIntegrityHold(tx, org, OPERATOR);
      }),
    ).rejects.toMatchObject(refused);
    const again = newId();
    await expect(
      withSignedStates(app, again, services(), async (tx, states) => {
        await tx.insertInto('probe.agents').values({ org_id: again, id: again, status: 'ACTIVE' }).execute();
        await states.record(tx, AGENTS, { orgId: again, id: again }, 'new', { status: 'ACTIVE' }, CREATED);
        await states.startIntegrityHold(tx, again, OPERATOR);
        await states.startIntegrityHold(tx, again, OPERATOR);
      }),
    ).rejects.toMatchObject(refused);
    expect((await holdEvents()).map(({ action }) => action)).toEqual(['integrity_hold.created']);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it("refused when the organisation's own row is created again, its first deleted past the app: not the chain's first event", async () => {
    await newAgent();
    await attacker.query('delete from probe.agents where org_id = $1 and id = $1', [org]);
    await attacker.query("delete from audit.events where org_id = $1 and subject_type = 'agent' and subject_id = $1", [
      org,
    ]);

    await expect(
      inOrg(async (tx, states) => {
        await insertAgent(tx, states, org);
        await states.startIntegrityHold(tx, org, OPERATOR);
      }),
    ).rejects.toMatchObject({ name: 'SignedStateFailed', reason: 'basis' });

    expect((await holdEvents()).map(({ action, version }) => [action, version])).toEqual([
      ['integrity_hold.created', 1],
    ]);
  });

  it('more than a thousand events about it since its newest signed state: tampered (log), not an error', async () => {
    await newAgent();
    // Unsealed events about the hold, put under the head's number with the head moved past them.
    await attacker.query(
      `insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id,
         subject_version, details, prev_hash, hash, mac, mac_key_version)
       select h.org_id, h.seq + g, gen_random_uuid(), pg_catalog.now(), 'system', 'planted', 'integrity_hold.cleared',
         'integrity_hold', h.org_id, 1, '{}', pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
         pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), 1
       from audit.heads h, pg_catalog.generate_series(1, 1001) as g where h.org_id = $1`,
      [org],
    );
    await attacker.query('update audit.heads set seq = seq + 1001 where org_id = $1', [org]);

    expect(await hold()).toEqual({ outcome: 'tampered', sign: 'log' });
  });

  it("is read, with or without the head's lock, only in withTenant's transaction for the organisation", async () => {
    await newAgent();
    const other = newId();

    for (const lock of ['none', 'head'] as const) {
      await expect(
        withSignedStates(app, other, services(), (tx, states) => states.integrityHold(tx, org, lock)),
      ).rejects.toBeInstanceOf(TenantContextError);
    }
  });

  it("is recorded only by its own steps: the trail's public record refuses its subject type", async () => {
    await newAgent();
    const subject = { type: 'integrity_hold', id: org, version: 2 };
    const seal = sealState(keys, { orgId: org, subject, fields: [['status', 'CLEAR']] });

    await expect(
      withTenant(app, org, (tx) =>
        trail.record(tx, org, {
          actor: OPERATOR,
          action: 'integrity_hold.cleared',
          subject,
          details: { ...stateSealDetails(seal) },
        }),
      ),
    ).rejects.toMatchObject({ name: 'AuditEventRefused' });
    await expect(
      withTenant(app, org, (tx) =>
        recordHoldEvent(trail, tx, org, {
          actor: OPERATOR,
          action: 'agent.created',
          subject: { ...subject, type: 'agent' },
          details: {},
        }),
      ),
    ).rejects.toMatchObject({ name: 'AuditEventRefused' });
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 1 });
  });

  it("belongs to no table: one recorded under the hold's subject type is refused before any SQL", async () => {
    const posing = { ...AGENTS, subject: 'integrity_hold' } as const;

    await expect(
      inOrg((tx, states) => states.verifiedState(tx, posing, { orgId: org, id: org }, 'share')),
    ).rejects.toThrow("The subject type integrity_hold is the integrity hold's own");
    await expect(
      inOrg((tx, states) =>
        states.record(
          tx,
          posing,
          { orgId: org, id: org },
          'new',
          { status: 'ACTIVE' },
          {
            actor: OPERATOR,
            action: 'agent.created',
            details: {},
          },
        ),
      ),
    ).rejects.toThrow("The subject type integrity_hold is the integrity hold's own");
  });
});

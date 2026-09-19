// Signed state (ADR-012 §2), the whole: an authority row recorded and checked
// against the audit log (verifiedState, record, changeStatus), on a stand-in
// table built as a module will build one: a tenant table with a status, its
// guard, and the signed-state columns. The attacker is the server's superuser,
// past every wall, holding none of the app's keys (FX-TAMPER). A3d adds the
// catalogue's full tamper scripts; these prove each check bites.
import { AsyncResource } from 'node:async_hooks';

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
  StatusChangeFailed,
  TenantContextError,
  withTenant,
} from '@agentx/platform/db';
import { createKeyProvider, type KeyMaterial, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { defineStateMachine } from '../../../shared-kernel/index.ts';
import { AuditEventRefused } from '../domain/event.ts';
import { type AuditTrail, type AuditTransaction, createAuditTrail } from './audit-trail.ts';
import { createSignedStates, type SignedStateFailed, type SignedStates, type TamperSign } from './signed-states.ts';
import type { AuditTables } from './tables.ts';

const MACHINE = defineStateMachine({
  name: 'agent',
  states: ['ACTIVE', 'SUSPENDED', 'REVOKED'],
  initial: 'ACTIVE',
  events: {
    suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
    reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
    revoke: { from: ['ACTIVE', 'SUSPENDED'], to: 'REVOKED' },
  },
});

/** probe.agents: status and role hold authority, label doesn't. */
const AGENTS = {
  table: 'probe.agents',
  subject: 'agent',
  fields: [
    { column: 'status', type: 'text' },
    { column: 'role', type: 'text' },
  ],
  rules: MACHINE,
} as const satisfies SignedStateTable & { rules: typeof MACHINE };

const GUARD_ARGUMENTS = [MACHINE.initial, ...MACHINE.moves.map(({ from, to }) => `${from}>${to}`)]
  .map((argument) => `'${argument}'`)
  .join(', ');
const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  "create table probe.agents (org_id uuid not null, id uuid not null, status text not null check (status in ('ACTIVE', 'SUSPENDED', 'REVOKED')), role text not null, label text not null default '', state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))",
  'alter table probe.agents enable row level security',
  'alter table probe.agents force row level security',
  `create policy tenant_isolation on probe.agents ${TENANT_POLICY}`,
  `create trigger status_guard before insert or update on probe.agents for each row execute function state_rules.guard_status(${GUARD_ARGUMENTS})`,
  // As an authority table's rights must be: no DELETE, no UPDATE of org_id or id.
  'grant usage on schema probe to agentx_app',
  'grant select, insert on probe.agents to agentx_app',
  'grant update (status, role, label, state_version, state_event_id) on probe.agents to agentx_app',
];

interface ProbeTables {
  'probe.agents': {
    org_id: string;
    id: string;
    status: string;
    role: string;
    label?: string;
    state_version?: number;
    state_event_id?: string | null;
  };
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
const trail: AuditTrail = createAuditTrail({ keys, ids: new SequentialIds(0x100) });
let capture: LogCapture;
let states: SignedStates;

function loggerFor(destination: LogCapture) {
  return createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
}

const statesWith = (using: AuditTrail): SignedStates =>
  createSignedStates({ keys, trail: using, logger: loggerFor(capture) });

let number = 0;
/** A new UUID, so no two tests share an organisation or a row. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x1000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;

const USER = '0199a0f0-0000-7000-8000-0000000000aa';
const change = (action: string) => ({
  actor: { type: 'user' as const, id: USER },
  action,
  details: { reason: 'test' },
});

/** Inserts an agent and records its first signed state, in one transaction, as a module creates one. */
async function newAgent(role = 'reader', id = newId()): Promise<string> {
  await withTenant(app, org, async (tx) => {
    await tx.insertInto('probe.agents').values({ org_id: org, id, status: 'ACTIVE', role }).execute();
    await states.record(tx, AGENTS, { orgId: org, id }, 'new', change('agent.created'));
  });
  return id;
}

const check = (id: string, using = states) =>
  withTenant(app, org, (tx) => using.verifiedState(tx, AGENTS, { orgId: org, id }, 'share'));

const changeStatus = (id: string, event: 'suspend' | 'reactivate' | 'revoke') =>
  withTenant(app, org, (tx) => states.changeStatus(tx, AGENTS, { orgId: org, id }, event, change(`agent.${event}`)));

/** Runs one statement as the attacker, with the organisation as $1 and the agent as $2. */
const tamper = (statement: string, id: string): Promise<unknown> =>
  // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
  attacker.query(statement, [org, id]);

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

async function eventsAbout(id: string) {
  return attacker.query<{ id: string; seq: string; action: string; subject_version: number; details: string }>(
    'select id, seq, action, subject_version, details from audit.events where org_id = $1 and subject_id = $2 order by seq',
    [org, id],
  );
}

async function rowOf(id: string) {
  const rows = await attacker.query<{ status: string; state_version: number; state_event_id: string | null }>(
    'select status, state_version, state_event_id from probe.agents where org_id = $1 and id = $2',
    [org, id],
  );
  return rows[0];
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 12 }, loggerFor(new LogCapture()));
  attacker = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
  states = statesWith(trail);
  org = newId();
});

describe('ADR-012 §2 an authority row recorded and verified against the log', () => {
  it("records a new row's first state, points the row at it, and verifies it", async () => {
    const id = await newAgent('reader');
    const [created] = await eventsAbout(id);

    expect(created).toMatchObject({ action: 'agent.created', subject_version: 1 });
    const details = JSON.parse(created?.details ?? '{}') as Record<string, unknown>;
    expect(details).toMatchObject({ reason: 'test', stateKeyVersion: 1 });
    expect(details.stateFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(await rowOf(id)).toEqual({ status: 'ACTIVE', state_version: 1, state_event_id: created?.id });
    expect(await check(id)).toEqual({
      outcome: 'verified',
      version: 1,
      eventId: created?.id,
      fields: new Map([
        ['status', 'ACTIVE'],
        ['role', 'reader'],
      ]),
    });
    expect(alarms()).toEqual([]);
  });

  it('changes a status with its signed event, the move in its details (ADR-007 §1.3)', async () => {
    const id = await newAgent();

    const changed = await changeStatus(id, 'suspend');
    const [, suspended] = await eventsAbout(id);

    expect(changed).toEqual({
      outcome: 'changed',
      from: 'ACTIVE',
      to: 'SUSPENDED',
      version: 2,
      eventId: suspended?.id,
    });
    expect(suspended).toMatchObject({ action: 'agent.suspend', subject_version: 2 });
    expect(JSON.parse(suspended?.details ?? '{}')).toMatchObject({
      reason: 'test',
      statusFrom: 'ACTIVE',
      statusTo: 'SUSPENDED',
    });
    expect(await check(id)).toMatchObject({
      outcome: 'verified',
      version: 2,
      fields: new Map([
        ['status', 'SUSPENDED'],
        ['role', 'reader'],
      ]),
    });
    expect(await withTenant(app, org, (tx) => trail.verify(tx, org, undefined))).toMatchObject({ ok: true, seq: 2n });
  });

  it("records a change to another authority field from the row's state verified for change", async () => {
    const id = await newAgent('reader');

    const recorded = await withTenant(app, org, async (tx) => {
      const current = await states.verifiedState(tx, AGENTS, { orgId: org, id }, 'change');
      if (current.outcome !== 'verified') throw new Error('The test expected a verified state');
      await tx
        .updateTable('probe.agents')
        .set({ role: 'admin' })
        .where('org_id', '=', org)
        .where('id', '=', id)
        .execute();
      return states.record(tx, AGENTS, { orgId: org, id }, current, change('agent.role_changed'));
    });

    expect(recorded).toMatchObject({ version: 2, seq: 2n });
    expect(await check(id)).toMatchObject({
      outcome: 'verified',
      version: 2,
      fields: new Map([
        ['status', 'ACTIVE'],
        ['role', 'admin'],
      ]),
    });
  });

  it("refuses a move the machine doesn't allow, and records nothing", async () => {
    const id = await newAgent();
    await changeStatus(id, 'revoke');

    expect(await changeStatus(id, 'reactivate')).toEqual({ outcome: 'refused', from: 'REVOKED' });
    expect(await eventsAbout(id)).toHaveLength(2);
    expect(await check(id)).toMatchObject({ outcome: 'verified', version: 2 });
  });

  it("reports a row that doesn't exist, or is another organisation's, as missing, with no alarm (SEC-TEN-01)", async () => {
    const theirs = await newAgent();
    org = newId();

    expect(await check(newId())).toEqual({ outcome: 'missing' });
    expect(await check(theirs)).toEqual({ outcome: 'missing' });
    expect(await changeStatus(theirs, 'suspend')).toEqual({ outcome: 'missing' });
    expect(alarms()).toEqual([]);
  });

  it("refuses to run in another organisation's transaction, where the row and its log would look missing", async () => {
    const ours = await newAgent();
    const key = { orgId: org, id: ours };

    await expect(
      withTenant(app, newId(), (tx) => states.verifiedState(tx, AGENTS, key, 'share')),
    ).rejects.toBeInstanceOf(TenantContextError);
    await expect(
      withTenant(app, newId(), (tx) => states.changeStatus(tx, AGENTS, key, 'suspend', change('agent.suspend'))),
    ).rejects.toBeInstanceOf(TenantContextError);
  });

  it('checks only the fields that hold authority', async () => {
    const id = await newAgent();
    await tamper("update probe.agents set label = 'renamed' where org_id = $1 and id = $2", id);

    expect(await check(id)).toMatchObject({ outcome: 'verified' });
  });
});

describe('what a signed state is recorded from', () => {
  const recordFrom = (id: string, lock: 'share' | 'change') =>
    withTenant(app, org, async (tx) => {
      const current = await states.verifiedState(tx, AGENTS, { orgId: org, id }, lock);
      if (current.outcome !== 'verified') throw new Error('The test expected a verified state');
      return states.record(tx, AGENTS, { orgId: org, id }, current, change('agent.touched'));
    });

  const refusedFor = (reason: SignedStateFailed['reason']): unknown =>
    expect.objectContaining({ name: 'SignedStateFailed', reason });

  it('refuses a state verified for a decision (share): a change locks the row for change from the start', async () => {
    const id = await newAgent();

    await expect(recordFrom(id, 'share')).rejects.toEqual(refusedFor('basis'));
    await expect(recordFrom(id, 'change')).resolves.toMatchObject({ version: 2 });
  });

  it('refuses a state verified in another transaction, or used once already', async () => {
    const id = await newAgent();
    const current = await withTenant(app, org, (tx) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'change'));
    if (current.outcome !== 'verified') throw new Error('The test expected a verified state');

    await expect(
      withTenant(app, org, (tx) => states.record(tx, AGENTS, { orgId: org, id }, current, change('agent.touched'))),
    ).rejects.toEqual(refusedFor('basis'));
    const second = await withTenant(app, org, async (tx) => {
      const again = await states.verifiedState(tx, AGENTS, { orgId: org, id }, 'change');
      if (again.outcome !== 'verified') throw new Error('The test expected a verified state');
      await states.record(tx, AGENTS, { orgId: org, id }, again, change('agent.touched'));
      return states.record(tx, AGENTS, { orgId: org, id }, again, change('agent.touched')).then(
        () => 'recorded twice',
        (error: unknown) => error,
      );
    });

    expect(second).toEqual(refusedFor('basis'));
    expect(await rowOf(id)).toMatchObject({ state_version: 2 });
  });

  it("refuses another row's verified state", async () => {
    const [one, two] = [await newAgent(), await newAgent()];

    await expect(
      withTenant(app, org, async (tx) => {
        const current = await states.verifiedState(tx, AGENTS, { orgId: org, id: one }, 'change');
        if (current.outcome !== 'verified') throw new Error('The test expected a verified state');
        return states.record(tx, AGENTS, { orgId: org, id: two }, current, change('agent.touched'));
      }),
    ).rejects.toEqual(refusedFor('basis'));
  });

  it('refuses `new` for a row that already has its signed state', async () => {
    const id = await newAgent();

    await expect(
      withTenant(app, org, (tx) => states.record(tx, AGENTS, { orgId: org, id }, 'new', change('agent.created'))),
    ).rejects.toEqual(refusedFor('basis'));
  });

  it('refuses details that carry a seal of their own', async () => {
    const id = newId();

    await expect(
      withTenant(app, org, async (tx) => {
        await tx.insertInto('probe.agents').values({ org_id: org, id, status: 'ACTIVE', role: 'reader' }).execute();
        return states.record(tx, AGENTS, { orgId: org, id }, 'new', {
          ...change('agent.created'),
          details: { stateKeyVersion: 1 },
        });
      }),
    ).rejects.toBeInstanceOf(AuditEventRefused);
  });

  it("refuses a status change on a table that doesn't seal its status", async () => {
    const id = await newAgent();
    const unsealed = { ...AGENTS, fields: [{ column: 'role', type: 'text' }] } as const;

    await expect(
      withTenant(app, org, (tx) =>
        states.changeStatus(tx, unsealed, { orgId: org, id }, 'suspend', change('agent.suspend')),
      ),
    ).rejects.toBeInstanceOf(RangeError);
  });
});

describe('FX-TAMPER: an authority row changed past the app is denied, with the alarm (SEC-DB-10 mechanics)', () => {
  /** The alarm line for the agent: SEV-1's event, the organisation and the object named, nothing else. */
  const alarmFor = (id: string, reason: TamperSign): unknown =>
    expect.objectContaining({
      level: 'error',
      event: 'audit.integrity_failed',
      chain: 'organisation',
      check: 'state',
      reason,
      subjectType: 'agent',
      objectId: id,
      orgId: org,
    });

  /** An edit to the agent's events that keeps each seal where it was: only their own MACs can tell. */
  const EDIT_EVENT = `update audit.events set details = pg_catalog.replace(details, '"reason":"test"', '"reason":"tost"') where org_id = $1 and subject_id = $2`;

  const deniedWith = async (id: string, sign: TamperSign) => {
    expect(await check(id)).toEqual({ outcome: 'tampered', sign });
    expect(alarms()).toEqual([alarmFor(id, sign)]);
  };

  it('a status flipped along a move the guard allows: the fields no longer match the seal', async () => {
    const id = await newAgent();
    await tamper("update probe.agents set status = 'SUSPENDED' where org_id = $1 and id = $2", id);

    await deniedWith(id, 'seal');
  });

  it('a role raised', async () => {
    const id = await newAgent('reader');
    await tamper("update probe.agents set role = 'admin' where org_id = $1 and id = $2", id);

    await deniedWith(id, 'seal');
  });

  it('a row pointed back at an older valid event, its version and status rolled back with it', async () => {
    const id = await newAgent();
    await changeStatus(id, 'suspend');
    const [first] = await eventsAbout(id);
    await attacker.query(
      "update probe.agents set status = 'ACTIVE', state_version = 1, state_event_id = $3 where org_id = $1 and id = $2",
      [org, id, first?.id],
    );

    await deniedWith(id, 'pointer');
  });

  it('a pointer cleared', async () => {
    const id = await newAgent();
    await tamper('update probe.agents set state_event_id = null where org_id = $1 and id = $2', id);

    await deniedWith(id, 'pointer');
  });

  it.each([
    ['rolled back', 1],
    ['moved on', 3],
  ])('a version %s, the pointer left at the latest event', async (_, version) => {
    const id = await newAgent();
    await changeStatus(id, 'suspend');
    await attacker.query('update probe.agents set state_version = $3 where org_id = $1 and id = $2', [
      org,
      id,
      version,
    ]);

    await deniedWith(id, 'version');
  });

  it('its signed event edited, the seal left in place: the event no longer passes its own check', async () => {
    const id = await newAgent();
    await tamper(EDIT_EVENT, id);

    await deniedWith(id, 'log');
  });

  it.each([
    [
      'the seal stripped from its only signed event',
      `update audit.events set details = '{"reason":"test"}' where org_id = $1 and subject_id = $2`,
    ],
    ['its signed events deleted', 'delete from audit.events where org_id = $1 and subject_id = $2'],
    [
      'a row planted past the app, no event about it',
      "insert into probe.agents (org_id, id, status, role, state_event_id) values ($1, $2, 'ACTIVE', 'admin', $2)",
    ],
  ])('%s: nothing signs the row', async (_, statement) => {
    const id = statement.startsWith('insert') ? newId() : await newAgent();
    await tamper(statement, id);

    await deniedWith(id, 'unsigned');
  });

  it("a row deleted, which the app role can't do: its signed state is still in the log", async () => {
    const id = await newAgent();
    await tamper('delete from probe.agents where org_id = $1 and id = $2', id);

    await deniedWith(id, 'deleted');
  });

  it('a row deleted and its latest event edited: the log is the first thing wrong', async () => {
    const id = await newAgent();
    await tamper('delete from probe.agents where org_id = $1 and id = $2', id);
    await tamper(EDIT_EVENT, id);

    await deniedWith(id, 'log');
  });

  it('a version the app never writes', async () => {
    const id = await newAgent();
    await tamper('update probe.agents set state_version = 0 where org_id = $1 and id = $2', id);

    await deniedWith(id, 'row');
  });

  it('is denied on a status change too, which changes nothing', async () => {
    const id = await newAgent();
    await tamper("update probe.agents set role = 'admin' where org_id = $1 and id = $2", id);

    expect(await changeStatus(id, 'suspend')).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(await rowOf(id)).toMatchObject({ status: 'ACTIVE', state_version: 1 });
    expect(await eventsAbout(id)).toHaveLength(1);
  });

  it('a new row whose ID the log already signed: nothing is recorded, and the alarm is raised', async () => {
    const id = await newAgent();
    await tamper('delete from probe.agents where org_id = $1 and id = $2', id);

    await expect(
      withTenant(app, org, async (tx) => {
        await tx.insertInto('probe.agents').values({ org_id: org, id, status: 'ACTIVE', role: 'admin' }).execute();
        return states.record(tx, AGENTS, { orgId: org, id }, 'new', change('agent.created'));
      }),
    ).rejects.toEqual(expect.objectContaining({ name: 'SignedStateFailed', reason: 'tampered' }));
    expect(alarms()).toEqual([alarmFor(id, 'log')]);
    expect(await rowOf(id)).toBeUndefined();
  });

  describe('a trigger planted by the owner', () => {
    /** Adds a BEFORE UPDATE trigger running `body` for the test, and drops it after. */
    async function withTrigger(body: string, work: () => Promise<void>): Promise<void> {
      // eslint-disable-next-line agentx/no-string-built-sql -- The bodies are fixed text, written in the tests below.
      await attacker.query(
        `create function probe.planted() returns trigger language plpgsql as $$ begin ${body} end; $$`,
      );
      await attacker.query(
        'create trigger planted before update on probe.agents for each row execute function probe.planted()',
      );
      try {
        await work();
      } finally {
        await attacker.query('drop trigger planted on probe.agents');
        await attacker.query('drop function probe.planted()');
      }
    }

    it('keeping a status from moving: the change fails, with the alarm', async () => {
      const id = await newAgent();

      await withTrigger('new.status := old.status; return new;', async () => {
        await expect(changeStatus(id, 'suspend')).rejects.toBeInstanceOf(StatusChangeFailed);
      });
      expect(alarms()).toEqual([alarmFor(id, 'status')]);
      expect(await rowOf(id)).toMatchObject({ status: 'ACTIVE', state_version: 1 });
    });

    it('keeping the version from moving on: the change fails, with the alarm', async () => {
      const id = await newAgent();

      await withTrigger('new.state_version := old.state_version; return new;', async () => {
        await expect(changeStatus(id, 'suspend')).rejects.toEqual(
          expect.objectContaining({ name: 'SignedStateFailed', reason: 'not_applied' }),
        );
      });
      expect(alarms()).toEqual([alarmFor(id, 'row')]);
    });

    it('keeping the row from taking its pointer: the change fails, with the alarm', async () => {
      const id = await newAgent();

      await withTrigger(
        'if old.state_event_id is null and new.state_event_id is not null then return null; end if; return new;',
        async () => {
          await expect(changeStatus(id, 'suspend')).rejects.toEqual(
            expect.objectContaining({ name: 'SignedStateFailed', reason: 'not_applied' }),
          );
        },
      );
      expect(alarms()).toEqual([alarmFor(id, 'row')]);
      expect(await rowOf(id)).toMatchObject({ status: 'ACTIVE', state_version: 1 });
    });
  });
});

describe('FX-RACE: a check while the row changes never raises a false alarm', () => {
  it('waits for a status change to commit, then verifies the new state', async () => {
    const id = await newAgent();
    let release = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let recorded = (): void => undefined;
    const done = new Promise<void>((resolve) => {
      recorded = resolve;
    });
    const changing = withTenant(app, org, async (tx) => {
      const outcome = await states.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', change('agent.suspend'));
      recorded();
      await held;
      return outcome;
    });
    try {
      await done;
      const checking = check(id);
      await waitUntilQueued(attacker, 1);
      release();

      expect(await changing).toMatchObject({ outcome: 'changed', version: 2 });
      expect(await checking).toMatchObject({
        outcome: 'verified',
        version: 2,
        fields: new Map([
          ['status', 'SUSPENDED'],
          ['role', 'reader'],
        ]),
      });
    } finally {
      release();
    }
    expect(alarms()).toEqual([]);
  });

  it('holds a change back while a decision reads the row, and the change then goes ahead', async () => {
    const id = await newAgent();
    let release = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let read = (): void => undefined;
    const readDone = new Promise<void>((resolve) => {
      read = resolve;
    });
    const deciding = withTenant(app, org, async (tx) => {
      const checked = await states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share');
      read();
      await held;
      return checked;
    });
    try {
      await readDone;
      const changing = changeStatus(id, 'revoke');
      await waitUntilQueued(attacker, 1);
      release();

      expect(await deciding).toMatchObject({ outcome: 'verified', version: 1 });
      expect(await changing).toMatchObject({ outcome: 'changed', to: 'REVOKED', version: 2 });
    } finally {
      release();
    }
    expect(alarms()).toEqual([]);
  });

  it('checks a row created between reading the row and reading its log: read again, verified', async () => {
    const id = newId();
    // Bound to the test's own context, where no withTenant is open, so the creation is a transaction of its own.
    const create = AsyncResource.bind(() => newAgent('reader', id));
    let createdOnce = false;
    // The log is read only once the row's creation has committed, which a check can meet in production by chance.
    const late: AuditTrail = {
      ...trail,
      latestSignedState: async (tx: AuditTransaction, orgId, subject) => {
        if (!createdOnce) {
          createdOnce = true;
          await create();
        }
        return trail.latestSignedState(tx, orgId, subject);
      },
    };

    expect(await check(id, statesWith(late))).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('many checks while the row changes: every one verified, none alarmed', async () => {
    for (let round = 0; round < 3; round += 1) {
      const id = await newAgent();
      const outcomes = await Promise.all([
        changeStatus(id, 'suspend'),
        ...Array.from({ length: 5 }, () => check(id)),
        changeStatus(id, 'revoke'),
      ]);

      expect(outcomes.filter((outcome) => outcome.outcome === 'tampered')).toEqual([]);
    }
    expect(alarms()).toEqual([]);
  });
});

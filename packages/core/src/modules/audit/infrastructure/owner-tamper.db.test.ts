// A3d, FX-TAMPER on authority state (SEC-DB-10), as the database's owner:
// agentx_owner, the role the migration job logs in as, holding none of the
// app's keys. signed-states.db.test.ts proves each check bites with the
// server's superuser as the attacker; here the attacker is the role the threat
// is really about, working as someone with its password would: inside one
// organisation (forced row security binds it too), through the scripts of
// @agentx/testing's tamperAsOwner.
//
// Each case says which layer catches it: the row check (verifiedState denies
// and raises `audit.integrity_failed`, check `state`), the live schema guard
// (A3e-1b: the same alarm, check `schema`, at start and on every anchor run),
// or the chain's anchor. Two cases get past the row check alone, and are here
// to prove what does catch them: events hidden by a policy (the guard), and
// the chain wound back to an earlier sealed head (the anchor).
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import {
  createDatabase,
  type Database,
  liveSchemaProblems,
  type SignedStateTable,
  withTenant,
} from '@agentx/platform/db';
import { createKeyProvider, type KeyMaterial, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { defineStateMachine } from '../../../shared-kernel/index.ts';
import { type AuditTrail, createAuditTrail } from './audit-trail.ts';
import { createSignedStates, type SignedStates, type TamperSign } from './signed-states.ts';
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

/** A stand-in authority table, built as a module builds one: status and role hold authority. */
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

/** Made by the owner, as a migration would make it, so the schema guard starts with nothing to report. */
const FIXTURE = [
  'create schema probe',
  "create table probe.agents (org_id uuid not null, id uuid not null, status text not null check (status in ('ACTIVE', 'SUSPENDED', 'REVOKED')), role text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))",
  'alter table probe.agents enable row level security',
  'alter table probe.agents force row level security',
  `create policy tenant_isolation on probe.agents ${TENANT_POLICY}`,
  `create trigger status_guard before insert or update on probe.agents for each row execute function state_rules.guard_status(${GUARD_ARGUMENTS})`,
  'grant usage on schema probe to agentx_app',
  'grant select, insert on probe.agents to agentx_app',
  'grant update (status, role, state_version, state_event_id) on probe.agents to agentx_app',
];

interface ProbeTables {
  'probe.agents': {
    org_id: string;
    id: string;
    status: string;
    role: string;
    state_version?: number;
    state_event_id?: string | null;
  };
}

type Tables = AuditTables & ProbeTables;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. The owner has none of them. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ) as unknown as KeyMaterial,
);
const trail: AuditTrail = createAuditTrail({ keys, ids: new SequentialIds(0x300) });

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let capture: LogCapture;
let states: SignedStates;
let owner: OwnerTamper;

let number = 0;
/** A new UUID, so no two tests share an organisation or a row. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x3000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;

const USER = '0199a0f0-0000-7000-8000-0000000000aa';
const change = (action: string) => ({
  actor: { type: 'user' as const, id: USER },
  action,
  details: { reason: 'test' },
});

/** Inserts an agent and records its first signed state, as a module creates one. */
async function newAgent(role = 'reader'): Promise<string> {
  const id = newId();
  await withTenant(app, org, async (tx) => {
    await tx.insertInto('probe.agents').values({ org_id: org, id, status: 'ACTIVE', role }).execute();
    await states.record(tx, AGENTS, { orgId: org, id }, 'new', { status: 'ACTIVE', role }, change('agent.created'));
  });
  return id;
}

const check = (id: string, lock: 'share' | 'change' = 'share') =>
  withTenant(app, org, (tx) => states.verifiedState(tx, AGENTS, { orgId: org, id }, lock));

const changeStatus = (id: string, event: 'suspend' | 'reactivate' | 'revoke') =>
  withTenant(app, org, (tx) => states.changeStatus(tx, AGENTS, { orgId: org, id }, event, change(`agent.${event}`)));

/** The organisation's chain checked whole, against an anchor if one is given. */
const verifyChain = (anchor?: { seq: bigint; hash: Buffer }) =>
  withTenant(app, org, (tx) => trail.verify(tx, org, anchor));

/** What the live schema guard reports, read as the app role on the app's pool. */
const guard = (): Promise<string[]> => liveSchemaProblems(app, ROLES);

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

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

/** Denied read for a decision and read for a change, each with its alarm. */
async function deniedWith(id: string, sign: TamperSign): Promise<void> {
  expect(await check(id)).toEqual({ outcome: 'tampered', sign });
  expect(await check(id, 'change')).toEqual({ outcome: 'tampered', sign });
  expect(alarms()).toEqual([alarmFor(id, sign), alarmFor(id, sign)]);
}

async function eventIdsAbout(id: string): Promise<string[]> {
  const rows = await owner.query<{ id: string }>(
    "select id from audit.events where org_id = $1 and subject_type = 'agent' and subject_id = $2 order by seq",
    [org, id],
  );
  return rows.map((row) => row.id);
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  states = createSignedStates({ keys, trail, logger: loggerFor(capture) });
  org = newId();
  owner = await tamperAsOwner(database, AGENTS, org);
  // Every case starts from a schema the guard is happy with, so a leftover can't hide a miss.
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  // And ends with its tampering undone, or the next case would pass for the wrong reason.
  expect(await guard()).toEqual([]);
});

describe(`FX-TAMPER as the owner: an authority row changed past the app is denied by the row check (Postgres ${server.version})`, () => {
  it.each([
    ['status', 'SUSPENDED'],
    ['role', 'admin'],
  ])('its %s changed, along a move the status guard allows', async (column, value) => {
    const id = await newAgent('reader');
    await owner.setColumn(id, column, value);

    await deniedWith(id, 'seal');
  });

  it('un-revoked: the status guard refuses the move, so the owner switches it off around the change', async () => {
    const id = await newAgent();
    await changeStatus(id, 'revoke');

    await expect(owner.setColumn(id, 'status', 'ACTIVE')).rejects.toThrow(
      "the status of a row in probe.agents can't move from REVOKED to ACTIVE",
    );
    await owner.withoutStatusGuard(async () => {
      expect(await guard()).toContain("probe.agents's status_guard is switched off");
      await owner.setColumn(id, 'status', 'ACTIVE');
    });

    await deniedWith(id, 'seal');
  });

  it('reactivated by rolling the row back to its saved, validly signed state', async () => {
    const id = await newAgent();
    const saved = await owner.saveRow(id);
    await changeStatus(id, 'suspend');
    await owner.restoreRow(saved);

    await deniedWith(id, 'pointer');
  });

  it('un-revoked by rolling the row back, its version and pointer with it, past the switched-off guard', async () => {
    const id = await newAgent();
    const saved = await owner.saveRow(id);
    await changeStatus(id, 'revoke');
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));

    await deniedWith(id, 'pointer');
  });

  it('planted with no event, as an admin membership would be', async () => {
    const id = newId();
    await owner.query("insert into probe.agents (org_id, id, status, role) values ($1, $2, 'ACTIVE', 'admin')", [
      org,
      id,
    ]);

    await deniedWith(id, 'unsigned');
  });

  it('deleted, which the app role cannot do', async () => {
    const id = await newAgent();
    await owner.deleteRow(id);

    await deniedWith(id, 'deleted');
  });

  it.each([
    ['its events stripped of their seals', (tamper: OwnerTamper, id: string) => tamper.stripSeals(id)],
    ['its events deleted', (tamper: OwnerTamper, id: string) => tamper.deleteEvents(id)],
  ])('%s', async (_, tamper) => {
    const id = await newAgent();
    await changeStatus(id, 'suspend');
    await tamper(owner, id);

    await deniedWith(id, 'unsigned');
  });
});

describe('FX-TAMPER as the owner: what gets past the row check alone, and what catches it', () => {
  it('the newest event hidden by a policy of the owner’s and the row rolled back: the schema guard names the policy', async () => {
    const id = await newAgent();
    const saved = await owner.saveRow(id);
    await changeStatus(id, 'revoke');
    const [, revoked] = await eventIdsAbout(id);
    if (revoked === undefined) throw new Error('The test expected the revoke event');

    await owner.withEventsHidden([revoked], async () => {
      await owner.withoutStatusGuard(() => owner.restoreRow(saved));
      // Read through the owner's policy, the older state is the latest: the row check alone can't tell.
      expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
      expect(await guard()).toContain('audit.events does not have exactly one row-security policy');
    });

    // The policy gone, the revoke is the latest again and the row no longer points at it.
    await deniedWith(id, 'pointer');
  });

  it('SEC-DB-11 the chain wound back to its earlier sealed head and the row with it: only the anchor tells', async () => {
    const id = await newAgent();
    const savedRow = await owner.saveRow(id);
    const savedHead = await owner.saveHead();
    await changeStatus(id, 'revoke');
    // The anchor check saw the chain after the revoke and anchored it there.
    const anchored = await verifyChain();
    if (!anchored.ok) throw new Error('The chain should have checked out before the tampering');

    await owner.windBack(savedHead);
    await owner.withoutStatusGuard(() => owner.restoreRow(savedRow));

    // Every seal the owner left is genuine, and nothing in the schema changed.
    expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await verifyChain()).toMatchObject({ ok: true, seq: 1n });
    expect(await guard()).toEqual([]);
    expect(await verifyChain({ seq: anchored.seq, hash: anchored.hash })).toEqual({
      ok: false,
      problem: { reason: 'anchor', seq: 2n },
    });
  });
});

describe('FX-TAMPER as the owner: the S32 probe’s schema changes on an authority table, each named by the guard', () => {
  it('a planted trigger raising the role as a status changes: the change fails with the alarm, and the guard names it', async () => {
    const id = await newAgent('reader');
    await owner.query(
      "create function probe.raise() returns trigger language plpgsql set search_path = pg_catalog as $$ begin new.role := 'admin'; return new; end $$",
    );
    await owner.query('create trigger raise before update on probe.agents for each row execute function probe.raise()');
    try {
      expect(await guard()).toEqual(
        expect.arrayContaining([
          'probe.agents carries the trigger "raise"',
          'probe.raise is a function our schemas should not hold',
        ]),
      );
      await expect(changeStatus(id, 'suspend')).rejects.toEqual(
        expect.objectContaining({ name: 'SignedStateFailed', reason: 'not_applied' }),
      );
    } finally {
      await owner.query('drop trigger raise on probe.agents');
      await owner.query('drop function probe.raise()');
    }
    expect(alarms()).toEqual([alarmFor(id, 'row')]);
    expect(await check(id)).toMatchObject({
      outcome: 'verified',
      version: 1,
      fields: new Map(Object.entries({ status: 'ACTIVE', role: 'reader' })),
    });
  });

  it('a planted rule doing nothing instead of an update: no change goes through, and the guard names it', async () => {
    const id = await newAgent();
    await owner.query('create rule stay as on update to probe.agents do instead nothing');
    try {
      expect(await guard()).toContain('probe.agents carries the rewrite rule "stay"');
      // Postgres refuses the status update's RETURNING under a DO INSTEAD NOTHING rule, so the change stops there.
      await expect(changeStatus(id, 'suspend')).rejects.toThrow('cannot perform UPDATE RETURNING');
    } finally {
      await owner.query('drop rule stay on probe.agents');
    }
    expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await owner.query('select id from audit.events where org_id = $1', [org])).toHaveLength(1);
  });

  it('the table swapped for a view that shows every agent as an admin: the row check denies it, and the guard names it', async () => {
    const id = await newAgent('reader');
    await owner.query('alter table probe.agents rename to agents_real');
    await owner.query(
      "create view probe.agents as select org_id, id, status, 'admin'::text as role, state_version, state_event_id from probe.agents_real",
    );
    // Locking a row takes UPDATE as well as SELECT, and the owner can give both.
    await owner.query('grant select, update on probe.agents to agentx_app');
    try {
      expect(await guard()).toContain('probe.agents is no longer a plain table');
      await deniedWith(id, 'seal');
    } finally {
      await owner.query('drop view probe.agents');
      await owner.query('alter table probe.agents_real rename to agents');
    }
  });

  it.each([
    [
      'row security no longer forced on the owner',
      'alter table probe.agents no force row level security',
      'alter table probe.agents force row level security',
      'probe.agents does not have row-level security forced',
    ],
    [
      'the tenant wall rewritten to let everything through',
      'alter policy tenant_isolation on probe.agents using (true)',
      `alter policy tenant_isolation on probe.agents ${TENANT_POLICY}`,
      "probe.agents's policy reads differently",
    ],
  ])('%s: the guard names it', async (_, tamper, undo, problem) => {
    const id = await newAgent();
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the table above.
    await owner.query(tamper);
    try {
      expect(await guard()).toContain(problem);
      // Nothing about the row itself changed.
      expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
    } finally {
      // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the table above.
      await owner.query(undo);
    }
    expect(alarms()).toEqual([]);
  });

  // The live guard allows DELETE on a tenant table, and doesn't yet know which
  // tables hold authority: that comes with the first entry in
  // tooling/authority-tables.ts (B1). Until then, it is the row check that
  // catches a row the app role was given the right to delete.
  it('the app role given DELETE, and a row deleted with it: the row check denies it', async () => {
    const id = await newAgent();
    await owner.query('grant delete on probe.agents to agentx_app');
    try {
      await withTenant(app, org, (tx) =>
        tx.deleteFrom('probe.agents').where('org_id', '=', org).where('id', '=', id).execute(),
      );
      await deniedWith(id, 'deleted');
    } finally {
      await owner.query('revoke delete on probe.agents from agentx_app');
    }
  });

  it('a search_path pinned to the database over a planted function: new connections ignore it, and the guard names it', async () => {
    const id = await newAgent();
    await owner.query(
      'create function probe.strpos(text, text) returns integer language sql set search_path = pg_catalog as $$ select 0 $$',
    );
    await owner.query(
      "do $$ begin execute pg_catalog.format('alter database %I set search_path = probe, pg_catalog', pg_catalog.current_database()); end $$",
    );
    // A pool of its own, so every connection opens after the setting.
    const fresh = createDatabase<Tables>(
      { ...database.connection('app'), maxConnections: 1 },
      loggerFor(new LogCapture()),
    );
    try {
      expect(await guard()).toEqual(
        expect.arrayContaining([
          'a setting is pinned to this database or to a role',
          'probe.strpos is a function our schemas should not hold',
        ]),
      );
      expect(
        await withTenant(fresh, org, (tx) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share')),
      ).toMatchObject({ outcome: 'verified', version: 1 });
    } finally {
      await fresh.destroy();
      await owner.query(
        "do $$ begin execute pg_catalog.format('alter database %I reset search_path', pg_catalog.current_database()); end $$",
      );
      await owner.query('drop function probe.strpos(text, text)');
    }
    expect(alarms()).toEqual([]);
  });
});

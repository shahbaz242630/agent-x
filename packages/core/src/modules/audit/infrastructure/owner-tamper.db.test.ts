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
// to prove what does catch them: an event hidden from the signed-state read by
// a policy (the guard), and the chain wound back to an earlier sealed head
// (the anchor). The final describe block is what the owner is refused outright.
import {
  createFakeWriteOnceStore,
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  type SavedRow,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import {
  createDatabase,
  type Database,
  liveSchemaProblems,
  type SignedStateTable,
  withTenant,
} from '@agentx/platform/db';
import {
  CHAIN_START,
  type CheckedPoint,
  createDigestLog,
  type DigestAnchors,
  type DigestLog,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import type { WriteOnceStore } from '@agentx/platform/storage';
import { sql, type Transaction } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { defineStateMachine } from '../../../shared-kernel/index.ts';
import { type AuditTrail, createAuditTrail } from './audit-trail.ts';
import { createSignedStates, type SignedStates, type TamperFinding, type TamperSign } from './signed-states.ts';
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
  'create table probe.agents (org_id uuid not null, id uuid not null, status text not null, role text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))',
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
  ),
);
const trail: AuditTrail = createAuditTrail({ keys, ids: new SequentialIds(0x300) });

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

/**
 * What the live schema guard reports, read as the app role on the app's pool,
 * with the stand-in listed as the product lists its authority tables.
 */
const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: [AGENTS] });

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');
/** What every alarm handed on, for the integrity hold. */
let found: TamperFinding[];

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
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  found = [];
  states = createSignedStates({
    keys,
    trail,
    logger: testLogger(capture),
    onTamper: (finding) => found.push(finding),
    unrecorded: () => undefined,
  });
  org = newId();
  owner = await tamperAsOwner(database, AGENTS, org);
  // Every case starts from a schema the guard is happy with, so a leftover can't hide a miss.
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  // Every alarm hands its finding on, for the hold (B1b).
  expect(found).toEqual(
    alarms().map((line) => ({
      orgId: line.orgId,
      subjectType: line.subjectType,
      objectId: line.objectId,
      sign: line.reason,
    })),
  );
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

  it('copied, its key dropped so two rows hold it: the row alarm, not a failed statement (4D2d P3a review)', async () => {
    const id = await newAgent();
    await owner.query('alter table probe.agents drop constraint agents_pkey');
    await owner.query('insert into probe.agents select * from probe.agents where org_id = $1 and id = $2', [org, id]);
    try {
      await deniedWith(id, 'row');
    } finally {
      await owner.query('delete from probe.agents where org_id = $1 and id = $2', [org, id]);
      await owner.query('alter table probe.agents add primary key (org_id, id)');
    }
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
  it('the newest event hidden from the signed-state read alone and the row rolled back: only the schema guard tells', async () => {
    const id = await newAgent();
    const saved = await owner.saveRow(id);
    await changeStatus(id, 'revoke');
    const [, revoked] = await eventIdsAbout(id);
    if (revoked === undefined) throw new Error('The test expected the revoke event');

    // The policy hides the revoke only from a query whose text names strpos:
    // latestSignedState's search for the seal, and no read the chain's check makes.
    const hidden = { fromQueriesContaining: 'strpos' };
    await owner.withEventsHidden(
      [revoked],
      async () => {
        await owner.withoutStatusGuard(() => owner.restoreRow(saved));
        // Read through the owner's policy, the older state is the latest, and the chain still checks out whole.
        expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
        expect(await verifyChain()).toMatchObject({ ok: true, seq: 2n });
        expect(alarms()).toEqual([]);
        expect(await guard()).toContain('audit.events does not have exactly one row-security policy');
      },
      hidden,
    );

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

/**
 * The signed states' digest (AT13) as the anchor check keeps it, and signed states whose reads are held to it, as
 * withSignedStates builds them where a process keeps one. Their alarms hand on to `found`, as the others' do.
 */
/** When the digest's walks are dated: the anchor check's clock, held still. */
const AT13_AT = new Date('2026-11-20T09:00:00.000Z');
let digest: DigestLog;
let held: SignedStates;

/** A digest in memory alone, or kept in `store`, as the anchor check's: read whole first where it is kept. */
async function newDigest(store?: WriteOnceStore, anchors?: DigestAnchors): Promise<DigestLog> {
  const made = createDigestLog({
    store,
    anchors,
    keys,
    logger: testLogger(capture),
    now: () => AT13_AT,
    epoch: 1,
    alertAfterMs: 60_000,
    mostBytes: 64 * 1024 * 1024,
  });
  await made.read();
  return made;
}

/** Signed states whose reads are held to `kept`. */
function heldTo(kept: DigestLog): SignedStates {
  return createSignedStates({
    keys,
    trail: createAuditTrail({ keys, ids: new SequentialIds(0x900), digest: kept }),
    logger: testLogger(capture),
    onTamper: (finding) => found.push(finding),
    unrecorded: () => undefined,
  });
}

/** The anchor check's walk from `from` to the head, kept in the digest as a new anchor keeps it: its anchor. */
async function walked(from: CheckedPoint = CHAIN_START, into: DigestLog = digest): Promise<CheckedPoint> {
  const step = await trail.checkFromAnchor(app, org, from);
  if (!step.ok) throw new Error('The chain should have checked out before the tampering');
  into.record({ kind: 'organisation', orgId: org }, step.signed ?? new Map(), AT13_AT, { from: from.seq, to: step });
  return { seq: step.seq, hash: step.hash, macKeyVersion: step.macKeyVersion };
}

const heldCheck = (id: string, lock: 'share' | 'change' = 'share', states = held) =>
  withTenant(app, org, (tx) => states.verifiedState(tx, AGENTS, { orgId: org, id }, lock));

/** Refused at decision time, for a decision and for a change, each with its alarm naming where the event should be. */
async function caughtAtDecision(id: string, seq: bigint, states = held): Promise<void> {
  expect(await heldCheck(id, 'share', states)).toEqual({ outcome: 'tampered', sign: 'log' });
  expect(await heldCheck(id, 'change', states)).toEqual({ outcome: 'tampered', sign: 'log' });
  const named: unknown = expect.objectContaining({
    event: 'audit.integrity_failed',
    check: 'state',
    reason: 'log',
    subjectType: 'agent',
    objectId: id,
    seq: String(seq),
  });
  expect(alarms()).toEqual([named, named]);
}

describe('FX-TAMPER as the owner: a revocation deleted, or moved off its agent, with the row rolled back (4D2e E8, decisions 1 and 2b; AT13)', () => {
  /** How many of a chain's last events the probe counts and the day walks. */
  const LAST = 1000;

  beforeEach(async () => {
    digest = await newDigest();
    held = heldTo(digest);
  });

  /**
   * An agent revoked, its row saved as it stood before, then `after` events about something else: the revocation that
   * many from the head. The anchor is where the anchor check would have put it, at the head, its walk kept in the
   * digest. Past the last 1,000 is one more: the day's walk reads the event before its window whole, as its start.
   */
  async function revokedThen(after: number) {
    const id = await newAgent();
    const savedRow = await owner.saveRow(id);
    await changeStatus(id, 'revoke');
    const [revocation] = await owner.query<{ seq: string }>(
      "select seq::text as seq from audit.events where org_id = $1 and subject_id = $2 and action = 'agent.revoke'",
      [org, id],
    );
    await withTenant(app, org, async (tx) => {
      for (let step = 1; step <= after; step += 1) {
        await trail.record(tx, org, {
          actor: { type: 'user', id: USER },
          action: 'probe.stepped',
          subject: { type: 'probe', id: USER, version: step },
          details: { step },
        });
      }
    });
    if (revocation === undefined) throw new Error('The revocation should be in the log');
    const anchor = await walked();
    return { id, savedRow, revocation: BigInt(revocation.seq), anchor };
  }

  const probe = async (anchor: CheckedPoint) => (await trail.probeHeads(app, [{ orgId: org, from: anchor }])).get(org);

  /** The row rolled back to before the revocation: the row check alone reads the agent as active again. */
  async function unrevoked(id: string, savedRow: SavedRow): Promise<void> {
    await owner.withoutStatusGuard(() => owner.restoreRow(savedRow));
    expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
  }

  it("deleted among the last 1,000: refused at decision time, and the next run's probe finds it", async () => {
    const { id, savedRow, revocation, anchor } = await revokedThen(3);
    await owner.query('delete from audit.events where org_id = $1 and seq = $2', [org, String(revocation)]);
    await unrevoked(id, savedRow);

    await caughtAtDecision(id, revocation);
    expect(await probe(anchor)).toEqual({ kind: 'failed', problem: { reason: 'gap', seq: 1n } });
  });

  it('deleted among the last 1,000 and made up for by a copy of another, the keys dropped: refused at decision time, and the probe counts numbers, not rows', async () => {
    const { id, savedRow, revocation, anchor } = await revokedThen(3);
    await owner.query('alter table audit.events drop constraint events_pkey');
    await owner.query('alter table audit.events drop constraint events_org_id_id_key');
    try {
      await owner.query('delete from audit.events where org_id = $1 and seq = $2', [org, String(revocation)]);
      // A byte-for-byte copy of a sealed event at its own number: as many rows as before, one number fewer.
      await owner.query('insert into audit.events select * from audit.events where org_id = $1 and seq = $2', [
        org,
        String(revocation + 2n),
      ]);
      await unrevoked(id, savedRow);

      await caughtAtDecision(id, revocation);
      expect(await probe(anchor)).toEqual({ kind: 'failed', problem: { reason: 'gap', seq: 1n } });
      expect(await trail.countStep(app, org, 0n, anchor.seq)).toEqual({ reason: 'gap', seq: 1n });
    } finally {
      await owner.query('delete from audit.events where org_id = $1', [org]);
      await owner.query('alter table audit.events add constraint events_pkey primary key (org_id, seq)');
      await owner.query('alter table audit.events add constraint events_org_id_id_key unique (org_id, id)');
    }
  });

  it("deleted older than the last 1,000: past the probe, refused at decision time, and the day's count finds it too", async () => {
    const { id, savedRow, revocation, anchor } = await revokedThen(LAST + 1);
    await owner.query('delete from audit.events where org_id = $1 and seq = $2', [org, String(revocation)]);
    await unrevoked(id, savedRow);

    // Decision 1's limit, closed by the digest: the probe counts the last 1,000 alone.
    await caughtAtDecision(id, revocation);
    expect(await probe(anchor)).toEqual({ kind: 'same' });
    expect(await trail.countStep(app, org, 0n, anchor.seq)).toEqual({ reason: 'gap', seq: 1n });
  });

  it("moved off its agent among the last 1,000: refused at decision time, the count still exact, the day's walk finds it", async () => {
    const { id, savedRow, revocation, anchor } = await revokedThen(3);
    await owner.query('update audit.events set subject_id = $3 where org_id = $1 and seq = $2', [
      org,
      String(revocation),
      newId(),
    ]);
    await unrevoked(id, savedRow);

    await caughtAtDecision(id, revocation);
    expect(await probe(anchor)).toEqual({ kind: 'same' });
    expect(await trail.countStep(app, org, 0n, anchor.seq)).toBeUndefined();
    expect(await trail.walkLast(app, org, anchor, Number(anchor.seq))).toEqual({
      ok: false,
      problem: { reason: 'hash', seq: revocation },
    });
  });

  it("moved off its agent older than the last 1,000: past the day's walk, refused at decision time, and the full pass finds it too", async () => {
    const { id, savedRow, revocation, anchor } = await revokedThen(LAST + 1);
    await owner.query('update audit.events set subject_id = $3 where org_id = $1 and seq = $2', [
      org,
      String(revocation),
      newId(),
    ]);
    await unrevoked(id, savedRow);

    // Decision 2b's limit, closed by the digest: the day walks the last 1,000 alone.
    await caughtAtDecision(id, revocation);
    expect(await probe(anchor)).toEqual({ kind: 'same' });
    expect(await trail.walkLast(app, org, anchor, LAST)).toMatchObject({ ok: true, seq: anchor.seq });
    expect(await trail.passStep(app, org, CHAIN_START, anchor, 2000)).toEqual({
      ok: false,
      problem: { reason: 'hash', seq: revocation },
    });
  });

  it('deleted and a junk row put at its number, the keys kept: refused at decision time, whatever the row says', async () => {
    const { id, savedRow, revocation } = await revokedThen(3);
    await owner.query('delete from audit.events where org_id = $1 and seq = $2', [org, String(revocation)]);
    // Another event's row moved to the revocation's number under a new ID: the count is whole again.
    await owner.query(
      `insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id,
         subject_version, details, prev_hash, hash, mac, mac_key_version)
       select org_id, $3, gen_random_uuid(), recorded_at, actor_type, actor_id, action, subject_type, subject_id,
         subject_version, details, prev_hash, hash, mac, mac_key_version
       from audit.events where org_id = $1 and seq = $2`,
      [org, String(revocation + 1n), String(revocation)],
    );
    await unrevoked(id, savedRow);

    await caughtAtDecision(id, revocation);
    expect(await trail.countStep(app, org, 0n, revocation + 3n)).toBeUndefined();
  });

  it('a list read of the agents (verifiedStates) is refused the same way, the alarm in its order', async () => {
    const { id, savedRow, revocation } = await revokedThen(LAST + 1);
    await owner.query('delete from audit.events where org_id = $1 and seq = $2', [org, String(revocation)]);
    await unrevoked(id, savedRow);
    const checks = await withTenant(app, org, (tx) => held.verifiedStates(tx, AGENTS, org, [id]));
    expect(checks.get(id)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'log', objectId: id, seq: String(revocation) })]);
  });

  it('the revocation put back (chain-restore puts events back, no rebase): verified again, no further alarm', async () => {
    const { id, savedRow, revocation } = await revokedThen(3);
    await owner.query(
      'create temporary table kept_event as select * from audit.events where org_id = $1 and seq = $2',
      [org, String(revocation)],
    );
    try {
      await owner.query('delete from audit.events where org_id = $1 and seq = $2', [org, String(revocation)]);
      await unrevoked(id, savedRow);
      await caughtAtDecision(id, revocation);
      // The repair: the event back from the copy, the row as the revocation left it.
      await owner.query('insert into audit.events select * from kept_event');
      await owner.withoutStatusGuard(() => owner.setColumn(id, 'status', 'REVOKED'));
      await owner.query('update probe.agents set state_version = 2 where org_id = $1 and id = $2', [org, id]);
      await owner.query(
        'update probe.agents set state_event_id = (select id from kept_event) where org_id = $1 and id = $2',
        [org, id],
      );
      expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 2 });
      expect(alarms()).toHaveLength(2);
    } finally {
      await owner.query('drop table kept_event');
    }
  });

  it('a gathered read never raises the alarm on its own ask of the digest: a row not believed is read again alone', async () => {
    const id = await newAgent();
    await walked();
    // As if a walk had kept a later place between the gather's statement and its ask: the ask after it alone sees it.
    const asks = { count: 0 };
    const racing = heldTo({
      ...digest,
      latest: (chain, type, objectId) => {
        asks.count += 1;
        return asks.count === 1 ? 99n : digest.latest(chain, type, objectId);
      },
    });
    const check = await withTenant(app, org, async (tx) => {
      await racing.gather(tx, org, [{ table: AGENTS, id: { id }, lock: 'share' }]);
      return racing.verifiedState(tx, AGENTS, { orgId: org, id }, 'share');
    });
    expect(check).toMatchObject({ outcome: 'verified', version: 1 });
    expect(asks.count).toBeGreaterThan(1);
    expect(alarms()).toEqual([]);
  });

  it('the agent and every event about it deleted: refused at decision time as rolled back, never read as missing', async () => {
    const { id, revocation } = await revokedThen(3);
    await owner.query('delete from audit.events where org_id = $1 and subject_id = $2', [org, id]);
    await owner.query('delete from probe.agents where org_id = $1 and id = $2', [org, id]);
    expect(await check(id)).toEqual({ outcome: 'missing' });

    expect(await heldCheck(id)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'log', objectId: id, seq: String(revocation) })]);
  });
});

/** A transaction of its own held open at `begun` until `release`: the order forced, never left to chance. */
function heldOpen<T>(work: (tx: Transaction<Tables>, begun: () => void, gate: Promise<void>) => Promise<T>) {
  let release = (): void => undefined;
  let began = (): void => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const begun = new Promise<void>((resolve) => {
    began = resolve;
  });
  const done = withTenant(app, org, (tx) => work(tx, began, gate));
  return {
    begun,
    release: () => {
      release();
    },
    done,
  };
}

describe('SEC-DB-10, SEC-DB-11 AT13: the digest’s edges, as the owner tampers', () => {
  beforeEach(async () => {
    digest = await newDigest();
    held = heldTo(digest);
  });

  it('an object signed past the anchor is not in the digest yet: it reads as ever, and the next walk is what refuses it', async () => {
    const id = await newAgent();
    const anchor = await walked();
    const savedRow = await owner.saveRow(id);
    await changeStatus(id, 'revoke');
    // A change after the anchor reads as itself: the digest knows an older place, never a later one.
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 2 });
    const fresh = await newAgent();
    expect(await heldCheck(fresh)).toMatchObject({ outcome: 'verified', version: 1 });

    // The revocation, past the anchor, deleted and the row rolled back: the stated limit (anchor-check.ts), the next turn.
    const [revocation] = await owner.query<{ seq: string }>(
      "select seq::text as seq from audit.events where org_id = $1 and subject_id = $2 and action = 'agent.revoke'",
      [org, id],
    );
    await owner.query('delete from audit.events where org_id = $1 and seq = $2', [org, revocation?.seq]);
    await owner.withoutStatusGuard(() => owner.restoreRow(savedRow));
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await trail.checkFromAnchor(app, org, anchor)).toMatchObject({ ok: false });
  });

  it('kept in the store and read back by a process started since: still refused at decision time', async () => {
    const fake = createFakeWriteOnceStore();
    const kept = await newDigest(fake.store);
    const id = await newAgent();
    const savedRow = await owner.saveRow(id);
    await changeStatus(id, 'revoke');
    await walked(CHAIN_START, kept);
    await kept.flush();
    await owner.query("delete from audit.events where org_id = $1 and subject_id = $2 and action = 'agent.revoke'", [
      org,
      id,
    ]);
    await owner.withoutStatusGuard(() => owner.restoreRow(savedRow));

    const restarted = await newDigest(fake.store);
    expect(restarted.latest({ kind: 'organisation', orgId: org }, 'agent', id)).toBe(2n);
    await caughtAtDecision(id, 2n, heldTo(restarted));
  });

  it('a rebase of the chain after the walk sets its digest aside: the chain as rebased reads as before the digest', async () => {
    const rebased = new Map<string, Date>();
    const anchors: DigestAnchors = {
      rebasedAfter: (_, at) => (rebased.get(org) ?? new Date(0)) > at,
      holds: () => true,
    };
    const kept = await newDigest(undefined, anchors);
    const id = await newAgent();
    const savedRow = await owner.saveRow(id);
    await changeStatus(id, 'revoke');
    await walked(CHAIN_START, kept);
    await owner.query("delete from audit.events where org_id = $1 and subject_id = $2 and action = 'agent.revoke'", [
      org,
      id,
    ]);
    await owner.withoutStatusGuard(() => owner.restoreRow(savedRow));
    // The operator rebases the chain where it now stands (E11): what the digest knew of it before no longer holds.
    rebased.set(org, new Date(AT13_AT.getTime() + 1000));
    expect(await heldCheck(id, 'share', heldTo(kept))).toMatchObject({ outcome: 'verified', version: 1 });
  });

  it('a digest that knows nothing of the chain (unread, its shard let go) leaves the read as before', async () => {
    const letGo: DigestAnchors = { rebasedAfter: () => false, holds: () => false };
    const kept = await newDigest(undefined, letGo);
    const id = await newAgent();
    const savedRow = await owner.saveRow(id);
    await changeStatus(id, 'revoke');
    await walked(CHAIN_START, kept);
    await owner.query("delete from audit.events where org_id = $1 and subject_id = $2 and action = 'agent.revoke'", [
      org,
      id,
    ]);
    await owner.withoutStatusGuard(() => owner.restoreRow(savedRow));
    expect(kept.covers({ kind: 'organisation', orgId: org }, 1n)).toBe(false);
    expect(await heldCheck(id, 'share', heldTo(kept))).toMatchObject({ outcome: 'verified', version: 1 });
    const unread = createDigestLog({
      store: createFakeWriteOnceStore().store,
      keys,
      logger: testLogger(capture),
      now: () => AT13_AT,
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 1024 * 1024,
    });
    expect(unread.covers({ kind: 'organisation', orgId: org }, 1n)).toBe(false);
    expect(await heldCheck(id, 'share', heldTo(unread))).toMatchObject({ outcome: 'verified', version: 1 });
  });

  it('forced order: a decision whose transaction began before a change, read after the walk kept it, reads the change', async () => {
    const id = await newAgent();
    await walked();
    const decision = heldOpen(async (tx, begun, gate) => {
      // The decision's transaction has begun and read already, before the change below commits.
      await tx.selectFrom('probe.agents').select('id').where('id', '=', id).execute();
      begun();
      await gate;
      return held.verifiedState(tx, AGENTS, { orgId: org, id }, 'share');
    });
    await decision.begun;
    await changeStatus(id, 'suspend');
    await walked();
    expect(digest.latest({ kind: 'organisation', orgId: org }, 'agent', id)).toBe(2n);
    decision.release();
    // Each statement reads on a snapshot taken after the digest was asked: the suspension is there.
    expect(await decision.done).toMatchObject({ outcome: 'verified', version: 2 });
  });

  it('forced order: a walk while a change is under way keeps only what had committed, and the change reads as itself after', async () => {
    const id = await newAgent();
    const anchor = await walked();
    const changing = heldOpen(async (tx, begun, gate) => {
      await states.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', change('agent.suspend'));
      begun();
      await gate;
    });
    await changing.begun;
    // Not committed: the walk, on a connection of its own, reads the chain as it was.
    const step = await trail.checkFromAnchor(app, org, anchor);
    expect(step).toMatchObject({ ok: true, seq: anchor.seq });
    expect(step.signed).toBeUndefined();
    changing.release();
    await changing.done;
    await walked(anchor);
    expect(digest.latest({ kind: 'organisation', orgId: org }, 'agent', id)).toBe(2n);
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 2 });
  });
});

describe('SEC-DB-11 AT13f: the chain cut back past the head this process saw, as the owner tampers', () => {
  const chainOfOrg = () => ({ kind: 'organisation' as const, orgId: org });
  /** A trail whose reads are held to `kept`, for the reads signed states don't make (history, log page, one event). */
  const heldTrail = (kept: DigestLog) => createAuditTrail({ keys, ids: new SequentialIds(0xa00), digest: kept });

  beforeEach(async () => {
    digest = await newDigest();
    held = heldTo(digest);
  });

  /**
   * An agent made below the anchor, and one made above it, read by a decision (the head it read now seen here). Then the
   * owner cuts the chain's end off, the second agent's events with it, puts back the earlier sealed head and deletes the
   * second agent's row: every seal left true, no gap for the next walk.
   */
  async function cutOff(kept: DigestLog = digest) {
    const below = await newAgent();
    const anchor = await walked(CHAIN_START, kept);
    const savedHead = await owner.saveHead();
    const above = await newAgent();
    expect(await heldCheck(above, 'share', heldTo(kept))).toMatchObject({ outcome: 'verified', version: 1 });
    const seenAt = kept.heads(chainOfOrg())?.seen?.seq;
    if (seenAt === undefined || seenAt <= BigInt(savedHead.seq)) throw new Error('The read should have seen the head');
    const savedRow = await owner.saveRow(above);
    await owner.windBack(savedHead);
    await owner.deleteRow(above);
    return { below, above, anchor, seenAt, savedHead, savedRow };
  }

  const tamperedAt = (id: string, seq: bigint): unknown =>
    expect.objectContaining({ event: 'audit.integrity_failed', reason: 'log', objectId: id, seq: String(seq) });

  it('the positive control: read without the heads seen, the agent reads as never made, and the next walk finds nothing', async () => {
    const { above, below, anchor } = await cutOff();
    expect(await check(above)).toEqual({ outcome: 'missing' });
    // A digest of places alone knows nothing of an object signed past the anchor.
    const placesOnly = createSignedStates({
      keys,
      trail: createAuditTrail({
        keys,
        ids: new SequentialIds(0xb00),
        digest: { latest: (...asked) => digest.latest(...asked) },
      }),
      logger: testLogger(capture),
      onTamper: (finding) => found.push(finding),
      unrecorded: () => undefined,
    });
    expect(await heldCheck(above, 'share', placesOnly)).toEqual({ outcome: 'missing' });
    expect(await heldCheck(below, 'share', placesOnly)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await trail.checkFromAnchor(app, org, anchor)).toMatchObject({ ok: true });
    expect(alarms()).toEqual([]);
  });

  it('refused at decision time: the agent cut off and every other object on the chain, the alarm at the head seen', async () => {
    const { above, below, seenAt } = await cutOff();

    expect(await heldCheck(above)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(await heldCheck(below, 'change')).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([tamperedAt(above, seenAt), tamperedAt(below, seenAt)]);
    // Never lowered by what it read cut back.
    expect(digest.heads(chainOfOrg())?.seen?.seq).toBe(seenAt);
  });

  it('a list read and a gathered read are refused the same way; a history, an event and a log page read broken there', async () => {
    const { below, seenAt } = await cutOff();
    const checks = await withTenant(app, org, (tx) => held.verifiedStates(tx, AGENTS, org, [below]));
    expect(checks.get(below)).toEqual({ outcome: 'tampered', sign: 'log' });
    const gathered = await withTenant(app, org, async (tx) => {
      await held.gather(tx, org, [{ table: AGENTS, id: { id: below }, lock: 'share' }]);
      return held.verifiedState(tx, AGENTS, { orgId: org, id: below }, 'share');
    });
    expect(gathered).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([tamperedAt(below, seenAt), tamperedAt(below, seenAt)]);

    const reads = heldTrail(digest);
    const broken = { kind: 'broken', seq: seenAt };
    const about = { subjectTypes: ['agent'], subjectId: below, limit: 10 };
    await withTenant(app, org, async (tx) => {
      expect(await reads.recordedEvents(tx, org, about)).toEqual(broken);
      expect(await reads.recordedHistories(tx, org, [about, about])).toEqual([broken, broken]);
      expect(await reads.recordedEvent(tx, org, { onlyAbout: { type: 'agent', id: below } })).toEqual(broken);
      expect(await reads.recordedEvent(tx, org, { onlyAbout: { type: 'agent', id: newId() } })).toEqual(broken);
      expect(await reads.latestSignedStates(tx, org, 'agent', [below])).toEqual(new Map([[below, broken]]));
      const page = { from: new Date(0), to: new Date('2100-01-01T00:00:00.000Z'), limit: 10 };
      expect(await reads.logPage(tx, org, page)).toEqual(broken);
    });
  });

  it('the whole chain deleted, its head with it: refused, never read as a chain not yet begun', async () => {
    const id = await newAgent();
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    const seenAt = digest.heads(chainOfOrg())?.seen?.seq ?? 0n;
    await owner.query('delete from audit.events where org_id = $1', [org]);
    await owner.query('delete from audit.heads where org_id = $1', [org]);
    await owner.deleteRow(id);
    expect(await check(id)).toEqual({ outcome: 'missing' });

    expect(await heldCheck(id)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([tamperedAt(id, seenAt)]);
  });

  it('a chain grown honestly reads as ever, each read raising the head seen', async () => {
    const id = await newAgent();
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    const first = digest.heads(chainOfOrg())?.seen?.seq ?? 0n;
    expect(first).toBeGreaterThan(0n);
    await changeStatus(id, 'suspend');
    const other = await newAgent();
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 2 });
    expect(await heldCheck(other)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(digest.heads(chainOfOrg())?.seen?.seq).toBe(first + 2n);
    const history = await withTenant(app, org, (tx) =>
      heldTrail(digest).recordedEvents(tx, org, { subjectTypes: ['agent'], subjectId: id, limit: 10 }),
    );
    expect(history).toMatchObject({ kind: 'recorded' });
    expect(alarms()).toEqual([]);
  });

  it('cut back and written on past the head seen, as by a copy that never saw the end: another event at its place, refused', async () => {
    const { below, seenAt } = await cutOff();
    await withTenant(app, org, async (tx) => {
      for (let step = 1; step <= 4; step += 1) {
        await trail.record(tx, org, {
          actor: { type: 'user', id: USER },
          action: 'probe.stepped',
          subject: { type: 'probe', id: USER, version: step },
          details: { step },
        });
      }
    });
    expect(BigInt((await owner.saveHead()).seq)).toBeGreaterThan(seenAt);

    expect(await heldCheck(below)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([tamperedAt(below, seenAt)]);
  });

  it('the events cut off put back from a copy (chain-restore puts events back): read again, no further alarm', async () => {
    const below = await newAgent();
    await walked();
    const savedHead = await owner.saveHead();
    const above = await newAgent();
    expect(await heldCheck(above)).toMatchObject({ outcome: 'verified', version: 1 });
    const seenAt = digest.heads(chainOfOrg())?.seen?.seq ?? 0n;
    const savedRow = await owner.saveRow(above);
    const headThen = await owner.saveHead();
    await owner.query(
      'create temporary table kept_events as select * from audit.events where org_id = $1 and seq > $2::bigint',
      [org, savedHead.seq],
    );
    try {
      await owner.windBack(savedHead);
      await owner.deleteRow(above);
      expect(await heldCheck(below)).toEqual({ outcome: 'tampered', sign: 'log' });
      // The repair: the events back from the copy, the head as it stood, the row as it was.
      await owner.query('insert into audit.events select * from kept_events');
      await owner.query(
        'update audit.heads set seq = $2::bigint, hash = $3, mac = $4, mac_key_version = $5 where org_id = $1',
        [org, headThen.seq, headThen.hash, headThen.mac, headThen.macKeyVersion],
      );
      await owner.query(
        'insert into probe.agents select * from pg_catalog.jsonb_populate_record(null::probe.agents, $1::jsonb)',
        [savedRow.json],
      );
      expect(await heldCheck(above)).toMatchObject({ outcome: 'verified', version: 1 });
      expect(await heldCheck(below)).toMatchObject({ outcome: 'verified', version: 1 });
      expect(alarms()).toEqual([tamperedAt(below, seenAt)]);
    } finally {
      await owner.query('drop table kept_events');
    }
  });

  it('forced order: a transaction’s own events never raise the head seen, and a read beside it sees only what committed', async () => {
    const id = await newAgent();
    const other = await newAgent();
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    const seen = digest.heads(chainOfOrg())?.seen?.seq;
    const writing = heldOpen(async (tx, begun, gate) => {
      await held.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', change('agent.suspend'));
      // Its own read sees its own events: the head they moved, never committed.
      expect(await held.verifiedState(tx, AGENTS, { orgId: org, id }, 'share')).toMatchObject({ version: 2 });
      begun();
      await gate;
      throw new Error('rolled back');
    });
    await writing.begun;
    expect(digest.heads(chainOfOrg())?.seen?.seq).toBe(seen);
    // On its own connection meanwhile: the head as committed.
    expect(await heldCheck(other)).toMatchObject({ outcome: 'verified', version: 1 });
    writing.release();
    await expect(writing.done).rejects.toThrow('rolled back');

    expect(digest.heads(chainOfOrg())?.seen?.seq).toBe(seen);
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('a rebase of the chain after the head was seen sets it aside: the chain as rebased reads as before the digest', async () => {
    const rebased = new Map<string, Date>();
    const anchors: DigestAnchors = {
      rebasedAfter: (_, at) => (rebased.get(org) ?? new Date(0)) > at,
      holds: () => true,
    };
    const kept = await newDigest(undefined, anchors);
    const { above, below } = await cutOff(kept);
    // The operator rebases the chain where it now stands (E11): the head seen before, and the walk's, no longer hold.
    rebased.set(org, new Date(AT13_AT.getTime() + 1000));
    expect(await heldCheck(above, 'share', heldTo(kept))).toEqual({ outcome: 'missing' });
    expect(await heldCheck(below, 'share', heldTo(kept))).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('a restart holds the chain to its anchor read back from the store; what it saw above the anchor goes with the process', async () => {
    const fake = createFakeWriteOnceStore();
    const kept = await newDigest(fake.store);
    const first = await newAgent();
    const belowAnchor = await owner.saveHead();
    const second = await newAgent();
    // One more below the anchor, so the anchor's place is not the second agent's own.
    await newAgent();
    const anchor = await walked(CHAIN_START, kept);
    await kept.flush();
    const atAnchor = await owner.saveHead();
    const above = await newAgent();
    expect(await heldCheck(above, 'share', heldTo(kept))).toMatchObject({ outcome: 'verified', version: 1 });
    const restarted = await newDigest(fake.store);
    expect(restarted.heads(chainOfOrg())?.seen).toEqual({ seq: anchor.seq, hash: anchor.hash });

    // Cut back to the anchor: the agent above it reads as never made (the limit a restart leaves).
    await owner.windBack(atAnchor);
    await owner.deleteRow(above);
    expect(await heldCheck(above, 'share', heldTo(restarted))).toEqual({ outcome: 'missing' });
    // The process that saw it still refuses it.
    expect(await heldCheck(above, 'share', heldTo(kept))).toEqual({ outcome: 'tampered', sign: 'log' });

    // Cut back below the anchor: refused from the anchor read back, even for an object whose own events stand.
    await owner.windBack(belowAnchor);
    await owner.deleteRow(second);
    expect(await heldCheck(first, 'share', heldTo(restarted))).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms().at(-1)).toEqual(tamperedAt(first, anchor.seq));
    // An object the digest knows itself is named at its own place, not the head's: where its newest event should be.
    expect(await heldCheck(second, 'share', heldTo(restarted))).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms().at(-1)).toEqual(tamperedAt(second, BigInt(belowAnchor.seq) + 1n));
  });
});

describe('SEC-DB-11 AT13h: the chain cut back below a write this process committed, before any read of it', () => {
  const chainOfOrg = () => ({ kind: 'organisation' as const, orgId: org });
  const seenNow = (kept: DigestLog = digest) => kept.heads(chainOfOrg())?.seen;
  /** The agent suspended through `through`'s trail, in a transaction of its own that commits. */
  const suspended = (id: string, through: SignedStates = held) =>
    withTenant(app, org, (tx) =>
      through.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', change('agent.suspend')),
    );
  /** The head as the owner reads it, as the trail seals heads: its place and hash. */
  const headNow = async () => {
    const head = await owner.saveHead();
    return { seq: BigInt(head.seq), hash: head.hash };
  };

  beforeEach(async () => {
    digest = await newDigest();
    held = heldTo(digest);
  });

  /**
   * An agent read (the head seen there), then suspended through `writer`'s trail, a commit nobody reads after. The owner
   * then cuts the suspension off with the chain's end, puts back the head read before it and the row as it stood.
   */
  async function writtenThenCut(writer: SignedStates = held) {
    const id = await newAgent();
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    const before = await owner.saveHead();
    const savedRow = await owner.saveRow(id);
    await suspended(id, writer);
    const written = await headNow();
    await owner.windBack(before);
    await owner.withoutStatusGuard(() => owner.restoreRow(savedRow));
    return { id, before: BigInt(before.seq), written };
  }

  const tamperedAt = (id: string, seq: bigint): unknown =>
    expect.objectContaining({ event: 'audit.integrity_failed', reason: 'log', objectId: id, seq: String(seq) });

  it('the positive control: a write by a trail with no heads, never read after, is cut off and its object reads as before', async () => {
    const { id, before } = await writtenThenCut(states);
    expect(seenNow()?.seq).toBe(before);
    // What AT13f left: held to the head the process last read, the suspension reads as never made.
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('writes on the chain as cut, past the head seen, raise nothing: still refused, never hidden (S208)', async () => {
    const { id, written } = await writtenThenCut();
    const trail = createAuditTrail({ keys, ids: new SequentialIds(0xd00), digest });
    for (const step of [1, 2, 3]) {
      await withTenant(app, org, (tx) =>
        trail.record(tx, org, {
          actor: { type: 'user', id: USER },
          action: 'probe.stepped',
          subject: { type: 'probe', id: USER, version: step },
          details: { step },
        }),
      );
    }
    // The chain grown from the cut past the place written: the head seen is not moved onto it.
    expect((await headNow()).seq).toBeGreaterThan(written.seq);
    expect(seenNow()).toEqual(written);
    expect(await heldCheck(id)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([tamperedAt(id, written.seq)]);
  });

  it('a write raises the head seen once it commits: cut back below it, refused at decision time, the alarm at the write', async () => {
    const { id, written } = await writtenThenCut();
    expect(seenNow()).toEqual(written);

    expect(await heldCheck(id)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([tamperedAt(id, written.seq)]);
  });

  it('forced order: raised only once it commits; a read meanwhile sees the head as committed, and none after alarms', async () => {
    const id = await newAgent();
    const other = await newAgent();
    expect(await heldCheck(other)).toMatchObject({ outcome: 'verified', version: 1 });
    const seen = seenNow();
    const writing = heldOpen(async (tx, begun, gate) => {
      await held.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', change('agent.suspend'));
      begun();
      await gate;
    });
    await writing.begun;
    // Written, not committed: nothing raised, and a read on its own connection reads the head as committed.
    expect(seenNow()).toEqual(seen);
    expect(await heldCheck(other)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(seenNow()).toEqual(seen);
    writing.release();
    await writing.done;

    expect(seenNow()).toEqual(await headNow());
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 2 });
    expect(await heldCheck(other)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('forced order: a write rolled back to a savepoint after it, the transaction committed, is never raised', async () => {
    const id = await newAgent();
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    const seen = seenNow();
    await withTenant(app, org, async (tx) => {
      await sql`savepoint probe_write`.execute(tx);
      await held.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', change('agent.suspend'));
      await sql`rollback to savepoint probe_write`.execute(tx);
    });
    expect(seenNow()).toEqual(seen);
    // Nothing of it committed: read as ever, with no false alarm.
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('forced order: written again after the rollback, the second write is what commits, and is raised', async () => {
    const id = await newAgent();
    const other = await newAgent();
    await withTenant(app, org, async (tx) => {
      await sql`savepoint probe_write`.execute(tx);
      await held.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', change('agent.suspend'));
      await sql`rollback to savepoint probe_write`.execute(tx);
      // At the same place as the one rolled back, with another hash.
      await held.changeStatus(tx, AGENTS, { orgId: org, id: other }, 'suspend', change('agent.suspend'));
    });
    const written = await headNow();
    expect(seenNow()).toEqual(written);
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await heldCheck(other)).toMatchObject({ outcome: 'verified', version: 2 });
    expect(alarms()).toEqual([]);
  });

  it('events recorded together raise the head to the last of them, the one the chain moved to', async () => {
    const id = await newAgent();
    const before = await headNow();
    const stepped = (step: number) => ({
      actor: { type: 'user' as const, id: USER },
      action: 'probe.stepped',
      subject: { type: 'probe', id: USER, version: step },
      details: { step },
    });
    await withTenant(app, org, (tx) =>
      createAuditTrail({ keys, ids: new SequentialIds(0xc00), digest }).recordAllAlong(
        tx,
        org,
        [stepped(1), stepped(2), stepped(3)],
        (_, gate) => sql`select 1 as one where ${gate}`,
      ),
    );
    const written = await headNow();
    expect(written.seq).toBe(before.seq + 3n);
    expect(seenNow()).toEqual(written);
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('a write whose transaction rolls back is never raised', async () => {
    const id = await newAgent();
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    const seen = seenNow();
    await expect(
      withTenant(app, org, async (tx) => {
        await held.changeStatus(tx, AGENTS, { orgId: org, id }, 'suspend', change('agent.suspend'));
        throw new Error('rolled back');
      }),
    ).rejects.toThrow('rolled back');
    expect(seenNow()).toEqual(seen);
    expect(await heldCheck(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('a rebase dated after the write was begun sets its head aside: the chain as rebased reads as before', async () => {
    const rebased = new Map<string, Date>();
    const anchors: DigestAnchors = {
      rebasedAfter: (_, at) => (rebased.get(org) ?? new Date(0)) > at,
      holds: () => true,
    };
    const kept = await newDigest(undefined, anchors);
    const { id } = await writtenThenCut(heldTo(kept));
    rebased.set(org, new Date(AT13_AT.getTime() + 1000));
    expect(seenNow(kept)).toBeUndefined();
    expect(await heldCheck(id, 'share', heldTo(kept))).toMatchObject({ outcome: 'verified', version: 1 });
    expect(alarms()).toEqual([]);
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

  it('a planted trigger raising the role as a row is inserted: the signed state holds what the app declared, and the guard names it', async () => {
    await owner.query(
      "create function probe.raise() returns trigger language plpgsql set search_path = pg_catalog as $$ begin new.role := 'admin'; return new; end $$",
    );
    await owner.query('create trigger raise before insert on probe.agents for each row execute function probe.raise()');
    try {
      expect(await guard()).toContain('probe.agents carries the trigger "raise"');
      const id = await newAgent('reader');
      // record writes every declared field after the insert, which the insert trigger doesn't see.
      expect(await check(id)).toMatchObject({
        outcome: 'verified',
        fields: new Map(Object.entries({ status: 'ACTIVE', role: 'reader' })),
      });
    } finally {
      await owner.query('drop trigger raise on probe.agents');
      await owner.query('drop function probe.raise()');
    }
    expect(alarms()).toEqual([]);
  });

  it('a planted rule doing nothing instead of an update: no change goes through, and only the guard raises the alarm', async () => {
    const id = await newAgent();
    await owner.query('create rule stay as on update to probe.agents do instead nothing');
    try {
      expect(await guard()).toContain('probe.agents carries the rewrite rule "stay"');
      // Postgres refuses the status update's RETURNING under a DO INSTEAD NOTHING rule, so the change stops there,
      // as a database error rather than a tampering sign: the guard's next run (at start, or with the anchor check)
      // is what raises the alarm.
      await expect(changeStatus(id, 'suspend')).rejects.toThrow('cannot perform UPDATE RETURNING');
    } finally {
      await owner.query('drop rule stay on probe.agents');
    }
    expect(alarms()).toEqual([]);
    expect(await check(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await owner.query('select id from audit.events where org_id = $1', [org])).toHaveLength(1);
  });

  // Since 4D2d P3a (the partner's choice, S157) a check reads the row's version as locked and as its snapshot saw
  // it (xmin), which a view has none of: the read is refused outright, nothing decided on it, and the scheduled
  // schema check names the view (SEV-1), where before the row check denied it on its seal.
  it('the table swapped for a view that shows every agent as an admin: every check of it refused, and the guard names it', async () => {
    const id = await newAgent('reader');
    await owner.query('alter table probe.agents rename to agents_real');
    await owner.query(
      "create view probe.agents as select org_id, id, status, 'admin'::text as role, state_version, state_event_id from probe.agents_real",
    );
    // Locking a row takes UPDATE as well as SELECT, and the owner can give both.
    await owner.query('grant select, update on probe.agents to agentx_app');
    try {
      expect(await guard()).toContain('probe.agents is no longer a plain table');
      await expect(check(id)).rejects.toThrow('column target.xmin does not exist');
      await expect(check(id, 'change')).rejects.toThrow('column target.xmin does not exist');
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

  // DELETE is a right on an ordinary tenant table; on a listed authority table
  // the guard names it (A3f-2), and a row deleted with it is denied anyway.
  it('the app role given DELETE, and a row deleted with it: the guard names the right, and the row check denies the row', async () => {
    const id = await newAgent();
    await owner.query('grant delete on probe.agents to agentx_app');
    try {
      expect(await guard()).toEqual(['agentx_app may DELETE on probe.agents']);
      await withTenant(app, org, (tx) =>
        tx.deleteFrom('probe.agents').where('org_id', '=', org).where('id', '=', id).execute(),
      );
      await deniedWith(id, 'deleted');
    } finally {
      await owner.query('revoke delete on probe.agents from agentx_app');
    }
  });

  it('a search_path pinned to the database: new connections keep the pinned one, and the guard names it', async () => {
    const id = await newAgent();
    await owner.query(
      "do $$ begin execute pg_catalog.format('alter database %I set search_path = probe, pg_catalog', pg_catalog.current_database()); end $$",
    );
    // A pool of its own, so every connection opens after the setting.
    const fresh = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 1 }, testLogger());
    try {
      expect(await guard()).toContain('a setting is pinned to this database or to a role');
      const path = await sql<{ path: string }>`select pg_catalog.current_setting('search_path') as path`.execute(fresh);
      // A3e-1a's PINNED_SEARCH_PATH_VALUE, set in every connection's startup packet.
      expect(path.rows[0]?.path).toBe('pg_catalog,pg_temp');
      expect(
        await withTenant(fresh, org, (tx) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share')),
      ).toMatchObject({ outcome: 'verified', version: 1 });
    } finally {
      await fresh.destroy();
      await owner.query(
        "do $$ begin execute pg_catalog.format('alter database %I reset search_path', pg_catalog.current_database()); end $$",
      );
    }
    expect(alarms()).toEqual([]);
  });
});

describe('FX-TAMPER as the owner: what it is refused, which needs the server admin', () => {
  it.each([
    ['a cast between built-in types', 'create cast (bigint as text) without function', /must be owner of type/],
    [
      // Scoped to this test's own database, so a refusal that ever stopped
      // holding couldn't leave the setting on the shared test server.
      'a setting pinned to the app role',
      "do $$ begin execute pg_catalog.format('alter role agentx_app in database %I set search_path = probe, pg_catalog', pg_catalog.current_database()); end $$",
      /permission denied to alter role/,
    ],
  ])('%s', async (_, statement, refusal) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the table above.
    const refused = owner.query(statement);
    await expect(refused).rejects.toMatchObject({ code: '42501' });
    await expect(refused).rejects.toThrow(refusal);
  });
});

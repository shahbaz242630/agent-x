// Clearing the integrity hold past 10,000 paid payments (4D2e Stage F,
// decision 5): clearing checks a growing table's rows that can still act and
// its newest 10,000; its older ended ones are the history batches', which a
// clearing waits for (Phase 2 D1c). So no count of payments stops a hold
// clearing, and a paid payment tampered with past the newest is still found,
// by the history batch, and holds the organisation again. A stand-in payments
// table with the product's own live statuses for a transaction; its rows
// signed in bulk through the audit trail, as one module's signed states sign
// them, so 10,001 take seconds, not minutes. The database's owner is the
// attacker (@agentx/testing's tamperAsOwner).
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  type SavedRow,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { sealState, stateSealDetails } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, type SignedStateTable, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { sql, type Transaction } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { type AuditTrail, createAuditTrail, signedEvent } from './audit-trail.ts';
import type { CheckedTable, HistoryBatch, HoldClearing, SignedStates } from './signed-states.ts';
import type { AuditTables } from './tables.ts';
import { withSignedStates } from './with-signed-states.ts';

/** What clearing checks of a table beside its live rows: hold-clearing.ts's OBJECTS_CHECKED. */
const CHECKED = 10_000;
/** The history job's batch (apps/api hold-history-check.ts). */
const BATCH = 500;
/** Events recorded in one step of the chain while signing in bulk. */
const SIGNED_A_STEP = 1000;

/** The product's statuses a transaction can still act in: those clearing checks every row of. */
const LIVE = AUTHORITY_TABLES.find(({ subject }) => subject === 'transaction')?.liveStatuses ?? [];

/** A stand-in for the transactions table: its status sealed, its live statuses the product's own. */
const PAYMENTS = {
  table: 'probe.payments',
  subject: 'transaction',
  fields: [{ column: 'status', type: 'text' }],
  liveStatuses: LIVE,
} as const satisfies CheckedTable;

/** A stand-in for any other authority table: the hold is set from it, by a label changed. */
const AGENTS = {
  table: 'probe.agents',
  subject: 'agent',
  fields: [{ column: 'label', type: 'text' }],
} as const satisfies SignedStateTable;

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  'grant usage on schema probe to agentx_app',
  'create table probe.agents (org_id uuid not null, id uuid not null, label text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))',
  'create table probe.payments (org_id uuid not null, id uuid not null, status text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))',
  ...['agents', 'payments'].flatMap((name) => [
    `alter table probe.${name} enable row level security`,
    `alter table probe.${name} force row level security`,
    `create policy tenant_isolation on probe.${name} ${TENANT_POLICY}`,
    `grant select, insert on probe.${name} to agentx_app`,
  ]),
  'grant update (label, state_version, state_event_id) on probe.agents to agentx_app',
  'grant update (status, state_version, state_event_id) on probe.payments to agentx_app',
];

interface ProbeRow {
  org_id: string;
  id: string;
  state_version?: number;
  state_event_id?: string | null;
}
type Tables = AuditTables & {
  'probe.agents': ProbeRow & { label: string };
  'probe.payments': ProbeRow & { status: string };
};

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. The owner has none of them. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xf13_0000_0000);
const trail: AuditTrail = createAuditTrail({ keys, ids });

let capture: LogCapture;
const services = () => ({ keys, ids, logger: testLogger(capture) });

let number = 0;
/** A new UUID, rising, so a row made later sorts after: the newest are the last made. */
const newId = (): string => {
  number += 1;
  return `0199a0f1-0000-7000-8000-${number.toString(16).padStart(12, '0')}`;
};
let org: string;

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const ADMIN = { type: 'user' as const, id: '0199a0f0-0000-7000-8000-0000000000ad' };
const STEP_UP = {
  stepUpChallengeId: '0199a0f0-0000-7000-8000-0000000000c1',
  changeHash: 'ab'.repeat(32),
  methods: 'pwd user mfa',
};

const inOrg = <T>(work: (tx: Transaction<Tables>, states: SignedStates) => Promise<T>): Promise<T> =>
  withSignedStates(app, org, services(), work);

/**
 * Payments in this status, each with its first signed state, as a module's
 * signed states record one, a thousand events a step of the chain: their IDs,
 * oldest first.
 */
async function payments(count: number, status: string): Promise<string[]> {
  const made = Array.from({ length: count }, newId);
  await withTenant(app, org, async (tx) => {
    await sql`insert into probe.payments (org_id, id, status) select ${org}, made.id, ${status} from pg_catalog.unnest(${made}::uuid[]) as made(id)`.execute(
      tx,
    );
    for (let start = 0; start < made.length; start += SIGNED_A_STEP) {
      const step = made.slice(start, start + SIGNED_A_STEP);
      const events = step.map((id) => {
        const subject = { type: PAYMENTS.subject, id, version: 1 };
        const seal = sealState(keys, { orgId: org, subject, fields: [['status', status]] });
        const details = { ...stateSealDetails(seal) };
        return signedEvent({ actor: OPERATOR, action: 'transaction.opened', subject, details });
      });
      const { recorded } = await trail.recordAllAlong(
        tx,
        org,
        events,
        (last, gate) => sql`select ${last}::text where ${gate}`,
      );
      const eventIds = recorded.map(({ id }) => id);
      await sql`update probe.payments as target set state_event_id = signed.event_id from unnest(${step}::uuid[], ${eventIds}::uuid[]) as signed(id, event_id) where target.org_id = ${org} and target.id = signed.id`.execute(
        tx,
      );
    }
  });
  return made;
}

/** An agent row and its first signed state, in the caller's transaction. */
async function agent(tx: Transaction<Tables>, states: SignedStates, id: string): Promise<void> {
  await tx.insertInto('probe.agents').values({ org_id: org, id, label: 'first' }).execute();
  await states.record(
    tx,
    AGENTS,
    { orgId: org, id },
    'new',
    { label: 'first' },
    {
      actor: OPERATOR,
      action: 'agent.created',
      details: {},
    },
  );
}

/** The hold set as tampering sets it, an agent's label changed past the app and read, then put back; and investigated. */
async function heldAndInvestigated(): Promise<{ holdEventId: string; investigationId: string }> {
  const id = newId();
  await inOrg((tx, states) => agent(tx, states, id));
  const agents = await tamperAsOwner(database, AGENTS, org);
  try {
    const saved = await agents.saveRow(id);
    await agents.setColumn(id, 'label', 'changed');
    await inOrg((tx, states) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share'));
    await agents.restoreRow(saved);
  } finally {
    await agents.end();
  }
  const investigationId = newId();
  const recorded = await inOrg((tx, states) =>
    states.recordInvestigation(tx, org, {
      id: investigationId,
      actor: ADMIN,
      conclusion: 'CAUSE_REMOVED',
      reference: 'INC-13',
    }),
  );
  if (recorded.outcome !== 'recorded') throw new Error('the hold should be HELD');
  return { holdEventId: recorded.investigation.holdEventId, investigationId };
}

/** The history job's pass, a batch a transaction as it checks them: recorded once whole, or tampered. */
async function historyPass(investigationId: string): Promise<'checked' | 'tampered'> {
  const batchAfter = (after: string | null): Promise<HistoryBatch> =>
    inOrg((tx, states) => states.checkHistoryBatch(tx, org, PAYMENTS, after, BATCH));
  let batch = await batchAfter(null);
  let objects = 0;
  for (;;) {
    if (batch.outcome === 'tampered') return 'tampered';
    objects += batch.objects;
    if (batch.done) break;
    batch = await batchAfter(batch.last);
  }
  await inOrg((tx, states) => states.recordHistoryChecked(tx, org, investigationId, objects));
  return 'checked';
}

/** Clears as hold-clearing.ts does: every record checked as it checks them, the chain whole, the history checked. */
const clear = (asked: { holdEventId: string; investigationId: string }) =>
  inOrg(async (tx, states): Promise<HoldClearing | { outcome: 'not_whole' | 'history_unchecked' }> => {
    const whole = await states.verifyAll(tx, org, [AGENTS, PAYMENTS], CHECKED);
    if (whole.outcome !== 'verified' || !(await trail.verify(tx, org, undefined)).ok) return { outcome: 'not_whole' };
    if ((await states.historyChecked(tx, org, asked.investigationId)) !== 'checked')
      return { outcome: 'history_unchecked' };
    return states.clearIntegrityHold(tx, org, { actor: ADMIN, stepUp: STEP_UP, ...asked });
  });

const hold = () => inOrg((tx, states) => states.integrityHold(tx, org, 'none'));

/** Runs `work` as the database's owner on the payments, inside the organisation. */
async function onPayments(work: (owner: OwnerTamper) => Promise<unknown>): Promise<void> {
  const owner = await tamperAsOwner(database, PAYMENTS, org);
  try {
    await work(owner);
  } finally {
    await owner.end();
  }
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = newId();
  // Listed, as the app's organisations are: a finding meeting a hold on another record waits in a row keyed by it (D5).
  await database.as('admin').query('insert into directory.orgs (org_id) values ($1)', [org]);
  // The organisation's own row first in its chain, as the hold starts only beside it.
  await inOrg(async (tx, states) => {
    await agent(tx, states, org);
    await states.startIntegrityHold(tx, org, OPERATOR);
  });
});

describe(`clearing the integrity hold past 10,000 paid payments (4D2e Stage F, Postgres ${server.version})`, () => {
  it('a payment can still act until it is settled: a paid one is no live row', () => {
    expect(LIVE).toEqual(['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN']);
  });

  it('a hold clears past 10,000 paid payments', async () => {
    await payments(1, 'UNKNOWN');
    await payments(CHECKED + 1, 'SUCCEEDED');
    const asked = await heldAndInvestigated();

    expect(await historyPass(asked.investigationId)).toBe('checked');
    // The newest 10,000 and the older live one, never the oldest paid one: the history pass checked it.
    expect(await inOrg((tx, states) => states.verifyAll(tx, org, [PAYMENTS], CHECKED))).toEqual({
      outcome: 'verified',
      objects: CHECKED + 1,
    });
    expect(await clear(asked)).toMatchObject({ outcome: 'cleared' });
    expect(await hold()).toMatchObject({ outcome: 'clear' });
  }, 180_000);

  it('a tampered paid payment is found by the history batch and held again', async () => {
    const paid = await payments(CHECKED + 1, 'SUCCEEDED');
    const oldest = paid[0] ?? '';
    const asked = await heldAndInvestigated();
    let saved: SavedRow | undefined;
    await onPayments(async (owner) => {
      saved = await owner.saveRow(oldest);
      await owner.setColumn(oldest, 'status', 'FAILED');
    });

    // Past the newest and settled: not clearing's to read, the trade decision 5 makes.
    expect(await inOrg((tx, states) => states.verifyAll(tx, org, [PAYMENTS], CHECKED))).toMatchObject({
      outcome: 'verified',
    });
    // The history batch finds it: its alarm raised, so the hold, already standing for the agent, can't clear.
    expect(await historyPass(asked.investigationId)).toBe('tampered');
    expect(capture.lines().filter(({ event }) => event === 'audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ subjectType: 'transaction', objectId: oldest, reason: 'seal' }),
    );
    expect(await clear(asked)).toEqual({ outcome: 'history_unchecked' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });

    // Put back and checked whole, the hold clears; and the payment's own finding is the next hold.
    await onPayments((owner) => (saved === undefined ? Promise.resolve() : owner.restoreRow(saved)));
    expect(await historyPass(asked.investigationId)).toBe('checked');
    expect(await clear(asked)).toMatchObject({ outcome: 'cleared', version: 3 });
    // Denied from the clear on, the finding waiting behind it; that read's end records it as the hold.
    expect(await hold()).toEqual({ outcome: 'tampered', sign: 'seal' });
    const again = await hold();
    expect(again).toMatchObject({ outcome: 'held', version: 4 });
    const eventId = again.outcome === 'held' ? again.eventId : 'none';
    expect(await withTenant(app, org, (tx) => trail.recordedEvent(tx, org, { eventId }))).toMatchObject({
      kind: 'recorded',
      event: { details: { reason: 'seal', foundOn: 'transaction', objectId: oldest } },
    });
  }, 180_000);

  it('an unsettled payment older than the newest 10,000, tampered with, still stops clearing at once', async () => {
    const [unsettled] = await payments(1, 'SUBMITTED');
    await payments(CHECKED, 'SUCCEEDED');
    const asked = await heldAndInvestigated();
    expect(await historyPass(asked.investigationId)).toBe('checked');
    // After the history pass, so only clearing's own check can see it: still live, so listed.
    await onPayments((owner) => owner.setColumn(unsettled ?? '', 'status', 'PROCESSING'));

    expect(await clear(asked)).toEqual({ outcome: 'not_whole' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  }, 180_000);
});

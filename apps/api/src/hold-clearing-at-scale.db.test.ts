// Clearing the integrity hold past 10,000 paid payments (4D2e Stage F,
// decision 5), through the product's own steps: the admin's clearing
// (createHoldClearings: ask, step-up, confirm, with its own limit) and the
// API's history job (createHoldHistoryCheck, its own batch sizes). Clearing
// checks a growing table's rows that can still act, the record its hold names
// and the newest OBJECTS_CHECKED; the older ended ones are the history job's,
// which the confirm waits for. So no count of payments stops a hold clearing,
// and a paid payment tampered with past the newest is still found, by the
// history job, and holds the organisation again. A table that doesn't grow,
// past OBJECTS_CHECKED registered contacts, is checked whole, a page at a time
// (partner S170: no fixed ceiling), one tampered with on its second page found.
//
// The product's authority tables, with a stand-in for the transactions table
// (its status sealed, its live statuses the product's own), as the table's
// foreign keys would need a spend request and instruction for each payment,
// and one for the registered contacts, whose addresses are sealed apart.
// The rows are signed through the audit module's own signed states, a
// thousand to a transaction; the organisations are made at once, as their
// chains are apart. The database's owner is the attacker.
import { createHash } from 'node:crypto';

import { AUTHORITY_TABLES } from '@agentx/core/authority-tables';
import { type CheckedTable, createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import {
  addMembership,
  CLEAR_CONFIRM_OPERATION,
  CLEAR_OPERATION,
  type ClearingAdmin,
  createHoldClearings,
  createHoldInvestigations,
  createSessions,
  createStepUpChallenges,
  INVESTIGATE_OPERATION,
  MEMBERSHIPS,
  OBJECTS_CHECKED,
  RECORDS_FILLING,
  REGISTERED_CONTACTS,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createDatabase, type Database, type IdempotentRequest } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
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
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import {
  createHoldHistoryCheck,
  HOLD_HISTORY_BATCH,
  type HoldHistoryCheck,
  HOLD_HISTORY_BATCHES_A_RUN,
} from './hold-history-check.ts';
import type { UseCaseTables } from './use-case-work.ts';

const TRANSACTIONS = AUTHORITY_TABLES.find(({ subject }) => subject === 'transaction');
if (TRANSACTIONS?.liveStatuses === undefined) throw new Error('The transactions table grows, so it has live statuses');

/** The stand-in for the transactions table: its status sealed, its live statuses the product's own. */
const PAYMENTS = {
  table: 'probe.payments',
  subject: TRANSACTIONS.subject,
  fields: [{ column: 'status', type: 'text' }],
  liveStatuses: TRANSACTIONS.liveStatuses,
} as const satisfies CheckedTable;

/** The stand-in for the registered contacts, a table that doesn't grow: a status sealed. */
const CONTACTS = {
  table: 'probe.contacts',
  subject: REGISTERED_CONTACTS.subject,
  fields: [{ column: 'status', type: 'text' }],
} as const satisfies CheckedTable;

/** The product's authority tables, in their order, the stand-ins in the transactions' and contacts' places. */
const TABLES: readonly CheckedTable[] = AUTHORITY_TABLES.map((table) => {
  if (table === TRANSACTIONS) return PAYMENTS;
  return table === REGISTERED_CONTACTS ? CONTACTS : table;
});

/** Paid payments, one past what clearing reads of the newest; and one unsettled payment, older than all of them. */
const PAID = OBJECTS_CHECKED + 1;
/** Contacts, one past a page of what clearing reads, so the newest is on the second page. */
const CONTACTS_HELD = OBJECTS_CHECKED + 1;
/** The history job's runs to check them all: a run checks HOLD_HISTORY_BATCHES_A_RUN batches an organisation. */
const RUNS = Math.ceil((PAID + 1) / (HOLD_HISTORY_BATCH * HOLD_HISTORY_BATCHES_A_RUN));
/** Rows signed in one transaction while making them. */
const SIGNED_A_TRANSACTION = 1000;

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  'grant usage on schema probe to agentx_app',
  ...['payments', 'contacts'].flatMap((name) => [
    `create table probe.${name} (org_id uuid not null, id uuid not null, status text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))`,
    `alter table probe.${name} enable row level security`,
    `alter table probe.${name} force row level security`,
    `create policy tenant_isolation on probe.${name} ${TENANT_POLICY}`,
    `grant select, insert on probe.${name} to agentx_app`,
    `grant update (status, state_version, state_event_id) on probe.${name} to agentx_app`,
  ]),
];

interface ProbeRow {
  org_id: string;
  id: string;
  status: string;
  state_version?: number;
  state_event_id?: string;
}

type Tables = UseCaseTables & OrganizationsTables & { 'probe.payments': ProbeRow; 'probe.contacts': ProbeRow };

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xf130_0000_0000);
const clock = new FixedClock(new Date('2026-11-03T09:00:00Z'));
const challenges = () => createStepUpChallenges({ ids, clock });
const services = () => ({ keys, ids, logger: testLogger() });
const capture = new LogCapture();
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000bb';

/** An organisation as the tests use it: its admin, its one unsettled payment, its paid ones and its contacts, oldest first. */
interface World {
  readonly org: string;
  readonly admin: ClearingAdmin;
  readonly unsettled: string;
  readonly paid: readonly string[];
  readonly contacts: readonly string[];
  /** Another member's membership, read tampered with and put back: what the hold names. */
  readonly heldFor: string;
}

let people = 0;
/** A person in the organisation with this role, signed in: the admin's session, or the membership. */
async function member(org: string, role: 'admin' | 'viewer'): Promise<ClearingAdmin & { membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `at-scale-${String(people)}` },
    { ids, clock },
  );
  const { sessionId } = await createSessions({
    ids,
    clock,
    timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
  }).open(app, userId, { idpSessionId: 'V1_1', authTime: clock.now(), amr: ['pwd', 'user', 'mfa'] });
  const membershipId = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
}

/** Rows of a stand-in in this status, each signed through the signed states as a module records a new row: their IDs, in order. */
async function signedRows(
  table: typeof PAYMENTS | typeof CONTACTS,
  org: string,
  count: number,
  status: string,
): Promise<string[]> {
  const made = Array.from({ length: count }, () => ids.next());
  for (let start = 0; start < made.length; start += SIGNED_A_TRANSACTION) {
    const some = made.slice(start, start + SIGNED_A_TRANSACTION);
    await withSignedStates(app, org, services(), async (tx, states) => {
      await tx
        .insertInto(table.table)
        .values(some.map((id) => ({ org_id: org, id, status })))
        .execute();
      for (const id of some) {
        await states.record(
          tx,
          table,
          { orgId: org, id },
          'new',
          { status },
          { actor: OPERATOR, action: `${table.subject}.opened`, details: {} },
        );
      }
    });
  }
  return made;
}

/** Runs `work` as the database's owner on a table, inside the organisation. */
async function asOwner(
  org: string,
  table: Parameters<typeof tamperAsOwner>[1],
  work: (owner: OwnerTamper) => Promise<unknown>,
): Promise<void> {
  const owner = await tamperAsOwner(database, table, org);
  try {
    await work(owner);
  } finally {
    await owner.end();
  }
}

/**
 * An organisation with its admin, an unsettled payment, `paid` paid ones and `contacts` contacts, held for another
 * member's role changed and put back.
 */
async function world(paidCount: number, contactCount: number): Promise<World> {
  const org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  const admin = await member(org, 'admin');
  const [unsettled] = await signedRows(PAYMENTS, org, 1, 'SUBMITTED');
  const paid = await signedRows(PAYMENTS, org, paidCount, 'SUCCEEDED');
  const contacts = await signedRows(CONTACTS, org, contactCount, 'ACTIVE');
  const { membershipId: heldFor } = await member(org, 'viewer');
  await asOwner(org, MEMBERSHIPS, async (owner) => {
    const saved = await owner.saveRow(heldFor);
    await owner.setColumn(heldFor, 'role', 'admin');
    await withSignedStates(app, org, services(), (tx, states) =>
      states.verifiedState(tx, MEMBERSHIPS, { orgId: org, id: heldFor }, 'share'),
    );
    await owner.restoreRow(saved);
  });
  return { org, admin, unsettled: unsettled ?? '', paid, contacts, heldFor };
}

const keyed = (who: ClearingAdmin, operation: string, key: string, payload: string): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload,
});

const clearings = () =>
  createHoldClearings({
    database: app,
    keys,
    ids,
    challenges: challenges(),
    logger: testLogger(capture),
    authorityTables: TABLES,
  });

/** The admin records the investigation, asks to clear and signs in again: the investigation and the step-up. */
async function askedToClear({ admin }: World): Promise<{ investigationId: string; challengeId: string }> {
  const finding = { conclusion: 'CAUSE_REMOVED', reference: `INC-${ids.next().slice(-6)}` } as const;
  const written = await createHoldInvestigations({ database: app, keys, ids, logger: testLogger() }).record(
    admin,
    keyed(admin, INVESTIGATE_OPERATION, ids.next(), JSON.stringify(finding)),
    finding,
    CORRELATION,
  );
  if (written.outcome !== 'written') throw new Error(`not recorded: ${JSON.stringify(written)}`);
  const investigationId = written.investigation.id;
  const asked = await clearings().ask(
    admin,
    keyed(admin, CLEAR_OPERATION, `ask-${investigationId}`, investigationId),
    investigationId,
    CORRELATION,
  );
  if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
  await challenges().recordEvidence(app, asked.stepUpChallengeId, admin.sessionId, {
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });
  return { investigationId, challengeId: asked.stepUpChallengeId };
}

/** The admin's confirm, as the route sends it: a refusal rolls back, so the same key goes again. */
const confirm = (
  { admin }: World,
  { investigationId, challengeId }: { investigationId: string; challengeId: string },
) =>
  clearings().confirm(
    admin,
    keyed(admin, CLEAR_CONFIRM_OPERATION, `confirm-${challengeId}`, `${investigationId} ${challengeId}`),
    investigationId,
    challengeId,
    CORRELATION,
  );

/** The API's history job, one for each organisation, as it keeps where it got to in the process: by organisation. */
const jobs = new Map<string, HoldHistoryCheck>();

/** The API's history job for this organisation, with its own batch sizes, run `runs` times. */
async function historyJob({ org }: World, runs: number): Promise<void> {
  const job =
    jobs.get(org) ??
    createHoldHistoryCheck({
      list: () => Promise.resolve([org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      tables: TABLES,
    });
  jobs.set(org, job);
  for (let run = 0; run < runs; run += 1) await job.run();
}

const jobLines = ({ org }: World, event: string) =>
  capture.lines().filter((line) => line.event === event && line.orgId === org);

const hold = ({ org }: World) =>
  withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

let worlds: { clears: World; heldAgain: World; unsettled: World; contacts: World };

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  // Each organisation's chain is its own, so they are made at once.
  const [clears, heldAgain, unsettled, contacts] = await Promise.all([
    world(PAID, 0),
    world(PAID, 0),
    world(PAID, 0),
    world(0, CONTACTS_HELD),
  ]);
  worlds = { clears, heldAgain, unsettled, contacts };
}, 600_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`clearing the integrity hold past 10,000 payments or contacts (4D2e Stage F, Postgres ${server.version})`, () => {
  it('a hold clears past 10,000 paid payments', async () => {
    const w = worlds.clears;
    const asked = await askedToClear(w);

    // One run of the job leaves part of the history unchecked: the confirm waits for it.
    await historyJob(w, 1);
    expect(RUNS).toBeGreaterThan(1);
    expect(await confirm(w, asked)).toEqual({ outcome: 'refused', status: 409, code: 'HISTORY_UNCHECKED' });
    await historyJob(w, RUNS - 1);
    expect(jobLines(w, 'hold_history.checked')).toEqual([expect.objectContaining({ objects: PAID + 1 })]);

    expect(await confirm(w, asked)).toMatchObject({ outcome: 'cleared', hold: { outcome: 'clear', version: 3 } });
    // A growing table's rows are no table filling: no line, past the level though they are.
    expect(PAID).toBeGreaterThan(RECORDS_FILLING);
    expect(jobLines(w, 'identity.records_filling')).toEqual([]);
  }, 300_000);

  it('checks every contact past 10,000, a page at a time: one tampered with on the second page refuses it; put back, it clears, saying the table fills', async () => {
    const w = worlds.contacts;
    const newest = w.contacts.at(-1) ?? '';
    const asked = await askedToClear(w);
    await historyJob(w, 1);
    let restore = (): Promise<void> => Promise.resolve();
    await asOwner(w.org, CONTACTS, async (owner) => {
      const saved = await owner.saveRow(newest);
      await owner.setColumn(newest, 'status', 'REMOVED');
      restore = () => asOwner(w.org, CONTACTS, (again) => again.restoreRow(saved));
    });

    expect(await confirm(w, asked)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    expect(await hold(w)).toMatchObject({ outcome: 'held', version: 2 });
    expect(
      capture
        .lines()
        .filter(({ event, objectId }) => event === 'audit.integrity_failed' && objectId === newest)
        .map(({ reason }) => reason),
    ).toEqual(['seal']);

    await restore();
    expect(await confirm(w, asked)).toMatchObject({ outcome: 'cleared' });
    // Each confirm counted every contact, the refused one too: past the level watched, each said so.
    const filling = { level: 'warn', records: CONTACTS.subject, held: CONTACTS_HELD, during: 'hold_clearing' };
    expect(jobLines(w, 'identity.records_filling')).toEqual([
      expect.objectContaining(filling),
      expect.objectContaining(filling),
    ]);
  }, 300_000);

  it('a tampered paid payment is found by the history batch and held again', async () => {
    const w = worlds.heldAgain;
    const oldest = w.paid[0] ?? '';
    const asked = await askedToClear(w);
    let restore = (): Promise<void> => Promise.resolve();
    await asOwner(w.org, PAYMENTS, async (owner) => {
      const saved = await owner.saveRow(oldest);
      await owner.setColumn(oldest, 'status', 'FAILED');
      restore = () => asOwner(w.org, PAYMENTS, (again) => again.restoreRow(saved));
    });

    // The job finds it: its alarm raised, the history left unchecked, so the confirm can't clear the hold.
    await historyJob(w, RUNS);
    // Each run finds it, as each starts again from the beginning once a batch finds one.
    expect(jobLines(w, 'hold_history.tampered')).toContainEqual(
      expect.objectContaining({ subjectType: 'transaction', findings: 1 }),
    );
    expect(jobLines(w, 'hold_history.checked')).toEqual([]);
    expect(
      capture
        .lines()
        .filter(({ event, objectId }) => event === 'audit.integrity_failed' && objectId === oldest)
        .map(({ reason }) => reason),
    ).toContain('seal');
    expect(await confirm(w, asked)).toEqual({ outcome: 'refused', status: 409, code: 'HISTORY_UNCHECKED' });
    expect(await hold(w)).toMatchObject({ outcome: 'held', version: 2 });

    // Put back, the job checks it all from the start and the hold clears; the payment's finding is then the next hold.
    await restore();
    await historyJob(w, RUNS);
    expect(await confirm(w, asked)).toMatchObject({ outcome: 'cleared' });
    const again = await withSignedStates(app, w.org, services(), (tx, states) => states.holdRecord(tx, w.org));
    expect(again).toMatchObject({ outcome: 'held', version: 4, reason: 'seal', foundOn: 'transaction' });
    const eventId = again.outcome === 'held' ? again.eventId : 'none';
    const trail = createAuditTrail({ keys, ids });
    const event = await withSignedStates(app, w.org, services(), (tx) => trail.recordedEvent(tx, w.org, { eventId }));
    expect(event).toMatchObject({ kind: 'recorded', event: { details: { objectId: oldest } } });

    // Named by the hold, past the newest and settled, it is read whatever its status: changed after the job's check, refused at once.
    const named = await askedToClear(w);
    await historyJob(w, RUNS);
    await asOwner(w.org, PAYMENTS, (owner) => owner.setColumn(oldest, 'status', 'FAILED'));
    expect(await confirm(w, named)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    expect(await hold(w)).toMatchObject({ outcome: 'held', version: 4 });
  }, 300_000);

  it('an unsettled payment older than the newest 10,000, tampered with, still stops clearing at once', async () => {
    const w = worlds.unsettled;
    const asked = await askedToClear(w);
    await historyJob(w, RUNS);
    expect(jobLines(w, 'hold_history.checked')).toHaveLength(1);
    // After the job checked the whole history, so only the confirm's own check can see it: still live, so listed.
    await asOwner(w.org, PAYMENTS, (owner) => owner.setColumn(w.unsettled, 'status', 'PROCESSING'));

    expect(await confirm(w, asked)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    expect(await hold(w)).toMatchObject({ outcome: 'held', version: 2 });
  }, 300_000);
});

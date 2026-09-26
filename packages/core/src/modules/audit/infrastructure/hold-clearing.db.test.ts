// Clearing the integrity hold (B3+-2c-1; ADR-012 §2, SEC-DB-10's clearing,
// invariant 13): by a person, with the step-up they confirmed it with, from
// the HELD state asked about, after that state's investigation, and only once
// verifyAll has found every record of the organisation whole in the same
// transaction. The database's owner is the attacker, through
// @agentx/testing's tamperAsOwner, on a stand-in authority table whose first
// row is the organisation's own.
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  type SavedRow,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import { createDatabase, type Database, type SignedStateTable, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import type { Transaction } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTrail, createAuditTrail } from './audit-trail.ts';
import { type HoldClearing, type SignedStates, SignedStateFailed } from './signed-states.ts';
import type { AuditTables } from './tables.ts';
import { withSignedStates } from './with-signed-states.ts';

/** A stand-in authority table, sealing a label. */
const AGENTS = {
  table: 'probe.agents',
  subject: 'agent',
  fields: [{ column: 'label', type: 'text' }],
} as const satisfies SignedStateTable;

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  'create table probe.agents (org_id uuid not null, id uuid not null, label text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))',
  'alter table probe.agents enable row level security',
  'alter table probe.agents force row level security',
  `create policy tenant_isolation on probe.agents ${TENANT_POLICY}`,
  'grant usage on schema probe to agentx_app',
  'grant select, insert on probe.agents to agentx_app',
  'grant update (label, state_version, state_event_id) on probe.agents to agentx_app',
];

type Tables = AuditTables & {
  'probe.agents': { org_id: string; id: string; label: string; state_version?: number; state_event_id?: string | null };
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
const ids = new SequentialIds(0xb00);
const trail: AuditTrail = createAuditTrail({ keys, ids });

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

let number = 0;
/** A new UUID, so no two tests share an organisation or a row. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0xb000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;
let owner: OwnerTamper;

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const ADMIN = { type: 'user' as const, id: '0199a0f0-0000-7000-8000-0000000000ad' };
const STEP_UP = {
  stepUpChallengeId: '0199a0f0-0000-7000-8000-0000000000c1',
  changeHash: 'ab'.repeat(32),
  methods: 'pwd user mfa',
};

/** Work in this test's organisation, with signed states that hold it on any tamper sign. */
const inOrg = <T>(work: (tx: Transaction<Tables>, states: SignedStates) => Promise<T>): Promise<T> =>
  withSignedStates(app, org, services(), work);

/** A row and its first signed state, in the caller's transaction. */
async function insertAgent(tx: Transaction<Tables>, states: SignedStates, id: string): Promise<void> {
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

/**
 * Puts the organisation on hold as tampering does, a row's label changed past
 * the app and read, then puts the row back as it was signed: the cause taken
 * away, as an investigation would. Gives back the row, to tamper again.
 */
async function holdThenRepair(): Promise<{ id: string; saved: SavedRow }> {
  const id = newId();
  await inOrg((tx, states) => insertAgent(tx, states, id));
  const saved = await owner.saveRow(id);
  await owner.setColumn(id, 'label', 'changed');
  await inOrg((tx, states) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share'));
  await owner.restoreRow(saved);
  return { id, saved };
}

/** The hold as it now stands, HELD, with an investigation of it recorded. */
async function investigated(): Promise<{ holdVersion: number; holdEventId: string; investigationId: string }> {
  const investigationId = newId();
  const recorded = await inOrg((tx, states) =>
    states.recordInvestigation(tx, org, {
      id: investigationId,
      actor: ADMIN,
      conclusion: 'CAUSE_REMOVED',
      reference: 'INC-1',
    }),
  );
  if (recorded.outcome !== 'recorded') throw new Error('the hold should be HELD');
  const { holdVersion, holdEventId } = recorded.investigation;
  return { holdVersion, holdEventId, investigationId };
}

type Clearing = Parameters<SignedStates['clearIntegrityHold']>[2];

/** Clears as the use case does: every record verified first, then the hold, in one transaction. */
const clear = (clearing: Omit<Clearing, 'actor' | 'stepUp'> & Partial<Clearing>): Promise<HoldClearing> =>
  inOrg(async (tx, states) => {
    expect(await states.verifyAll(tx, org, [AGENTS], 100)).toMatchObject({ outcome: 'verified' });
    return states.clearIntegrityHold(tx, org, { actor: ADMIN, stepUp: STEP_UP, ...clearing });
  });

const hold = () => inOrg((tx, states) => states.integrityHold(tx, org, 'none'));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, services().logger);
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = newId();
  await inOrg(async (tx, states) => {
    await insertAgent(tx, states, org);
    await states.startIntegrityHold(tx, org, OPERATOR);
  });
  owner = await tamperAsOwner(database, AGENTS, org);
});

afterEach(async () => {
  await owner.end();
});

describe(`clearing the integrity hold (clearIntegrityHold, Postgres ${server.version})`, () => {
  it('clears a HELD hold after its investigation, recording who, the investigation and the step-up', async () => {
    await holdThenRepair();
    const asked = await investigated();

    const cleared = await clear(asked);

    expect(cleared).toMatchObject({ outcome: 'cleared', version: 3 });
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 3 });
    const eventId = cleared.outcome === 'cleared' ? cleared.eventId : 'none';
    expect(await withTenant(app, org, (tx) => trail.recordedEvent(tx, org, { eventId }))).toMatchObject({
      kind: 'recorded',
      event: {
        actor: ADMIN,
        action: 'integrity_hold.cleared',
        subject: { type: 'integrity_hold', id: org, version: 3 },
        details: {
          statusFrom: 'HELD',
          statusTo: 'CLEAR',
          investigationId: asked.investigationId,
          stepUpChallengeId: STEP_UP.stepUpChallengeId,
          changeHash: STEP_UP.changeHash,
          methods: STEP_UP.methods,
        },
      },
    });
  });

  it('can be set again once cleared, and needs an investigation of the new HELD state', async () => {
    const { id } = await holdThenRepair();
    const first = await investigated();
    await clear(first);
    const saved = await owner.saveRow(id);
    await owner.setColumn(id, 'label', 'again');
    await inOrg((tx, states) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share'));
    await owner.restoreRow(saved);
    const again = await hold();
    expect(again).toMatchObject({ outcome: 'held', version: 4 });
    const current = again.outcome === 'held' ? { holdVersion: again.version, holdEventId: again.eventId } : first;

    // The first investigation answers the first HELD state only.
    expect(await clear({ ...current, investigationId: first.investigationId })).toEqual({
      outcome: 'no_investigation',
    });
    expect(await clear(await investigated())).toMatchObject({ outcome: 'cleared', version: 5 });
  });

  it('refuses a hold that is CLEAR', async () => {
    const asked = { holdVersion: 1, holdEventId: newId(), investigationId: newId() };

    expect(await clear(asked)).toEqual({ outcome: 'not_held' });
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 1 });
  });

  it.each([
    ['another version', (asked: Awaited<ReturnType<typeof investigated>>) => ({ ...asked, holdVersion: 1 })],
    ['another event', (asked: Awaited<ReturnType<typeof investigated>>) => ({ ...asked, holdEventId: newId() })],
  ])('refuses a HELD state asked about at %s, leaving it HELD', async (_name, change) => {
    await holdThenRepair();
    const asked = await investigated();

    expect(await clear(change(asked))).toEqual({ outcome: 'moved_on' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('takes the HELD event named in any case', async () => {
    await holdThenRepair();
    const asked = await investigated();

    expect(await clear({ ...asked, holdEventId: asked.holdEventId.toUpperCase() })).toMatchObject({
      outcome: 'cleared',
    });
  });

  it('refuses with no investigation by that ID, leaving it HELD', async () => {
    await holdThenRepair();
    const asked = await investigated();

    expect(await clear({ ...asked, investigationId: newId() })).toEqual({ outcome: 'no_investigation' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it("refuses when the investigation's event was changed past the app, as tampered", async () => {
    await holdThenRepair();
    const asked = await investigated();
    await owner.query(
      "update audit.events set details = replace(details, 'CAUSE_REMOVED', 'NO_TAMPERING') where subject_id = $1",
      [asked.investigationId],
    );

    expect(await clear(asked)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it("refuses a hold that can't be believed, as tampered", async () => {
    await holdThenRepair();
    const asked = await investigated();
    await owner.query("update audit.events set details = '{}' where subject_type = $1", ['integrity_hold']);

    expect(await clear(asked)).toMatchObject({ outcome: 'tampered' });
  });

  it('is refused before anything is read unless verifyAll found every record whole in the same transaction', async () => {
    await holdThenRepair();
    const asked = await investigated();

    await expect(
      inOrg((tx, states) => states.clearIntegrityHold(tx, org, { actor: ADMIN, stepUp: STEP_UP, ...asked })),
    ).rejects.toThrow(SignedStateFailed);
    // verifyAll in another transaction counts for nothing.
    await inOrg((tx, states) => states.verifyAll(tx, org, [AGENTS], 100));
    await expect(
      inOrg((tx, states) => states.clearIntegrityHold(tx, org, { actor: ADMIN, stepUp: STEP_UP, ...asked })),
    ).rejects.toThrow("A hold is cleared only once verifyAll has found every one of the organisation's records whole");
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('is refused while any record is still tampered with: verifyAll names it, and the hold stays', async () => {
    const id = newId();
    await inOrg((tx, states) => insertAgent(tx, states, id));
    await owner.setColumn(id, 'label', 'changed');
    await inOrg((tx, states) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share'));
    const asked = await investigated();

    await expect(
      inOrg(async (tx, states) => {
        expect(await states.verifyAll(tx, org, [AGENTS], 100)).toMatchObject({ outcome: 'tampered' });
        return states.clearIntegrityHold(tx, org, { actor: ADMIN, stepUp: STEP_UP, ...asked });
      }),
    ).rejects.toThrow(SignedStateFailed);
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it.each([
    ['by the app itself', { actor: OPERATOR }, 'A hold is cleared by a person'],
    ['by an AI agent', { actor: { type: 'agent' as const, id: ADMIN.id } }, 'A hold is cleared by a person'],
    [
      'with a step-up that is no ID',
      { stepUp: { ...STEP_UP, stepUpChallengeId: 'not-an-id' } },
      'A hold is cleared with the step-up it names',
    ],
  ])('is refused %s, before anything is read', async (_name, overrides, message) => {
    await holdThenRepair();
    const asked = await investigated();

    await expect(clear({ ...asked, ...overrides })).rejects.toThrow(message);
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('reads the hold with the chain head locked, which comes last: no row is read after it', async () => {
    await holdThenRepair();
    const asked = await investigated();
    const id = newId();
    await inOrg((tx, states) => insertAgent(tx, states, id));

    await expect(
      inOrg(async (tx, states) => {
        await states.verifyAll(tx, org, [], 100);
        await states.clearIntegrityHold(tx, org, { actor: ADMIN, stepUp: STEP_UP, ...asked });
        return states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share');
      }),
    ).rejects.toThrow('A row is locked before the chain head, never after it');
  });
});

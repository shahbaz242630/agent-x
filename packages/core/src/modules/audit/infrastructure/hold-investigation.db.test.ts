// The integrity hold, shown and investigated (B3+-2b; ADR-012 §2, SEC-DB-10's
// clearing): holdRecord reads it for showing, recordInvestigation records an
// investigation of it by a person while it is HELD, and holdInvestigation
// reads one back, from its event, believed only whole (recordedEvent). The
// database's owner is the attacker, through @agentx/testing's tamperAsOwner,
// on a stand-in authority table whose first row is the organisation's own.
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import { createDatabase, type Database, type SignedStateTable, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import type { Transaction } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AuditEventRefused } from '../domain/event.ts';
import { type AuditTrail, createAuditTrail, recordHoldEvent } from './audit-trail.ts';
import { type SignedStates, SignedStateFailed } from './signed-states.ts';
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
const ids = new SequentialIds(0xa00);
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
  return `0199a0f0-0000-7000-8000-${(0xa000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;
let owner: OwnerTamper;

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const ADMIN = { type: 'user' as const, id: '0199a0f0-0000-7000-8000-0000000000ad' };

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

/** Puts the organisation on hold as tampering does: a row's label changed past the app, then read. */
async function putOnHold(): Promise<void> {
  const id = newId();
  await inOrg((tx, states) => insertAgent(tx, states, id));
  await owner.setColumn(id, 'label', 'changed');
  expect(await inOrg((tx, states) => states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share'))).toMatchObject({
    outcome: 'tampered',
  });
}

const holdRecord = () => inOrg((tx, states) => states.holdRecord(tx, org));

const investigate = (
  overrides: Partial<Parameters<SignedStates['recordInvestigation']>[2]> = {},
): ReturnType<SignedStates['recordInvestigation']> =>
  inOrg((tx, states) =>
    states.recordInvestigation(tx, org, {
      id: newId(),
      actor: ADMIN,
      conclusion: 'CAUSE_REMOVED',
      reference: 'INC-2026-0042',
      ...overrides,
    }),
  );

const readInvestigation = (id: string) => inOrg((tx, states) => states.holdInvestigation(tx, org, id));

/** The IDs of every investigation event in the organisation's log. */
const investigationEvents = () => withTenant(app, org, (tx) => trail.subjectIds(tx, org, 'hold_investigation', 100));

/** Stand-ins that match any value of their type, typed as it, for comparing whole objects. */
const A_DATE = expect.any(Date) as Date;
const A_STRING = expect.any(String) as string;
const A_BIGINT = expect.any(BigInt) as bigint;

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

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
  // The organisation as a module creates one: its own row, then its hold, CLEAR, in one transaction.
  await inOrg(async (tx, states) => {
    await insertAgent(tx, states, org);
    await states.startIntegrityHold(tx, org, OPERATOR);
  });
  owner = await tamperAsOwner(database, AGENTS, org);
});

afterEach(async () => {
  await owner.end();
});

describe(`the hold for showing (holdRecord, Postgres ${server.version})`, () => {
  it('reads a new organisation CLEAR, since its hold started', async () => {
    const shown = await holdRecord();

    expect(shown).toEqual({ outcome: 'clear', version: 1, since: A_DATE });
    expect(alarms()).toEqual([]);
  });

  it('reads it HELD once tampering is found, with the sign and the type it was found on', async () => {
    await putOnHold();
    const held = await inOrg((tx, states) => states.integrityHold(tx, org, 'none'));

    expect(await holdRecord()).toEqual({
      outcome: 'held',
      version: 2,
      eventId: held.outcome === 'held' ? held.eventId : 'not held',
      since: A_DATE,
      reason: 'seal',
      foundOn: 'agent',
    });
  });

  it("reads a hold whose events can't be believed as tampered with, with the alarm", async () => {
    // Its seal stripped: no state for it can be believed.
    await owner.query("update audit.events set details = '{}' where subject_type = $1", ['integrity_hold']);

    expect(await holdRecord()).toMatchObject({ outcome: 'tampered' });
    // Raised by the read, and again by the hold set for it once the read's transaction ended.
    expect(alarms().length).toBeGreaterThan(0);
    expect(alarms()).toEqual(
      alarms().map((): unknown => expect.objectContaining({ subjectType: 'integrity_hold', objectId: org })),
    );
  });

  it('takes no lock on the chain head: a row can still be read after it in the same transaction', async () => {
    const id = newId();
    await inOrg((tx, states) => insertAgent(tx, states, id));

    expect(
      await inOrg(async (tx, states) => {
        await states.holdRecord(tx, org);
        return states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share');
      }),
    ).toMatchObject({ outcome: 'verified' });
  });
});

describe(`an investigation of the hold (recordInvestigation and holdInvestigation, Postgres ${server.version})`, () => {
  it('is recorded while the hold is HELD, naming that state, and read back as recorded', async () => {
    await putOnHold();
    const shown = await holdRecord();
    const id = newId();

    const recorded = await investigate({ id, conclusion: 'NO_TAMPERING', reference: 'ticket_7.b-X' });

    const investigation = {
      id,
      holdVersion: 2,
      holdEventId: shown.outcome === 'held' ? shown.eventId : 'not held',
      conclusion: 'NO_TAMPERING',
      reference: 'ticket_7.b-X',
      recordedBy: ADMIN.id,
      recordedAt: A_DATE,
    };
    expect(recorded).toEqual({ outcome: 'recorded', investigation });
    expect(await readInvestigation(id)).toEqual({
      outcome: 'found',
      investigation: {
        ...investigation,
        recordedAt: recorded.outcome === 'recorded' && recorded.investigation.recordedAt,
      },
    });
    expect(await investigationEvents()).toEqual([id]);
    // Recording it changes nothing about the hold.
    expect(await holdRecord()).toEqual(shown);
  });

  it('names IDs in lower case, whatever case they were given in', async () => {
    await putOnHold();
    const id = newId();

    const recorded = await investigate({ id: id.toUpperCase(), actor: { type: 'user', id: ADMIN.id.toUpperCase() } });

    expect(recorded).toMatchObject({ outcome: 'recorded', investigation: { id, recordedBy: ADMIN.id } });
    expect(await readInvestigation(id.toUpperCase())).toMatchObject({ outcome: 'found', investigation: { id } });
  });

  it('is refused while the hold is CLEAR, recording nothing', async () => {
    expect(await investigate()).toEqual({ outcome: 'not_held' });
    expect(await investigationEvents()).toEqual([]);
  });

  it("is refused while the hold can't be believed, recording nothing", async () => {
    // Its seal stripped: no state for it can be believed.
    await owner.query("update audit.events set details = '{}' where subject_type = $1", ['integrity_hold']);

    expect(await investigate()).toMatchObject({ outcome: 'tampered' });
    expect(await investigationEvents()).toEqual([]);
  });

  it.each([
    ['by the app itself', { actor: OPERATOR }, 'An investigation is recorded by a person'],
    ['by an AI agent', { actor: { type: 'agent' as const, id: ADMIN.id } }, 'An investigation is recorded by a person'],
    [
      'with a conclusion of its own making',
      { conclusion: 'FIXED' as 'CAUSE_REMOVED' },
      'An investigation concludes as one of its own',
    ],
    ['with prose for a reference', { reference: 'the DBA did it' }, "An investigation's reference is an incident's ID"],
    [
      'with a reference starting with a dot',
      { reference: '.hidden' },
      "An investigation's reference is an incident's ID",
    ],
    [
      'with a reference past 64 characters',
      { reference: 'A'.repeat(65) },
      "An investigation's reference is an incident's ID",
    ],
  ])('is refused %s, before anything is read', async (_name, overrides, message) => {
    await putOnHold();

    await expect(investigate(overrides)).rejects.toThrow(message);
    expect(await investigationEvents()).toEqual([]);
  });

  it('takes a reference of exactly 64 characters', async () => {
    await putOnHold();

    expect(await investigate({ reference: `a${'-'.repeat(63)}` })).toMatchObject({ outcome: 'recorded' });
  });

  it('reads the hold with the chain head locked, which comes last: no row is read after it', async () => {
    await putOnHold();
    const id = newId();
    await inOrg((tx, states) => insertAgent(tx, states, id));

    await expect(
      inOrg(async (tx, states) => {
        await states.recordInvestigation(tx, org, {
          id: newId(),
          actor: ADMIN,
          conclusion: 'CAUSE_REMOVED',
          reference: 'INC-1',
        });
        return states.verifiedState(tx, AGENTS, { orgId: org, id }, 'share');
      }),
    ).rejects.toThrow(SignedStateFailed);
  });

  it("is recorded only by the hold's own steps: the trail's public record refuses its subject type", async () => {
    await putOnHold();
    const subject = { type: 'hold_investigation', id: newId(), version: 1 };

    await expect(
      withTenant(app, org, (tx) =>
        trail.record(tx, org, { actor: ADMIN, action: 'integrity_hold.investigated', subject, details: {} }),
      ),
    ).rejects.toThrow('subject.type hold_investigation is the integrity hold');
    expect(await investigationEvents()).toEqual([]);
  });

  it('can be read only as an investigation: another event by its ID, or none, is missing', async () => {
    await putOnHold();
    const shown = await holdRecord();

    expect(await readInvestigation(shown.outcome === 'held' ? shown.eventId : org)).toEqual({ outcome: 'missing' });
    expect(await readInvestigation(newId())).toEqual({ outcome: 'missing' });
    await expect(readInvestigation('not-an-id')).rejects.toThrow(AuditEventRefused);
  });

  it('can be read only in its own organisation', async () => {
    await putOnHold();
    const recorded = await investigate();
    const id = recorded.outcome === 'recorded' ? recorded.investigation.id : 'none';
    const mine = org;
    org = newId();
    await inOrg(async (tx, states) => {
      await insertAgent(tx, states, org);
      await states.startIntegrityHold(tx, org, OPERATOR);
    });

    expect(await readInvestigation(id)).toEqual({ outcome: 'missing' });
    org = mine;
  });

  it('is read from the first event about it: a later one, even whole, never replaces it', async () => {
    await putOnHold();
    const recorded = await investigate({ conclusion: 'CAUSE_REMOVED', reference: 'INC-FIRST' });
    const id = recorded.outcome === 'recorded' ? recorded.investigation.id : 'none';
    const { holdVersion, holdEventId } =
      recorded.outcome === 'recorded' ? recorded.investigation : { holdVersion: 0, holdEventId: '' };
    await withTenant(app, org, (tx) =>
      recordHoldEvent(trail, tx, org, {
        actor: ADMIN,
        action: 'integrity_hold.investigated',
        subject: { type: 'hold_investigation', id, version: 1 },
        details: { holdVersion, holdEventId, conclusion: 'NO_TAMPERING', reference: 'INC-SECOND' },
      }),
    );

    expect(await readInvestigation(id)).toMatchObject({
      outcome: 'found',
      investigation: { conclusion: 'CAUSE_REMOVED', reference: 'INC-FIRST' },
    });
  });

  it("belongs to no table: a table under an investigation's subject type is refused before any SQL", async () => {
    const posing = { ...AGENTS, subject: 'hold_investigation' } as const;

    await expect(
      inOrg((tx, states) => states.verifiedState(tx, posing, { orgId: org, id: org }, 'share')),
    ).rejects.toThrow("The subject type hold_investigation is the integrity hold's own");
  });

  it('is tampered with once its event is changed past the app, with the alarm', async () => {
    await putOnHold();
    const recorded = await investigate();
    const id = recorded.outcome === 'recorded' ? recorded.investigation.id : 'none';
    capture = new LogCapture();
    await owner.query(
      "update audit.events set details = replace(details, 'CAUSE_REMOVED', 'NO_TAMPERING') where subject_id = $1",
      [id],
    );

    expect(await readInvestigation(id)).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([
      expect.objectContaining({ reason: 'log', subjectType: 'hold_investigation', objectId: id, orgId: org }),
    ]);
  });
});

describe(`one event by its ID (recordedEvent, Postgres ${server.version})`, () => {
  it('is believed only up to the chain head: an event past a head put back, and any before it, are broken', async () => {
    await putOnHold();
    const before = await investigate();
    const saved = await owner.saveHead();
    const after = await investigate();
    // The head put back to an earlier one, genuinely sealed: the later event now lies past it.
    await owner.query('update audit.heads set seq = $2, hash = $3, mac = $4, mac_key_version = $5 where org_id = $1', [
      org,
      saved.seq,
      saved.hash,
      saved.mac,
      saved.macKeyVersion,
    ]);

    for (const recorded of [before, after]) {
      const id = recorded.outcome === 'recorded' ? recorded.investigation.id : 'none';
      expect(
        await withTenant(app, org, (tx) =>
          trail.recordedEvent(tx, org, { onlyAbout: { type: 'hold_investigation', id } }),
        ),
      ).toMatchObject({ kind: 'broken' });
    }
  });

  it('is broken when the head fails its own MAC', async () => {
    await putOnHold();
    const recorded = await investigate();
    const id = recorded.outcome === 'recorded' ? recorded.investigation.id : 'none';
    await owner.query('update audit.heads set mac = $2 where org_id = $1', [org, Buffer.alloc(32, 7)]);

    expect(
      await withTenant(app, org, (tx) =>
        trail.recordedEvent(tx, org, { onlyAbout: { type: 'hold_investigation', id } }),
      ),
    ).toMatchObject({ kind: 'broken' });
  });

  it('gives the event as it was recorded', async () => {
    await putOnHold();
    const recorded = await investigate({ reference: 'INC-9' });
    const id = recorded.outcome === 'recorded' ? recorded.investigation.id : 'none';

    expect(
      await withTenant(app, org, (tx) =>
        trail.recordedEvent(tx, org, { onlyAbout: { type: 'hold_investigation', id } }),
      ),
    ).toEqual({
      kind: 'recorded',
      id: A_STRING,
      seq: A_BIGINT,
      recordedAt: A_DATE,
      event: {
        actor: ADMIN,
        action: 'integrity_hold.investigated',
        subject: { type: 'hold_investigation', id, version: 1 },
        details: expect.objectContaining({
          conclusion: 'CAUSE_REMOVED',
          reference: 'INC-9',
          holdVersion: 2,
        }) as Record<string, unknown>,
      },
    });
  });

  it("is read only in withTenant's transaction for the organisation", async () => {
    await expect(withTenant(app, newId(), (tx) => trail.recordedEvent(tx, org, { eventId: newId() }))).rejects.toThrow(
      "the transaction isn't withTenant's for this organisation",
    );
  });

  it('refuses the hold recorder anything but the hold and its investigations', async () => {
    await expect(
      withTenant(app, org, (tx) =>
        recordHoldEvent(trail, tx, org, {
          actor: ADMIN,
          action: 'agent.created',
          subject: { type: 'agent', id: newId(), version: 1 },
          details: {},
        }),
      ),
    ).rejects.toThrow('only the integrity hold and its investigations are recorded by their own steps');
  });
});

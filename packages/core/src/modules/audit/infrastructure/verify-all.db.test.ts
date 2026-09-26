// verifyAll (B3+-2a; ADR-012 §2, SEC-DB-10's clearing): every object of an
// organisation's authority tables checked against the log at once, as
// clearing its integrity hold needs, with the database's owner as the
// attacker (@agentx/testing's tamperAsOwner). Two stand-in tables, built as a
// module builds one, so the order across tables shows. The objects are the
// rows and every object the log holds events about: a row changed, planted,
// stripped of its seals or deleted is named, and so is one deleted with its
// seals stripped too, which no single read of a row can tell from one never
// made.
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
  readSignedRow,
  type SignedStateTable,
  signedRowIds,
  TenantContextError,
  withTenant,
} from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { sql } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AuditEventRefused } from '../domain/event.ts';
import { HOLD_SUBJECT } from '../domain/integrity-hold.ts';
import { type AuditTrail, createAuditTrail } from './audit-trail.ts';
import { createSignedStates, type SignedStates, type TamperFinding, type TamperSign } from './signed-states.ts';
import type { AuditTables } from './tables.ts';

/** Two stand-in authority tables, each sealing a label: not a status, so a test can record a change to it. */
const AGENTS = {
  table: 'probe.agents',
  subject: 'agent',
  fields: [{ column: 'label', type: 'text' }],
} as const satisfies SignedStateTable;
const KEYS = {
  table: 'probe.keys',
  subject: 'agent_key',
  fields: [{ column: 'label', type: 'text' }],
} as const satisfies SignedStateTable;

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

/** Made by the owner, as a migration would make them, so the schema guard starts with nothing to report. */
const FIXTURE = ['agents', 'keys'].flatMap((name) => [
  `create table probe.${name} (org_id uuid not null, id uuid not null, label text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))`,
  `alter table probe.${name} enable row level security`,
  `alter table probe.${name} force row level security`,
  `create policy tenant_isolation on probe.${name} ${TENANT_POLICY}`,
  `grant select, insert on probe.${name} to agentx_app`,
  `grant update (label, state_version, state_event_id) on probe.${name} to agentx_app`,
]);

interface ProbeRow {
  org_id: string;
  id: string;
  label: string;
  state_version?: number;
  state_event_id?: string | null;
}

type Tables = AuditTables & { 'probe.agents': ProbeRow; 'probe.keys': ProbeRow };

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
const trail: AuditTrail = createAuditTrail({ keys, ids: new SequentialIds(0x900) });

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let capture: LogCapture;
let states: SignedStates;
let found: TamperFinding[];
let agents: OwnerTamper;
let agentKeys: OwnerTamper;

let number = 0;
/** A new UUID, rising, so no two tests share an organisation or a row, and a later one sorts after. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x9000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;

const USER = '0199a0f0-0000-7000-8000-0000000000aa';
const change = (action: string) => ({ actor: { type: 'user' as const, id: USER }, action, details: {} });

/** Inserts a row and records its first signed state, as a module creates one. */
async function newRow(table: typeof AGENTS | typeof KEYS, orgId = org): Promise<string> {
  const id = newId();
  await withTenant(app, orgId, async (tx) => {
    await tx.insertInto(table.table).values({ org_id: orgId, id, label: 'ACTIVE' }).execute();
    await states.record(tx, table, { orgId, id }, 'new', { label: 'ACTIVE' }, change(`${table.subject}.created`));
  });
  return id;
}

/** Records a new label for the row: a second signed event about it. */
const relabel = (table: typeof AGENTS | typeof KEYS, id: string) =>
  withTenant(app, org, async (tx) => {
    const current = await states.verifiedState(tx, table, { orgId: org, id }, 'change');
    if (current.outcome !== 'verified') throw new Error('the row should verify');
    await states.record(
      tx,
      table,
      { orgId: org, id },
      current,
      { label: 'RENAMED' },
      change(`${table.subject}.renamed`),
    );
  });

const verifyAll = (tables: readonly SignedStateTable[] = [AGENTS, KEYS], limit = 100) =>
  withTenant(app, org, (tx) => states.verifyAll(tx, org, tables, limit));

const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: [AGENTS, KEYS] });

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

const finding = (subjectType: string, objectId: string, sign: TamperSign): TamperFinding => ({
  orgId: org,
  subjectType,
  objectId,
  sign,
});

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  await database.as('owner').query('create schema probe');
  await database.as('owner').query('grant usage on schema probe to agentx_app');
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
  found = [];
  states = createSignedStates({ keys, trail, logger: loggerFor(capture), onTamper: (one) => found.push(one) });
  org = newId();
  agents = await tamperAsOwner(database, AGENTS, org);
  agentKeys = await tamperAsOwner(database, KEYS, org);
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await agents.end();
  await agentKeys.end();
  // Every alarm hands its finding on, for the hold (B1b), the one verifyAll raises itself among them.
  expect(found).toEqual(
    alarms().map((line) => ({
      orgId: line.orgId,
      subjectType: line.subjectType,
      objectId: line.objectId,
      sign: line.reason,
    })),
  );
});

describe(`verifyAll: every object of an organisation's authority tables (Postgres ${server.version})`, () => {
  it('verifies every row of every table given, and counts them', async () => {
    await newRow(AGENTS);
    await newRow(AGENTS);
    await newRow(KEYS);

    expect(await verifyAll()).toEqual({ outcome: 'verified', objects: 3 });
    expect(alarms()).toEqual([]);
  });

  it('verifies an organisation with no rows at all', async () => {
    expect(await verifyAll()).toEqual({ outcome: 'verified', objects: 0 });
  });

  it("sees only its own organisation's rows and events", async () => {
    await newRow(AGENTS);
    const other = newId();
    await newRow(AGENTS, other);
    await newRow(KEYS, other);

    expect(await verifyAll()).toEqual({ outcome: 'verified', objects: 1 });
  });

  it.each<[string, (tamper: OwnerTamper, id: string) => Promise<void>, TamperSign]>([
    ['its label changed', (tamper, id) => tamper.setColumn(id, 'label', 'REVOKED'), 'seal'],
    ['its events stripped of their seals', (tamper, id) => tamper.stripSeals(id), 'unsigned'],
    ['the row deleted', (tamper, id) => tamper.deleteRow(id), 'deleted'],
    [
      'the row deleted and its seals stripped, as if it was never made',
      async (tamper, id) => {
        await tamper.stripSeals(id);
        await tamper.deleteRow(id);
      },
      'deleted',
    ],
  ])('names a row %s, with its alarm', async (_name, tamper, sign) => {
    await newRow(AGENTS);
    const id = await newRow(AGENTS);
    await tamper(agents, id);

    expect(await verifyAll()).toEqual({ outcome: 'tampered', findings: [finding('agent', id, sign)] });
    expect(alarms()).toEqual([
      expect.objectContaining({
        level: 'error',
        chain: 'organisation',
        check: 'state',
        reason: sign,
        subjectType: 'agent',
        objectId: id,
        orgId: org,
      }),
    ]);
  });

  it('names a row planted with no event about it', async () => {
    const id = newId();
    await agentKeys.query("insert into probe.keys (org_id, id, label) values ($1, $2, 'ACTIVE')", [org, id]);

    expect(await verifyAll()).toEqual({ outcome: 'tampered', findings: [finding('agent_key', id, 'unsigned')] });
  });

  it('counts nothing for a row planted and deleted again, of which nothing is left', async () => {
    const id = newId();
    await agents.query("insert into probe.agents (org_id, id, label) values ($1, $2, 'ACTIVE')", [org, id]);
    await agents.deleteRow(id);

    expect(await verifyAll()).toEqual({ outcome: 'verified', objects: 0 });
  });

  it('names every finding, table by table in the order given and by ID within each', async () => {
    const [agentA, agentB, keyA] = [await newRow(AGENTS), await newRow(AGENTS), await newRow(KEYS)];
    await agentKeys.setColumn(keyA, 'label', 'REVOKED');
    // The first by ID is deleted, so it is listed from the log alone, after the rows.
    await agents.deleteRow(agentA);
    await agents.setColumn(agentB, 'label', 'REVOKED');

    expect(await verifyAll([KEYS, AGENTS])).toEqual({
      outcome: 'tampered',
      findings: [
        finding('agent_key', keyA, 'seal'),
        finding('agent', agentA, 'deleted'),
        finding('agent', agentB, 'seal'),
      ],
    });
  });

  it.each([
    ['rows', async () => [await newRow(KEYS), await newRow(KEYS), await newRow(KEYS)]],
    [
      'objects the log holds events about, their rows gone',
      async () => {
        const made = [await newRow(KEYS), await newRow(KEYS), await newRow(KEYS)];
        for (const id of made) await agentKeys.deleteRow(id);
        return made;
      },
    ],
    [
      'rows and objects in the log together',
      async () => {
        const made = [await newRow(KEYS), await newRow(KEYS)];
        const planted = newId();
        await agentKeys.query("insert into probe.keys (org_id, id, label) values ($1, $2, 'ACTIVE')", [org, planted]);
        await agentKeys.deleteRow(made[0] ?? '');
        return [...made, planted];
      },
    ],
  ])('judges nothing past the limit in one table: %s', async (_name, make) => {
    await newRow(AGENTS);
    await make();

    expect(await verifyAll([AGENTS, KEYS], 2)).toEqual({ outcome: 'too_many', subjectType: 'agent_key' });
    expect(alarms()).toEqual([]);
  });

  it('judges every object up to the limit', async () => {
    await newRow(KEYS);
    await newRow(KEYS);

    expect(await verifyAll([KEYS], 2)).toEqual({ outcome: 'verified', objects: 2 });
  });

  it('holds each row locked for a decision to the end of its transaction: read again for a decision, not for a change', async () => {
    const id = await newRow(AGENTS);
    let release = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let checked = (): void => undefined;
    const done = new Promise<void>((resolve) => {
      checked = resolve;
    });
    const open = withTenant(app, org, async (tx) => {
      expect(await states.verifyAll(tx, org, [AGENTS], 10)).toEqual({ outcome: 'verified', objects: 1 });
      checked();
      await held;
    });
    await done;
    const readAs = (lock: 'share' | 'change') =>
      withTenant(app, org, async (tx) => {
        await sql`set local lock_timeout = '200ms'`.execute(tx);
        return readSignedRow(tx, AGENTS, { orgId: org, id }, lock);
      });
    try {
      expect(await readAs('share')).toMatchObject({ outcome: 'found' });
      await expect(readAs('change')).rejects.toThrow('lock timeout');
    } finally {
      release();
      await open;
    }
  });

  it("refuses the integrity hold's own subject type, whose state has no row", async () => {
    const hold = {
      table: 'probe.agents',
      subject: HOLD_SUBJECT,
      fields: [{ column: 'label', type: 'text' }],
    } as const;

    await expect(verifyAll([hold])).rejects.toThrow(`The subject type ${HOLD_SUBJECT} is the integrity hold's own`);
  });
});

describe('the lists verifyAll is built on', () => {
  it.each([0, 1.5, -1])('refuses a limit of %s', async (limit) => {
    await expect(withTenant(app, org, (tx) => signedRowIds(tx, AGENTS, org, limit))).rejects.toThrow(
      'The limit is a whole number from 1',
    );
    await expect(withTenant(app, org, (tx) => trail.subjectIds(tx, org, 'agent', limit))).rejects.toThrow(
      'The limit is a whole number from 1',
    );
  });

  it('lists IDs in lower case and in order, each once and only of the table or type asked, one more than the limit at most', async () => {
    const made = [await newRow(AGENTS), await newRow(AGENTS), await newRow(AGENTS)];
    await newRow(KEYS);
    await relabel(AGENTS, made[0] ?? '');

    expect(await withTenant(app, org, (tx) => signedRowIds(tx, AGENTS, org, 2))).toEqual(made);
    expect(await withTenant(app, org, (tx) => trail.subjectIds(tx, org.toUpperCase(), 'agent', 2))).toEqual(made);
    expect(await withTenant(app, org, (tx) => signedRowIds(tx, AGENTS, org, 1))).toEqual(made.slice(0, 2));
  });

  it('refuses an organisation that is not a UUID, and a subject type the log never holds', async () => {
    await expect(withTenant(app, org, (tx) => signedRowIds(tx, AGENTS, 'not-an-id', 5))).rejects.toThrow(
      'A signed row is named by UUIDs',
    );
    await expect(withTenant(app, org, (tx) => trail.subjectIds(tx, org, 'Agent Key', 5))).rejects.toThrow(
      AuditEventRefused,
    );
  });

  it("refuses to list outside withTenant's transaction for the organisation", async () => {
    const other = newId();
    await expect(withTenant(app, other, (tx) => signedRowIds(tx, AGENTS, org, 5))).rejects.toThrow(TenantContextError);
    await expect(withTenant(app, other, (tx) => trail.subjectIds(tx, org, 'agent', 5))).rejects.toThrow(
      TenantContextError,
    );
  });
});

// FX-TAMPER on the organisation's row (SEC-DB-10, B1a) and its integrity hold
// (B1b), as the database's owner: agentx_owner, the role the migration job
// logs in as, holding none of the app's keys, working inside one organisation
// (forced row security binds it too) through @agentx/testing's tamperAsOwner,
// the same scripts A3d proved on a stand-in table.
//
// Each change to the row is denied by the row check, with the SEV-1 alarm, and
// puts the organisation on its integrity hold: HELD, recorded in its audit log
// once the transaction that found it has ended, though the row a hold would
// otherwise live on is the very one tampered with. The hold's own events
// deleted or stripped read as tampering too, which holds it again. A right
// given past the migrations is named by the live schema guard, which holds
// this table to its own rights and is clean before and after each case, so a
// leftover can't hide a miss.
//
// Two cases show what the hold alone can't see, as A3d did for rows: its HELD
// event deleted from the middle of the chain (the chain's check names it) or
// wound back off the end (only the anchor does). Organisation chains join the
// running anchor check in B1d, which sets the hold again.
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import { createDatabase, type Database, liveSchemaProblems, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import {
  type AuditTables,
  type AuditTrail,
  createAuditTrail,
  type TamperSign,
  withSignedStates,
} from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, ORGANIZATIONS } from './organizations.ts';
import type { OrganizationsTables } from './tables.ts';

type Tables = OrganizationsTables & DirectoryTables & AuditTables;

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
const ids = new SequentialIds(0x500);
const trail: AuditTrail = createAuditTrail({ keys, ids });

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let capture: LogCapture;
let owner: OwnerTamper;

let number = 0;
/** A new UUID, so no two tests share an organisation. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x5000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;

/** What withSignedStates builds each transaction's signed states from, logging to this test's capture. */
const services = () => ({ keys, ids, logger: loggerFor(capture) });

const change = (action: string) => ({ actor: { type: 'user' as const, id: newId() }, action, details: {} });

const check = (lock: 'share' | 'change' = 'share') =>
  withSignedStates(app, org, services(), (tx, states) =>
    states.verifiedState(tx, ORGANIZATIONS, { orgId: org, id: org }, lock),
  );

const freeze = () =>
  withSignedStates(app, org, services(), (tx, states) =>
    states.changeStatus(tx, ORGANIZATIONS, { orgId: org, id: org }, 'freeze', change('organization.freeze')),
  );

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

/** The organisation's chain checked whole, against an anchor if one is given. */
const verifyChain = (anchor?: { seq: bigint; hash: Buffer }) =>
  withTenant(app, org, (tx) => trail.verify(tx, org, anchor));

/** What the live schema guard reports, as the API runs it: with the product's own list of authority tables. */
const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const alarms = () => lines('audit.integrity_failed');

/** The alarm line for a tamper sign on the organisation's row, or on its hold. */
const alarmFor = (sign: TamperSign, subjectType = 'organization'): unknown =>
  expect.objectContaining({
    level: 'error',
    event: 'audit.integrity_failed',
    chain: 'organisation',
    check: 'state',
    reason: sign,
    subjectType,
    objectId: org,
    orgId: org,
  });

interface HoldEvent {
  seq: string;
  id: string;
  action: string;
  actor_type: string;
  actor_id: string;
  subject_version: number;
  details: Record<string, unknown>;
}

/** The hold's events as the owner reads them, oldest first. */
const holdEvents = async (): Promise<HoldEvent[]> => {
  const rows = await owner.query<Omit<HoldEvent, 'details'> & { details: string }>(
    "select seq::text as seq, id, action, actor_type, actor_id, subject_version, details from audit.events where org_id = $1 and subject_type = 'integrity_hold' order by seq",
    [org],
  );
  return rows.map((row) => ({ ...row, details: JSON.parse(row.details) as Record<string, unknown> }));
};

/** Denied read for a decision and read for a change, each with its alarm. */
async function deniedWith(sign: TamperSign): Promise<void> {
  expect(await check()).toEqual({ outcome: 'tampered', sign });
  expect(await check('change')).toEqual({ outcome: 'tampered', sign });
  expect(alarms()).toEqual([alarmFor(sign), alarmFor(sign)]);
}

/**
 * Held for the first sign found on the organisation's row: one HELD event, set
 * by the app itself after the first denied read (the second found it held
 * already), recorded over the CLEAR it was created with, or over none.
 */
async function heldFor(sign: TamperSign, over: 'CLEAR' | null = 'CLEAR'): Promise<void> {
  expect(await hold()).toMatchObject({ outcome: 'held' });
  const set = (await holdEvents()).filter((event) => event.action === 'integrity_hold.set');
  expect(set).toEqual([
    expect.objectContaining({
      actor_type: 'system',
      actor_id: 'integrity-hold',
      subject_version: over === 'CLEAR' ? 2 : 1,
      details: expect.objectContaining({
        statusFrom: over,
        statusTo: 'HELD',
        reason: sign,
        foundOn: 'organization',
        objectId: org,
        findings: 1,
      }) as unknown,
    }),
  ]);
  expect(lines('audit.integrity_hold_set')).toEqual([
    expect.objectContaining({ level: 'warn', orgId: org, reason: sign, subjectType: 'organization', findings: 1 }),
  ]);
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = newId();
  owner = await tamperAsOwner(database, ORGANIZATIONS, org);
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  expect(await guard()).toEqual([]);
});

/** Creates this test's organisation, as the operator's command will, logging to a capture of its own. */
async function created(): Promise<void> {
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    createOrganization(tx, states, {
      id: org,
      name: 'Acme Trading LLC',
      actor: { type: 'system', id: 'test-operator' },
    }),
  );
}

describe(`FX-TAMPER as the owner on an organisation's row: denied by the row check, and held (Postgres ${server.version})`, () => {
  it('unfrozen: the status set back to ACTIVE, along a move the status guard allows', async () => {
    await created();
    await freeze();
    await owner.setColumn(org, 'status', 'ACTIVE');

    await deniedWith('seal');
    await heldFor('seal');
  });

  it('unfrozen by rolling the row back to its saved, validly signed state', async () => {
    await created();
    const saved = await owner.saveRow(org);
    await freeze();
    await owner.restoreRow(saved);

    await deniedWith('pointer');
    await heldFor('pointer');
  });

  it('planted with no event, an organisation the app never created: held over no hold at all', async () => {
    await owner.query('insert into directory.orgs (org_id) values ($1)', [org]);
    await owner.query(
      "insert into organizations.organizations (org_id, id, name, status) values ($1, $1, 'Planted', 'ACTIVE')",
      [org],
    );

    expect(await check()).toEqual({ outcome: 'tampered', sign: 'unsigned' });
    expect(await check('change')).toEqual({ outcome: 'tampered', sign: 'unsigned' });
    // The hold has no state either, which is tampering of its own, found as the hold is set over it.
    expect(alarms()).toEqual([alarmFor('unsigned'), alarmFor('unsigned', 'integrity_hold'), alarmFor('unsigned')]);
    await heldFor('unsigned', null);
  });

  it('deleted, which the app role cannot do', async () => {
    await created();
    await owner.deleteRow(org);

    await deniedWith('deleted');
    await heldFor('deleted');
  });

  it.each([
    ['its events stripped of their seals', (tamper: OwnerTamper, id: string) => tamper.stripSeals(id)],
    ['its events deleted', (tamper: OwnerTamper, id: string) => tamper.deleteEvents(id)],
  ])('%s', async (_, tamper) => {
    await created();
    await freeze();
    await tamper(owner, org);

    await deniedWith('unsigned');
    await heldFor('unsigned');
  });

  it('the app role given DELETE on it: the guard names the right, and nothing is held', async () => {
    await created();
    await owner.query('grant delete on organizations.organizations to agentx_app');
    try {
      expect(await guard()).toEqual(['agentx_app may DELETE on organizations.organizations']);
    } finally {
      await owner.query('revoke delete on organizations.organizations from agentx_app');
    }
    expect(await check()).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 1 });
    expect(alarms()).toEqual([]);
  });

  it('found in a change that then failed and rolled back: the hold is set all the same', async () => {
    await created();
    await freeze();
    await owner.setColumn(org, 'status', 'ACTIVE');

    await expect(
      withSignedStates(app, org, services(), async (tx, states) => {
        expect(await states.verifiedState(tx, ORGANIZATIONS, { orgId: org, id: org }, 'change')).toMatchObject({
          outcome: 'tampered',
        });
        throw new Error('the change gives up');
      }),
    ).rejects.toThrow('the change gives up');

    await heldFor('seal');
  });
});

describe(`FX-TAMPER as the owner on the integrity hold itself (Postgres ${server.version})`, () => {
  it("its events deleted (the catalogue's 'delete the integrity hold'): read as tampering, and held", async () => {
    await created();
    await owner.query("delete from audit.events where org_id = $1 and subject_type = 'integrity_hold'", [org]);

    expect(await hold()).toEqual({ outcome: 'tampered', sign: 'unsigned' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 1 });
    expect(alarms()).toEqual([alarmFor('unsigned', 'integrity_hold'), alarmFor('unsigned', 'integrity_hold')]);
    expect((await holdEvents()).map(({ action, subject_version }) => [action, subject_version])).toEqual([
      ['integrity_hold.set', 1],
    ]);
  });

  it('its seals stripped: read as tampering, and held over them', async () => {
    await created();
    await owner.query(
      "update audit.events set details = ((details::jsonb - 'stateFingerprint') - 'stateKeyVersion')::text where org_id = $1 and subject_type = 'integrity_hold'",
      [org],
    );

    expect(await hold()).toEqual({ outcome: 'tampered', sign: 'unsigned' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 1 });
  });

  it("HELD, then its event's details edited: it fails its own check, and is held again over it, from version 1", async () => {
    await created();
    await owner.setColumn(org, 'status', 'FROZEN');
    await check();
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });

    await owner.query(
      'update audit.events set details = pg_catalog.replace(details, \'"statusTo":"HELD"\', \'"statusTo":"CLEAR"\') where org_id = $1 and action = \'integrity_hold.set\'',
      [org],
    );

    expect(await hold()).toEqual({ outcome: 'tampered', sign: 'log' });
    // Nothing in a state that can't be believed is trusted, its version included.
    expect(await hold()).toMatchObject({ outcome: 'held', version: 1 });
    expect((await holdEvents()).at(-1)?.details).toMatchObject({
      statusFrom: null,
      reason: 'log',
      foundOn: 'integrity_hold',
    });
  });

  it("the organisation's row tampered with and its hold's events deleted at once: held all the same", async () => {
    await created();
    await owner.setColumn(org, 'status', 'FROZEN');
    await owner.query("delete from audit.events where org_id = $1 and subject_type = 'integrity_hold'", [org]);

    expect(await check()).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 1 });
    expect((await holdEvents())[0]?.details).toMatchObject({
      statusFrom: null,
      reason: 'seal',
      foundOn: 'organization',
    });
  });

  it("the chain's head broken: no hold can be recorded, so every read of it is denied, with the alarm naming the hold", async () => {
    await created();
    await owner.setColumn(org, 'status', 'FROZEN');
    await owner.query(
      "update audit.heads set mac = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') where org_id = $1",
      [org],
    );

    // The read is denied, and its answer still reaches the caller once the hold has failed.
    expect(await check()).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(lines('audit.integrity_failed')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ check: 'hold', reason: 'not_recorded', orgId: org, level: 'error' }),
      ]),
    );
    expect(await hold()).toEqual({ outcome: 'tampered', sign: 'log' });
    expect((await holdEvents()).map(({ action }) => action)).toEqual(['integrity_hold.created']);
    expect(lines('audit.integrity_hold_set')).toEqual([]);
  });

  it.each([
    [
      'an event planted past its head',
      async () => {
        await owner.query(
          `insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id,
             subject_version, details, prev_hash, hash, mac, mac_key_version)
           select h.org_id, h.seq + 1, gen_random_uuid(), pg_catalog.now(), 'system', 'planted', 'planted.event',
             'planted', gen_random_uuid(), 1, '{}', h.hash, h.hash, h.mac, 1
           from audit.heads h where h.org_id = $1`,
          [org],
        );
      },
    ],
    [
      'its head put back to an earlier sealed one, the events after it kept',
      async () => {
        const earlier = await owner.saveHead();
        await freeze();
        await owner.query('update audit.heads set seq = $2::bigint, hash = $3, mac = $4 where org_id = $1', [
          org,
          earlier.seq,
          earlier.hash,
          earlier.mac,
        ]);
      },
    ],
  ])(
    'the chain refusing new events, %s: no hold can be recorded, and every read is denied, never clear',
    async (_, tamper) => {
      await created();
      await tamper();

      expect(await check()).toEqual({ outcome: 'tampered', sign: 'log' });
      expect(await hold()).toEqual({ outcome: 'tampered', sign: 'log' });
      expect(lines('audit.integrity_failed')).toEqual(
        expect.arrayContaining([expect.objectContaining({ check: 'hold', reason: 'not_recorded', orgId: org })]),
      );
      expect(lines('audit.integrity_hold_set')).toEqual([]);
    },
  );

  it('HELD, and its event deleted from the middle of the chain with the row put back: only the chain check tells', async () => {
    await created();
    const saved = await owner.saveRow(org);
    await owner.setColumn(org, 'status', 'FROZEN');
    await check();
    const [, held] = await holdEvents();
    if (held === undefined) throw new Error('The hold should have been set');
    await owner.restoreRow(saved);
    // A later event, so the one deleted is in the middle of the chain.
    await freeze();

    await owner.query('delete from audit.events where org_id = $1 and id = $2', [org, held.id]);

    expect(await hold()).toMatchObject({ outcome: 'clear', version: 1 });
    expect(await verifyChain()).toMatchObject({ ok: false });
  });

  it('SEC-DB-11 HELD, then the chain wound back past it and the row put back: only the anchor tells', async () => {
    await created();
    const savedRow = await owner.saveRow(org);
    const savedHead = await owner.saveHead();
    await owner.setColumn(org, 'status', 'FROZEN');
    await check();
    expect(await hold()).toMatchObject({ outcome: 'held' });
    // The anchor check saw the chain with the hold on it and anchored it there.
    const anchored = await verifyChain();
    if (!anchored.ok) throw new Error('The chain should have checked out before the winding back');

    await owner.windBack(savedHead);
    await owner.restoreRow(savedRow);

    expect(await check()).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 1 });
    expect(await verifyChain({ seq: anchored.seq, hash: anchored.hash })).toMatchObject({
      ok: false,
      problem: { reason: 'anchor' },
    });
  });
});

// S206 V6: the security rows from before 0106 given their MACs at start, on
// the real migrated schema as the app role. Each table's rows without a MAC
// sealed once, the record of it on the platform chain, and a second start
// doing nothing; then no row without a MAC is believed. A record deleted
// while rows carry MACs, or edited, is never sealed again: the alarm. A start
// that finds sealing begun waits for its end and never seals a row itself.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createPlatformChain, type PlatformControlsTables } from '../../platform-controls/index.ts';
import { eventMacHolds } from './event-seals.ts';
import { ALL_SEALED, SEALING_STARTED, sealLegacyRows } from './legacy-seal.ts';
import type { SecurityEventsTables } from './tables.ts';

type Tables = SecurityEventsTables & PlatformControlsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;
let capture: LogCapture;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x1e9a_0000_0000);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const AT = new Date('2026-11-25T09:00:00.000Z');

const owner = () => database.as('admin');

/** 0106's rule that every row written carries a MAC, off: as before 0106, or as the database's owner can. */
const DROP_RULE = `
  alter table security.events drop constraint if exists event_mac_required;
  alter table security.org_events drop constraint if exists org_event_mac_required;
  alter table security.partner_event_evidence drop constraint if exists evidence_mac_required`;

const ownerDropsRule = () => owner().query(DROP_RULE);

/** Rows of every table as the release before wrote them: no MAC, marked from before 0106 as it marks them. */
async function legacyRows(): Promise<void> {
  for (let n = 0; n < 3; n += 1) {
    await owner().query(
      `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at, before_macs)
       values ($1, 'sign_in_failed', 'state_mismatch', '203.0.113.7', null, $2, 1, $2, true)`,
      [ids.next(), AT],
    );
  }
  await owner().query(
    `insert into security.org_events (org_id, id, kind, reason, ip, user_id, agent_id, window_start, count, created_at,
       before_macs)
     values ($1, $2, 'rate_limited', 'per_user', null, null, null, $3, 2, $3, true)`,
    [ORG, ids.next(), AT],
  );
  await owner().query(
    `insert into security.partner_event_evidence (id, reason, ip, body_ciphertext, body_key_version, body_bytes,
       received_at, before_macs)
     values ($1, 'signature', null, $2, 1, 2, $3, true)`,
    [ids.next(), Buffer.alloc(40, 1), AT],
  );
}

const unsealed = async () =>
  (
    await owner().query<{ rows: string }>(
      `select (select count(*) from security.events where mac is null)
         + (select count(*) from security.org_events where mac is null)
         + (select count(*) from security.partner_event_evidence where mac is null) as rows`,
    )
  )[0]?.rows;

const records = async () =>
  (
    await app
      .selectFrom('platform_controls.audit_events')
      .select('action')
      .where('action', 'in', [SEALING_STARTED, ALL_SEALED])
      .orderBy('seq')
      .execute()
  ).map(({ action }) => action);

const seal = (waitForOtherMs = 0) =>
  sealLegacyRows(app, { keys, ids, logger: testLogger(capture), orgs: () => Promise.resolve([ORG]), waitForOtherMs });

const alarms = () =>
  capture
    .lines()
    .filter((line) => line.event === 'audit.integrity_failed')
    .map(({ reason }) => reason);

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
  capture = new LogCapture();
});

afterEach(async () => {
  await app.destroy();
  await database.drop();
});

describe('0106: every row written from now on carries a MAC (S206 V6)', () => {
  it('refuses a row without one in every table, as the release before would write it during the roll-out', async () => {
    const at = new Date('2026-11-25T09:00:00.000Z');
    await expect(
      app
        .insertInto('security.events')
        .values({
          id: ids.next(),
          kind: 'sign_in_failed',
          reason: 'state_mismatch',
          ip: null,
          user_id: null,
          window_start: at,
          count: 1,
          created_at: at,
        })
        .execute(),
    ).rejects.toMatchObject({ code: '23514' });
    await expect(
      withTenant(app, ORG, (tx) =>
        tx
          .insertInto('security.org_events')
          .values({
            org_id: ORG,
            id: ids.next(),
            kind: 'rate_limited',
            reason: 'per_user',
            ip: null,
            user_id: null,
            agent_id: null,
            window_start: at,
            count: 1,
            created_at: at,
          })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '23514' });
    await expect(
      owner().query(
        `insert into security.partner_event_evidence (id, reason, ip, body_ciphertext, body_key_version, body_bytes, received_at)
         values ($1, 'signature', null, $2, 1, 2, $3)`,
        [ids.next(), Buffer.alloc(40, 1), at],
      ),
    ).rejects.toMatchObject({ code: '23514' });
  });
});

describe('the security rows from before 0106 sealed at start (S206 V6)', () => {
  it('gives each row of every table its MAC, once, records it, and a second start does nothing', async () => {
    await legacyRows();
    expect(await unsealed()).toBe('5');

    expect(await seal()).toBe('sealed');
    expect(await unsealed()).toBe('0');
    expect(await records()).toEqual([SEALING_STARTED, ALL_SEALED]);
    // The MAC each was given is the one every reader checks.
    const [row] = await withTenant(app, ORG, (tx) => tx.selectFrom('security.org_events').selectAll().execute());
    expect(
      row !== undefined &&
        eventMacHolds(
          keys,
          {
            id: row.id,
            orgId: row.org_id,
            kind: row.kind,
            reason: row.reason,
            ip: row.ip,
            userId: row.user_id,
            agentId: row.agent_id,
            windowStart: row.window_start,
            count: row.count,
            createdAt: row.created_at,
          },
          row,
        ),
    ).toBe(true);

    // A row without a MAC planted after: never sealed, by a later start or any.
    await legacyRows();
    expect(await seal()).toBe('sealed');
    expect(await unsealed()).toBe('5');
    expect(await records()).toEqual([SEALING_STARTED, ALL_SEALED]);
    expect(alarms()).toEqual([]);
  });

  it('its record deleted while rows carry MACs: nothing sealed again, nothing recorded, the alarm', async () => {
    await legacyRows();
    await seal();
    await owner().query('delete from platform_controls.audit_events where action in ($1, $2)', [
      SEALING_STARTED,
      ALL_SEALED,
    ]);
    await legacyRows();

    expect(await seal()).toBe('deleted');
    expect(await unsealed()).toBe('5');
    expect(await records()).toEqual([]);
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  const NULL_ORG_MACS = 'update security.org_events set mac = null, mac_key_version = null';
  const NULL_GLOBAL_MACS = 'update security.events set mac = null, mac_key_version = null';

  it.each([
    ['the global table’s', true],
    ['an organisation’s', false],
  ])('its records deleted while only %s rows carry MACs: the alarm all the same', async (_which, globalKept) => {
    await legacyRows();
    await seal();
    await owner().query('delete from platform_controls.audit_events where action in ($1, $2)', [
      SEALING_STARTED,
      ALL_SEALED,
    ]);
    await ownerDropsRule();
    await owner().query('update security.partner_event_evidence set mac = null, mac_key_version = null');
    if (globalKept) await owner().query(NULL_ORG_MACS);
    else await owner().query(NULL_GLOBAL_MACS);

    expect(await seal()).toBe('deleted');
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  it('sealing begun but its end not recorded: never sealed again, whoever began it; the alarm once the wait is up', async () => {
    await legacyRows();
    await seal();
    // Its end removed for one start, the owner's rows tampered with and their MACs taken off, to be sealed afresh.
    await owner().query('delete from platform_controls.audit_events where action = $1', [ALL_SEALED]);
    await ownerDropsRule();
    await owner().query(
      "update security.events set mac = null, mac_key_version = null, reason = 'callback_incomplete'",
    );

    expect(await seal(0)).toBe('deleted');
    expect(await unsealed()).toBe('3');
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  it('its end recorded meanwhile by the start that began it: this start waits for it and seals nothing', async () => {
    await legacyRows();
    await seal();
    await owner().query('delete from platform_controls.audit_events where action = $1', [ALL_SEALED]);
    const waiting = seal(60_000);
    // The other start finishing: its record of the end written now.
    await ownerDropsRule();
    await owner().query('update security.events set mac = null, mac_key_version = null');
    await app.transaction().execute((tx) =>
      createPlatformChain({ keys, ids }).record(tx, {
        actor: { type: 'system', id: 'api' },
        action: ALL_SEALED,
        details: {},
      }),
    );

    expect(await waiting).toBe('sealed');
    expect(await unsealed()).toBe('3');
    expect(alarms()).toEqual([]);
  });

  it('a record whose action the owner changed for one start: nothing sealed, the alarm', async () => {
    await legacyRows();
    await seal();
    await owner().query("update platform_controls.audit_events set action = 'x.y' where action = $1", [ALL_SEALED]);
    await ownerDropsRule();
    await owner().query('update security.events set mac = null, mac_key_version = null');

    expect(await seal(0)).toBe('deleted');
    expect(await unsealed()).toBe('3');
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  it('a record the owner rewrote is never believed: the alarm, nothing sealed', async () => {
    await legacyRows();
    await seal();
    await owner().query('update platform_controls.audit_events set details = \'{"x":1}\' where action = $1', [
      ALL_SEALED,
    ]);
    await legacyRows();

    expect(await seal()).toBe('unsealed');
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual(['seal_record_unsealed']);
  });
});

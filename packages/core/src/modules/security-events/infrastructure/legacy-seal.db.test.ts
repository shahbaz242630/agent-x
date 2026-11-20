// S206 V6: the security rows from before 0105 given their MACs at start, on
// the real migrated schema as the app role. Each table's rows without a MAC
// sealed once, the record of it on the platform chain, and a second start
// doing nothing; then no row without a MAC is believed. A record deleted
// while rows carry MACs, or edited, is never sealed again: the alarm. A start
// that finds sealing begun waits for its end and never seals a row itself.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  within,
} from '@agentx/testing';
import { sql } from 'kysely';
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createPlatformChain, type PlatformControlsTables } from '../../platform-controls/index.ts';
import { eventMac, eventMacHolds } from './event-seals.ts';
import { DAY_MS } from '../../../shared-kernel/index.ts';
import {
  ALL_SEALED,
  type ChainPlace,
  databaseBirth,
  legacyManifest,
  legacyRowsAt,
  ROW_MACS_FROM,
  SEALER_LOCK,
  SEALING_STARTED,
  SECURITY_SEAL_BACKFILL_UNTIL,
  sealLegacyRows,
} from './legacy-seal.ts';
import { createSecurityEvents } from './security-events.ts';
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
/** When a start's sealing runs: a minute after the rows from before 0105 were written. */
const STARTS = new Date(AT.getTime() + 60_000);

const owner = () => database.as('admin');

/** 0105's rule that every row written carries a MAC, off: as before 0105, or as the database's owner can. */
const DROP_RULE = `
  alter table security.events drop constraint if exists event_mac_required;
  alter table security.org_events drop constraint if exists org_event_mac_required;
  alter table security.partner_event_evidence drop constraint if exists evidence_mac_required`;

const ownerDropsRule = () => owner().query(DROP_RULE);

/** Rows of every table as the release before wrote them: no MAC, marked from before 0105 as it marks them. */
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

/** The platform chain's head now, as the anchor check would anchor it; undefined for an empty chain. */
const headNow = async (): Promise<ChainPlace | undefined> => {
  const [head] = await owner().query<{ seq: string; hash: Buffer; mac_key_version: number }>(
    'select seq, hash, mac_key_version from platform_controls.audit_head',
  );
  return head === undefined
    ? undefined
    : { seq: BigInt(head.seq), hash: head.hash, macKeyVersion: head.mac_key_version };
};

const RETENTION = 30;

/** The chain's head row as it stands, every column the owner would keep to put it back. */
interface HeadRow {
  readonly seq: string;
  readonly hash: Buffer;
  readonly mac: Buffer;
  readonly mac_key_version: number;
}
const headRow = async (): Promise<HeadRow | undefined> =>
  (await owner().query<HeadRow>('select seq, hash, mac, mac_key_version from platform_controls.audit_head'))[0];

type Row = Readonly<Record<string, unknown>>;

/** The MAC the app gives a global row from before 0105 as it seals it. */
const eventMacOf = (row: Row | undefined) =>
  eventMac(keys, {
    id: String(row?.id),
    orgId: null,
    kind: String(row?.kind),
    reason: String(row?.reason),
    ip: typeof row?.ip === 'string' ? row.ip : null,
    userId: null,
    agentId: null,
    windowStart: row?.window_start as Date,
    count: Number(row?.count),
    createdAt: row?.created_at as Date,
  });

/** The record each of the sealing's anchors was taken after, in order. */
let anchoredAt: string[] = [];

/** A sealing at `now`, the chain held to `anchor` (its head as the sealing reads it, unless named). */
const seal = (now = STARTS, anchor: () => Promise<ChainPlace | undefined> = headNow) =>
  sealLegacyRows(app, {
    keys,
    ids,
    clock: new FixedClock(now),
    logger: testLogger(capture),
    orgs: () => Promise.resolve([ORG]),
    retentionDays: RETENTION,
    // Which record each anchor is taken after: the newest of them then.
    anchorNow: async () => {
      anchoredAt.push(String((await records()).at(-1)));
    },
    anchor,
  });

/** An event of the app's on the platform chain, as another start records it. */
const recorded = (action: string, details: Readonly<Record<string, string | number>> = {}) =>
  app
    .transaction()
    .execute((tx) =>
      createPlatformChain({ keys, ids }).record(tx, { actor: { type: 'system', id: 'api' }, action, details }),
    );

/** The manifest a start would record as it began sealing at AT, as its record's details hold it. */
const manifestNow = async () => {
  const manifest = await legacyManifest(
    app,
    () => Promise.resolve([ORG]),
    new Date(AT.getTime() - (RETENTION - 2) * DAY_MS),
  );
  return { since: manifest.since, until: STARTS.toISOString(), days: JSON.stringify(manifest.days) };
};

const alarms = () =>
  capture
    .lines()
    .filter((line) => line.event === 'audit.integrity_failed')
    .map(({ reason }) => reason);

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
  capture = new LogCapture();
  anchoredAt = [];
  // A chain already under way, as every environment's is, for its head to be anchored.
  await recorded('platform.started');
});

afterEach(async () => {
  await app.destroy();
  await database.drop();
});

describe('SEC-DB-18 0105: every row written from now on carries a MAC (S206 V6)', () => {
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

describe('SEC-DB-18 the security rows from before 0105 sealed at start (S206 V6)', () => {
  it('gives each row of every table its MAC, once, records it, and a second start does nothing', async () => {
    await legacyRows();
    expect(await unsealed()).toBe('5');

    expect(await seal()).toBe('sealed');
    expect(await unsealed()).toBe('0');
    expect(await records()).toEqual([SEALING_STARTED, ALL_SEALED]);
    // Anchored at once after each record, so deleting either is a chain wound back past an anchor.
    expect(anchoredAt).toEqual([SEALING_STARTED, ALL_SEALED]);
    // The sealer's lock given back (this database's alone: other tests share the server).
    expect(
      await owner().query(
        "select 1 from pg_catalog.pg_locks l join pg_catalog.pg_database d on d.oid = l.database where l.locktype = 'advisory' and d.datname = pg_catalog.current_database()",
      ),
    ).toEqual([]);
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

  it('gives no MAC to a marked row written after the sealing began (no release writes one): its time is recorded, the row left unbelieved', async () => {
    await legacyRows();
    const later = ids.next();
    await owner().query(
      `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at, before_macs)
       values ($1, 'sign_in_failed', 'state_mismatch', null, null, $2, 1, $2, true)`,
      [later, new Date(STARTS.getTime() + 1)],
    );

    expect(await seal()).toBe('sealed');
    expect(
      (await owner().query<{ id: string }>('select id from security.events where mac is null')).map(({ id }) => id),
    ).toEqual([later]);
    const [started] = await owner().query<{ details: string }>(
      'select details from platform_controls.audit_events where action = $1',
      [SEALING_STARTED],
    );
    expect((JSON.parse(started?.details ?? '{}') as Record<string, unknown>).until).toBe(STARTS.toISOString());
  });

  it('tells the day seal which marked rows with no MAC to excuse: before the start, the start’s time, the scope; none past the cutoff or for a record that can’t be believed', async () => {
    const told = (now = STARTS) => app.transaction().execute((tx) => legacyRowsAt(tx, keys, now));
    expect(await told()).toEqual({ excusedBefore: STARTS });
    expect(await told(new Date(SECURITY_SEAL_BACKFILL_UNTIL))).toEqual({ excusedBefore: null });

    // A record from before it kept its time: the chain's own time of it.
    await recorded(SEALING_STARTED, { since: '2026-10-28T09:00:00.000Z', days: '{}' });
    const [{ recorded_at: recordedAt } = { recorded_at: undefined }] = await owner().query<{ recorded_at: Date }>(
      'select recorded_at from platform_controls.audit_events where action = $1',
      [SEALING_STARTED],
    );
    expect(await told()).toEqual({ excusedBefore: recordedAt });
    await owner().query('delete from platform_controls.audit_events where action = $1', [SEALING_STARTED]);

    await recorded(SEALING_STARTED, await manifestNow());
    expect(await told(new Date(STARTS.getTime() + DAY_MS))).toEqual({ excusedBefore: STARTS });
    await recorded(ALL_SEALED);
    expect(await told(new Date(SECURITY_SEAL_BACKFILL_UNTIL))).toEqual({
      excusedBefore: new Date(AT.getTime() - (RETENTION - 2) * DAY_MS),
    });

    await owner().query(`update platform_controls.audit_events set details = '{"since":"x"}' where action = $1`, [
      SEALING_STARTED,
    ]);
    expect(await told()).toBe('unsealed');
  });

  it('before any sealing, bounds the old rows by the first start that records its time, and by when the job first found the lock taken', async () => {
    const told = (now = STARTS) => app.transaction().execute((tx) => legacyRowsAt(tx, keys, now));
    const firstStart = new Date(AT.getTime() + 30_000);
    await recorded('platform.started', { release: 'r-before' });
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: firstStart.toISOString() });
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: STARTS.toISOString() });
    expect(await told()).toEqual({ excusedBefore: firstStart });
    expect(await told(AT)).toEqual({ excusedBefore: AT });

    // Rows marked by the owner after that start, or after the job first found the lock taken: never given a MAC.
    await legacyRows();
    const marked = async (at: Date) => {
      const id = ids.next();
      await owner().query(
        `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at, before_macs)
         values ($1, 'sign_in_failed', 'state_mismatch', null, null, $2, 1, $2, true)`,
        [id, at],
      );
      return id;
    };
    const afterStart = await marked(new Date(firstStart.getTime() + 1));
    const afterBusy = await marked(new Date(AT.getTime() + 20_000));
    const sealed = await sealLegacyRows(app, {
      keys,
      ids,
      clock: new FixedClock(STARTS),
      logger: testLogger(capture),
      orgs: () => Promise.resolve([ORG]),
      retentionDays: RETENTION,
      anchorNow: () => Promise.resolve(),
      anchor: headNow,
      notAfter: new Date(AT.getTime() + 10_000),
    });
    expect(sealed).toBe('sealed');
    expect(
      (await owner().query<{ id: string }>('select id from security.events where mac is null order by id')).map(
        ({ id }) => id,
      ),
    ).toEqual([afterStart, afterBusy]);
  });

  it('a start’s record of its time edited by the owner: the day seal is told it can’t be believed, the sealing raises the alarm', async () => {
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: AT.toISOString() });
    // A later event the head, so the chain held to it from there passes: only the start's own MAC can say.
    await recorded('platform.started', { release: 'r-after' });
    await owner().query(
      `update platform_controls.audit_events set details = '{"release":"r","rowMacsFrom":"2027-01-01T00:00:00.000Z"}'
       where action = 'platform.started' and details like '%rowMacsFrom%'`,
    );

    expect(await app.transaction().execute((tx) => legacyRowsAt(tx, keys, STARTS))).toBe('unsealed');
    expect(await seal()).toBe('unsealed');
    expect(alarms()).toEqual(['seal_record_unsealed']);
  });

  it('a start’s time removed from its record by the owner, to pass for a start from before: can’t be believed, at once', async () => {
    await recorded('platform.started', { release: 'r-before' });
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: AT.toISOString() });
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: STARTS.toISOString() });
    const told = () => app.transaction().execute((tx) => legacyRowsAt(tx, keys, STARTS));
    expect(await told()).toEqual({ excusedBefore: AT });

    await owner().query(
      `update platform_controls.audit_events set details = '{"release":"r"}'
       where action = 'platform.started' and details like $1`,
      [`%${AT.toISOString()}%`],
    );
    expect(await told()).toBe('unsealed');
  });

  it('a start’s time that isn’t a time is never read as one', async () => {
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: 7 });
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: STARTS.toISOString() });

    expect(await app.transaction().execute((tx) => legacyRowsAt(tx, keys, STARTS))).toBe('unsealed');
  });

  it('leaves a row within two days of the retention to the sweep, unsealed (never believed): it would go before a start took a sealing up again', async () => {
    await legacyRows();
    const old = new Date(AT.getTime() - (RETENTION - 1) * DAY_MS);
    await owner().query(
      `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at, before_macs)
       values ($1, 'sign_in_failed', 'state_mismatch', null, null, $2, 1, $2, true)`,
      [ids.next(), old],
    );

    expect(await seal()).toBe('sealed');
    expect(await unsealed()).toBe('1');
  });

  /** The owner's deletion of the sealing's records from the chain's tail, its head put back as `kept` left it. */
  const deletedFromTail = async (kept: HeadRow | undefined) => {
    await owner().query('delete from platform_controls.audit_events where action in ($1, $2)', [
      SEALING_STARTED,
      ALL_SEALED,
    ]);
    await owner().query('update platform_controls.audit_head set seq = $1, hash = $2, mac = $3, mac_key_version = $4', [
      kept?.seq,
      kept?.hash,
      kept?.mac,
      kept?.mac_key_version,
    ]);
  };

  it('its records deleted from the tail before an anchor passed them, the head put back, while rows carry MACs: nothing sealed again, nothing recorded, the alarm', async () => {
    await legacyRows();
    const kept = await headRow();
    await seal();
    await deletedFromTail(kept);
    await legacyRows();

    expect(await seal()).toBe('deleted');
    expect(await unsealed()).toBe('5');
    expect(await records()).toEqual([]);
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  it('its records deleted from the tail with the head left: the chain fails, nothing sealed, the alarm', async () => {
    await legacyRows();
    await seal();
    await owner().query('delete from platform_controls.audit_events where action in ($1, $2)', [
      SEALING_STARTED,
      ALL_SEALED,
    ]);
    await legacyRows();

    expect(await seal()).toBe('unsealed');
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual(['seal_record_unsealed']);
  });

  const NULL_ORG_MACS = 'update security.org_events set mac = null, mac_key_version = null';
  const NULL_GLOBAL_MACS = 'update security.events set mac = null, mac_key_version = null';

  it.each([
    ['the global table’s', true],
    ['an organisation’s', false],
  ])('its records deleted while only %s rows carry MACs: the alarm all the same', async (_which, globalKept) => {
    await legacyRows();
    const kept = await headRow();
    await seal();
    await deletedFromTail(kept);
    await ownerDropsRule();
    await owner().query('update security.partner_event_evidence set mac = null, mac_key_version = null');
    if (globalKept) await owner().query(NULL_ORG_MACS);
    else await owner().query(NULL_GLOBAL_MACS);

    expect(await seal()).toBe('deleted');
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  it('a sealing begun and left part way (a stop) is taken up by the next start, from the rows still without a MAC', async () => {
    await legacyRows();
    // Another start's record of its beginning, with its manifest, and one row it reached sealed, as a stop leaves them.
    await recorded(SEALING_STARTED, await manifestNow());
    const [first] = await owner().query<Row>(
      'select id, kind, reason, ip, user_id, window_start, count, created_at from security.events order by id limit 1',
    );
    const { mac, mac_key_version } = eventMacOf(first);
    await app
      .updateTable('security.events')
      .set({ mac, mac_key_version })
      .where('id', '=', String(first?.id))
      .execute();
    expect(await unsealed()).toBe('4');

    expect(await seal()).toBe('sealed');
    expect(await unsealed()).toBe('0');
    expect(await records()).toEqual([SEALING_STARTED, ALL_SEALED]);
    expect(alarms()).toEqual([]);
  });

  it('a sealing begun and left, its end then deleted from the chain’s tail and the head put back, rows planted: the manifest no longer holds, nothing sealed, the alarm', async () => {
    await legacyRows();
    await recorded(SEALING_STARTED, await manifestNow());
    // The head as it stood with the beginning the last event, kept by the owner.
    const [kept] = await owner().query<{ seq: string; hash: Buffer; mac: Buffer; mac_key_version: number }>(
      'select seq, hash, mac, mac_key_version from platform_controls.audit_head',
    );
    await recorded(ALL_SEALED);
    await owner().query('delete from platform_controls.audit_events where action = $1', [ALL_SEALED]);
    await owner().query('update platform_controls.audit_head set seq = $1, hash = $2, mac = $3, mac_key_version = $4', [
      kept?.seq,
      kept?.hash,
      kept?.mac,
      kept?.mac_key_version,
    ]);
    await legacyRows();

    expect(await seal()).toBe('manifest');
    expect(await unsealed()).toBe('10');
    expect(alarms()).toEqual(['seal_record_manifest']);
  });

  it('a chain wiped by the owner, its MAC’d rows gone and rows planted: the chain fails its last anchor, nothing sealed, the alarm', async () => {
    await legacyRows();
    await seal();
    const anchored = await headNow();
    await owner().query('truncate platform_controls.audit_events, platform_controls.audit_head');
    await owner().query('delete from security.events');
    await owner().query('delete from security.org_events');
    await owner().query('delete from security.partner_event_evidence');
    await legacyRows();

    expect(await seal(STARTS, () => Promise.resolve(anchored))).toBe('unsealed');
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual(['seal_record_unsealed']);
  });

  it('no anchor to hold the chain to: nothing sealed, the alarm', async () => {
    await legacyRows();

    expect(await seal(STARTS, () => Promise.resolve(undefined))).toBe('unanchored');
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual(['seal_record_unanchored']);
  });

  it('a long sealing keeps its lock: no transaction left waiting for the idle limit to end, a second start busy meanwhile', async () => {
    await legacyRows();
    const { promise: reached, resolve: reachedNow } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    let asked = 0;
    const long = sealLegacyRows(app, {
      keys,
      ids,
      clock: new FixedClock(STARTS),
      logger: testLogger(capture),
      // The sealing held part way, as a long one is between steps.
      orgs: async () => {
        asked += 1;
        if (asked === 1) {
          reachedNow(undefined);
          await gate;
        }
        return [ORG];
      },
      retentionDays: RETENTION,
      anchorNow: () => Promise.resolve(),
      anchor: headNow,
    });
    await reached;
    try {
      const waiting = await owner().query<{ state: string }>(
        "select state from pg_catalog.pg_stat_activity where datname = pg_catalog.current_database() and state = 'idle in transaction'",
      );
      expect(waiting).toEqual([]);
      expect(await seal()).toBe('busy');
    } finally {
      open(undefined);
    }
    expect(await long).toBe('sealed');
    expect(await unsealed()).toBe('0');
    expect(alarms()).toEqual([]);
  });

  it('taken up again days later, after the sweep took rows of the oldest days: those days left out of the manifest’s comparison, the rest sealed', async () => {
    // Rows of an old day, written well inside the scope then, and of the day the sealing began.
    const oldDay = new Date(AT.getTime() - 25 * DAY_MS);
    await owner().query(
      `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at, before_macs)
       values ($1, 'sign_in_failed', 'state_mismatch', null, null, $2, 1, $2, true)`,
      [ids.next(), oldDay],
    );
    await legacyRows();
    await recorded(SEALING_STARTED, await manifestNow());
    // Ten days on, the sweep has taken the old day's rows.
    await owner().query('delete from security.events where created_at = $1', [oldDay]);

    expect(await seal(new Date(AT.getTime() + 10 * DAY_MS))).toBe('sealed');
    expect(await unsealed()).toBe('0');
    expect(alarms()).toEqual([]);
  });

  it('past the cutoff, every row from before 0105 sealed though no record says so: quiet, nothing left to seal', async () => {
    await legacyRows();
    const kept = await headRow();
    await seal();
    await deletedFromTail(kept);

    expect(await seal(new Date(SECURITY_SEAL_BACKFILL_UNTIL))).toBe('sealed');
    expect(alarms()).toEqual([]);
  });

  it('past the cutoff, a database with no row from before 0105 left unsealed (one made after it, say): quiet', async () => {
    expect(await seal(new Date(SECURITY_SEAL_BACKFILL_UNTIL))).toBe('sealed');
    expect(await records()).toEqual([]);
    expect(alarms()).toEqual([]);
  });

  it('past the cutoff, a row from before 0105 still without a MAC and no record of its sealing: the alarm', async () => {
    await legacyRows();

    expect(await seal(new Date(SECURITY_SEAL_BACKFILL_UNTIL))).toBe('deleted');
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  it('past the cutoff, a sealing begun and left is not taken up: the alarm, the rows left unbelieved', async () => {
    await legacyRows();
    await recorded(SEALING_STARTED, await manifestNow());

    expect(await seal(new Date(SECURITY_SEAL_BACKFILL_UNTIL))).toBe('deleted');
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  it('a start that finds another sealing leaves it to that one, quietly: nothing sealed, no alarm', async () => {
    await legacyRows();
    const { promise: held, resolve: heldNow } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const sealer = app.transaction().execute(async (tx) => {
      await sql`select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(${SEALER_LOCK}, 0))`.execute(tx);
      heldNow(undefined);
      await gate;
    });
    await held;
    try {
      expect(await within(10_000, seal(), 'the start that finds the sealer at work')).toBe('busy');
    } finally {
      open(undefined);
      await sealer;
    }
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual([]);
  });

  it('its end deleted from the middle of the chain: the gap shows, nothing sealed again, the alarm', async () => {
    await legacyRows();
    await seal();
    // Later events past it, then the record of its end deleted from between them, the owner's rows put back unsealed.
    await recorded('platform.started');
    await owner().query('delete from platform_controls.audit_events where action = $1', [ALL_SEALED]);
    await ownerDropsRule();
    await owner().query('update security.events set mac = null, mac_key_version = null');

    expect(await seal()).toBe('unsealed');
    expect(await unsealed()).toBe('3');
    expect(alarms()).toEqual(['seal_record_unsealed']);
  });

  it('past the cutoff no sealing runs: records deleted and rows without MACs planted, the alarm', async () => {
    await legacyRows();
    await seal();
    await owner().query('delete from platform_controls.audit_events where action in ($1, $2)', [
      SEALING_STARTED,
      ALL_SEALED,
    ]);
    await ownerDropsRule();
    await owner().query('update security.events set mac = null, mac_key_version = null');
    await owner().query('update security.org_events set mac = null, mac_key_version = null');
    await owner().query('update security.partner_event_evidence set mac = null, mac_key_version = null');

    expect(await seal(new Date(SECURITY_SEAL_BACKFILL_UNTIL))).toBe('deleted');
    expect(await unsealed()).toBe('5');
    expect(await records()).toEqual([]);
    expect(alarms()).toEqual(['seal_record_deleted']);
  });

  it('takes no row written after 0105, with its MAC, for a sealing already done: the first sealing seals the rest', async () => {
    await legacyRows();
    // Written by this release as it serves, before the sealing in the background has run.
    await createSecurityEvents({ ids, clock: new FixedClock(AT), keys, retentionDays: 30 }).record(app, [
      {
        kind: 'sign_in_failed',
        reason: 'state_mismatch',
        ip: '203.0.113.9',
        userId: undefined,
        windowStart: AT,
        count: 1,
      },
    ]);

    expect(await seal()).toBe('sealed');
    expect(await unsealed()).toBe('0');
    expect(alarms()).toEqual([]);
  });

  it('a record whose action the owner changed for one start: nothing sealed, the alarm', async () => {
    await legacyRows();
    await seal();
    await owner().query("update platform_controls.audit_events set action = 'x.y' where action = $1", [ALL_SEALED]);
    await ownerDropsRule();
    await owner().query('update security.events set mac = null, mac_key_version = null');

    expect(await seal()).toBe('unsealed');
    expect(await unsealed()).toBe('3');
    expect(alarms()).toEqual(['seal_record_unsealed']);
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

// R-15, S207: a database whose first start was already 0105's release's (production's) holds no row from before 0105.
// Every row marked so is the owner's: never sealed as genuine, never excused, whatever dates it says.
describe('SEC-DB-18 a database born sealed: no pass, no excuse (R-15, S207)', () => {
  const told = (now = STARTS) => app.transaction().execute((tx) => legacyRowsAt(tx, keys, now));

  /** The platform chain begun again with no start: this database's first start is the next recorded. */
  const freshChain = () => owner().query('truncate platform_controls.audit_events, platform_controls.audit_head');

  /** A first start as boot records it from 0105's release on: with its time, ROW_MACS_FROM. */
  const bornSealed = async () => {
    await freshChain();
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: STARTS.toISOString() });
  };

  it('the owner plants marked rows with no MAC, dated in scope: nothing sealed, nothing recorded, none excused', async () => {
    await bornSealed();
    await legacyRows();

    expect(await seal()).toBe('born_sealed');
    expect(await unsealed()).toBe('5');
    expect(await records()).toEqual([]);
    expect(anchoredAt).toEqual([]);
    expect(alarms()).toEqual([]);
    // The day seal and the admins' page excuse none: each planted row is the alarm as they meet it.
    expect(await told()).toEqual({ excusedBefore: null });
    // A later start, whatever it records, changes nothing: the first one decides.
    await recorded('platform.started', { release: 'r-before' });
    expect(await seal()).toBe('born_sealed');
    expect(await told()).toEqual({ excusedBefore: null });
  });

  it('a genuine row, its MAC stripped and the row marked and edited by the owner: never given a MAC again', async () => {
    await bornSealed();
    const id = ids.next();
    const written = new Date(AT.getTime() - DAY_MS);
    const { mac, mac_key_version: version } = eventMac(keys, {
      id,
      orgId: null,
      kind: 'sign_in_failed',
      reason: 'state_mismatch',
      ip: null,
      userId: null,
      agentId: null,
      windowStart: written,
      count: 1,
      createdAt: written,
    });
    await owner().query(
      `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at, mac, mac_key_version)
       values ($1, 'sign_in_failed', 'state_mismatch', null, null, $2, 1, $2, $3, $4)`,
      [id, written, mac, version],
    );
    await ownerDropsRule();
    await owner().query(
      'update security.events set before_macs = true, mac = null, mac_key_version = null, count = 99 where id = $1',
      [id],
    );

    expect(await seal()).toBe('born_sealed');
    expect(await unsealed()).toBe('1');
  });

  it('no start on the chain at all (each start records its own before any pass, so they were deleted): the alarm, nothing sealed, none excused', async () => {
    await freshChain();
    await recorded('notice.legacy_sealed', { notices: 0 });
    await legacyRows();

    expect(await told()).toBe('unsealed');
    expect(await seal()).toBe('unsealed');
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual(['seal_record_unsealed']);
  });

  it('the first start’s time removed by the owner, to pass for a database from before: can’t be believed, the alarm', async () => {
    await bornSealed();
    await legacyRows();
    await owner().query(`update platform_controls.audit_events set details = '{"release":"r"}' where seq = 1`);

    // Read by its own MAC, never as the edited row says: not a database from before.
    expect(await app.transaction().execute((tx) => databaseBirth(tx, keys))).toBe('unsealed');
    expect(await told()).toBe('unsealed');
    expect(await seal()).toBe('unsealed');
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual(['seal_record_unsealed']);
  });

  it('a first start whose time isn’t a time: can’t be believed, the alarm', async () => {
    await freshChain();
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: 7 });
    await legacyRows();

    expect(await seal()).toBe('unsealed');
    expect(await unsealed()).toBe('5');
    expect(alarms()).toEqual(['seal_record_unsealed']);
  });

  it('a database from before, its first start with no time and a later one with it: sealed once, as staging’s was', async () => {
    await recorded('platform.started', { release: 'r', [ROW_MACS_FROM]: STARTS.toISOString() });
    await legacyRows();

    expect(await seal()).toBe('sealed');
    expect(await unsealed()).toBe('0');
  });
});

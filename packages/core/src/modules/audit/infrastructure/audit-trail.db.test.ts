import { AsyncResource } from 'node:async_hooks';

import {
  createTestDatabase,
  failures,
  LogCapture,
  race,
  SequentialIds,
  successes,
  type TestDatabase,
  type TestSession,
} from '@agentx/testing';
import {
  ChainBroken,
  type ChainReport,
  linkHash,
  sealState,
  type StateFacts,
  stateSealDetails,
  stateSealMatches,
} from '@agentx/platform/audit-chain';
import { createDatabase, type Database, TenantContextError, withTenant } from '@agentx/platform/db';
import { createKeyProvider, type KeyMaterial, type KeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { canonicalDetails } from '../../../shared-kernel/index.ts';
import { type AuditEvent, AuditEventRefused, eventContent } from '../domain/event.ts';
import { type AuditTrail, createAuditTrail } from './audit-trail.ts';
import type { AuditTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<AuditTables>;
/** The FX-TAMPER attacker: the server's superuser, past every wall, holding none of the app's keys. */
let attacker: TestSession;

/** Stand-in keys, one per purpose; `auditMac` replaces the audit MAC key's versions. */
function keysWith(auditMac?: { current: number; versions: Map<number, Buffer> }): KeyProvider {
  const material = Object.fromEntries(
    PURPOSES.map((purpose, index) => [
      purpose,
      purpose === 'audit-mac' && auditMac !== undefined
        ? auditMac
        : { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) },
    ]),
  ) as unknown as KeyMaterial;
  return createKeyProvider(material);
}

const keys = keysWith();

/** The audit MAC key rotated: version 1 as every other test's, and version 2 made current. */
const ROTATED_MAC = {
  current: 2,
  versions: new Map([
    [1, Buffer.alloc(32, PURPOSES.indexOf('audit-mac') + 1)],
    [2, Buffer.alloc(32, 99)],
  ]),
};
const ids = new SequentialIds(0x100);
const trail: AuditTrail = createAuditTrail({ keys, ids });

let orgNumber = 0;
/** A fresh organisation for each test, so their chains never meet. */
const newOrg = (): string => {
  orgNumber += 1;
  return `0199a0f0-0000-7000-8000-${orgNumber.toString(16).padStart(12, '0')}`;
};
let org: string;

const USER = '0199a0f0-0000-7000-8000-0000000000aa';
const event = (step: number): AuditEvent => ({
  actor: { type: 'user', id: USER },
  action: 'probe.stepped',
  subject: { type: 'probe', id: USER, version: step },
  details: { step },
});

const record = (orgId: string, ...events: AuditEvent[]) =>
  withTenant(app, orgId, async (tx) => {
    const recorded = [];
    for (const one of events) recorded.push(await trail.record(tx, orgId, one));
    return recorded;
  });

const verify = (orgId: string, using: AuditTrail = trail): Promise<ChainReport> =>
  withTenant(app, orgId, (tx) => using.verify(tx, orgId, undefined));

const problemOf = async (orgId: string): Promise<unknown> => {
  const report = await verify(orgId);
  return report.ok ? 'ok' : report.problem;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: new LogCapture(),
  });
  app = createDatabase<AuditTables>({ ...database.connection('app'), maxConnections: 12 }, logger);
  attacker = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  org = newOrg();
});

describe('recording audit events (ADR-011 §3)', () => {
  it('adds events in order, each linked to the last, and the chain checks out', async () => {
    const recorded = await record(org, event(1), event(2), event(3));

    expect(recorded.map((one) => one.seq)).toEqual([1n, 2n, 3n]);
    expect(await verify(org)).toMatchObject({ ok: true, seq: 3n });
  });

  it("stores the event as given, in canonical form, at the database's time to the millisecond", async () => {
    const [recorded] = await record(org, {
      ...event(1),
      actor: { type: 'user', id: USER.toUpperCase() },
      details: { zeta: 'z', alpha: 1 },
    });
    const [row] = await attacker.query('select * from audit.events where org_id = $1', [org]);

    expect(row).toMatchObject({
      org_id: org,
      seq: '1',
      id: recorded?.id,
      actor_type: 'user',
      actor_id: USER,
      action: 'probe.stepped',
      subject_type: 'probe',
      subject_id: USER,
      subject_version: 1,
      details: '{"alpha":1,"zeta":"z"}',
      mac_key_version: 1,
    });
    expect(row?.recorded_at).toEqual(recorded?.recordedAt);
    const [timing] = await attacker.query(
      `select recorded_at = pg_catalog.date_trunc('milliseconds', recorded_at) as whole_ms,
              pg_catalog.now() - recorded_at < interval '1 minute' as recent
       from audit.events where org_id = $1`,
      [org],
    );
    expect(timing).toEqual({ whole_ms: true, recent: true });
  });

  it('writes nothing when the change it records rolls back', async () => {
    await record(org, event(1));
    await expect(
      withTenant(app, org, async (tx) => {
        await trail.record(tx, org, event(2));
        throw new Error('the change failed');
      }),
    ).rejects.toThrow('the change failed');

    expect(await verify(org)).toMatchObject({ ok: true, seq: 1n });
  });

  it('names the organisation by its ID in lower case, however it was written', async () => {
    await record(org.toUpperCase(), event(1));

    expect(await verify(org)).toMatchObject({ ok: true, seq: 1n });
  });

  it('reports a chain that was never started as empty', async () => {
    expect(await verify(org)).toMatchObject({ ok: true, seq: 0n });
  });

  it('keeps checking events sealed before a key rotation, and seals new ones with the new key', async () => {
    await record(org, event(1));
    const rotated = createAuditTrail({ keys: keysWith(ROTATED_MAC), ids });
    await withTenant(app, org, (tx) => rotated.record(tx, org, event(2)));

    expect(await verify(org, rotated)).toMatchObject({ ok: true, seq: 2n });
    const versions = await attacker.query<{ mac_key_version: number }>(
      'select mac_key_version from audit.events where org_id = $1 order by seq',
      [org],
    );
    expect(versions.map((row) => row.mac_key_version)).toEqual([1, 2]);

    // A process still on version 1 as current, but holding version 2 (a release rolled back, or the old
    // revision still running), stays on 2 for this chain, so the check raises no alarm.
    const rolledBack = createAuditTrail({
      keys: keysWith({ current: 1, versions: new Map([...ROTATED_MAC.versions]) }),
      ids,
    });
    await withTenant(app, org, (tx) => rolledBack.record(tx, org, event(3)));
    expect(await verify(org, rotated)).toMatchObject({ ok: true, seq: 3n });

    // A process that doesn't hold version 2 at all can't add to the chain: new keys go everywhere first.
    await expect(withTenant(app, org, (tx) => trail.record(tx, org, event(4)))).rejects.toThrow(ChainBroken);
  });

  it('refuses an event that breaks the rules, and writes nothing', async () => {
    await expect(record(org, { ...event(1), action: 'Bad' })).rejects.toThrow(AuditEventRefused);

    expect(await attacker.query('select 1 from audit.heads where org_id = $1', [org])).toEqual([]);
  });

  it("refuses details named like the logger's secret and personal fields (ADR-014 §3)", async () => {
    await expect(record(org, { ...event(1), details: { contactEmail: 'x' } })).rejects.toThrow(
      new AuditEventRefused([
        'details.contactEmail looks like a secret or personal data, which audit rows never hold (ADR-014 §3)',
      ]),
    );
  });

  it('keeps a detail named like a code when its value is a plain constant, as the logger does', async () => {
    await record(org, { ...event(1), details: { reasonCode: 'DUPLICATE_ORDER_REFERENCE' } });

    expect(await verify(org)).toMatchObject({ ok: true, seq: 1n });
  });

  it("stores the ID generator's IDs in lower case, so the chain checks out whatever case they came in", async () => {
    const shouting = createAuditTrail({ keys, ids: { next: () => ids.next().toUpperCase() } });
    await withTenant(app, org, (tx) => shouting.record(tx, org, event(1)));

    expect(await verify(org)).toMatchObject({ ok: true, seq: 1n });
  });

  it('refuses an ID from the generator that is not a UUID, and writes nothing', async () => {
    const broken = createAuditTrail({ keys, ids: { next: () => 'not-a-uuid' } });

    await expect(withTenant(app, org, (tx) => broken.record(tx, org, event(1)))).rejects.toThrow(
      new RangeError('The ID generator gave an ID that is not a UUID'),
    );
    expect(await attacker.query('select 1 from audit.events where org_id = $1', [org])).toEqual([]);
  });

  it('refuses an organisation ID that is not a UUID', async () => {
    await withTenant(app, org, async (tx) => {
      await expect(trail.record(tx, 'org-1', event(1))).rejects.toThrow(
        new AuditEventRefused(['the organisation ID must be a UUID']),
      );
      await expect(trail.verify(tx, 'org-1', undefined)).rejects.toThrow(TenantContextError);
    });
  });
});

describe('the tenant walls (SEC-TEN-01 on the audit tables)', () => {
  it("keeps one organisation's chain out of another's sight", async () => {
    await record(org, event(1), event(2));
    const other = newOrg();
    const seen = await withTenant(app, other, (tx) =>
      tx.selectFrom('audit.events').select('seq').where('org_id', '=', org).execute(),
    );

    expect(seen).toEqual([]);
  });

  it("refuses to check a chain from another organisation's transaction, where it would look empty", async () => {
    await record(org, event(1));
    const other = newOrg();

    await expect(withTenant(app, other, (tx) => trail.verify(tx, org, undefined))).rejects.toThrow(TenantContextError);
  });

  it("refuses to record into another organisation's chain", async () => {
    const other = newOrg();

    await expect(withTenant(app, other, (tx) => trail.record(tx, org, event(1)))).rejects.toThrow(/row-level security/);
  });
});

describe('SEC-EVD-01 the app role only adds to and reads the audit trail', () => {
  // Postgres checks the table right before row-level security, so no tenant is needed to be refused.
  // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
  const asApp = (statement: string) => database.as('app').query(statement);

  beforeEach(async () => {
    await record(org, event(1));
  });

  it.each([
    'update audit.events set action = $$probe.forged$$',
    'delete from audit.events',
    'truncate audit.events',
    'delete from audit.heads',
    'truncate audit.heads',
  ])('refuses: %s', async (statement) => {
    await expect(asApp(statement)).rejects.toThrow(/permission denied/);
  });

  it('lets it move the chain head on, the one row it changes', async () => {
    await expect(asApp('update audit.heads set seq = seq')).resolves.toBeDefined();
  });
});

describe('FX-RACE recording at the same time', () => {
  it('puts every event in its own place, in one unbroken chain', async () => {
    await record(org, event(100));
    const outcomes = await race(10, (party, sync) =>
      withTenant(app, org, async (tx) => {
        await sync();
        return trail.record(tx, org, event(party + 1));
      }),
    );

    expect(failures(outcomes)).toEqual([]);
    expect(
      successes(outcomes)
        .map((one) => one.seq)
        .sort((a, b) => Number(a - b)),
    ).toEqual(Array.from({ length: 10 }, (_, i) => BigInt(i + 2)));
    expect(await verify(org)).toMatchObject({ ok: true, seq: 11n });
    // Each time is read once the head's lock is held, so the times rise with the numbers.
    const times = await attacker.query<{ recorded_at: Date }>(
      'select recorded_at from audit.events where org_id = $1 order by seq',
      [org],
    );
    const ms = times.map((row) => row.recorded_at.getTime());
    expect(ms).toEqual([...ms].sort((a, b) => a - b));
  });

  it("starts a new organisation's chain once when its first events race", async () => {
    const outcomes = await race(6, (party, sync) =>
      withTenant(app, org, async (tx) => {
        await sync();
        return trail.record(tx, org, event(party + 1));
      }),
    );

    expect(failures(outcomes)).toEqual([]);
    expect(await verify(org)).toMatchObject({ ok: true, seq: 6n });
  });
});

/** The event columns the migration makes NOT NULL, other than the key. */
const EVENT_COLUMNS = [
  'id',
  'recorded_at',
  'actor_type',
  'actor_id',
  'action',
  'subject_type',
  'subject_id',
  'subject_version',
  'details',
  'prev_hash',
  'hash',
  'mac',
  'mac_key_version',
];

describe('SEC-EVD-02, FX-TAMPER: changes made past the app are found', () => {
  beforeEach(async () => {
    await record(org, event(1), event(2), event(3), event(4));
  });

  /** Runs statements as the attacker, one after another; the organisation is $1 wherever a statement names it. */
  const tamper = async (...statements: string[]): Promise<void> => {
    for (const statement of statements) {
      // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
      await attacker.query(statement, statement.includes('$1') ? [org] : []);
    }
  };

  /** Puts back every rule the unreadable-row cases take away, now that their rows are gone. */
  const restoreRules = (): Promise<void> =>
    tamper(
      ...EVENT_COLUMNS.map((column) => `alter table audit.events alter column ${column} set not null`),
      ...['seq', 'hash', 'mac', 'mac_key_version'].map(
        (column) => `alter table audit.heads alter column ${column} set not null`,
      ),
    );

  it('passes a chain whose rows Postgres has stored out of order, since it reads them by number', async () => {
    // A no-op update writes a row's new version at the end of the table, so a plain scan meets event 1 last.
    await tamper('update audit.events set action = action where org_id = $1 and seq = 1');

    expect(await verify(org)).toMatchObject({ ok: true, seq: 4n });
  });

  it('an event edited', async () => {
    await tamper(`update audit.events set details = '{"step":9}' where org_id = $1 and seq = 3`);

    expect(await problemOf(org)).toEqual({ reason: 'hash', seq: 3n });
  });

  it("an event's details rewritten with the same meaning", async () => {
    await tamper(`update audit.events set details = '{"step": 3}' where org_id = $1 and seq = 3`);

    expect(await problemOf(org)).toEqual({ reason: 'hash', seq: 3n });
  });

  it('an event forged at a number the check never reads, 0', async () => {
    await tamper(
      'alter table audit.events drop constraint events_seq_check',
      `insert into audit.events
         select org_id, 0, '0199a0f0-0000-7000-8000-0000000000fe', recorded_at, actor_type, actor_id, 'probe.forged',
                subject_type, subject_id, subject_version, details, prev_hash, hash, mac, mac_key_version
         from audit.events where org_id = $1 and seq = 1`,
    );
    try {
      expect(await problemOf(org)).toEqual({ reason: 'head', seq: 4n });
    } finally {
      await tamper(
        'delete from audit.events where org_id = $1',
        'alter table audit.events add constraint events_seq_check check (seq >= 1)',
      );
    }
  });

  it("another organisation's events copied in, under that organisation's own sealed head", async () => {
    // The target has a real head for four events of its own; its events are swapped for ours, MACs and all.
    const other = newOrg();
    await record(other, event(1), event(2), event(3), event(4));
    await attacker.query('delete from audit.events where org_id = $1', [other]);
    await attacker.query(
      `insert into audit.events
         select $2::uuid, seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id, subject_version,
                details, prev_hash, hash, mac, mac_key_version
         from audit.events where org_id = $1`,
      [org, other],
    );

    // Every event's hash names the chain it was made for.
    expect(await problemOf(other)).toEqual({ reason: 'hash', seq: 1n });
  });

  it('a correctly chained event appended with no valid MAC, and the head moved to it', async () => {
    // The attacker can compute every hash: the format is public. Only the MAC needs the key.
    const [head] = await attacker.query<{ hash: Buffer }>('select hash from audit.heads where org_id = $1', [org]);
    if (head === undefined) throw new Error('The chain has no head');
    const forged = { ...event(5), action: 'probe.forged' };
    const entry = {
      seq: 5n,
      id: '0199a0f0-0000-7000-8000-0000000000ff',
      recordedAt: new Date('2026-09-19T08:00:00.000Z'),
      content: eventContent(forged, canonicalDetails(forged.details)),
    };
    const hash = linkHash({ kind: 'organisation', orgId: org }, head.hash, entry);
    await attacker.query(
      `insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id,
         subject_version, details, prev_hash, hash, mac, mac_key_version)
       values ($1, 5, $2, $3, 'user', $4, 'probe.forged', 'probe', $5, 5, '{"step":5}', $6, $7, $8, 1)`,
      [org, entry.id, entry.recordedAt, USER, USER, head.hash, hash, Buffer.alloc(32)],
    );

    expect(await problemOf(org)).toEqual({ reason: 'head', seq: 4n });
    await tamper(
      'update audit.heads set seq = 5, hash = (select hash from audit.events where org_id = $1 and seq = 5) where org_id = $1',
    );
    expect(await problemOf(org)).toEqual({ reason: 'head', seq: 5n });
  });

  it('a mid-chain event deleted', async () => {
    await tamper('delete from audit.events where org_id = $1 and seq = 2');

    expect(await problemOf(org)).toEqual({ reason: 'gap', seq: 2n });
  });

  it('the tail deleted, the head left', async () => {
    await tamper('delete from audit.events where org_id = $1 and seq = 4');

    expect(await problemOf(org)).toEqual({ reason: 'head', seq: 4n });
  });

  it('an event moved into another organisation', async () => {
    const other = newOrg();
    await record(other, event(1));
    await attacker.query('update audit.events set org_id = $2, seq = 2 where org_id = $1 and seq = 4', [org, other]);
    await attacker.query(
      'update audit.heads set seq = 2, hash = (select hash from audit.events where org_id = $1 and seq = 2) where org_id = $1',
      [other],
    );

    expect(await problemOf(org)).toEqual({ reason: 'head', seq: 4n });
    expect(await problemOf(other)).toEqual({ reason: 'head', seq: 2n });
  });

  it('a MAC made under a key version the app does not hold', async () => {
    await tamper('update audit.events set mac_key_version = 7 where org_id = $1 and seq = 1');

    expect(await problemOf(org)).toEqual({ reason: 'mac', seq: 1n });
  });

  // Each case takes away a column's NOT NULL (or CHECK) and spoils the second event's value, then puts the rule back.
  it.each([
    [
      'id',
      [
        'alter table audit.events alter column id drop not null',
        'update audit.events set id = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'recorded_at',
      [
        'alter table audit.events alter column recorded_at drop not null',
        'update audit.events set recorded_at = null where org_id = $1 and seq = 2',
      ],
    ],
    ['recorded_at at infinity', ["update audit.events set recorded_at = 'infinity' where org_id = $1 and seq = 2"]],
    [
      "recorded_at past JavaScript's range",
      ["update audit.events set recorded_at = '290000-01-01' where org_id = $1 and seq = 2"],
    ],
    [
      'recorded_at off a whole millisecond',
      ["update audit.events set recorded_at = recorded_at + interval '500 microseconds' where org_id = $1 and seq = 2"],
    ],
    [
      'actor_type',
      [
        'alter table audit.events alter column actor_type drop not null',
        'update audit.events set actor_type = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'actor_id',
      [
        'alter table audit.events alter column actor_id drop not null',
        'update audit.events set actor_id = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'action',
      [
        'alter table audit.events alter column action drop not null',
        'update audit.events set action = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'subject_type',
      [
        'alter table audit.events alter column subject_type drop not null',
        'update audit.events set subject_type = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'subject_id',
      [
        'alter table audit.events alter column subject_id drop not null',
        'update audit.events set subject_id = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'subject_version',
      [
        'alter table audit.events alter column subject_version drop not null',
        'update audit.events set subject_version = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'details',
      [
        'alter table audit.events alter column details drop not null',
        'update audit.events set details = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'prev_hash',
      [
        'alter table audit.events alter column prev_hash drop not null',
        'update audit.events set prev_hash = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'hash',
      [
        'alter table audit.events alter column hash drop not null',
        'update audit.events set hash = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'mac',
      [
        'alter table audit.events alter column mac drop not null',
        'update audit.events set mac = null where org_id = $1 and seq = 2',
      ],
    ],
    [
      'mac_key_version',
      [
        'alter table audit.events alter column mac_key_version drop not null',
        'update audit.events set mac_key_version = null where org_id = $1 and seq = 2',
      ],
    ],
  ])('an event the app cannot read at all: %s', async (_column, statements) => {
    await tamper(...statements);
    try {
      expect(await problemOf(org)).toEqual({ reason: 'unreadable', seq: 2n });
    } finally {
      await tamper('delete from audit.events where org_id = $1', 'delete from audit.heads where org_id = $1');
      await restoreRules();
    }
  });

  it('the head edited: the chain fails its check, and nothing more is recorded on it', async () => {
    await tamper('update audit.heads set seq = 9 where org_id = $1');

    expect(await problemOf(org)).toEqual({ reason: 'head', seq: 9n });
    await expect(record(org, event(5))).rejects.toThrow(ChainBroken);
  });

  it.each([
    [
      'seq',
      ['alter table audit.heads alter column seq drop not null', 'update audit.heads set seq = null where org_id = $1'],
    ],
    [
      'hash',
      [
        'alter table audit.heads alter column hash drop not null',
        'update audit.heads set hash = null where org_id = $1',
      ],
    ],
    [
      'mac',
      ['alter table audit.heads alter column mac drop not null', 'update audit.heads set mac = null where org_id = $1'],
    ],
    [
      'mac_key_version',
      [
        'alter table audit.heads alter column mac_key_version drop not null',
        'update audit.heads set mac_key_version = null where org_id = $1',
      ],
    ],
  ])('the head unreadable (%s): the same', async (_column, statements) => {
    await tamper(...statements);
    try {
      expect(await problemOf(org)).toEqual({ reason: 'head', seq: 0n });
      await expect(record(org, event(5))).rejects.toThrow(ChainBroken);
    } finally {
      await tamper('delete from audit.events where org_id = $1', 'delete from audit.heads where org_id = $1');
      await restoreRules();
    }
  });

  it('the head deleted: the events are left headless, and nothing more is recorded on them', async () => {
    await tamper('delete from audit.heads where org_id = $1');

    expect(await problemOf(org)).toEqual({ reason: 'head', seq: 0n });
    await expect(record(org, event(5))).rejects.toThrow(ChainBroken);
  });

  it('the head wound back to an earlier sealed value, with events left after it: nothing more is recorded', async () => {
    const [earlier] = await attacker.query(
      'select seq, hash, mac, mac_key_version from audit.heads where org_id = $1',
      [org],
    );
    if (earlier === undefined) throw new Error('The chain has no head');
    await record(org, event(5), event(6));
    // Event 5 deleted, event 6 left: the next record would otherwise take place 5 and carry on from there.
    await tamper('delete from audit.events where org_id = $1 and seq = 5');
    await attacker.query(
      'update audit.heads set seq = $2, hash = $3, mac = $4, mac_key_version = $5 where org_id = $1',
      [org, earlier.seq, earlier.hash, earlier.mac, earlier.mac_key_version],
    );

    await expect(record(org, event(7))).rejects.toThrow(ChainBroken);
    expect(await problemOf(org)).toEqual({ reason: 'head', seq: 4n });
  });

  it('the head and the first event deleted: the chain does not start again on the rest', async () => {
    await tamper('delete from audit.heads where org_id = $1', 'delete from audit.events where org_id = $1 and seq = 1');

    await expect(record(org, event(5))).rejects.toThrow(ChainBroken);
    expect(await problemOf(org)).toEqual({ reason: 'head', seq: 0n });
  });

  it('SEC-DB-11 the tail deleted and the head wound back to its earlier sealed value: the chain alone looks whole, its anchor does not', async () => {
    const other = newOrg();
    await record(other, event(1), event(2));
    const [earlier] = await attacker.query(
      'select seq, hash, mac, mac_key_version from audit.heads where org_id = $1',
      [org],
    );
    if (earlier === undefined) throw new Error('The chain has no head');
    await record(org, event(5), event(6));
    // The anchor check saw the chain at 6 and anchored it there.
    const anchored = await verify(org);
    if (!anchored.ok) throw new Error('The chain should have checked out before the tampering');
    await tamper('delete from audit.events where org_id = $1 and seq > 4');
    await attacker.query(
      'update audit.heads set seq = $2, hash = $3, mac = $4, mac_key_version = $5 where org_id = $1',
      [org, earlier.seq, earlier.hash, earlier.mac, earlier.mac_key_version],
    );

    expect(await verify(org)).toMatchObject({ ok: true, seq: 4n });
    const anchor = { seq: anchored.seq, hash: anchored.hash };
    expect(await withTenant(app, org, (tx) => trail.verify(tx, org, anchor))).toEqual({
      ok: false,
      problem: { reason: 'anchor', seq: 6n },
    });

    // The app then records on the wound-back head, as it would, and the chain grows whole again, but not the one anchored.
    await record(org, event(7), event(8), event(9));
    expect(await verify(org)).toMatchObject({ ok: true, seq: 7n });
    expect(await withTenant(app, org, (tx) => trail.verify(tx, org, anchor))).toEqual({
      ok: false,
      problem: { reason: 'anchor', seq: 6n },
    });
  });
});

describe('checking a chain while events are added', () => {
  it('checks the chain as its head stood, and takes no later event for tampering', async () => {
    await record(org, event(1), event(2), event(3), event(4));
    // Another transaction adds an event the moment the check has read the head, before it reads any event.
    // It is bound to the test's own context, where no withTenant is open, so it is a transaction of its own.
    const addEvent = AsyncResource.bind(() => record(org, event(5)));
    const headReads = new WeakSet<object>();
    let added = false;
    const racing = app.withPlugin({
      transformQuery: ({ node, queryId }) => {
        if (node.kind === 'RawNode' && node.sqlFragments.join('').includes('has_head')) headReads.add(queryId);
        return node;
      },
      transformResult: async ({ result, queryId }) => {
        if (headReads.has(queryId) && !added) {
          added = true;
          await addEvent();
        }
        return result;
      },
    });

    expect(await withTenant(racing, org, (tx) => trail.verify(tx, org, undefined))).toMatchObject({
      ok: true,
      seq: 4n,
    });
    expect(added).toBe(true);
    expect(await verify(org)).toMatchObject({ ok: true, seq: 5n });
  });
});

describe('a long chain', () => {
  it('counts an event hidden as a second copy at the end of a batch, which the batches never read', async () => {
    await record(org, ...Array.from({ length: 501 }, (_, i) => event(i + 1)));
    await attacker.query('alter table audit.events drop constraint events_pkey');
    await attacker.query('alter table audit.events drop constraint events_org_id_id_key');
    try {
      // An exact copy, so whichever of the two Postgres returns first, the batches read one and skip the other.
      await attacker.query('insert into audit.events select * from audit.events where org_id = $1 and seq = 500', [
        org,
      ]);

      expect(await problemOf(org)).toEqual({ reason: 'head', seq: 501n });
    } finally {
      await attacker.query('delete from audit.events where org_id = $1', [org]);
      await attacker.query('alter table audit.events add constraint events_pkey primary key (org_id, seq)');
      await attacker.query('alter table audit.events add constraint events_org_id_id_key unique (org_id, id)');
    }
  });

  it('is checked in batches, and a problem deep in it is found', async () => {
    await record(org, ...Array.from({ length: 1000 }, (_, i) => event(i + 1)));

    expect(await verify(org)).toMatchObject({ ok: true, seq: 1000n });
    await attacker.query(`update audit.events set details = '{"step":0}' where org_id = $1 and seq = 777`, [org]);
    expect(await problemOf(org)).toEqual({ reason: 'hash', seq: 777n });
  });
});

describe("ADR-012 §2 an object's latest signed state, read from the log itself", () => {
  const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
  const OTHER_AGENT = '0199a0f0-0000-7000-8000-0000000000a2';

  /** The agent's state at `version`, as A3b-2's row side will seal it. */
  const facts = (orgId: string, version: number, status: string, id = AGENT): StateFacts => ({
    orgId,
    subject: { type: 'agent', id, version },
    fields: [['status', status]],
  });

  /** An event that signs the agent's state: its details carry the seal. */
  const signed = (orgId: string, version: number, status: string, id = AGENT, type = 'agent'): AuditEvent => ({
    actor: { type: 'user', id: USER },
    action: `${type}.status_changed`,
    subject: { type, id, version },
    details: { status, ...stateSealDetails(sealState(keys, facts(orgId, version, status, id))) },
  });

  /** An event about the agent that signs nothing, such as a rename. */
  const unsigned = (version: number): AuditEvent => ({
    actor: { type: 'user', id: USER },
    action: 'agent.renamed',
    subject: { type: 'agent', id: AGENT, version },
    details: {},
  });

  const latest = (orgId: string, subject = { type: 'agent', id: AGENT }) =>
    withTenant(app, orgId, (tx) => trail.latestSignedState(tx, orgId, subject));

  /** Runs one statement as the attacker; the organisation is $1 wherever the statement names it. */
  const tamper = (statement: string): Promise<unknown> =>
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
    attacker.query(statement, statement.includes('$1') ? [org] : []);

  it('finds none for an object no event has signed', async () => {
    expect(await latest(org)).toEqual({ kind: 'none' });
    await record(org, unsigned(1));
    expect(await latest(org)).toEqual({ kind: 'none' });
  });

  it('finds the signed event, and its seal matches the state it signed', async () => {
    const [recorded] = await record(org, signed(org, 1, 'ACTIVE'));
    const found = await latest(org);

    expect(found).toEqual({
      kind: 'signed',
      id: recorded?.id,
      seq: recorded?.seq,
      recordedAt: recorded?.recordedAt,
      version: 1,
      seal: sealState(keys, facts(org, 1, 'ACTIVE')),
    });
    if (found.kind !== 'signed') throw new Error('The test expected a signed state');
    expect(stateSealMatches(keys, facts(org, 1, 'ACTIVE'), found.seal)).toBe(true);
    expect(stateSealMatches(keys, facts(org, 1, 'REVOKED'), found.seal)).toBe(false);
  });

  it('finds the newest of several, and passes over newer events that sign nothing', async () => {
    await record(org, signed(org, 1, 'ACTIVE'), signed(org, 2, 'SUSPENDED'), unsigned(2), event(1));

    expect(await latest(org)).toMatchObject({ kind: 'signed', seq: 2n, version: 2 });
  });

  it("keeps each object's apart: another ID, another type with the same ID, another organisation", async () => {
    const other = newOrg();
    await record(org, signed(org, 1, 'ACTIVE'));
    await record(org, signed(org, 5, 'REVOKED', OTHER_AGENT), signed(org, 7, 'REVOKED', AGENT, 'agent_key'));
    await record(other, signed(other, 9, 'REVOKED'));

    expect(await latest(org)).toMatchObject({ kind: 'signed', seq: 1n, version: 1 });
    expect(await latest(org, { type: 'agent', id: OTHER_AGENT })).toMatchObject({ version: 5 });
    expect(await latest(org, { type: 'agent_key', id: AGENT })).toMatchObject({ version: 7 });
    expect(await latest(other)).toMatchObject({ kind: 'signed', version: 9 });
  });

  it('finds an object by its ID in any case', async () => {
    await record(org, signed(org, 1, 'ACTIVE'));

    expect(await latest(org, { type: 'agent', id: AGENT.toUpperCase() })).toMatchObject({ kind: 'signed' });
  });

  it("refuses to look from another organisation's transaction, where the object would look unsigned", async () => {
    await record(org, signed(org, 1, 'ACTIVE'));

    await expect(
      withTenant(app, newOrg(), (tx) => trail.latestSignedState(tx, org, { type: 'agent', id: AGENT })),
    ).rejects.toBeInstanceOf(TenantContextError);
  });

  it.each([
    ['a type written wrong', { type: 'Agent', id: AGENT }, 'subject.type must be lower-case words joined by _'],
    ['an ID that is not a UUID', { type: 'agent', id: 'agent-1' }, 'subject.id must be a UUID'],
  ])('refuses to look for %s', async (_what, subject, problem) => {
    await expect(latest(org, subject)).rejects.toEqual(new AuditEventRefused([problem]));
  });

  it.each([
    ['only a fingerprint', { stateFingerprint: 'ab'.repeat(32) }],
    ['only a key version', { stateKeyVersion: 1 }],
    ['a fingerprint that is not one', { stateFingerprint: 'not-a-fingerprint', stateKeyVersion: 1 }],
  ])('refuses to record details carrying %s, and writes nothing', async (_what, details) => {
    await expect(record(org, { ...unsigned(1), details })).rejects.toEqual(
      new AuditEventRefused([
        'details.stateFingerprint and details.stateKeyVersion must hold a state seal, both of them or neither',
      ]),
    );
    expect(await verify(org)).toMatchObject({ ok: true, seq: 0n });
  });

  describe('FX-TAMPER: a signed event changed past the app is not believed', () => {
    beforeEach(async () => {
      await record(org, signed(org, 1, 'ACTIVE'), signed(org, 2, 'REVOKED'), signed(org, 1, 'ACTIVE', OTHER_AGENT));
    });

    it("another object's signed event moved onto it, newer than its own", async () => {
      await tamper(
        `update audit.events set subject_id = '0199a0f0-0000-7000-8000-0000000000a1' where org_id = $1 and seq = 3`,
      );

      expect(await latest(org)).toEqual({ kind: 'broken', seq: 3n });
    });

    it('a later event about the object that signs nothing, edited', async () => {
      await record(org, unsigned(2));
      await tamper(`update audit.events set details = '{"note":"x"}' where org_id = $1 and seq = 4`);

      expect(await latest(org)).toEqual({ kind: 'broken', seq: 4n });
    });

    it.each([
      ["the head's MAC replaced", `update audit.heads set mac = pg_catalog.decode('00', 'hex') where org_id = $1`],
      ['the head deleted', 'delete from audit.heads where org_id = $1'],
    ])('%s: nothing about the chain can be believed', async (_change, statement) => {
      await tamper(statement);

      expect(await latest(org)).toEqual({ kind: 'broken', seq: 2n });
    });

    it('a sealed signed event past the head, as a leaked old key would let someone add: the head wound back under it', async () => {
      const [saved] = await attacker.query<{ seq: bigint; hash: Buffer; mac: Buffer }>(
        'select seq, hash, mac from audit.heads where org_id = $1',
        [org],
      );
      if (saved === undefined) throw new Error('The chain has no head');
      await record(org, signed(org, 3, 'ACTIVE'));
      await attacker.query('update audit.heads set seq = $2, hash = $3, mac = $4 where org_id = $1', [
        org,
        saved.seq,
        saved.hash,
        saved.mac,
      ]);

      expect(await latest(org)).toEqual({ kind: 'broken', seq: 4n });
    });

    it("another organisation's signed event about the object moved in, past the head", async () => {
      const other = newOrg();
      await record(other, signed(other, 9, 'ACTIVE'));
      await attacker.query('update audit.events set org_id = $1, seq = 9 where org_id = $2 and seq = 1', [org, other]);

      expect(await latest(org)).toEqual({ kind: 'broken', seq: 9n });
    });

    it.each([
      [
        'its details edited, the seal kept',
        `update audit.events set details = replace(details, 'REVOKED', 'ACTIVE') where org_id = $1 and seq = 2`,
      ],
      ['its version wound back', 'update audit.events set subject_version = 1 where org_id = $1 and seq = 2'],
      [
        "the older state's seal copied onto it",
        `update audit.events set details = (select details from audit.events where org_id = $1 and seq = 1) where org_id = $1 and seq = 2`,
      ],
      [
        'its MAC replaced',
        `update audit.events set mac = pg_catalog.decode('00', 'hex') where org_id = $1 and seq = 2`,
      ],
      [
        'its time moved off a whole millisecond',
        `update audit.events set recorded_at = recorded_at + interval '1 microsecond' where org_id = $1 and seq = 2`,
      ],
      [
        'stripped of its seal, so an older one would look latest',
        `update audit.events set details = '{"status":"REVOKED"}' where org_id = $1 and seq = 2`,
      ],
      [
        'its seal renamed by one letter',
        `update audit.events set details = replace(details, '"stateFingerprint"', '"stateFingerprinx"') where org_id = $1 and seq = 2`,
      ],
      [
        'its seal spaced out, so the search misses it',
        `update audit.events set details = replace(details, '"stateFingerprint":', '"stateFingerprint" :') where org_id = $1 and seq = 2`,
      ],
    ])('%s', async (_change, statement) => {
      await tamper(statement);

      expect(await latest(org)).toEqual({ kind: 'broken', seq: 2n });
    });

    it("a signed event forged with the chain's real hashes but no key, as the newest", async () => {
      const [head] = await attacker.query<{ hash: Buffer }>('select hash from audit.heads where org_id = $1', [org]);
      if (head === undefined) throw new Error('The chain has no head');
      const forged = signed(org, 3, 'ACTIVE');
      const detailsText = canonicalDetails({ ...forged.details, stateFingerprint: 'ab'.repeat(32) });
      const entry = {
        seq: 4n,
        id: '0199a0f0-0000-7000-8000-0000000000fe',
        recordedAt: new Date('2026-09-19T08:00:00.000Z'),
        content: eventContent(forged, detailsText),
      };
      await attacker.query(
        `insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id,
           subject_version, details, prev_hash, hash, mac, mac_key_version)
         values ($1, 4, $2, $3, 'user', $4, 'agent.status_changed', 'agent', $5, 3, $6, $7, $8, $9, 1)`,
        [
          org,
          entry.id,
          entry.recordedAt,
          USER,
          AGENT,
          detailsText,
          head.hash,
          linkHash({ kind: 'organisation', orgId: org }, head.hash, entry),
          Buffer.alloc(32),
        ],
      );

      expect(await latest(org)).toEqual({ kind: 'broken', seq: 4n });
    });

    it('details that are not JSON at all, with the rule that keeps them JSON dropped', async () => {
      await tamper('alter table audit.events drop constraint events_details_check');
      try {
        await tamper(`update audit.events set details = '{"stateFingerprint": broken' where org_id = $1 and seq = 2`);

        expect(await latest(org)).toEqual({ kind: 'broken', seq: 2n });
      } finally {
        await tamper(`delete from audit.events where org_id = $1`);
        await tamper(
          `alter table audit.events add constraint events_details_check check (pg_catalog.jsonb_typeof(details::jsonb) = 'object')`,
        );
      }
    });

    // The limit, which the chain's check and its anchor cover (ADR-012 §2): an event
    // deleted leaves the older one latest.
    it('the newest signed event deleted: the older one is found, and the chain check fails', async () => {
      await tamper('delete from audit.events where org_id = $1 and seq = 2');

      expect(await latest(org)).toMatchObject({ kind: 'signed', seq: 1n, version: 1 });
      expect(await verify(org)).toMatchObject({ ok: false });
    });
  });
});

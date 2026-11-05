// The platform chain's store over its tables (Rule Book §6: real Postgres).
// The steps it gives them (appendEvent, verifyChain) are tested in
// @agentx/platform/audit-chain, and in depth through the organisation chains'
// store; these prove this store keeps the contract: one head, locked, read
// with the count in one statement, and events read back exactly.
import { AsyncResource } from 'node:async_hooks';
import { createPrivateKey, createPublicKey } from 'node:crypto';

import { CHAIN_START, ChainBroken, type ChainReport } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, limitStatements } from '@agentx/platform/db';
import { API_PURPOSES, createKeyProvider, KeyError, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  failures,
  race,
  SequentialIds,
  type TestDatabase,
  testLogger,
  type TestSession,
  within,
} from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type PlatformEvent, PlatformEventRefused } from '../domain/event.ts';
import { createPlatformChain, HEAD_WAIT_SECONDS } from './platform-chain.ts';
import type { PlatformControlsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<PlatformControlsTables>;
/** The operator's own role (PL-57): its events, and only its, may be signed; the API's role may add the rest. */
let operator: Database<PlatformControlsTables>;
/** The FX-TAMPER attacker: the server's superuser, past every wall, holding none of the app's keys. */
let attacker: TestSession;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x200) });

/** The API's keys (PL-57): every key but the operator's, whose public half alone it checks with. */
const apiKeys = createKeyProvider(
  Object.fromEntries(
    API_PURPOSES.map((purpose) => [
      purpose,
      { current: 1, versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1)]]) },
    ]),
  ),
  API_PURPOSES,
  {
    'operator-signing': new Map([[1, publicHalf(Buffer.alloc(32, PURPOSES.indexOf('operator-signing') + 1))]]),
  },
);

/** An Ed25519 seed's public half, as the API is given it. */
function publicHalf(seed: Buffer): Buffer {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const key = createPrivateKey({ key: Buffer.concat([prefix, seed]), format: 'der', type: 'pkcs8' });
  return Buffer.from(String(createPublicKey(key).export({ format: 'jwk' }).x), 'base64url');
}

/** A forger's keys: the chains' MAC as the API holds it, and an operator's signing key of its own making. */
const forgerKeys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [
      purpose,
      { current: 1, versions: new Map([[1, Buffer.alloc(32, purpose === 'operator-signing' ? 0xf0 : index + 1)]]) },
    ]),
  ),
);

const OPERATOR_ACT: PlatformEvent = {
  actor: { type: 'system', id: 'operator' },
  action: 'platform.handoff_resumed',
  details: { reason: 'INC-2026/0057', release: 'r-1', run: null },
};

/** IDs for the operator's records, one generator for them all, so no two runs give the same. */
const operatorIds = new SequentialIds(0x300);

/** Records as the operator's role, with the keys given (the operator's own by default). */
const recordAsOperator = (events: readonly PlatformEvent[], withKeys = keys) =>
  operator.transaction().execute(async (tx) => {
    const own = createPlatformChain({ keys: withKeys, ids: operatorIds });
    const recorded = [];
    for (const one of events) recorded.push(await own.record(tx, one));
    return recorded;
  });

const started = (n: number): PlatformEvent => ({
  actor: { type: 'system', id: 'api' },
  action: 'platform.started',
  details: { configHash: `sha256:${n.toString(16).padStart(64, '0')}`, release: `r-${n}` },
});

const record = (...events: PlatformEvent[]) =>
  operator.transaction().execute(async (tx) => {
    const recorded = [];
    for (const one of events) recorded.push(await chain.record(tx, one));
    return recorded;
  });

const verify = (): Promise<ChainReport> => app.transaction().execute((tx) => chain.verify(tx, undefined));

const problem = async (): Promise<unknown> => {
  const report = await verify();
  return report.ok ? 'ok' : report.problem;
};

/** Runs statements as the attacker, one after another. */
const tamper = async (...statements: string[]): Promise<void> => {
  // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
  for (const statement of statements) await attacker.query(statement);
};

/** Runs statements as the owner: past 0080, the one role beside the operator's that may add an operator's event. */
const tamperAsOwner = async (...statements: string[]): Promise<void> => {
  // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
  for (const statement of statements) await database.as('owner').query(statement);
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  const logger = testLogger();
  app = createDatabase<PlatformControlsTables>({ ...database.connection('app'), maxConnections: 12 }, logger);
  operator = createDatabase<PlatformControlsTables>({ ...database.connection('operator'), maxConnections: 4 }, logger);
  attacker = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await operator.destroy();
  await database.drop();
});

// One chain for the whole platform, so every test starts from none.
beforeEach(async () => {
  await tamper(
    'truncate platform_controls.audit_events, platform_controls.audit_head, platform_controls.operator_signatures',
    // Signing starts at the chain's first place, as 0079 found it on the template.
    'update platform_controls.operator_signing set signed_from = 1',
  );
});

describe('recording platform events (ADR-011 §3, ADR-014 §8)', () => {
  it('starts the chain, adds events in order, and the chain checks out', async () => {
    const recorded = await record(started(1), started(2), started(3));

    expect(recorded.map((one) => one.seq)).toEqual([1n, 2n, 3n]);
    expect(await verify()).toMatchObject({ ok: true, seq: 3n });
  });

  it('stores the event as given, with its details as the exact text that was sealed', async () => {
    const [recorded] = await record(started(1));
    const [row] = await attacker.query('select * from platform_controls.audit_events');

    expect(row).toMatchObject({
      seq: '1',
      id: recorded?.id,
      actor_type: 'system',
      actor_id: 'api',
      action: 'platform.started',
      details: `{"configHash":"sha256:${'1'.padStart(64, '0')}","release":"r-1"}`,
      mac_key_version: 1,
    });
    expect(row?.recorded_at).toEqual(recorded?.recordedAt);
  });

  it('reports a chain that was never started as empty', async () => {
    expect(await verify()).toMatchObject({ ok: true, seq: 0n });
  });

  it("gives up after HEAD_WAIT_SECONDS when something else holds the head's lock, in the caller's transaction too", async () => {
    await record(started(1));
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('select * from platform_controls.audit_head for update');
    try {
      const began = performance.now();
      await expect(within(20_000, record(started(2)), 'the event')).rejects.toThrow(/lock timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual((HEAD_WAIT_SECONDS - 1) * 1000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
    expect(await verify()).toMatchObject({ ok: true, seq: 1n });
  });

  it("brings a longer limit the caller's transaction set down to HEAD_WAIT_SECONDS", async () => {
    await record(started(1));
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('select * from platform_controls.audit_head for update');
    try {
      const began = performance.now();
      await expect(
        within(
          20_000,
          app.transaction().execute(async (tx) => {
            await sql`set local lock_timeout = '1min'`.execute(tx);
            return chain.record(tx, started(2));
          }),
          'the event',
        ),
      ).rejects.toThrow(/lock timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual((HEAD_WAIT_SECONDS - 1) * 1000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it("ends as the lock timeout it is in a request's transaction, its statements limited, never as a statement cut short", async () => {
    await record(started(1));
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('select * from platform_controls.audit_head for update');
    try {
      await expect(
        within(
          20_000,
          app.transaction().execute(async (tx) => {
            await limitStatements(tx);
            return chain.record(tx, started(2));
          }),
          'the event',
        ),
      ).rejects.toThrow(/lock timeout/);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it("keeps a shorter limit the caller's transaction set, rather than lengthen it to HEAD_WAIT_SECONDS", async () => {
    await record(started(1));
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('select * from platform_controls.audit_head for update');
    try {
      const began = performance.now();
      await expect(
        within(
          20_000,
          app.transaction().execute(async (tx) => {
            await sql`set local lock_timeout = '1s'`.execute(tx);
            return chain.record(tx, started(2));
          }),
          'the event',
        ),
      ).rejects.toThrow(/lock timeout/);
      expect(performance.now() - began).toBeLessThan(5_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('refuses an event that breaks the rules, and writes nothing', async () => {
    await expect(record({ ...started(1), action: 'started' })).rejects.toThrow(PlatformEventRefused);

    expect(await attacker.query('select 1 from platform_controls.audit_head')).toEqual([]);
  });
});

describe('recording in a transaction of its own, as a process start does', () => {
  it('records the event and commits it', async () => {
    const recorded = await chain.recordAlone(app, started(1));

    expect(recorded.seq).toBe(1n);
    expect(await verify()).toMatchObject({ ok: true, seq: 1n });
  });

  it("gives up after HEAD_WAIT_SECONDS when something else holds the head's lock, rather than hang", async () => {
    await record(started(1));
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('select * from platform_controls.audit_head for update');
    try {
      const began = performance.now();
      await expect(within(20_000, chain.recordAlone(app, started(2)), 'the start')).rejects.toThrow(/lock timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual((HEAD_WAIT_SECONDS - 1) * 1000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
    expect(await verify()).toMatchObject({ ok: true, seq: 1n });
  });
});

describe('checking in a transaction of its own, as the anchor check does', () => {
  it('checks the chain against the anchor it is given', async () => {
    await record(started(1), started(2));
    const report = await chain.verifyAlone(app, undefined);
    if (!report.ok) throw new Error('The chain should check out');

    expect(report.seq).toBe(2n);
    expect(await chain.verifyAlone(app, { seq: 2n, hash: Buffer.alloc(32, 7) })).toEqual({
      ok: false,
      problem: { reason: 'anchor', seq: 2n },
    });
  });

  it('gives up on a statement after 10 seconds, a wait for a lock included, rather than hang', async () => {
    await record(started(1));
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table platform_controls.audit_events in access exclusive mode');
    try {
      const began = performance.now();
      await expect(chain.verifyAlone(app, undefined)).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe('the organisations it records as created, for the anchor check (B1d-2)', () => {
  const ORGS = ['0199a0f0-0000-7000-8000-00000000c001', '0199a0f0-0000-7000-8000-00000000c002'];
  const created = (orgId: string): PlatformEvent => ({
    actor: { type: 'system', id: 'operator' },
    action: 'organization.created',
    details: { orgId, release: 'r-1', run: null },
  });

  it('gives each organisation created, in the order recorded, and nothing from other events', async () => {
    // Another action carrying an orgId counts for nothing.
    const noted: PlatformEvent = {
      actor: { type: 'system', id: 'api' },
      action: 'probe.noted',
      details: { orgId: ORGS[0] ?? '' },
    };
    await record(started(1), created(ORGS[1] ?? ''), noted, started(2), created(ORGS[0] ?? ''));

    expect(await chain.createdOrganizations(app)).toEqual([ORGS[1], ORGS[0]]);
    // In pages: at the page's edge, and past it, the same.
    expect(await chain.createdOrganizations(app, 1)).toEqual([ORGS[1], ORGS[0]]);
    expect(await chain.createdOrganizations(app, 2)).toEqual([ORGS[1], ORGS[0]]);
  });

  it('gives nothing for details planted without an orgId text, which the chain check names', async () => {
    await record(created(ORGS[0] ?? ''));
    // The owner can drop the table's check that details are a JSON object, as here.
    await tamper('alter table platform_controls.audit_events drop constraint audit_events_details_check');
    try {
      // Copies of the operator's event, so added as the owner (0080 refuses any other role).
      await tamperAsOwner(
        `insert into platform_controls.audit_events
         select seq + 1, gen_random_uuid(), recorded_at, actor_type, actor_id, action, '{"orgId":7}', prev_hash, hash, mac,
                mac_key_version from platform_controls.audit_events where seq = 1`,
        `insert into platform_controls.audit_events
         select seq + 2, gen_random_uuid(), recorded_at, actor_type, actor_id, action, '[]', prev_hash, hash, mac,
                mac_key_version from platform_controls.audit_events where seq = 1`,
        `insert into platform_controls.audit_events
         select seq + 3, gen_random_uuid(), recorded_at, actor_type, actor_id, action, '{}', prev_hash, hash, mac,
                mac_key_version from platform_controls.audit_events where seq = 1`,
        `insert into platform_controls.audit_events
         select seq + 4, gen_random_uuid(), recorded_at, actor_type, actor_id, action, 'not json', prev_hash, hash, mac,
                mac_key_version from platform_controls.audit_events where seq = 1`,
      );

      expect(await chain.createdOrganizations(app)).toEqual([ORGS[0]]);
    } finally {
      await tamper(
        'truncate platform_controls.audit_events, platform_controls.audit_head',
        "alter table platform_controls.audit_events add constraint audit_events_details_check check (pg_catalog.jsonb_typeof(details::jsonb) = 'object')",
      );
    }
  });

  it('gives up on a statement after 10 seconds, a wait for a lock included, rather than hang', async () => {
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table platform_controls.audit_events in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, chain.createdOrganizations(app), 'the read')).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe('SEC-EVD-01 the app role only adds to and reads the platform chain', () => {
  // Postgres checks the table right before anything else.
  // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
  const asApp = (statement: string) => database.as('app').query(statement);

  beforeEach(async () => {
    await record(started(1));
  });

  it.each([
    'update platform_controls.audit_events set action = $$platform.forged$$',
    'delete from platform_controls.audit_events',
    'truncate platform_controls.audit_events',
    'delete from platform_controls.audit_head',
    'truncate platform_controls.audit_head',
    'update platform_controls.audit_head set only_row = only_row',
  ])('refuses: %s', async (statement) => {
    await expect(asApp(statement)).rejects.toThrow(/permission denied/);
  });

  it("lets it move the head's own columns on", async () => {
    await expect(asApp('update platform_controls.audit_head set seq = seq')).resolves.toBeDefined();
  });
});

describe('FX-RACE recording at the same time', () => {
  it('starts the chain once and puts every event in its own place, times rising with the numbers', async () => {
    const outcomes = await race(8, (party, sync) =>
      app.transaction().execute(async (tx) => {
        await sync();
        return chain.record(tx, started(party + 1));
      }),
    );

    expect(failures(outcomes)).toEqual([]);
    expect(await verify()).toMatchObject({ ok: true, seq: 8n });
    const times = await attacker.query<{ recorded_at: Date }>(
      'select recorded_at from platform_controls.audit_events order by seq',
    );
    const ms = times.map((row) => row.recorded_at.getTime());
    expect(ms).toEqual([...ms].sort((a, b) => a - b));
  });

  it('checks the chain as its head stood, and takes no later event for tampering', async () => {
    await record(started(1), started(2));
    const addEvent = AsyncResource.bind(() => record(started(3)));
    const headReads = new WeakSet<object>();
    let added = false;
    const racing = app.withPlugin({
      transformQuery: ({ node, queryId }) => {
        if (node.kind === 'RawNode' && node.sqlFragments.join('').includes('as heads')) headReads.add(queryId);
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

    expect(await racing.transaction().execute((tx) => chain.verify(tx, undefined))).toMatchObject({
      ok: true,
      seq: 2n,
    });
    expect(added).toBe(true);
    expect(await verify()).toMatchObject({ ok: true, seq: 3n });
  });
});

describe('SEC-EVD-02, FX-TAMPER: changes made past the app are found', () => {
  beforeEach(async () => {
    await record(started(1), started(2), started(3));
  });

  it('passes a chain whose rows Postgres has stored out of order, since it reads them by number', async () => {
    // A no-op update writes a row's new version at the end of the table, so a plain scan meets event 1 last.
    await tamper('update platform_controls.audit_events set action = action where seq = 1');

    expect(await verify()).toMatchObject({ ok: true, seq: 3n });
  });

  it('an event edited', async () => {
    await tamper(`update platform_controls.audit_events set details = '{"release":"r-9"}' where seq = 2`);

    expect(await problem()).toEqual({ reason: 'hash', seq: 2n });
  });

  it('an event forged at a number the check never reads, 0', async () => {
    await tamper(
      'alter table platform_controls.audit_events drop constraint audit_events_seq_check',
      `insert into platform_controls.audit_events
         select 0, '0199a0f0-0000-7000-8000-0000000000fe', recorded_at, actor_type, actor_id, 'platform.forged',
                details, prev_hash, hash, mac, mac_key_version
         from platform_controls.audit_events where seq = 1`,
    );
    try {
      expect(await problem()).toEqual({ reason: 'head', seq: 3n });
    } finally {
      await tamper(
        'delete from platform_controls.audit_events where seq = 0',
        'alter table platform_controls.audit_events add constraint audit_events_seq_check check (seq >= 1)',
      );
    }
  });

  it('a second head row beside the first: no head can be trusted, and nothing more is recorded', async () => {
    await tamper(
      'alter table platform_controls.audit_head drop constraint audit_head_pkey',
      'insert into platform_controls.audit_head select * from platform_controls.audit_head',
    );
    try {
      expect(await problem()).toEqual({ reason: 'head', seq: 0n });
      await expect(record(started(4))).rejects.toThrow(ChainBroken);
    } finally {
      await tamper(
        'truncate platform_controls.audit_events, platform_controls.audit_head',
        'alter table platform_controls.audit_head add constraint audit_head_pkey primary key (only_row)',
      );
    }
  });

  it('a second head row, an earlier sealed one: nothing more is recorded on either', async () => {
    const [earlier] = await attacker.query('select seq, hash, mac, mac_key_version from platform_controls.audit_head');
    if (earlier === undefined) throw new Error('The chain has no head');
    await record(started(4));
    await tamper('alter table platform_controls.audit_head drop constraint audit_head_pkey');
    try {
      await attacker.query(
        'insert into platform_controls.audit_head (only_row, seq, hash, mac, mac_key_version) values (true, $1, $2, $3, $4)',
        [earlier.seq, earlier.hash, earlier.mac, earlier.mac_key_version],
      );

      await expect(record(started(5))).rejects.toThrow(ChainBroken);
      expect(await problem()).toEqual({ reason: 'head', seq: 0n });
    } finally {
      await tamper(
        'truncate platform_controls.audit_events, platform_controls.audit_head',
        'alter table platform_controls.audit_head add constraint audit_head_pkey primary key (only_row)',
      );
    }
  });

  it("the head's row unreadable on a chain with no events: still no head to trust, not an empty chain", async () => {
    await tamper(
      'delete from platform_controls.audit_events',
      'alter table platform_controls.audit_head alter column mac drop not null',
      'update platform_controls.audit_head set mac = null',
    );
    try {
      expect(await problem()).toEqual({ reason: 'head', seq: 0n });
    } finally {
      await tamper(
        'truncate platform_controls.audit_events, platform_controls.audit_head',
        'alter table platform_controls.audit_head alter column mac set not null',
      );
    }
  });

  it('the head wound back to an earlier sealed value, with events left after it: nothing more is recorded', async () => {
    const [earlier] = await attacker.query('select seq, hash, mac, mac_key_version from platform_controls.audit_head');
    if (earlier === undefined) throw new Error('The chain has no head');
    await record(started(4), started(5));
    await tamper('delete from platform_controls.audit_events where seq = 4');
    await attacker.query(
      'update platform_controls.audit_head set seq = $1, hash = $2, mac = $3, mac_key_version = $4',
      [earlier.seq, earlier.hash, earlier.mac, earlier.mac_key_version],
    );

    await expect(record(started(6))).rejects.toThrow(ChainBroken);
    expect(await problem()).toEqual({ reason: 'head', seq: 3n });
  });

  it("the head's row unreadable: no head can be trusted, and nothing more is recorded", async () => {
    await tamper(
      'alter table platform_controls.audit_head alter column mac drop not null',
      'update platform_controls.audit_head set mac = null',
    );
    try {
      expect(await problem()).toEqual({ reason: 'head', seq: 0n });
      await expect(record(started(4))).rejects.toThrow(ChainBroken);
    } finally {
      await tamper(
        'truncate platform_controls.audit_events, platform_controls.audit_head',
        'alter table platform_controls.audit_head alter column mac set not null',
      );
    }
  });

  it('SEC-DB-11 the whole chain wound back, then grown again: whole and sealed, but not what was anchored', async () => {
    const [earlier] = await attacker.query('select seq, hash, mac, mac_key_version from platform_controls.audit_head');
    if (earlier === undefined) throw new Error('The chain has no head');
    await record(started(4));
    const anchored = await verify();
    if (!anchored.ok) throw new Error('The chain should have checked out before the tampering');
    const anchor = { seq: anchored.seq, hash: anchored.hash };
    await tamper('delete from platform_controls.audit_events where seq = 4');
    await attacker.query(
      'update platform_controls.audit_head set seq = $1, hash = $2, mac = $3, mac_key_version = $4',
      [earlier.seq, earlier.hash, earlier.mac, earlier.mac_key_version],
    );
    const against = () => app.transaction().execute((tx) => chain.verify(tx, anchor));

    expect(await verify()).toMatchObject({ ok: true, seq: 3n });
    expect(await against()).toEqual({ ok: false, problem: { reason: 'anchor', seq: 4n } });
    await record(started(5), started(6));
    expect(await verify()).toMatchObject({ ok: true, seq: 5n });
    expect(await against()).toEqual({ ok: false, problem: { reason: 'anchor', seq: 4n } });
  });

  it('the head deleted: the events are left headless, and nothing more is recorded on them', async () => {
    await tamper('delete from platform_controls.audit_head');

    expect(await problem()).toEqual({ reason: 'head', seq: 0n });
    await expect(record(started(4))).rejects.toThrow(ChainBroken);
  });

  it('an event the app cannot read at all', async () => {
    await tamper(
      'alter table platform_controls.audit_events alter column details drop not null',
      'update platform_controls.audit_events set details = null where seq = 2',
    );
    try {
      expect(await problem()).toEqual({ reason: 'unreadable', seq: 2n });
    } finally {
      await tamper(
        'truncate platform_controls.audit_events, platform_controls.audit_head',
        'alter table platform_controls.audit_events alter column details set not null',
      );
    }
  });
});

describe('checking the platform chain from its anchor (4D2e E2)', () => {
  const ORGS = ['0199a0f0-0000-7000-8000-00000000c001', '0199a0f0-0000-7000-8000-00000000c002'];
  const created = (orgId: string | undefined): PlatformEvent => ({
    actor: { type: 'system', id: 'api' },
    action: 'organization.created',
    details: { orgId: orgId ?? '' },
  });

  const checked = async () => {
    const report = await verify();
    if (!report.ok) throw new Error('the chain should check out');
    const { seq, hash, macKeyVersion } = report;
    return { seq, hash, macKeyVersion };
  };

  it('reads an empty chain as empty, in one trip', async () => {
    expect(await chain.checkFromAnchor(app, CHAIN_START)).toMatchObject({ ok: true, seq: 0n, to: 0n });
  });

  it('goes on past its anchor, stopping at its limit, and passes a count and a full pass', async () => {
    await record(started(1), started(2));
    const from = await checked();
    await record(started(3), started(4));

    expect(await chain.checkFromAnchor(app, from)).toMatchObject({ ok: true, seq: 4n, to: 4n, macKeyVersion: 1 });
    expect(await chain.checkFromAnchor(app, from, 1)).toMatchObject({ ok: true, seq: 3n, to: 4n });
    expect(await chain.countStep(app, 0n, 4n)).toBeUndefined();
    expect(await chain.passStep(app, CHAIN_START, from, 10)).toMatchObject({ ok: true, seq: 2n, to: 2n });
  });

  it('finds the tail removed, the anchored event gone, and a middle event by the count of the last 1,000 and a pass', async () => {
    await record(started(1), started(2), started(3));
    const whole = await checked();

    await tamper('delete from platform_controls.audit_events where seq = 2');
    // Counted with the edges since 4D2e E8 (decision 1): where the count starts, as a count can't say which.
    expect(await chain.checkFromAnchor(app, whole)).toEqual({ ok: false, problem: { reason: 'gap', seq: 1n } });
    expect(await chain.countStep(app, 0n, 3n)).toEqual({ reason: 'gap', seq: 1n });
    expect(await chain.passStep(app, CHAIN_START, whole, 10)).toEqual({
      ok: false,
      problem: { reason: 'gap', seq: 2n },
    });

    await tamper('delete from platform_controls.audit_events where seq = 3');
    expect(await chain.checkFromAnchor(app, whole)).toEqual({ ok: false, problem: { reason: 'head', seq: 3n } });
  });

  it('counts numbers, not rows: one deleted and made up for by a copy of another, the keys dropped (4D2e E8 review)', async () => {
    await record(started(1), started(2), started(3));
    const whole = await checked();
    await tamper(
      'alter table platform_controls.audit_events drop constraint audit_events_pkey',
      'alter table platform_controls.audit_events drop constraint audit_events_id_key',
      'delete from platform_controls.audit_events where seq = 2',
      // A copy of the first: the lowest and highest numbers, and the anchored event, all as they were.
      'insert into platform_controls.audit_events select * from platform_controls.audit_events where seq = 1',
    );
    try {
      expect(await chain.checkFromAnchor(app, whole)).toEqual({ ok: false, problem: { reason: 'gap', seq: 1n } });
      expect(await chain.countStep(app, 0n, 3n)).toEqual({ reason: 'gap', seq: 1n });
    } finally {
      await tamper(
        'delete from platform_controls.audit_events',
        'alter table platform_controls.audit_events add constraint audit_events_pkey primary key (seq)',
        'alter table platform_controls.audit_events add constraint audit_events_id_key unique (id)',
      );
    }
  });

  it('finds the anchored event edited', async () => {
    await record(started(1), started(2));
    const from = await checked();
    await tamper(`update platform_controls.audit_events set action = 'probe.edited' where seq = 2`);

    expect(await chain.checkFromAnchor(app, from)).toEqual({ ok: false, problem: { reason: 'anchor', seq: 2n } });
  });

  it("reads two heads as none it can use, the table's only-row key gone", async () => {
    await record(started(1));
    const from = await checked();
    await tamper(
      'alter table platform_controls.audit_head drop constraint audit_head_pkey',
      'insert into platform_controls.audit_head select * from platform_controls.audit_head',
    );
    try {
      expect(await chain.checkFromAnchor(app, from)).toEqual({ ok: false, problem: { reason: 'head', seq: 0n } });
    } finally {
      await tamper(
        'truncate platform_controls.audit_head',
        'alter table platform_controls.audit_head add primary key (only_row)',
      );
    }
  });

  describe('FX-TAMPER: the attacker, holding none of the keys', () => {
    const savedHead = async () => {
      const [head] = await attacker.query<{ seq: bigint; hash: Buffer; mac: Buffer; mac_key_version: number }>(
        'select seq, hash, mac, mac_key_version from platform_controls.audit_head',
      );
      if (head === undefined) throw new Error('no head');
      return head;
    };

    /** The head put back to one it genuinely had, its own MAC and all. */
    const putBack = async ({ seq, hash, mac, mac_key_version: version }: Awaited<ReturnType<typeof savedHead>>) => {
      await attacker.query(
        'update platform_controls.audit_head set seq = $1, hash = $2, mac = $3, mac_key_version = $4',
        [seq, hash, mac, version],
      );
    };

    it('finds a chain wound back, its head moved with its tail', async () => {
      await record(started(1), started(2));
      const earlier = await savedHead();
      await record(started(3), started(4));
      const from = await checked();
      await tamper('delete from platform_controls.audit_events where seq > 2');
      await putBack(earlier);

      expect(await chain.checkFromAnchor(app, from)).toEqual({ ok: false, problem: { reason: 'anchor', seq: 4n } });
    });

    it('finds an event left past a wound-back head, reading no event', async () => {
      await record(started(1), started(2));
      const earlier = await savedHead();
      const from = await checked();
      await record(started(3));
      await putBack(earlier);

      expect(await chain.checkFromAnchor(app, from)).toEqual({ ok: false, problem: { reason: 'head', seq: 2n } });
    });

    it('finds the first event deleted, wherever the anchor stands', async () => {
      await record(started(1), started(2), started(3));
      const from = await checked();
      await tamper('delete from platform_controls.audit_events where seq = 1');

      expect(await chain.checkFromAnchor(app, from)).toEqual({ ok: false, problem: { reason: 'gap', seq: 1n } });
    });

    it('finds an event after the anchor edited, at its place', async () => {
      await record(started(1), started(2));
      const from = await checked();
      await record(started(3));
      await tamper(`update platform_controls.audit_events set action = 'probe.edited' where seq = 3`);

      expect(await chain.checkFromAnchor(app, from)).toEqual({ ok: false, problem: { reason: 'hash', seq: 3n } });
    });
  });

  it("believes no anchored event with another at its number, the table's key gone", async () => {
    await record(started(1), started(2));
    const from = await checked();
    await tamper(
      'alter table platform_controls.audit_events drop constraint audit_events_pkey cascade',
      `insert into platform_controls.audit_events
       select seq, gen_random_uuid(), recorded_at, actor_type, actor_id, action, details, prev_hash, hash, mac,
              mac_key_version from platform_controls.audit_events where seq = 2`,
    );
    try {
      expect(await chain.checkFromAnchor(app, from)).toEqual({ ok: false, problem: { reason: 'anchor', seq: 2n } });
    } finally {
      await tamper(
        'truncate platform_controls.audit_events',
        'alter table platform_controls.audit_events add primary key (seq)',
      );
    }
  });

  it('gives the organisations recorded past a number, and the number to ask from next', async () => {
    const [first, second] = ORGS;
    expect(await chain.createdOrganizationsSince(app, 0n, 0n)).toEqual({ orgIds: [], seq: 0n });

    await record(started(1), created(first), started(2), created(second), started(3));

    expect(await chain.createdOrganizationsSince(app, 0n, 5n)).toEqual({ orgIds: [first, second], seq: 4n });
    // With the job's limit on each trip's answer, as the anchor check reads it (4D2e E8).
    expect(await chain.createdOrganizationsSince(app, 2n, 5n, 30_000)).toEqual({ orgIds: [second], seq: 4n });
    expect(await chain.createdOrganizationsSince(app, 4n, 5n)).toEqual({ orgIds: [], seq: 4n });
  });

  it('reads nothing past where the chain check reached: a step short of the head goes on from there', async () => {
    const [first, second] = ORGS;
    await record(started(1), created(first), started(2), created(second));

    const short = await chain.createdOrganizationsSince(app, 0n, 3n);
    expect(short).toEqual({ orgIds: [first], seq: 2n });
    expect(await chain.createdOrganizationsSince(app, short.seq, 4n)).toEqual({ orgIds: [second], seq: 4n });
  });

  it('neither reads a row planted past the head nor moves its number, so later organisations are still found', async () => {
    const [first, second] = ORGS;
    await record(created(first));
    await attacker.query(
      `insert into platform_controls.audit_events
       select 4611686018427387904, gen_random_uuid(), recorded_at, actor_type, actor_id, action, $1, prev_hash,
              hash, mac, mac_key_version from platform_controls.audit_events where seq = 1`,
      [JSON.stringify({ orgId: second })],
    );

    const read = await chain.createdOrganizationsSince(app, 0n, 1n);
    expect(read).toEqual({ orgIds: [first], seq: 1n });

    await tamper('delete from platform_controls.audit_events where seq = 4611686018427387904');
    await record(created(second));
    expect(await chain.createdOrganizationsSince(app, read.seq, 2n)).toEqual({ orgIds: [second], seq: 2n });
  });

  it('moves its number on past an event whose details give no organisation', async () => {
    const [first] = ORGS;
    await record(created(first));
    await record({ actor: { type: 'system', id: 'api' }, action: 'organization.created', details: { note: 'none' } });

    expect(await chain.createdOrganizationsSince(app, 1n, 2n)).toEqual({ orgIds: [], seq: 2n });
  });
});

describe("the operator's events, believed only signed with its own key (PL-57)", () => {
  /** The chain checked as the API checks it: the operator's public half alone. */
  const verifiedByApi = (): Promise<ChainReport> =>
    app
      .transaction()
      .execute((tx) => createPlatformChain({ keys: apiKeys, ids: new SequentialIds(0x400) }).verify(tx, undefined));

  it("signs the operator's event as it records it, and the API checks it with the public half alone", async () => {
    const [, act] = await recordAsOperator([started(1), OPERATOR_ACT]);
    const signatures = await attacker.query<{ seq: string; id: string; key_version: number }>(
      'select seq::text, id::text, key_version from platform_controls.operator_signatures',
    );

    expect(signatures).toEqual([{ seq: '2', id: act?.id, key_version: 1 }]);
    expect(await verifiedByApi()).toMatchObject({ ok: true, seq: 2n });
  });

  it("refuses to record an operator's event for a process without the operator's key: the API can't sign one", async () => {
    await expect(
      app
        .transaction()
        .execute((tx) =>
          createPlatformChain({ keys: apiKeys, ids: new SequentialIds(0x500) }).record(tx, OPERATOR_ACT),
        ),
    ).rejects.toThrow(KeyError);
    expect(await attacker.query('select 1 from platform_controls.audit_events')).toEqual([]);
  });

  it("refuses the API's role a signature of its own: only the operator's role adds them", async () => {
    await expect(
      app.transaction().execute((tx) =>
        tx
          .insertInto('platform_controls.operator_signatures')
          .values({ seq: 1n, id: '0199a0f0-0000-7000-8000-00000000a571', signature: Buffer.alloc(64), key_version: 1 })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it("names an operator's event signed with another key, where the API forged it, as unsealed", async () => {
    await recordAsOperator([OPERATOR_ACT]);
    // The chains' MAC as the API holds it, and an Ed25519 key of the forger's own.
    await recordAsOperator([OPERATOR_ACT], forgerKeys);

    expect(await verifiedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 2n } });
  });

  it("believes an unsigned operator's event before where 0079 started signing, and names one from there on", async () => {
    await recordAsOperator([OPERATOR_ACT, OPERATOR_ACT, OPERATOR_ACT]);
    // As if 0079 ran with the chain at 2: the first recorded before PL-57, the last unsigned at its very start.
    await tamper(
      'update platform_controls.operator_signing set signed_from = 3',
      'delete from platform_controls.operator_signatures where seq in (1, 3)',
    );

    expect(await verifiedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 3n } });
  });

  it("names an unsigned operator's event past the cut-over before any signed run: the window is closed", async () => {
    // As a foothold in the API could add one before the operator's first signed run: no signature exists at all.
    await recordAsOperator([started(1), OPERATOR_ACT]);
    await tamper('delete from platform_controls.operator_signatures');

    expect(await verifiedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 2n } });
  });

  it("names an unsigned operator's event before the first signature, where 0079 started signing", async () => {
    // Signing starts at 1: a signature further on doesn't move the start past the unsigned first.
    await recordAsOperator([OPERATOR_ACT, OPERATOR_ACT]);
    await tamper('delete from platform_controls.operator_signatures where seq = 1');

    expect(await verifiedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 1n } });
  });

  it("believes no unsigned operator's event when where signing starts can't be read", async () => {
    await recordAsOperator([OPERATOR_ACT]);
    await tamper('update platform_controls.operator_signing set signed_from = 5');
    expect(await verifiedByApi()).toMatchObject({ ok: true, seq: 1n });
    await tamper('delete from platform_controls.operator_signatures', 'delete from platform_controls.operator_signing');
    try {
      expect(await verifiedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 1n } });
    } finally {
      await tamper('insert into platform_controls.operator_signing (signed_from) values (1)');
    }
  });

  it("refuses the API's role and the operator's a move of where signing starts: 0079 wrote it, as the owner", async () => {
    for (const role of [app, operator]) {
      await expect(
        role
          .transaction()
          .execute((tx) => tx.updateTable('platform_controls.operator_signing').set({ signed_from: 99n }).execute()),
      ).rejects.toMatchObject({ code: '42501' });
    }
  });

  it('names a signature that claims a key version the API has no public half for', async () => {
    await recordAsOperator([OPERATOR_ACT]);
    await tamper('update platform_controls.operator_signatures set key_version = 2');

    expect(await verifiedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 1n } });
  });

  it("names a signature moved onto another operator's event", async () => {
    await recordAsOperator([OPERATOR_ACT, OPERATOR_ACT]);
    // The first as if before PL-57, so the moved signature alone is at fault.
    await tamper(
      'update platform_controls.operator_signing set signed_from = 2',
      'delete from platform_controls.operator_signatures where seq = 2',
      'update platform_controls.operator_signatures set seq = 2 where seq = 1',
    );

    expect(await verifiedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 2n } });
  });
});

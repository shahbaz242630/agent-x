// The platform chain's store over its tables (Rule Book §6: real Postgres).
// The steps it gives them (appendEvent, verifyChain) are tested in
// @agentx/platform/audit-chain, and in depth through the organisation chains'
// store; these prove this store keeps the contract: one head, locked, read
// with the count in one statement, and events read back exactly.
import { AsyncResource } from 'node:async_hooks';

import { ChainBroken, type ChainReport } from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  failures,
  LogCapture,
  race,
  SequentialIds,
  type TestDatabase,
  type TestSession,
  within,
} from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type PlatformEvent, PlatformEventRefused } from '../domain/event.ts';
import { createPlatformChain } from './platform-chain.ts';
import type { PlatformControlsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<PlatformControlsTables>;
/** The FX-TAMPER attacker: the server's superuser, past every wall, holding none of the app's keys. */
let attacker: TestSession;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x200) });

const started = (n: number): PlatformEvent => ({
  actor: { type: 'system', id: 'api' },
  action: 'platform.started',
  details: { configHash: `sha256:${n.toString(16).padStart(64, '0')}`, release: `r-${n}` },
});

const record = (...events: PlatformEvent[]) =>
  app.transaction().execute(async (tx) => {
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

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: new LogCapture(),
  });
  app = createDatabase<PlatformControlsTables>({ ...database.connection('app'), maxConnections: 12 }, logger);
  attacker = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

// One chain for the whole platform, so every test starts from none.
beforeEach(async () => {
  await tamper('truncate platform_controls.audit_events, platform_controls.audit_head');
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

  it("gives up after 10 seconds when something else holds the head's lock, in the caller's transaction too", async () => {
    await record(started(1));
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('select * from platform_controls.audit_head for update');
    try {
      const began = performance.now();
      await expect(within(20_000, record(started(2)), 'the event')).rejects.toThrow(/lock timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
    expect(await verify()).toMatchObject({ ok: true, seq: 1n });
  });

  it("brings a longer limit the caller's transaction set down to 10 seconds", async () => {
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
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it("keeps a shorter limit the caller's transaction set, rather than lengthen it to 10 seconds", async () => {
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

  it("gives up after 10 seconds when something else holds the head's lock, rather than hang", async () => {
    await record(started(1));
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('select * from platform_controls.audit_head for update');
    try {
      const began = performance.now();
      await expect(within(20_000, chain.recordAlone(app, started(2)), 'the start')).rejects.toThrow(/lock timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
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

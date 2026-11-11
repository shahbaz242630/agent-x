// B6-2b: reading the platform chain's events by their facts, on the real
// migrated schema, as the app role: only events of the action asked for
// count, whatever the others hold. B6-3d: the latest time among events of
// several kinds, each by its action and facts. SA2: the copier's and the
// restriction's reads planned on 0082's indexes, on a chain of thousands.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { type Compilable, sql, type Transaction } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createPlatformChain } from './platform-chain.ts';
import {
  latestPlatformTime,
  latestPlatformTimeOf,
  latestPlatformTimeOfRead,
  latestPlatformTimeRead,
  platformEventWith,
  platformEventWithRead,
} from './platform-events.ts';
import type { PlatformControlsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<PlatformControlsTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xc6e0) });
const ACTOR = { type: 'system', id: 'api' } as const;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<PlatformControlsTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the platform chain's events by their facts (B6-2b, Postgres ${server.version})`, () => {
  it('finds nothing, and no time, on a chain that holds none of the action', async () => {
    expect(await platformEventWith(app, 'idp.event_copied', { event: 'e-1' })).toBe(false);
    expect(await latestPlatformTime(app, 'idp.event_copied', 'at')).toBeUndefined();
  });

  it('counts only the action asked for, even when another holds the same facts and a later time', async () => {
    await chain.recordAlone(app, {
      actor: ACTOR,
      action: 'other.thing_done',
      details: { event: 'e-2', org: 'none', at: '2026-09-28T00:00:00.000Z' },
    });
    await chain.recordAlone(app, {
      actor: ACTOR,
      action: 'idp.event_copied',
      details: { event: 'e-3', org: 'none', at: '2026-09-27T08:00:00.000Z' },
    });

    expect(await platformEventWith(app, 'idp.event_copied', { event: 'e-2', org: 'none' })).toBe(false);
    expect(await platformEventWith(app, 'idp.event_copied', { event: 'e-3', org: 'none' })).toBe(true);
    expect(await platformEventWith(app, 'idp.event_copied', { event: 'e-3', org: 'another' })).toBe(false);
    expect(await latestPlatformTime(app, 'idp.event_copied', 'at')).toEqual(new Date('2026-09-27T08:00:00.000Z'));
  });

  it('fails, rather than passes, on a latest time not written as toISOString writes it', async () => {
    await chain.recordAlone(app, { actor: ACTOR, action: 'kind.cursor', details: { at: '2026-09-28T09:00:00Z' } });
    await chain.recordAlone(app, { actor: ACTOR, action: 'kind.unreadable', details: { at: 'not a time' } });

    await expect(latestPlatformTime(app, 'kind.cursor', 'at')).rejects.toThrow(/not a time as toISOString/);
    await expect(latestPlatformTime(app, 'kind.unreadable', 'at')).rejects.toThrow(/not a time as toISOString/);
  });

  it('binds a fact’s name it doesn’t index as a value, never as SQL', async () => {
    await chain.recordAlone(app, { actor: ACTOR, action: 'kind.named', details: { org: 'x' } });

    expect(await platformEventWith(app, 'kind.named', { org: 'x' })).toBe(true);
    expect(await platformEventWith(app, 'kind.named', { "org') is not null or ('": 'x' })).toBe(false);
  });
});

describe(`the copier's and the restriction's reads, from 0082's indexes (SA2, Postgres ${server.version})`, () => {
  type PlanNode = Readonly<Record<string, unknown>>;
  const nodes = (plan: PlanNode): PlanNode[] => [
    plan,
    ...((plan.Plans as PlanNode[] | undefined) ?? []).flatMap(nodes),
  ];
  const COPIED = 5000;

  /**
   * Each read's plan on a chain holding COPIED copied events of 500 people, planned by
   * Postgres on its own statistics, no kind of scan set aside; the rows are made and
   * planned in one transaction, rolled back. Only the nodes that read the chain are kept.
   */
  async function plansOf(
    reads: (tx: Transaction<PlatformControlsTables>) => Readonly<Record<string, Compilable>>,
  ): Promise<Record<string, PlanNode[]>> {
    const owner = createDatabase<PlatformControlsTables>(
      { ...database.connection('owner'), maxConnections: 1 },
      testLogger(),
    );
    const plans: Record<string, PlanNode[]> = {};
    const rolledBack = new Error('rolled back');
    try {
      await owner.transaction().execute(async (tx) => {
        await sql`
          insert into platform_controls.audit_events
            (seq, id, recorded_at, actor_type, actor_id, action, details, prev_hash, hash, mac, mac_key_version)
          select 1000000 + g, gen_random_uuid(), now(), 'system', 'api', 'idp.event_copied',
                 json_build_object(
                   'event', 'user:' || g || ':1', 'org', 'none', 'type', 'user.human.mfa.otp.removed', 'by', 'other',
                   'person', 'p-' || (g % 500), 'subject', 's-' || (g % 500),
                   'at', to_char(timestamp '2026-01-01' + g * interval '1 second', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
                 )::text,
                 decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode('00', 'hex'), 1
          from generate_series(1, ${COPIED}::int) as g`.execute(tx);
        await sql`analyze platform_controls.audit_events`.execute(tx);
        for (const [name, read] of Object.entries(reads(tx))) {
          const explained = await sql<{ 'QUERY PLAN': [{ Plan: PlanNode }] }>`explain (format json) ${read}`.execute(
            tx,
          );
          plans[name] = nodes(explained.rows[0]?.['QUERY PLAN'][0].Plan ?? {}).filter(
            (node) => node['Relation Name'] === 'audit_events' || node['Index Name'] !== undefined,
          );
        }
        throw rolledBack;
      });
    } catch (error) {
      if (error !== rolledBack) throw error;
    } finally {
      await owner.destroy();
    }
    return plans;
  }

  const indexesOf = (plan: readonly PlanNode[] | undefined) =>
    (plan ?? []).flatMap((node) => (node['Index Name'] === undefined ? [] : [node['Index Name']]));

  it('finds an event copied, where the copier got to, and a person’s or a login’s removals by index, never reading every copy', async () => {
    const removed = {
      action: 'idp.event_copied',
      oneOf: { type: ['user.human.mfa.otp.removed'] },
      noneOf: { by: ['self'] },
    };
    const plans = await plansOf((tx) => ({
      copied: platformEventWithRead(tx, 'idp.event_copied', { event: 'user:77:1', org: 'none' }),
      copiedAnywhere: platformEventWithRead(tx, 'idp.event_copied', { event: 'user:77:1' }),
      cursor: latestPlatformTimeRead(tx, 'idp.event_copied', 'at'),
      restriction: latestPlatformTimeOfRead(tx, 'at', [
        { ...removed, facts: { person: 'p-7' } },
        { action: 'idp.event_copied', facts: { person: 'p-7', counts: 'yes' } },
        { action: 'person.second_factors_removed', facts: { person: 'p-7' } },
        { ...removed, facts: { subject: 's-7' } },
      ]),
    }));

    for (const plan of Object.values(plans)) {
      expect(plan.map((node) => node['Node Type'])).not.toContain('Seq Scan');
      expect(indexesOf(plan)).not.toContain('audit_events_by_action');
    }
    expect(indexesOf(plans.copied)).toEqual(['audit_events_by_event']);
    expect(indexesOf(plans.copiedAnywhere)).toEqual(['audit_events_by_event']);
    expect(plans.cursor).toEqual([
      expect.objectContaining({
        'Node Type': 'Index Scan',
        'Scan Direction': 'Backward',
        'Index Name': 'audit_events_by_at',
      }),
    ]);
    // The copies by person and by login from their indexes; the resets (none here) by any index's action alone.
    expect(indexesOf(plans.restriction)).toEqual(
      expect.arrayContaining(['audit_events_by_person', 'audit_events_by_subject']) as unknown,
    );
  });

  it('answers as before through the indexes: the latest time copied, and an event copied or not', async () => {
    const record = (event: string, at: string) =>
      chain.recordAlone(app, { actor: ACTOR, action: 'kind.indexed', details: { event, org: 'none', at } });
    await record('e-9', '2026-09-29T10:00:00.000Z');
    await record('e-10', '2026-09-29T09:59:59.999Z');

    expect(await latestPlatformTime(app, 'kind.indexed', 'at')).toEqual(new Date('2026-09-29T10:00:00.000Z'));
    expect(await platformEventWith(app, 'kind.indexed', { event: 'e-10' })).toBe(true);
    expect(await platformEventWith(app, 'kind.indexed', { event: 'e-1' })).toBe(false);
  });
});

describe(`the latest time among the chain's events matching any of several kinds (B6-3d, Postgres ${server.version})`, () => {
  const record = (action: string, details: Record<string, string>) =>
    chain.recordAlone(app, { actor: ACTOR, action, details });

  it('reads the latest time among the events each kind matches: its action, its facts, one of, none of', async () => {
    await record('kind.one', { person: 'p-1', type: 'a', by: 'other', at: '2026-09-28T01:00:00.000Z' });
    await record('kind.one', { person: 'p-1', type: 'b', by: 'system', at: '2026-09-28T02:00:00.000Z' });
    // Not one of the types, by the one excluded, another person's, another action's: none counts.
    await record('kind.one', { person: 'p-1', type: 'c', by: 'other', at: '2026-09-28T09:00:00.000Z' });
    await record('kind.one', { person: 'p-1', type: 'a', by: 'self', at: '2026-09-28T09:00:00.000Z' });
    await record('kind.one', { person: 'p-2', type: 'a', by: 'other', at: '2026-09-28T09:00:00.000Z' });
    await record('kind.other', { person: 'p-1', type: 'a', by: 'other', at: '2026-09-28T09:00:00.000Z' });
    const one = { action: 'kind.one', facts: { person: 'p-1' }, oneOf: { type: ['a', 'b'] }, noneOf: { by: ['self'] } };

    expect(await latestPlatformTimeOf(app, 'at', [one])).toEqual(new Date('2026-09-28T02:00:00.000Z'));
    expect(await latestPlatformTimeOf(app, 'at', [{ ...one, oneOf: { type: ['a'] } }])).toEqual(
      new Date('2026-09-28T01:00:00.000Z'),
    );
    expect(await latestPlatformTimeOf(app, 'at', [{ ...one, noneOf: {} }])).toEqual(
      new Date('2026-09-28T09:00:00.000Z'),
    );
  });

  it('takes the latest across the kinds, a kind of another action among them', async () => {
    await record('kind.three', { person: 'p-3', at: '2026-09-28T03:00:00.000Z' });
    await record('kind.four', { person: 'p-3', at: '2026-09-28T04:00:00.000Z' });
    const three = { action: 'kind.three', facts: { person: 'p-3' } };
    const four = { action: 'kind.four', facts: { person: 'p-3' } };

    expect(await latestPlatformTimeOf(app, 'at', [three])).toEqual(new Date('2026-09-28T03:00:00.000Z'));
    expect(await latestPlatformTimeOf(app, 'at', [three, four])).toEqual(new Date('2026-09-28T04:00:00.000Z'));
    expect(await latestPlatformTimeOf(app, 'at', [four, three])).toEqual(new Date('2026-09-28T04:00:00.000Z'));
  });

  it('counts an event without the fact none of the values names, and no event without one of the values', async () => {
    await record('kind.five', { person: 'p-5', at: '2026-09-28T05:00:00.000Z' });

    expect(
      await latestPlatformTimeOf(app, 'at', [
        { action: 'kind.five', facts: { person: 'p-5' }, noneOf: { by: ['self'] } },
      ]),
    ).toEqual(new Date('2026-09-28T05:00:00.000Z'));
    expect(
      await latestPlatformTimeOf(app, 'at', [
        { action: 'kind.five', facts: { person: 'p-5' }, oneOf: { by: ['other'] } },
      ]),
    ).toBeUndefined();
  });

  it('finds no time for no kinds, or for kinds no event matches', async () => {
    expect(await latestPlatformTimeOf(app, 'at', [])).toBeUndefined();
    expect(await latestPlatformTimeOf(app, 'at', [{ action: 'kind.none', facts: {} }])).toBeUndefined();
  });

  it('fails, rather than passes, on a time that isn’t one', async () => {
    await record('kind.six', { person: 'p-6', at: 'not a time' });

    await expect(latestPlatformTimeOf(app, 'at', [{ action: 'kind.six', facts: { person: 'p-6' } }])).rejects.toThrow();
  });
});

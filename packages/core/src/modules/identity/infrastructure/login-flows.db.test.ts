// B2-3a-1: the sign-in flows under way (0011), on the real migrated schema, as the app role.
import { createTestDatabase, FixedClock, type TestDatabase, testLogger } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import {
  createLoginFlows,
  LOGIN_FLOW_SECONDS,
  MOST_OPEN_SIGN_INS_A_NETWORK,
  QUIET_NETWORK_SIGN_INS,
} from './login-flows.ts';
import type { LoginFlow } from './oidc-client.ts';
import type { IdentityTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const START = new Date('2026-09-24T09:00:00Z');
let flows = 0;
/** A flow no other test has: 43-character values, as the OIDC client makes them. */
const newFlow = (): LoginFlow => {
  flows += 1;
  const mark = String(flows).padStart(4, '0');
  return {
    state: `s${mark}${'S'.repeat(38)}`,
    nonce: `n${mark}${'N'.repeat(38)}`,
    verifier: `v${mark}${'V'.repeat(38)}`,
  };
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the sign-in flows under way (Postgres ${server.version})`, () => {
  it('keeps a flow by its ID, and gives it back once', async () => {
    const store = createLoginFlows({ clock: new FixedClock(START) });
    const flow = newFlow();
    const flowId = await store.save(app, flow, '/agents?tab=keys');

    expect(flowId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await store.take(app, flowId)).toEqual({ flow, returnTo: '/agents?tab=keys', startedAt: START });
    expect(await store.take(app, flowId)).toBeUndefined();
  });

  it('B3-3a keeps the step-up challenge a flow was started for, and gives it back with the flow', async () => {
    const store = createLoginFlows({ clock: new FixedClock(START) });
    const flow = newFlow();
    const challengeId = '0199a0f0-0000-7000-8000-0000000000c1';
    const flowId = await store.save(app, flow, '/members/confirm', challengeId);

    expect(await store.take(app, flowId)).toEqual({
      flow,
      returnTo: '/members/confirm',
      stepUpChallengeId: challengeId,
      startedAt: START,
    });
  });

  it('B3-3a refuses a step-up flow naming a challenge that is not a UUID, keeping nothing', async () => {
    const store = createLoginFlows({ clock: new FixedClock(START) });
    const flow = newFlow();
    await expect(store.save(app, flow, '/', 'not-a-uuid')).rejects.toThrow(RangeError);
    expect(
      await app.selectFrom('identity.login_flows').select('state').where('state', '=', flow.state).execute(),
    ).toEqual([]);
  });

  it('keeps only the hash of the flow ID', async () => {
    const store = createLoginFlows({ clock: new FixedClock(START) });
    const flow = newFlow();
    const flowId = await store.save(app, flow, '/');

    const [row] = await app.selectFrom('identity.login_flows').selectAll().where('state', '=', flow.state).execute();
    expect(row?.cookie_hash).toHaveLength(32);
    expect(JSON.stringify(row)).not.toContain(flowId);
  });

  it('gives back nothing after ten minutes, and takes the flow all the same', async () => {
    const clock = new FixedClock(START);
    const store = createLoginFlows({ clock });
    const flow = newFlow();
    const flowId = await store.save(app, flow, '/');
    clock.advanceBy(LOGIN_FLOW_SECONDS * 1000);

    expect(await store.take(app, flowId)).toBeUndefined();
    expect(
      await app.selectFrom('identity.login_flows').select('state').where('state', '=', flow.state).execute(),
    ).toEqual([]);
  });

  it('gives it back just inside its ten minutes', async () => {
    const clock = new FixedClock(START);
    const store = createLoginFlows({ clock });
    const flow = newFlow();
    const flowId = await store.save(app, flow, '/');
    clock.advanceBy(LOGIN_FLOW_SECONDS * 1000 - 1);

    expect(await store.take(app, flowId)).toMatchObject({ flow });
  });

  it('gives back nothing for an ID it never gave, or text that is none, and takes no other flow', async () => {
    const store = createLoginFlows({ clock: new FixedClock(START) });
    const flow = newFlow();
    const flowId = await store.save(app, flow, '/');

    for (const other of ['A'.repeat(43), '', 'A'.repeat(44), `${'A'.repeat(42)}=`, undefined as unknown as string]) {
      expect(await store.take(app, other)).toBeUndefined();
    }
    expect(await store.take(app, flowId)).toMatchObject({ flow });
  });

  it('sweeps flows past their ten minutes, a batch at a time, and leaves the rest', async () => {
    // Later than every other test's flows, so theirs are swept first and this counts only its own.
    const clock = new FixedClock(new Date(START.getTime() + 86_400_000));
    const store = createLoginFlows({ clock });
    await store.sweep(app, 10_000);
    // Whatever other tests left behind is gone, so each count below is this test's own.
    expect(
      await app.selectFrom('identity.login_flows').select('state').where('ends_at', '<=', clock.now()).execute(),
    ).toEqual([]);
    const oldest = newFlow();
    const older = newFlow();
    const fresh = newFlow();
    await store.save(app, oldest, '/');
    clock.advanceBy(1000);
    await store.save(app, older, '/');
    clock.advanceBy(LOGIN_FLOW_SECONDS * 1000 - 1000);
    await store.save(app, fresh, '/');
    const mine = [oldest.state, older.state, fresh.state];
    const left = async () =>
      (
        await app
          .selectFrom('identity.login_flows')
          .select('state')
          .where('state', 'in', mine)
          .orderBy('ends_at')
          .execute()
      ).map((row) => row.state);

    // Only the oldest is past its ten minutes yet.
    expect(await store.sweep(app, 10)).toBe(1);
    expect(await left()).toEqual([older.state, fresh.state]);

    clock.advanceBy(LOGIN_FLOW_SECONDS * 1000);
    await store.save(app, oldest, '/');
    expect(await store.sweep(app, 1)).toBe(1);
    expect(await left()).toHaveLength(2);
    expect(await store.sweep(app, 10)).toBe(1);
    expect(await left()).toEqual([oldest.state]);
  });

  it('refuses a sweep of no flows', async () => {
    const store = createLoginFlows({ clock: new FixedClock(START) });

    for (const most of [0, -1, 1.5, Number.NaN]) {
      await expect(store.sweep(app, most)).rejects.toThrow(RangeError);
    }
  });

  it('refuses to keep a flow that would send the browser elsewhere', async () => {
    const store = createLoginFlows({ clock: new FixedClock(START) });

    await expect(store.save(app, newFlow(), '//evil.example')).rejects.toThrow(RangeError);
  });

  it('never lets the app change a flow', async () => {
    const store = createLoginFlows({ clock: new FixedClock(START) });
    const flow = newFlow();
    await store.save(app, flow, '/');

    await expect(
      app
        .updateTable('identity.login_flows')
        .set({ return_to: '/elsewhere' })
        .where('state', '=', flow.state)
        .execute(),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it("holds a row the module didn't write to the table's own limits", async () => {
    const row = {
      cookie_hash: Buffer.alloc(32, 1),
      state: 'S'.repeat(43),
      nonce: 'N'.repeat(43),
      verifier: 'V'.repeat(43),
      return_to: '/',
      created_at: START,
      ends_at: new Date(START.getTime() + 1000),
    };
    for (const change of [
      { cookie_hash: Buffer.alloc(31, 2) },
      { verifier: 'V'.repeat(42) },
      { verifier: 'V'.repeat(129) },
      { return_to: '' },
      { state: '' },
      { ends_at: START },
      { network_key: '' },
      { network_key: 'n'.repeat(65) },
    ]) {
      await expect(
        app
          .insertInto('identity.login_flows')
          .values({ ...row, ...change })
          .execute(),
      ).rejects.toMatchObject({ code: '23514' });
    }
  });
});

// S206 V8 (0106): anyone can start a sign-in with an anonymous GET, so its flows are held to a cap, every network's
// together and each network's own, as the OAuth flows are. A step-up's flow is never counted. Each test at a time of
// its own, after every other test's flows have ended, so each count is its own.
describe(`the sign-ins under way, held to their caps (S206 V8, Postgres ${server.version})`, () => {
  const openFrom = (network: string) =>
    app
      .selectFrom('identity.login_flows')
      .select(['network_key', 'step_up_challenge_id'])
      .where('network_key', '=', network)
      .execute();

  it(`holds one network to ${String(MOST_OPEN_SIGN_INS_A_NETWORK)} sign-ins under way, keeping none past it`, async () => {
    const clock = new FixedClock(new Date('2027-01-01T09:00:00Z'));
    const store = createLoginFlows({ clock });
    const network = '198.51.100.7';
    for (let open = 1; open < MOST_OPEN_SIGN_INS_A_NETWORK; open += 1) {
      expect(await store.start(app, newFlow(), '/', network)).toMatchObject({ outcome: 'started' });
    }
    // A step-up's flow is never counted: it needs a live session, and a flood of sign-ins must never stop it.
    await store.save(app, newFlow(), '/members/confirm', '0199a0f0-0000-7000-8000-0000000000c2');
    const last = await store.start(app, newFlow(), '/agents', network);
    if (last.outcome !== 'started') throw new Error(`not started: ${last.outcome}`);
    expect(await store.take(app, last.flowId)).toMatchObject({ returnTo: '/agents' });
    // Taken at its callback, its place is free again.
    expect(await store.start(app, newFlow(), '/', network)).toMatchObject({ outcome: 'started' });

    expect(await store.start(app, newFlow(), '/', network)).toEqual({ outcome: 'network_full' });
    expect(await openFrom(network)).toHaveLength(MOST_OPEN_SIGN_INS_A_NETWORK);
    expect((await openFrom(network)).every((row) => row.step_up_challenge_id === null)).toBe(true);
    // Another network is not held by it; a step-up still starts; once its flows end, this one isn't held either.
    expect(await store.start(app, newFlow(), '/', '198.51.100.8')).toMatchObject({ outcome: 'started' });
    await expect(
      store.save(app, newFlow(), '/members/confirm', '0199a0f0-0000-7000-8000-0000000000c3'),
    ).resolves.toMatch(/^[A-Za-z0-9_-]{43}$/);
    clock.advanceBy(LOGIN_FLOW_SECONDS * 1000);
    expect(await store.start(app, newFlow(), '/', network)).toMatchObject({ outcome: 'started' });
  });

  it(`past every network's backstop, still lets a quiet network in and refuses only a busy one: no lockout`, async () => {
    const at = new Date('2027-02-01T09:00:00Z');
    // A backstop of 50 here rather than add MOST_OPEN_SIGN_INS rows: the rule is the same at any size.
    const store = createLoginFlows({ clock: new FixedClock(at), mostOpen: 50 });
    const admin = database.as('admin');
    // Each from a network of its own, as a crowd filling the table would be. Beside them, step-ups' flows, never
    // counted: were they, the busy network's fourth below would be refused too.
    const added = (count: number, stepUp: boolean) =>
      admin.query(
        `insert into identity.login_flows
           (cookie_hash, state, nonce, verifier, return_to, created_at, ends_at, network_key, step_up_challenge_id)
         select pg_catalog.sha256(('s206-v8-' || $4::text || n)::bytea), 'S', 'N', pg_catalog.repeat('V', 43), '/',
           $1, $2, 'net-' || n,
           case when $4::boolean then ('0199a0f0-0000-7000-8000-' || pg_catalog.lpad(n::text, 12, '0'))::uuid end
         from pg_catalog.generate_series(1, $3::int) as n`,
        [at, new Date(at.getTime() + 1000), count, stepUp],
      );
    await added(46, false);
    await added(5, true);
    const busy = '203.0.113.9';
    const start = (network: string) => store.start(app, newFlow(), '/', network);
    try {
      // Under the backstop, the busy network's first four start (50 under way after the fourth).
      for (let open = 0; open < QUIET_NETWORK_SIGN_INS + 1; open += 1) {
        expect(await start(busy)).toMatchObject({ outcome: 'started' });
      }
      // At it, the busy network is refused, keeping nothing more,
      expect(await start(busy)).toEqual({ outcome: 'full' });
      expect(await openFrom(busy)).toHaveLength(QUIET_NETWORK_SIGN_INS + 1);
      // while a quiet one is let in, up to its few, and only then refused.
      const quiet = '203.0.113.10';
      for (let open = 0; open < QUIET_NETWORK_SIGN_INS; open += 1) {
        expect(await start(quiet)).toMatchObject({ outcome: 'started' });
      }
      expect(await start(quiet)).toEqual({ outcome: 'full' });
      // Ended, they hold nothing: the backstop counts only the sign-ins under way.
      const later = createLoginFlows({ clock: new FixedClock(new Date(at.getTime() + 1000)), mostOpen: 50 });
      expect(await later.start(app, newFlow(), '/', busy)).toMatchObject({ outcome: 'started' });
    } finally {
      await admin.query("delete from identity.login_flows where network_key like 'net-%' or created_at = $1", [at]);
    }
  });

  it('counts the sign-ins under way from the partial indexes alone, never reading the rows', async () => {
    // One connection, so its settings hold for its plans: no scan of the table, nor a bitmap over it, to fall back on.
    const client = await database.connect('app');
    const planOf = async (explained: Promise<{ readonly 'QUERY PLAN': string }[]>) =>
      (await explained).map((row) => row['QUERY PLAN']).join(' ');
    try {
      await client.query('set enable_seqscan = off');
      await client.query('set enable_bitmapscan = off');
      // As login-flows.ts counts them: every network's, then one network's.
      expect(
        await planOf(
          client.query(
            `explain select pg_catalog.count(*) from (select 1 from identity.login_flows
               where ends_at > now() and step_up_challenge_id is null limit 100) as open`,
          ),
        ),
      ).toMatch(/Index Only Scan using login_flows_(sign_ins_open|by_network)/);
      expect(
        await planOf(
          client.query(
            `explain select pg_catalog.count(*) from (select 1 from identity.login_flows
               where ends_at > now() and step_up_challenge_id is null and network_key = $1 limit 100) as open`,
            ['203.0.113.9'],
          ),
        ),
      ).toMatch(/Index Only Scan using login_flows_by_network/);
    } finally {
      await client.end();
    }
  });
});

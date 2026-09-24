// B2-3a-1: the sign-in flows under way (0011), on the real migrated schema, as the app role.
import { createTestDatabase, FixedClock, LogCapture, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLoginFlows, LOGIN_FLOW_SECONDS } from './login-flows.ts';
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
  app = createDatabase<IdentityTables>(
    { ...database.connection('app'), maxConnections: 2 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
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
    expect(await store.take(app, flowId)).toEqual({ flow, returnTo: '/agents?tab=keys' });
    expect(await store.take(app, flowId)).toBeUndefined();
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

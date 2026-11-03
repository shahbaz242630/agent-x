// The anchor check's lanes on the real schema (4D2e E6): an organisation whose hold
// is locked out holds its own lane, and no other organisation's check, anchor or
// durable write, while real chains are read on real connections.
import { createAuditTrail, holdOrganisation, type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createAnchorLog } from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createFakeWriteOnceStore,
  createTestDatabase,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import { type OrganisationChains, createAnchorCheck } from './anchor-check.ts';

const server = inject('postgres');
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe600_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const clock = { now: () => new Date() };

let database: TestDatabase;
let app: Database<AuditTables & OrganizationsTables>;
const organisations: string[] = [];

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<AuditTables & OrganizationsTables>(
    { ...database.connection('app'), maxConnections: 8 },
    testLogger(),
  );
  for (let index = 0; index < 8; index += 1) {
    const id = ids.next();
    organisations.push(id);
    await withSignedStates(app, id, { keys, ids, logger: testLogger() }, (tx, states) =>
      createOrganization(tx, states, { id, name: `Acme ${String(index)} LLC`, actor: OPERATOR }),
    );
  }
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`one organisation locked out holds no one else (Postgres ${server.version})`, () => {
  it('its hold waits behind a held lock, while every other organisation is checked, anchored and written', async () => {
    const [locked = '', ...rest] = organisations;
    const capture = new LogCapture();
    const logger = testLogger(capture);
    const trail = createAuditTrail({ keys, ids });
    const organizations: OrganisationChains = {
      list: () => Promise.resolve(organisations),
      recorded: () => Promise.resolve(organisations),
      // The locked one's chain reads as failed, so its turn goes on to its hold, as a tampered chain's would.
      verify: (orgId, anchor) =>
        orgId === locked
          ? Promise.resolve({ ok: false, problem: { reason: 'hash', seq: 1n } })
          : trail.verifyAlone(app, orgId, anchor),
      hold: (orgId, failure) => holdOrganisation(app, orgId, { keys, ids, logger }, failure),
    };
    const fake = createFakeWriteOnceStore();
    const durable = createAnchorLog({
      store: fake.store,
      keys,
      logger,
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 600_000,
    });
    const check = createAnchorCheck({
      chains: [],
      organizations,
      keys,
      clock,
      logger,
      staleAfterMs: 600_000,
      deadlineMs: 30_000,
      durable,
      lanes: 2,
      writeEveryMs: 20,
    });

    // The lock a hold's event waits behind: its chain's head, in a transaction left open.
    const holder = await database.connect('owner');
    await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [locked]);
    await holder.query('begin');
    await holder.query('select org_id from audit.heads where org_id = $1 for update', [locked]);

    const running = check.run();
    await waitUntilQueued(database.as('admin'), 1);
    await vi.waitFor(() => {
      for (const orgId of rest) expect(durable.latest({ kind: 'organisation', orgId })?.seq).toBeGreaterThan(0n);
    });
    // Written too, while the hold still waits: on the store's own list, not only in memory.
    await vi.waitFor(() => {
      expect(fake.files.size).toBeGreaterThan(0);
    });
    expect(capture.lines().filter((line) => line.event === 'audit.anchor_check_done')).toEqual([]);
    expect(await waitUntilQueued(database.as('admin'), 1)).toHaveLength(1);

    await holder.query('commit');
    await holder.end();
    await running;
    const done = capture.lines().filter((line) => line.event === 'audit.anchor_check_done');
    expect(done).toEqual([expect.objectContaining({ anchored: rest.length, failed: 1, left: 0 })]);
    const held = await withSignedStates(app, locked, { keys, ids, logger: testLogger() }, (tx, states) =>
      states.holdRecord(tx, locked),
    );
    expect(held).toMatchObject({ outcome: 'held' });
    // No anchor for the one that failed.
    expect(durable.latest({ kind: 'organisation', orgId: locked })).toBeUndefined();
  });
});

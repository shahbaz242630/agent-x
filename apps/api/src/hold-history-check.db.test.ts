// The whole history checked while an integrity hold stands (Phase 2 D1c), on
// the real migrated schema, as the app role: a stand-in growing table (built
// as a module builds one, with `liveStatuses`), its rows sealed as a module
// seals them, and the database's owner as the attacker. The job checks a held
// organisation's every row, ended ones too, a batch at a time across runs,
// and records it once whole; a record tampered with starts it again; a CLEAR
// organisation, or one already checked, is left alone.
import { type CheckedTable, withSignedStates } from '@agentx/core/modules/audit';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHoldHistoryCheck } from './hold-history-check.ts';
import type { UseCaseTables } from './use-case-work.ts';

/** A stand-in growing table: a status sealed, checked at clearing in its LIVE rows alone. */
const REQUESTS = {
  table: 'probe.requests',
  subject: 'spend_request',
  fields: [{ column: 'status', type: 'text' }],
  liveStatuses: ['LIVE'],
} as const satisfies CheckedTable;

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  'grant usage on schema probe to agentx_app',
  'create table probe.requests (org_id uuid not null, id uuid not null, status text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))',
  'alter table probe.requests enable row level security',
  'alter table probe.requests force row level security',
  `create policy tenant_isolation on probe.requests ${TENANT_POLICY}`,
  'grant select, insert on probe.requests to agentx_app',
  'grant update (status, state_version, state_event_id) on probe.requests to agentx_app',
];

type Tables = UseCaseTables &
  OrganizationsTables & {
    'probe.requests': { org_id: string; id: string; status: string; state_version?: number; state_event_id?: string };
  };

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xd1c0_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const services = () => ({ keys, ids, logger: testLogger() });

let capture: LogCapture;
let org: string;
let owner: OwnerTamper;

/** Adds a request in the status given and seals it, as a module does. */
async function request(status: 'LIVE' | 'ENDED'): Promise<string> {
  const id = ids.next();
  await withSignedStates(app, org, services(), async (tx, states) => {
    await tx.insertInto('probe.requests').values({ org_id: org, id, status }).execute();
    await states.record(
      tx,
      REQUESTS,
      { orgId: org, id },
      'new',
      { status },
      {
        actor: OPERATOR,
        action: 'spend_request.created',
        details: {},
      },
    );
  });
  return id;
}

/** A request changed past the app and read, then put back: the organisation HELD, its cause removed. */
async function held(): Promise<string> {
  const id = await request('ENDED');
  const saved = await owner.saveRow(id);
  await owner.setColumn(id, 'status', 'LIVE');
  await withSignedStates(app, org, services(), (tx, states) =>
    states.verifiedState(tx, REQUESTS, { orgId: org, id }, 'share'),
  );
  await owner.restoreRow(saved);
  return id;
}

const holdNow = () => withSignedStates(app, org, services(), (tx, states) => states.holdRecord(tx, org));

const checked = async () => {
  const now = await holdNow();
  if (now.outcome !== 'held') return 'not held';
  return withSignedStates(app, org, services(), (tx, states) => states.historyChecked(tx, org, now.eventId));
};

const job = (batch = 2, batchesARun = 1, tables: readonly CheckedTable[] = [REQUESTS]) =>
  createHoldHistoryCheck({
    list: () => Promise.resolve([org]),
    database: app,
    keys,
    ids,
    logger: testLogger(capture),
    tables,
    batch,
    batchesARun,
  });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  owner = await tamperAsOwner(database, REQUESTS, org);
});

afterEach(async () => {
  await owner.end();
});

describe(`the whole history checked while a hold stands (Phase 2 D1c, Postgres ${server.version})`, () => {
  it('checks every row, ended ones too, a batch at a time across runs, and records it once whole', async () => {
    await request('LIVE');
    await request('ENDED');
    await held();
    await request('ENDED');
    const checking = job();

    // Four rows, two a batch, one batch a run: the second run takes the last of them.
    await checking.run();
    expect(await checked()).toBe('unchecked');
    await checking.run();

    expect(await checked()).toBe('checked');
    expect(lines('hold_history.checked')).toEqual([expect.objectContaining({ objects: 4 })]);
    // Checked already: a later run records nothing more.
    await checking.run();
    expect(lines('hold_history.checked')).toHaveLength(1);
  });

  it('starts again from the beginning when a batch finds a record tampered with, and records nothing till it is whole', async () => {
    const first = await request('ENDED');
    await held();
    const saved = await owner.saveRow(first);
    await owner.setColumn(first, 'status', 'GONE');
    const checking = job(10);

    await checking.run();
    expect(await checked()).toBe('unchecked');
    expect(lines('hold_history.tampered')).toEqual([
      expect.objectContaining({ subjectType: 'spend_request', findings: 1 }),
    ]);

    await owner.restoreRow(saved);
    await checking.run();
    expect(await checked()).toBe('checked');
  });

  it('finds a row deleted from the log, and keeps the hold unchecked', async () => {
    await held();
    const gone = await request('ENDED');
    await owner.deleteRow(gone);

    await job(10).run();

    expect(await checked()).toBe('unchecked');
    expect(lines('hold_history.tampered')).toHaveLength(1);
  });

  it('leaves a CLEAR organisation alone', async () => {
    await request('ENDED');

    await job(10).run();

    expect(await holdNow()).toMatchObject({ outcome: 'clear' });
    expect(lines('hold_history.checked')).toEqual([]);
  });

  it('stops when told to, and goes on from where it got to', async () => {
    await request('ENDED');
    await request('ENDED');
    await held();
    const checking = job(1, 1);
    const stop = new AbortController();
    stop.abort();

    await checking.run(stop.signal);
    expect(await checked()).toBe('unchecked');
    for (let run = 0; run < 4; run += 1) await checking.run();

    expect(await checked()).toBe('checked');
    expect(lines('hold_history.checked')).toEqual([expect.objectContaining({ objects: 3 })]);
  });

  it('does nothing when no table grows', async () => {
    await held();

    await job(10, 1, []).run();

    expect(await checked()).toBe('unchecked');
  });
});

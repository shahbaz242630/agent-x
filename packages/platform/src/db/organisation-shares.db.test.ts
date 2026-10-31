// Each organisation's share of the connections (PL-63), against a real Postgres:
// past its share only that organisation waits, holding no connection, and another
// goes straight on, whatever the first is holding.
import { createTestDatabase, LogCapture, type TestDatabase, testLogger } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';
import { OrganisationBusy } from './organisation-shares.ts';
import { noStatementTimes, timingStatements } from './statement-times.ts';
import { limitedTransaction, withTenant } from './tenant.ts';

const ORG_A = '0199a000-0000-7000-8000-00000000000a';
const ORG_B = '0199a000-0000-7000-8000-00000000000b';
const server = inject('postgres');
let database: TestDatabase;
let logs: LogCapture;
let db: Kysely<unknown>;

/** A transaction of the organisation's, held open until let go: it has taken its place, and a connection, once `open` settles. */
function held(orgId: string, options?: { readonly unshared?: boolean }) {
  const { promise: letGo, resolve: release } = Promise.withResolvers<undefined>();
  const { promise: open, resolve: opened } = Promise.withResolvers<undefined>();
  const ended = withTenant(
    db,
    orgId,
    async () => {
      opened(undefined);
      await letGo;
    },
    options,
  );
  return { open, ended, release: () => void release(undefined) };
}

const answerOf = (orgId: string) =>
  withTenant(db, orgId, async (tx) => (await sql<{ one: number }>`select 1 as one`.execute(tx)).rows[0]?.one);

/** Lets the wait begin: long enough for an uncontested transaction to have opened. */
const aMoment = () => new Promise((resolve) => setTimeout(resolve, 200));

/** Whether a promise has settled yet. */
const settled = (promise: Promise<unknown>) =>
  Promise.race([promise.then(() => true), new Promise<boolean>((resolve) => setImmediate(() => resolve(false)))]);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  logs = new LogCapture();
  db = createDatabase(
    { ...database.connection('admin'), applicationName: 'shares', maxConnections: 4, organisationShare: 1 },
    testLogger(logs),
  );
});

afterAll(async () => {
  await db.destroy();
  await database.drop();
});

describe('an organisation past its share of the connections', () => {
  it('waits, while another organisation goes straight on, and takes its turn when one ends', async () => {
    const first = held(ORG_A);
    await first.open;
    const second = answerOf(ORG_A);
    await aMoment();
    expect(await settled(second)).toBe(false);

    await expect(answerOf(ORG_B)).resolves.toBe(1);
    expect(await settled(second)).toBe(false);

    first.release();
    await first.ended;
    await expect(second).resolves.toBe(1);
  });

  it('holds no connection while it waits, so it can never fill the pool', async () => {
    const first = held(ORG_A);
    await first.open;
    const waiting = Array.from({ length: 10 }, () => answerOf(ORG_A));
    await aMoment();
    // Four connections: one held, and three still free for three other organisations' at once.
    const others = held(ORG_B);
    await others.open;
    await expect(limitedTransaction(db, async () => 'free')).resolves.toBe('free');
    others.release();
    await others.ended;
    first.release();
    await first.ended;
    await expect(Promise.all(waiting)).resolves.toEqual(Array.from({ length: 10 }, () => 1));
  });

  it(
    'is answered busy past its bound, nothing begun, says so in the log, and gets its place back',
    { timeout: 30_000 },
    async () => {
      const first = held(ORG_A);
      await first.open;
      const before = logs.lines().length;
      await expect(answerOf(ORG_A)).rejects.toBeInstanceOf(OrganisationBusy);
      const said = logs.lines().slice(before);
      expect(said).toEqual([
        expect.objectContaining({ event: 'db.organisation_busy', orgId: ORG_A, waitedMs: 10_000 }),
      ]);
      first.release();
      await first.ended;
      await expect(answerOf(ORG_A)).resolves.toBe(1);
    },
  );

  it('gets its place back when its transaction fails', async () => {
    await expect(
      withTenant(db, ORG_A, () => {
        throw new Error('the work failed');
      }),
    ).rejects.toThrow('the work failed');
    await expect(answerOf(ORG_A)).resolves.toBe(1);
  });

  it('counts the wait as the wait for a connection', async () => {
    const first = held(ORG_A);
    await first.open;
    const times = noStatementTimes();
    const second = timingStatements(times, () => answerOf(ORG_A));
    await aMoment();
    first.release();
    await first.ended;
    await second;
    expect(times.poolWaitMs).toBeGreaterThan(100);
  });

  it('never makes an integrity hold’s transaction wait its turn', async () => {
    const first = held(ORG_A);
    await first.open;
    const hold = held(ORG_A, { unshared: true });
    await hold.open;
    hold.release();
    await hold.ended;
    first.release();
    await first.ended;
  });

  it('never makes a transaction begun inside its work wait on its own share', async () => {
    await expect(withTenant(db, ORG_A, () => limitedTransaction(db, async () => 'inside'))).resolves.toBe('inside');
  });
});

describe('a database with no share set', () => {
  it('lets one organisation hold as many as the pool has, as a job’s and a test’s do', async () => {
    const plain = createDatabase(
      { ...database.connection('admin'), applicationName: 'no-shares', maxConnections: 3 },
      testLogger(new LogCapture()),
    );
    try {
      const { promise: letGo, resolve } = Promise.withResolvers<undefined>();
      const all = Array.from({ length: 3 }, () => withTenant(plain, ORG_A, () => letGo));
      await aMoment();
      const { rows } = await sql<{ n: string }>`
        select pg_catalog.count(*) as n from pg_catalog.pg_stat_activity
        where application_name = 'no-shares' and state = 'idle in transaction'
      `.execute(db);
      expect(Number(rows[0]?.n)).toBe(3);
      resolve(undefined);
      await Promise.all(all);
    } finally {
      await plain.destroy();
    }
  });
});

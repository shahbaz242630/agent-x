// Each organisation's share of the connections (PL-63), against a real Postgres:
// past its share only that organisation's agents wait, holding no connection, and
// another goes straight on, as do its own people and jobs, whatever is held.
import { createTestDatabase, LogCapture, type TestDatabase, testLogger } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';
import { asAgentTraffic, OrganisationBusy } from './organisation-shares.ts';
import { noStatementTimes, timingStatements } from './statement-times.ts';
import { withTenant } from './tenant.ts';

const ORG_A = '0199a000-0000-7000-8000-00000000000a';
const ORG_B = '0199a000-0000-7000-8000-00000000000b';
const server = inject('postgres');
let database: TestDatabase;
let logs: LogCapture;
let db: Kysely<unknown>;

/** An agent's transaction, held open until let go: it has taken its place, and a connection, once `open` settles. */
function held(orgId: string, options?: { readonly unshared?: boolean }) {
  const { promise: letGo, resolve: release } = Promise.withResolvers<undefined>();
  const { promise: open, resolve: opened } = Promise.withResolvers<undefined>();
  const ended = asAgentTraffic(() =>
    withTenant(
      db,
      orgId,
      async () => {
        opened(undefined);
        await letGo;
      },
      options,
    ),
  );
  return {
    open,
    ended,
    release: () => {
      release(undefined);
    },
  };
}

const answerIn = (orgId: string) =>
  withTenant(db, orgId, async (tx) => (await sql<{ one: number }>`select 1 as one`.execute(tx)).rows[0]?.one);

/** An agent's request's answer. */
const agentsAnswer = (orgId: string) => asAgentTraffic(() => answerIn(orgId));

/** Lets the wait begin: long enough for an uncontested transaction to have opened. */
const aMoment = () => new Promise((resolve) => setTimeout(resolve, 200));

/** Whether a promise has settled yet. */
const settled = (promise: Promise<unknown>) =>
  Promise.race([
    promise.then(() => true),
    new Promise<boolean>((resolve) => {
      setImmediate(() => {
        resolve(false);
      });
    }),
  ]);

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

describe('agents of an organisation past its share of the connections', () => {
  it('wait, while another organisation’s go straight on, and take their turn when one ends', async () => {
    const first = held(ORG_A);
    await first.open;
    const second = agentsAnswer(ORG_A);
    await aMoment();
    expect(await settled(second)).toBe(false);

    await expect(agentsAnswer(ORG_B)).resolves.toBe(1);
    expect(await settled(second)).toBe(false);

    first.release();
    await first.ended;
    await expect(second).resolves.toBe(1);
  });

  it('never hold up the organisation’s own people or background jobs, who count against no share', async () => {
    const first = held(ORG_A);
    await first.open;
    await expect(answerIn(ORG_A)).resolves.toBe(1);
    first.release();
    await first.ended;
  });

  it('hold no connection while they wait, so they can never fill the pool', async () => {
    const first = held(ORG_A);
    await first.open;
    const waiting = Array.from({ length: 10 }, () => agentsAnswer(ORG_A));
    await aMoment();
    // Four connections, one held: three others' at once, each needing one, so none of the ten waiting holds any.
    const others = await Promise.all(
      Array.from({ length: 3 }, async () => {
        const open = Promise.withResolvers<undefined>();
        const letGo = Promise.withResolvers<undefined>();
        const ended = withTenant(db, ORG_B, async () => {
          open.resolve(undefined);
          await letGo.promise;
        });
        await open.promise;
        return { ended, release: letGo.resolve };
      }),
    );
    for (const other of others) other.release(undefined);
    await Promise.all(others.map(({ ended }) => ended));
    first.release();
    await first.ended;
    await expect(Promise.all(waiting)).resolves.toEqual(Array.from({ length: 10 }, () => 1));
  });

  it('are answered busy past the bound, said in the log, and get their place back', { timeout: 30_000 }, async () => {
    const first = held(ORG_A);
    await first.open;
    const before = logs.lines().length;
    await expect(agentsAnswer(ORG_A)).rejects.toBeInstanceOf(OrganisationBusy);
    expect(logs.lines().slice(before)).toEqual([
      expect.objectContaining({ event: 'db.organisation_busy', orgId: ORG_A, waitedMs: 10_000 }),
    ]);
    first.release();
    await first.ended;
    await expect(agentsAnswer(ORG_A)).resolves.toBe(1);
  });

  it('get their place back when a transaction fails', async () => {
    await expect(
      asAgentTraffic(() =>
        withTenant(db, ORG_A, () => {
          throw new Error('the work failed');
        }),
      ),
    ).rejects.toThrow('the work failed');
    await expect(agentsAnswer(ORG_A)).resolves.toBe(1);
  });

  it('get their place back when no connection can be made', { timeout: 30_000 }, async () => {
    const unreachable = createDatabase(
      { ...database.connection('admin'), host: '127.0.0.1', port: 1, applicationName: 'x', organisationShare: 1 },
      testLogger(new LogCapture()),
    );
    try {
      const attempt = () => asAgentTraffic(() => withTenant(unreachable, ORG_A, () => Promise.resolve()));
      // A place kept would make the second wait out the share and answer busy, not the connection's own error.
      await expect(attempt()).rejects.not.toBeInstanceOf(OrganisationBusy);
      await expect(attempt()).rejects.not.toBeInstanceOf(OrganisationBusy);
    } finally {
      await unreachable.destroy();
    }
  });

  it('count the wait as the wait for a connection', async () => {
    const first = held(ORG_A);
    await first.open;
    const times = noStatementTimes();
    const second = timingStatements(times, () => agentsAnswer(ORG_A));
    await aMoment();
    first.release();
    await first.ended;
    await second;
    expect(times.poolWaitMs).toBeGreaterThan(100);
  });

  it('never make an integrity hold’s or activity row’s transaction wait its turn', async () => {
    const first = held(ORG_A);
    await first.open;
    const hold = held(ORG_A, { unshared: true });
    await hold.open;
    hold.release();
    await hold.ended;
    first.release();
    await first.ended;
  });

  it('never wait on their own share from inside their own transaction', async () => {
    const inside = asAgentTraffic(() =>
      withTenant(db, ORG_A, async () => {
        const { rows } = await sql<{ two: number }>`select 2 as two`.execute(db);
        const row = await db.transaction().execute(async (tx) => sql<{ three: number }>`select 3 as three`.execute(tx));
        return [rows[0]?.two, row.rows[0]?.three];
      }),
    );
    await expect(inside).resolves.toEqual([2, 3]);
  });
});

describe('a database with no share set', () => {
  it('lets one organisation’s agents hold as many as the pool has, as a job’s and a test’s do', async () => {
    const plain = createDatabase(
      { ...database.connection('admin'), applicationName: 'no-shares', maxConnections: 3 },
      testLogger(new LogCapture()),
    );
    try {
      const { promise: letGo, resolve } = Promise.withResolvers<undefined>();
      const opens = Array.from({ length: 3 }, () => Promise.withResolvers<undefined>());
      const all = opens.map((open) =>
        asAgentTraffic(() =>
          withTenant(plain, ORG_A, async () => {
            open.resolve(undefined);
            await letGo;
          }),
        ),
      );
      await Promise.all(opens.map(({ promise }) => promise));
      resolve(undefined);
      await Promise.all(all);
    } finally {
      await plain.destroy();
    }
  });
});

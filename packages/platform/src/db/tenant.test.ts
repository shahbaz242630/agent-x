import { LogCapture, testLogger } from '@agentx/testing';
import {
  DummyDriver,
  Kysely,
  PostgresAdapter,
  PostgresIntrospector,
  PostgresQueryCompiler,
  sql,
  type Transaction,
} from 'kysely';
import type pg from 'pg';
import { describe, expect, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { PINNED_SEARCH_PATH_VALUE } from './search-path.ts';
import { limitedTransaction, TenantContextError, tenantCheckedDialect, withTenant } from './tenant.ts';

/** What a sound connection reports: the pin poolConfig puts in the startup packet. */
const PINNED = PINNED_SEARCH_PATH_VALUE;

const ORG = '0199a000-0000-7000-8000-00000000000a';

const CHECK =
  "select pg_catalog.current_setting('app.org_id', true) as org_id, pg_catalog.current_setting('search_path', true) as search_path";

interface Stand {
  readonly client: pg.PoolClient;
  /** Each round trip's text, in order. */
  readonly sent: string[];
  readonly released: unknown[];
}

/**
 * A stand-in connection that reports `tenant` and `searchPath` to its check,
 * reads back `setBack` (by default what it was given) at a transaction's
 * start, and refuses the commit's read-back with `commitRefusal`. The search path
 * defaults to the pinned one, so each test names only the fault it is about.
 */
function connection(
  tenant: string | null | Error,
  {
    searchPath = PINNED,
    setBack,
    commitRefusal,
  }: { searchPath?: string | null; setBack?: string; commitRefusal?: Error } = {},
): Stand {
  const sent: string[] = [];
  const released: unknown[] = [];
  const state = { org_id: tenant, search_path: searchPath };
  const query = (text: string): Promise<unknown> => {
    sent.push(text);
    if (tenant instanceof Error) return Promise.reject(tenant);
    if (text === CHECK) return Promise.resolve({ command: 'SELECT', rows: [state] });
    if (text.startsWith('select 1 / ')) {
      return commitRefusal
        ? Promise.reject(commitRefusal)
        : Promise.resolve([
            { command: 'SELECT', rows: [{ unchanged: 1 }] },
            { command: 'COMMIT', rows: [] },
          ]);
    }
    if (text.includes('; ')) {
      const given = /'app\.org_id', '([^']*)'/.exec(text)?.[1];
      return Promise.resolve([
        { command: 'START', rows: [] },
        { command: 'SELECT', rows: [state] },
        { command: 'SELECT', rows: [{ org_id: setBack ?? given }] },
      ]);
    }
    return Promise.resolve({ command: text.split(' ')[0]?.toUpperCase(), rowCount: 1, rows: [{ answer: 1 }] });
  };
  const client = {
    query,
    release: (how?: unknown) => {
      released.push(how);
    },
  };
  return { client: client as unknown as pg.PoolClient, sent, released };
}

/** A stand-in pool that hands out the given connections in turn. */
function poolOf(...stands: Stand[]): { pool: pg.Pool; ended: () => boolean } {
  let ended = false;
  const queue = stands.map((each) => each.client);
  const pool = {
    options: { max: 3 },
    connect: () => {
      const next = queue.shift();
      return next === undefined ? Promise.reject(new Error('no connections left')) : Promise.resolve(next);
    },
    end: () => {
      ended = true;
      return Promise.resolve();
    },
  };
  return { pool: pool as unknown as pg.Pool, ended: () => ended };
}

function logger(): { capture: LogCapture; logger: ReturnType<typeof createLogger> } {
  const capture = new LogCapture();
  return { capture, logger: testLogger(capture) };
}

/** A database over the stand-in connections, `attempts` tries each. */
function databaseOf(attempts: number, log: ReturnType<typeof logger>, ...stands: Stand[]): Kysely<unknown> {
  return new Kysely<unknown>({ dialect: tenantCheckedDialect(poolOf(...stands).pool, log.logger, attempts) });
}

const one = (db: Kysely<unknown> | Transaction<unknown>) => sql`select 1 as answer`.execute(db);

describe('SEC-TEN-06 every connection is checked before its first statement', () => {
  it('runs the statement on a connection with no tenant, whether the setting is missing or empty', async () => {
    for (const tenant of [null, '']) {
      const clean = connection(tenant);
      const log = logger();
      expect((await one(databaseOf(3, log, clean))).rows).toEqual([{ answer: 1 }]);
      expect(clean.sent).toEqual([CHECK, 'select 1 as answer']);
      expect(clean.released).toEqual([undefined]);
      expect(log.capture.lines()).toEqual([]);
    }
  });

  it('closes a connection left with a tenant, logs it without the tenant, and uses the next', async () => {
    const poisoned = connection(ORG);
    const clean = connection(null);
    const log = logger();

    await one(databaseOf(3, log, poisoned, clean));
    expect(poisoned.sent).toEqual([CHECK]);
    expect(poisoned.released).toEqual([true]);
    expect(clean.sent).toEqual([CHECK, 'select 1 as answer']);
    expect(log.capture.lines()).toMatchObject([{ level: 'error', event: 'db.tenant.leftover_discarded', attempt: 1 }]);
    expect(log.capture.text).not.toContain(ORG);
  });

  it('gives up after the allowed number of tries', async () => {
    const tries = [connection(ORG), connection(ORG), connection(ORG)];

    await expect(one(databaseOf(2, logger(), ...tries))).rejects.toThrow(
      new TenantContextError('no sound connection after 2 tries'),
    );
    expect(tries.map((each) => each.released)).toEqual([[true], [true], []]);
  });

  it.each([
    ['a schema in front of pg_catalog', 'audit,pg_catalog,pg_temp'],
    ['a schema after it', 'pg_catalog,pg_temp,audit'],
    ['pg_temp moved in front, where it shadows type names', 'pg_temp,pg_catalog'],
    ['pg_temp dropped, which puts it in front again', 'pg_catalog'],
    ['the default path', '"$user", public'],
    ['nothing at all', ''],
    ['no setting', null],
    ['the same schemas written differently', 'pg_catalog, pg_temp'],
  ])('closes a connection whose search_path is %s, and uses the next', async (_case, searchPath) => {
    const poisoned = connection(null, { searchPath });
    const clean = connection(null);
    const log = logger();

    await one(databaseOf(3, log, poisoned, clean));
    expect(poisoned.released).toEqual([true]);
    expect(log.capture.lines()).toMatchObject([
      {
        level: 'error',
        event: 'db.tenant.leftover_discarded',
        attempt: 1,
        problem: expect.stringContaining('search_path') as unknown,
      },
    ]);
  });

  it('never echoes the schemas a poisoned search_path names', async () => {
    const log = logger();
    await one(databaseOf(3, log, connection(null, { searchPath: 'planted_schema, pg_catalog' }), connection(null)));
    expect(log.capture.text).not.toContain('planted_schema');
  });

  it('closes a connection whose check fails, and passes the error on', async () => {
    const failure = new Error('connection reset');
    const broken = connection(failure);

    await expect(one(databaseOf(3, logger(), broken))).rejects.toBe(failure);
    expect(broken.released).toEqual([true]);
  });

  it('checks a connection once, however many statements it then runs', async () => {
    const clean = connection(null);
    await databaseOf(3, logger(), clean)
      .connection()
      .execute(async (db) => {
        await one(db);
        await one(db);
      });
    expect(clean.sent).toEqual([CHECK, 'select 1 as answer', 'select 1 as answer']);
  });

  it('ends the pool at shutdown', async () => {
    const stand = poolOf(connection(null));
    const db = new Kysely<unknown>({ dialect: tenantCheckedDialect(stand.pool, logger().logger, 1) });
    // Kysely starts its driver at the first statement, and ends only one it started.
    await one(db);
    await db.destroy();
    expect(stand.ended()).toBe(true);
  });
});

/** withTenant's start: the check and the organisation with the limit, in one round trip. */
const tenantStart = (limit: boolean): string =>
  [
    'start transaction isolation level read committed',
    CHECK,
    `select pg_catalog.set_config('app.org_id', '${ORG}', true) as org_id${limit ? ", pg_catalog.set_config('statement_timeout', '10s', true) as statement_timeout" : ''}`,
  ].join('; ');

describe('4D2d P11: a transaction opens and commits with its checks, a round trip each', () => {
  it("opens withTenant's transaction with the check and the organisation, and commits it after reading it back", async () => {
    for (const limited of [false, true]) {
      const clean = connection(null);
      await withTenant(databaseOf(3, logger(), clean), ORG.toUpperCase(), (tx) => one(tx), { limited });
      expect(clean.sent).toEqual([
        tenantStart(limited),
        'select 1 as answer',
        `select 1 / (case when pg_catalog.lower(pg_catalog.current_setting('app.org_id', true)) is distinct from '${ORG}' then 0 else 1 end) as unchanged; commit`,
      ]);
      expect(clean.released).toEqual([undefined]);
    }
  });

  it('opens on the next connection when the first carries a tenant, and logs it', async () => {
    const poisoned = connection(ORG);
    const clean = connection(null);
    const log = logger();

    await withTenant(databaseOf(3, log, poisoned, clean), ORG, (tx) => one(tx));
    expect(poisoned.sent).toEqual([tenantStart(false)]);
    expect(poisoned.released).toEqual([true]);
    expect(clean.sent[0]).toBe(tenantStart(false));
    expect(log.capture.lines()).toMatchObject([{ event: 'db.tenant.leftover_discarded', attempt: 1 }]);
  });

  it("refuses the work when the start's read-back isn't the organisation, and closes the connection", async () => {
    for (const setBack of ['', '0199b000-0000-7000-8000-00000000000b']) {
      const odd = connection(null, { setBack });
      let ran = false;
      await expect(
        withTenant(databaseOf(3, logger(), odd), ORG, () => {
          ran = true;
          return Promise.resolve();
        }),
      ).rejects.toThrow(new TenantContextError("the organisation setting didn't take"));
      expect(ran).toBe(false);
      expect(odd.sent).toEqual([tenantStart(false)]);
      expect(odd.released).toEqual([true]);
    }
  });

  it("refuses the commit when the commit's read-back says the setting changed, and rolls back", async () => {
    const changed = connection(null, {
      commitRefusal: Object.assign(new Error('division by zero'), { code: '22012' }),
    });
    await expect(withTenant(databaseOf(3, logger(), changed), ORG, (tx) => one(tx))).rejects.toThrow(
      new TenantContextError('the organisation setting changed inside the transaction, so nothing it wrote is kept'),
    );
    expect(changed.sent.at(-1)).toBe('rollback');
  });

  it('passes on any other failure of the commit', async () => {
    const failure = Object.assign(new Error('could not serialize'), { code: '40001' });
    const failing = connection(null, { commitRefusal: failure });

    await expect(withTenant(databaseOf(3, logger(), failing), ORG, (tx) => one(tx))).rejects.toBe(failure);
  });

  it("opens a transaction begun inside withTenant's work as a plain one, with no organisation", async () => {
    const first = connection(null);
    const second = connection(null);
    const db = databaseOf(3, logger(), first, second);
    await withTenant(db, ORG, () => db.transaction().execute((tx) => one(tx)));
    expect(second.sent).toEqual([`begin; ${CHECK}`, 'select 1 as answer', 'commit']);
  });

  it('opens a limited transaction with the check and the limit alone, and commits it plainly', async () => {
    const clean = connection(null);
    await limitedTransaction(databaseOf(3, logger(), clean), (tx) => one(tx));
    expect(clean.sent).toEqual([
      `start transaction isolation level read committed; ${CHECK}; select pg_catalog.set_config('statement_timeout', '10s', true) as statement_timeout`,
      'select 1 as answer',
      'commit',
    ]);
  });
});

/** A database whose driver sends nothing anywhere: Kysely's own stand-in, each statement noted in `seen`. */
const elsewhere = (seen: string[] = []): Kysely<unknown> =>
  new Kysely<unknown>({
    log: (event) => {
      seen.push(event.query.sql);
    },
    dialect: {
      createAdapter: () => new PostgresAdapter(),
      createDriver: () => new DummyDriver(),
      createIntrospector: (db) => new PostgresIntrospector(db),
      createQueryCompiler: () => new PostgresQueryCompiler(),
    },
  });

describe("a database createDatabase didn't make", () => {
  it('runs no tenant work, as it could not set the organisation', async () => {
    let ran = false;
    await expect(
      withTenant(elsewhere(), ORG, () => {
        ran = true;
        return Promise.resolve();
      }),
    ).rejects.toThrow(new TenantContextError("this database can't set an organisation"));
    expect(ran).toBe(false);
  });

  it('still runs a limited transaction, the limit set by a statement of its own', async () => {
    const seen: string[] = [];
    expect(await limitedTransaction(elsewhere(seen), () => Promise.resolve('read'))).toBe('read');
    expect(seen).toEqual(["select pg_catalog.set_config('statement_timeout', $1, true)"]);
  });
});

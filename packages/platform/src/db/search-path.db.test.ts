// A3e: the app's connections look names up in pg_catalog alone, whatever the
// database says.
//
// The database's owner is no superuser and can't set `search_path` on the app's
// role (Postgres wants CREATEROLE and ADMIN for that), but it can set one on
// the database it owns, and every new connection takes that up. With another
// schema in front of pg_catalog, a function or operator planted there stands in
// for one of Postgres's own: the app then reads a different value for the very
// text a state seal is built from (ADR-012 §2), so a tampered row could be made
// to seal alike.
//
// The startup packet's own setting beats a setting on the database or the role,
// so poolConfig pins it there (PINNED_SEARCH_PATH). These tests prove both
// halves on a real server: the attack works without the pin, and doesn't with
// it. Without the second half the first would pass on its own for the wrong
// reason, so the unpinned control is part of the proof, not a curiosity.
import { createTestDatabase, LogCapture, type TestDatabase } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase, PINNED_SEARCH_PATH, poolConfig } from './database.ts';
import { TenantContextError, tenantCheckedPool } from './tenant.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<Record<string, never>>;

/** What the planted stand-in answers, so a shadowed call can't be mistaken for the real one (kept with the statement above). */
const PLANTED_ANSWER = 999;

function testLogger(): { capture: LogCapture; logger: ReturnType<typeof createLogger> } {
  const capture = new LogCapture();
  return {
    capture,
    logger: createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: capture,
    }),
  };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  const admin = database.as('admin');
  // The trap, exactly as the database's owner could lay it: a schema the app
  // may use, a stand-in for a built-in, and the database told to look there
  // first. The database is named through format(%I) inside the server, so the
  // statement this file holds is fixed text (SEC-TEN-07).
  await admin.query('create schema planted');
  await admin.query('grant usage on schema planted to agentx_app');
  await admin.query("create function planted.length(text) returns integer language sql immutable as 'select 999'");
  await admin.query(
    "do $$ begin execute pg_catalog.format('alter database %I set search_path = planted, pg_catalog', pg_catalog.current_database()); end $$",
  );

  app = createDatabase<Record<string, never>>({ ...database.connection('app'), tls: 'disable' }, testLogger().logger);
}, 60_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe('A3e: a planted search_path on the database', () => {
  it('shadows a built-in on a connection that is not pinned (the attack)', async () => {
    // The control: pg's own defaults, which is what the app would have had before A3e.
    const unpinned = new pg.Client({ ...database.connection('app'), ssl: false });
    await unpinned.connect();
    try {
      const { rows } = await unpinned.query<{ answer: number }>("select length('abc') as answer");
      expect(rows[0]?.answer).toBe(PLANTED_ANSWER);
      // SHOW names its own column, so the setting is read as a value instead.
      const path = await unpinned.query<{ path: string }>("select pg_catalog.current_setting('search_path') as path");
      expect(path.rows[0]?.path).toBe('planted, pg_catalog');
    } finally {
      await unpinned.end();
    }
  });

  it('does not reach a pinned connection, so the app still reads the built-in', async () => {
    const answer = await sql<{ answer: number }>`select length('abc') as answer`.execute(app);
    expect(answer.rows[0]?.answer).toBe(3);

    const path = await sql<{ path: string }>`select pg_catalog.current_setting('search_path') as path`.execute(app);
    expect(path.rows[0]?.path).toBe('pg_catalog');
  });

  it('leaves a schema-qualified read working, which is how every one of ours is written', async () => {
    // A table the app role may read. Row security lets no row through without a
    // tenant, which is the point: the read runs, so the pin breaks no query.
    const { rows } = await sql<{ events: string }>`
      select count(*)::text as events from audit.events
    `.execute(app);
    expect(rows[0]?.events).toBe('0');
  });

  it('is pinned for the migration role too, so a migration cannot be poisoned either', async () => {
    const owner = new pg.Client({ ...poolConfig({ ...database.connection('owner'), tls: 'disable' }) });
    await owner.connect();
    try {
      const { rows } = await owner.query<{ answer: number }>("select length('abc') as answer");
      expect(rows[0]?.answer).toBe(3);
    } finally {
      await owner.end();
    }
  });
});

describe('A3e: a connection that lost the pin is refused', () => {
  it('is closed and logged rather than used, and the schemas are never echoed', async () => {
    // A pool built without the pin, so the database's setting reaches it: what
    // the app would face if poolConfig ever stopped pinning.
    const { capture, logger } = testLogger();
    const pool = new pg.Pool({ ...database.connection('app'), ssl: false, max: 2 });
    const guarded = tenantCheckedPool(pool, logger, 2);
    try {
      await expect(guarded.connect()).rejects.toThrow(new TenantContextError('no sound connection after 2 tries'));
      expect(capture.lines()).toMatchObject([
        { event: 'db.tenant.leftover_discarded', problem: expect.stringContaining('search_path') as unknown },
        { event: 'db.tenant.leftover_discarded' },
      ]);
      expect(capture.text).not.toContain('planted');
    } finally {
      await pool.end();
    }
  });

  it('accepts the same pool once the pin is put back', async () => {
    const { logger } = testLogger();
    const pool = new pg.Pool({
      ...database.connection('app'),
      ssl: false,
      max: 2,
      options: PINNED_SEARCH_PATH,
    });
    const guarded = tenantCheckedPool(pool, logger, 2);
    try {
      const client = await guarded.connect();
      client.release();
    } finally {
      await pool.end();
    }
  });
});

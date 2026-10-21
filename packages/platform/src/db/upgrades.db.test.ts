// Migrations that fill rows already there, run as staging and production run
// them: on a database migrated to the one before, holding rows, as the owner
// with no organisation named. The test databases every other test uses start
// empty, so a fill that reaches no rows (a tenant wall binding the owner)
// passes there and fails a real release (S135: 0054's first release).
import { copyFile, mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createTestDatabase, LogCapture, type TestDatabase } from '@agentx/testing';
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { runMigrations } from './migrate.ts';

const REPO_MIGRATIONS = fileURLToPath(new URL('../../../../db/migrations', import.meta.url));
const ORG = '0199a000-0000-7000-8000-0000000000a1';
const AGENT = '0199a000-0000-7000-8000-0000000000b1';

const server = inject('postgres');
let database: TestDatabase;
let folder: string;

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'empty' });
  folder = await mkdtemp(path.join(tmpdir(), 'agentx-upgrades-'));
});

afterEach(async () => {
  await database.drop();
  await rm(folder, { recursive: true, force: true });
});

/** The repository's migrations up to and including `last`, copied into the test's folder, then run as the owner. */
async function migratedTo(last: string): Promise<void> {
  for (const name of (await readdir(REPO_MIGRATIONS)).filter((file) => file.endsWith('.sql')).sort()) {
    if (name > last) break;
    await copyFile(path.join(REPO_MIGRATIONS, name), path.join(folder, name));
  }
  await runMigrations({
    connection: database.connection('owner'),
    directory: folder,
    logger: createLogger({
      service: 'migrate',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
      destination: new LogCapture(),
    }),
  });
}

describe('migrations that fill rows already there', () => {
  it("0054 gives every organisation's kept zone its agent's ID, whatever organisation the owner names", async () => {
    await migratedTo('0053_activity_exports.sql');
    const owner = database.as('owner');
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [ORG]);
    await owner.query(
      "insert into limit_reservations.agent_zones (org_id, agent_id, time_zone, created_at) values ($1, $2, 'Asia/Dubai', now())",
      [ORG, AGENT],
    );
    await owner.query("select pg_catalog.set_config('app.org_id', '', false)");

    await migratedTo('0054_agent_zones_signed.sql');

    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [ORG]);
    expect(
      await owner.query('select id::text, state_version, state_event_id from limit_reservations.agent_zones'),
    ).toEqual([{ id: AGENT, state_version: 1, state_event_id: null }]);
    // The wall is back on the owner too.
    expect(
      await owner.query(
        "select relforcerowsecurity from pg_catalog.pg_class where oid = 'limit_reservations.agent_zones'::regclass",
      ),
    ).toEqual([{ relforcerowsecurity: true }]);
  });
});

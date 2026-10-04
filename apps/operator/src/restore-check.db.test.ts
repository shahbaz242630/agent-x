// S78: the restore drill's check against a real Postgres. The copy is made
// the way a restore makes one: a database cloned from the live one as it was
// (TestDatabase.copy). The check passes a true earlier copy, the live server
// grown on from it included, and fails a copy whose chains don't lead to the
// live ones, or whose directory has lost an organisation the platform chain
// records. Both sides read-only.
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, transactionsReadOnly } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { createTestDatabase, type TestClient, type TestDatabase, testLogger, writeTestKeys } from '@agentx/testing';
import { afterAll, afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createOrganizationAsOperator, type OperatorTables } from './create-organization.ts';
import { checkRestoredCopy } from './restore-check.ts';

const server = inject('postgres');
const keyFiles = writeTestKeys(['audit-mac', 'field-encryption']);
const keys = loadKeys({ directory: keyFiles.directory, current: {} }, ['audit-mac', 'field-encryption']);

const quiet = () => testLogger();

let live: TestDatabase;
let copy: TestDatabase | undefined;
const open: Database<OperatorTables>[] = [];

/** The app's role on a test database, read-only as the check connects, or not, to write. */
function appOn(database: TestDatabase, readOnly: boolean): Database<OperatorTables> {
  const handle = createDatabase<OperatorTables>(
    { ...database.connection('app'), maxConnections: 1, readOnly },
    quiet(),
  );
  open.push(handle);
  return handle;
}

/** Makes an organisation as the operator's command does, on the database given. */
async function organisationOn(database: TestDatabase): Promise<string> {
  const writer = appOn(database, false);
  const orgId = uuidV7Ids.next();
  await createOrganizationAsOperator(
    writer,
    { keys, ids: uuidV7Ids, logger: quiet() },
    { orgId, name: `Restore Drill Test ${orgId.slice(-6)}`, release: 'r-1', run: null },
  );
  return orgId;
}

/** Closes every handle opened so far: a database is copied only once no one is connected to it. */
async function closeAll(): Promise<void> {
  await Promise.all(open.splice(0).map((handle) => handle.destroy()));
}

/** The test's copy, once made. */
function theCopy(): TestDatabase {
  if (copy === undefined) throw new Error('No copy made yet.');
  return copy;
}

/** The check of the test's copy against its live database. */
function check() {
  return checkRestoredCopy({ copy: appOn(theCopy(), true), live: appOn(live, true), keys });
}

beforeEach(async () => {
  live = await createTestDatabase(server, { schema: 'migrated' });
});

afterEach(async () => {
  await closeAll();
  await copy?.drop();
  copy = undefined;
  await live.drop();
});

afterAll(() => {
  keyFiles.remove();
});

/**
 * Changes the copy as its superuser with every trigger and key check off
 * (`session_replication_role = replica`): what a broken restore could leave,
 * which the app's own rules would never let it write.
 */
async function breakCopy(change: (admin: TestClient) => Promise<unknown>): Promise<void> {
  const admin = await theCopy().connect('admin');
  try {
    await admin.query('set session_replication_role = replica');
    await change(admin);
  } finally {
    await admin.end();
  }
}

/** A copy of the live database as it is now, with one organisation on it. */
async function copyWithOrganisation(): Promise<string> {
  const orgId = await organisationOn(live);
  await closeAll();
  copy = await live.copy();
  return orgId;
}

describe('SEC-AV-06 the restore drill check', () => {
  it('passes a copy the live server is, and one it has grown on from', async () => {
    await copyWithOrganisation();

    const same = await check();
    expect(same).toMatchObject({
      problems: [],
      chainsChecked: 2,
      chainsHeld: 2,
      copyOrganizations: 1,
      newSinceCopy: 0,
    });
    expect(same.platformCopySeq).toBeGreaterThan(0n);
    expect(same.platformLiveSeq).toBe(same.platformCopySeq);

    // The live server moves on after the restore point: the copy is still its earlier state.
    await organisationOn(live);
    const grown = await check();
    expect(grown).toMatchObject({ problems: [], chainsHeld: 2, newSinceCopy: 1 });
    expect(grown.platformLiveSeq).toBeGreaterThan(grown.platformCopySeq ?? 0n);
  });

  it('fails a copy whose chains do not lead to the live ones', async () => {
    await copyWithOrganisation();
    // Each side goes on alone: the platform chain forks at the copy's head,
    // and the copy's own new organisation has no chain live.
    const onlyOnCopy = await organisationOn(theCopy());
    await organisationOn(live);
    const report = await check();
    expect(report.problems).toEqual([
      expect.stringMatching(/^platform on the live server, from the copy's head: anchor at \d+$/),
      expect.stringMatching(
        new RegExp(`^organisation ${onlyOnCopy} on the live server, from the copy's head: anchor at \\d+$`),
      ),
      `organisation ${onlyOnCopy}: on the copy, but not listed live`,
    ]);
    expect(report).toMatchObject({ chainsChecked: 3, chainsHeld: 1, platformLiveSeq: null });
  });

  it('fails a copy broken on its own side, before the live server is read', async () => {
    await copyWithOrganisation();
    await breakCopy((admin) => admin.query('delete from platform_controls.audit_head'));
    const report = await check();
    expect(report.problems).toEqual(['platform on the copy: head at 0']);
    expect(report).toMatchObject({ chainsHeld: 1, platformCopySeq: null });
  });

  it("says a chain or a list the copy won't let it read, by the database's code alone", async () => {
    const orgId = await copyWithOrganisation();
    // The test server's app role (tooling/test-db), as the check connects.
    await breakCopy((admin) => admin.query('revoke select on audit.events from agentx_app'));
    expect((await check()).problems).toEqual([`organisation ${orgId} on the copy: unreadable (42501)`]);
    await breakCopy((admin) => admin.query('revoke select on directory.orgs from agentx_app'));
    const report = await check();
    expect(report.problems).toEqual(["the organisations' lists: unreadable (42501)"]);
    expect(report.copyOrganizations).toBe(0);
  });

  it('fails a copy whose directory has lost an organisation the platform chain records', async () => {
    const orgId = await copyWithOrganisation();
    await breakCopy((admin) => admin.query('delete from directory.orgs where org_id = $1', [orgId]));
    const report = await check();
    expect(report.problems).toEqual([`organisation ${orgId}: recorded as created on the copy, but not listed`]);
  });

  it('connects read-only: Postgres says so, and refuses a write', async () => {
    const reader = appOn(live, true);
    expect(await transactionsReadOnly(reader)).toBe(true);
    expect(await transactionsReadOnly(appOn(live, false))).toBe(false);
    await expect(
      createOrganizationAsOperator(
        reader,
        { keys, ids: uuidV7Ids, logger: quiet() },
        { orgId: uuidV7Ids.next(), name: 'Restore Drill Read Only', release: 'r-1', run: null },
      ),
    ).rejects.toMatchObject({ code: '25006' });
  });

  it('reads a copy with nothing in it: the chains start empty on both sides', async () => {
    copy = await live.copy();
    const report = await check();
    expect(report).toMatchObject({ problems: [], chainsChecked: 1, chainsHeld: 1, copyOrganizations: 0 });
  });
});

// S78: the restore drill's check against a real Postgres. The copy is made
// the way a restore makes one: a database cloned from the live one as it was
// (TestDatabase.copy). The check passes a true earlier copy, the live server
// grown on from it included, and fails a copy whose chains don't lead to the
// live ones, or whose directory has lost an organisation the platform chain
// records. Both sides read-only.
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, transactionsReadOnly } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, LogCapture, type TestDatabase, writeTestKeys } from '@agentx/testing';
import { afterAll, afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createOrganizationAsOperator, type OperatorTables } from './create-organization.ts';
import { checkRestoredCopy } from './restore-check.ts';

const server = inject('postgres');
const keyFiles = writeTestKeys(['audit-mac', 'field-encryption']);
const keys = loadKeys({ directory: keyFiles.directory, current: {} }, ['audit-mac', 'field-encryption']);

const quiet = () =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: new LogCapture(),
  });

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

/** The check of the test's copy against its live database. */
function check() {
  if (copy === undefined) throw new Error('No copy made yet.');
  return checkRestoredCopy({ copy: appOn(copy, true), live: appOn(live, true), keys });
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

describe('SEC-AV-06 the restore drill check', () => {
  it('passes a copy the live server is, and one it has grown on from', async () => {
    const first = await organisationOn(live);
    await closeAll();
    copy = await live.copy();

    const same = await check();
    expect(same.problems).toEqual([]);
    expect(same.copyOrganizations).toBe(1);
    expect(same.newSinceCopy).toBe(0);
    expect(same.chains.map((chain) => chain.chain)).toEqual(['platform', `organisation ${first}`]);
    for (const chain of same.chains) {
      expect(chain.copySeq).toBeGreaterThan(0n);
      expect(chain.liveSeq).toBe(chain.copySeq);
    }

    // The live server moves on after the restore point: the copy is still its earlier state.
    await organisationOn(live);
    const grown = await check();
    expect(grown.problems).toEqual([]);
    expect(grown.newSinceCopy).toBe(1);
    const platform = grown.chains.find((chain) => chain.chain === 'platform');
    expect(platform?.liveSeq).toBeGreaterThan(platform?.copySeq ?? 0n);
  });

  it('fails a copy whose chain does not lead to the live one', async () => {
    await organisationOn(live);
    await closeAll();
    copy = await live.copy();
    // Each side goes on alone: the platform chain forks at the copy's head.
    await organisationOn(copy);
    await organisationOn(live);
    const report = await check();
    expect(report.problems).toEqual([expect.stringMatching(/^platform on the live server, from the copy's head: /)]);
    expect(report.chains.find((chain) => chain.chain === 'platform')?.liveSeq).toBeUndefined();
  });

  it('fails a copy whose directory has lost an organisation the platform chain records', async () => {
    const orgId = await organisationOn(live);
    await closeAll();
    copy = await live.copy();
    await copy.as('owner').query('delete from directory.orgs where org_id = $1', [orgId]);
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
    expect(report.problems).toEqual([]);
    expect(report.copyOrganizations).toBe(0);
  });
});

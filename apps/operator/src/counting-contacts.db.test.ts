// OR2b (playbook K): the operator lists an organisation's registered contacts that
// count now, against a real Postgres as the operator's own role (0088's read and no
// more): what it refuses, and that a contact it can't believe gives no list. Which
// contacts count, and the read past the app, are registered-contacts.db.test.ts's;
// the masked line, counting-contacts.test.ts's.
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import {
  createTestDatabase,
  LogCapture,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  writeTestKeys,
} from '@agentx/testing';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { type CountingContactsTables, listCountingContacts } from './counting-contacts.ts';
import { createOrganizationAsOperator } from './create-organization.ts';

const server = inject('postgres');
const HELD = ['audit-mac', 'field-encryption', 'operator-signing', 'audit-rebase'] as const;
const mounted = writeTestKeys([...HELD]);
const keys = loadKeys({ directory: mounted.directory, current: {} }, [...HELD]);
let database: TestDatabase;
/** The operator's command's own role (PL-57): every command below runs as it. */
let operator: Database<CountingContactsTables>;
const NOW = new Date('2026-11-12T09:00:00Z');

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  operator = createDatabase<CountingContactsTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
});

afterAll(async () => {
  await operator.destroy();
  await database.drop();
  mounted.remove();
});

/** A new organisation, made by the operator. */
async function organization(): Promise<string> {
  const orgId = uuidV7Ids.next();
  await createOrganizationAsOperator(
    operator,
    { keys, ids: uuidV7Ids, logger: testLogger() },
    { orgId, name: `Contacts ${orgId.slice(-6)}`, release: 'r-test', run: null },
  );
  return orgId;
}

/** Runs the command, its log captured. */
async function listed(orgId: string, on: Database<CountingContactsTables> = operator) {
  const capture = new LogCapture();
  const code = await listCountingContacts(on, { keys, ids: uuidV7Ids, logger: testLogger(capture) }, orgId, NOW);
  const lines = capture.lines();
  return { code, line: (event: string) => lines.find((line) => line.event === event) };
}

describe(`OR2b the operator lists an organisation's counting contacts (playbook K; Postgres ${server.version})`, () => {
  it('lists none for an organisation with none, and says so', async () => {
    const orgId = await organization();
    const { code, line } = await listed(orgId);
    expect(code).toBe(0);
    expect(line('operator.counting_contacts')).toMatchObject({ orgId, count: 0, contacts: [] });
  });

  it('refuses an organisation that does not exist', async () => {
    const orgId = uuidV7Ids.next();
    const { code, line } = await listed(orgId);
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({ orgId, problems: ['no organisation has this ID'] });
  });

  it("refuses an organisation whose own record can't be believed, its alarm raised as every read of it does", async () => {
    const orgId = await organization();
    const owner = await tamperAsOwner(database, ORGANIZATIONS, orgId);
    try {
      await owner.stripSeals(orgId);
    } finally {
      await owner.end();
    }
    const { code, line } = await listed(orgId);
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({ problems: ["the organisation's records can't be verified"] });
    expect(line('audit.integrity_failed')).toMatchObject({ orgId });
  });

  it('gives no list once a contact was planted past the app: the runbook stops', async () => {
    const orgId = await organization();
    const owner = await database.connect('owner');
    try {
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [orgId]);
      const userId = randomUUID();
      const membershipId = randomUUID();
      await owner.query(
        "insert into identity.users (id, issuer, subject, created_at) values ($1, 'https://login.test', $2, pg_catalog.now())",
        [userId, userId],
      );
      await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
        userId,
        orgId,
        membershipId,
      ]);
      await owner.query(
        "insert into identity.memberships (org_id, id, user_id, role, status, joined_at) values ($1, $2, $3, 'admin', 'ACTIVE', pg_catalog.now())",
        [orgId, membershipId, userId],
      );
      await owner.query(
        "insert into identity.registered_contacts (org_id, id, status, added_by, counts_from, step_up_challenge_id, created_at, email_ciphertext, email_key_version) values ($1, $2, 'DRAFT', $3, null, $4, pg_catalog.now(), $5, 1)",
        [orgId, randomUUID(), membershipId, randomUUID(), Buffer.alloc(40)],
      );
    } finally {
      await owner.end();
    }
    const { code, line } = await listed(orgId);
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({
      orgId,
      problems: ["a registered contact's record can't be verified: no list, and no reset goes on"],
    });
    expect(line('operator.counting_contacts')).toBeUndefined();
  });

  it('fails, naming its command, when its reads are refused (here, a role that may read but never lock)', async () => {
    const backup = createDatabase<CountingContactsTables>({ ...database.connection('backup') }, testLogger());
    try {
      const { code, line } = await listed(await organization(), backup);
      expect(code).toBe(1);
      expect(line('operator.failed')).toMatchObject({ command: 'counting-contacts' });
    } finally {
      await backup.destroy();
    }
  });
});

// OR2 (playbook K): the operator tells an organisation's members, and its
// registered contacts that count now, that our team is resetting a person's
// second factor, against a real Postgres as the operator's own role: both
// chains and the notices in one transaction, a request run again recording and
// telling nothing twice, the other organisations the person is in named, and
// what it refuses, with nothing recorded. The sender's fan-out of the notices
// is sender.db.test.ts's; the run from its request file, main.db.test.ts's.
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
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

import { createOrganizationAsOperator } from './create-organization.ts';
import {
  type FactorResetNoticeRequest,
  type FactorResetNoticeTables,
  noticeFactorReset,
  NOTIFIED,
  PLATFORM_NOTIFIED,
} from './factor-reset-notice.ts';

const server = inject('postgres');
const HELD = ['audit-mac', 'field-encryption', 'operator-signing', 'audit-rebase'] as const;
const mounted = writeTestKeys([...HELD]);
const keys = loadKeys({ directory: mounted.directory, current: {} }, [...HELD]);
let database: TestDatabase;
let app: Database<FactorResetNoticeTables>;
/** The operator's command's own role (PL-57), as the job connects: every command below runs as it. */
let operator: Database<FactorResetNoticeTables>;

/** Plain words a test can look for in every log line. */
const REASON = 'INC-2026/0099';

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<FactorResetNoticeTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
  operator = createDatabase<FactorResetNoticeTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
});

afterAll(async () => {
  await app.destroy();
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
    { orgId, name: `Reset Notice ${orgId.slice(-6)}`, release: 'r-test', run: null },
  );
  return orgId;
}

/** A person the directory lists in each of these organisations (IDs alone, as the product's own entry is). */
async function person(...orgIds: readonly string[]): Promise<string> {
  const userId = randomUUID();
  const owner = database.as('owner');
  await owner.query(
    "insert into identity.users (id, issuer, subject, created_at) values ($1, 'https://login.test', $2, pg_catalog.now())",
    [userId, userId],
  );
  for (const orgId of orgIds) {
    await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
      userId,
      orgId,
      randomUUID(),
    ]);
  }
  return userId;
}

const asked = (orgId: string, userId: string, noticeId = uuidV7Ids.next()): FactorResetNoticeRequest => ({
  orgId,
  userId,
  reason: REASON,
  noticeId,
  release: 'r-test',
  run: null,
});

/** Runs the command, its log captured. */
async function noticed(request: FactorResetNoticeRequest) {
  const capture = new LogCapture();
  const code = await noticeFactorReset(operator, { keys, ids: uuidV7Ids, logger: testLogger(capture) }, request);
  const lines = capture.lines();
  return {
    code,
    text: capture.text,
    events: lines.map((line) => String(line.event)),
    line: (event: string) => lines.find((line) => line.event === event),
  };
}

/** The organisation's records of our team's resets, in chain order. */
const recordsOf = (orgId: string) =>
  withTenant(app, orgId, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['id', 'actor_type', 'actor_id', 'action', 'subject_type', 'subject_id', 'details'])
      .where('action', '=', NOTIFIED)
      .orderBy('seq')
      .execute(),
  );

/** Its notices of them. */
const noticesOf = (orgId: string) =>
  withTenant(app, orgId, (tx) =>
    tx
      .selectFrom('notifications.outbox')
      .select(['kind', 'about_id', 'recipient_user_id', 'recipient_contact_id', 'to_contacts'])
      .where('org_id', '=', orgId)
      .where('kind', '=', 'factor_reset_by_support')
      .orderBy('to_contacts')
      .execute(),
  );

/** The platform chain's records of them. */
const platformRecords = (noticeId: string) =>
  database
    .as('owner')
    .query<{ action: string; actor_id: string; details: string }>(
      "select action, actor_id, details from platform_controls.audit_events where action = $1 and details::jsonb ->> 'noticeId' = $2",
      [PLATFORM_NOTIFIED, noticeId],
    );

describe(`OR2 the operator tells an organisation of a reset under way (playbook K; Postgres ${server.version})`, () => {
  it('records it on both chains, writes a notice to every member and one to the counting contacts, never logging the reference', async () => {
    const orgId = await organization();
    const userId = await person(orgId);
    const request = asked(orgId, userId);

    const { code, events, line, text } = await noticed(request);

    expect(code).toBe(0);
    expect(events).toEqual(['operator.factor_reset_notified']);
    expect(line('operator.factor_reset_notified')).toMatchObject({
      noticeId: request.noticeId,
      orgId,
      recordedBefore: false,
      elsewhere: [],
    });
    const [record, ...more] = await recordsOf(orgId);
    expect(more).toEqual([]);
    expect(record).toMatchObject({
      id: request.noticeId,
      actor_type: 'system',
      actor_id: 'operator',
      subject_type: 'support_factor_reset',
      subject_id: request.noticeId,
    });
    expect(JSON.parse(String(record?.details))).toEqual({ userId, reason: REASON });
    expect(await noticesOf(orgId)).toEqual([
      {
        kind: 'factor_reset_by_support',
        about_id: userId,
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: false,
      },
      {
        kind: 'factor_reset_by_support',
        about_id: userId,
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: true,
      },
    ]);
    const [platform, ...others] = await platformRecords(request.noticeId);
    expect(others).toEqual([]);
    expect(platform).toMatchObject({ action: PLATFORM_NOTIFIED, actor_id: 'operator' });
    expect(JSON.parse(String(platform?.details))).toEqual({
      orgId,
      noticeId: request.noticeId,
      userId,
      reason: REASON,
      release: 'r-test',
      run: null,
    });
    expect(text).not.toContain(REASON);
  });

  it('names the other organisations the directory lists the person in, each to be told by its own request', async () => {
    const [here, there, third] = [await organization(), await organization(), await organization()];
    const userId = await person(here, there, third);

    const { code, line } = await noticed(asked(here, userId));

    expect(code).toBe(0);
    expect(line('operator.factor_reset_notified')?.elsewhere).toEqual([there, third].sort());
    expect(await noticesOf(there)).toEqual([]);
  });

  it('run again, records and tells nothing twice', async () => {
    const orgId = await organization();
    const userId = await person(orgId);
    const request = asked(orgId, userId);
    await noticed(request);

    const { code, line } = await noticed(request);

    expect(code).toBe(0);
    expect(line('operator.factor_reset_notified')).toMatchObject({ recordedBefore: true });
    expect(await recordsOf(orgId)).toHaveLength(1);
    expect(await noticesOf(orgId)).toHaveLength(2);
    expect(await platformRecords(request.noticeId)).toHaveLength(1);
  });

  it.each([
    ['another person', (request: FactorResetNoticeRequest, other: string) => ({ ...request, userId: other })],
    ['another reference', (request: FactorResetNoticeRequest) => ({ ...request, reason: 'INC-2026/0100' })],
  ])('refuses its ID run again for %s: nothing recorded again', async (_what, changed) => {
    const orgId = await organization();
    const [userId, other] = [await person(orgId), await person(orgId)];
    const request = asked(orgId, userId);
    await noticed(request);

    const { code, line } = await noticed(changed(request, other));

    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({
      noticeId: request.noticeId,
      problems: ['the ID names another record: write a new request'],
    });
    expect(await recordsOf(orgId)).toHaveLength(1);
    expect(await noticesOf(orgId)).toHaveLength(2);
  });

  it("refuses an ID another organisation's notice took, on the platform chain", async () => {
    const [first, second] = [await organization(), await organization()];
    const userId = await person(first, second);
    const request = asked(first, userId);
    await noticed(request);

    const { code, line } = await noticed({ ...request, orgId: second });

    expect(code).toBe(1);
    expect(line('operator.refused')?.problems).toEqual(['the ID names another record: write a new request']);
    expect(await recordsOf(second)).toEqual([]);
  });

  it('refuses a person the directory lists in another organisation only, or none: nothing recorded, nobody told', async () => {
    const [orgId, elsewhere] = [await organization(), await organization()];
    for (const userId of [await person(elsewhere), randomUUID()]) {
      const { code, line } = await noticed(asked(orgId, userId));
      expect(code).toBe(1);
      expect(line('operator.refused')?.problems).toEqual(['the directory lists no such person in this organisation']);
    }
    expect(await recordsOf(orgId)).toEqual([]);
    expect(await noticesOf(orgId)).toEqual([]);
  });

  it('refuses an organisation missing, or one whose record was tampered with (its alarm raised): nothing recorded', async () => {
    const missing = await noticed(asked(uuidV7Ids.next(), randomUUID()));
    expect(missing.code).toBe(1);
    expect(missing.line('operator.refused')?.problems).toEqual(['no organisation has this ID']);

    const orgId = await organization();
    const userId = await person(orgId);
    const owner = await tamperAsOwner(database, ORGANIZATIONS, orgId);
    try {
      await owner.setColumn(orgId, 'status', 'FROZEN');
    } finally {
      await owner.end();
    }
    const tampered = await noticed(asked(orgId, userId));
    expect(tampered.code).toBe(1);
    expect(tampered.line('operator.refused')?.problems).toEqual(["the organisation's records can't be verified"]);
    expect(await recordsOf(orgId)).toEqual([]);
  });

  it('fails, nothing recorded, when a write is refused part-way (the outbox away): run again, it records once', async () => {
    const orgId = await organization();
    const userId = await person(orgId);
    const request = asked(orgId, userId);
    const owner = database.as('owner');
    await owner.query('revoke insert on notifications.outbox from agentx_operator');
    try {
      const { code, line } = await noticed(request);
      expect(code).toBe(1);
      expect(line('operator.failed')).toMatchObject({ command: 'factor-reset-notice', noticeId: request.noticeId });
    } finally {
      await owner.query('grant insert on notifications.outbox to agentx_operator');
    }
    expect(await recordsOf(orgId)).toEqual([]);
    expect(await platformRecords(request.noticeId)).toEqual([]);

    expect((await noticed(request)).code).toBe(0);
    expect(await recordsOf(orgId)).toHaveLength(1);
  });
});

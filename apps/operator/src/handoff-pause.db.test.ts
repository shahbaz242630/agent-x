// Phase 4 B1: the operator's pause and resume of every hand-off against a
// real Postgres (Rule Book §6; SEC-OPS-03; partner decision 4): the change on
// the platform chain, then every organisation told on its own chain with a
// notice to its admins; a request run again telling only those not told yet;
// one organisation failing leaving the others told; and what it refuses, with
// nothing recorded. The run itself, from its request file, is main.db.test.ts.
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { HANDOFF_PAUSED, HANDOFF_RESUMED } from '@agentx/core/modules/platform-controls';
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
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createOrganizationAsOperator } from './create-organization.ts';
import { changeHandoffPauseAsOperator, type HandoffPauseRequest, type HandoffPauseTables } from './handoff-pause.ts';

const server = inject('postgres');
const mounted = writeTestKeys(['audit-mac', 'field-encryption']);
const keys = loadKeys({ directory: mounted.directory, current: {} }, ['audit-mac', 'field-encryption']);
let database: TestDatabase;
let app: Database<HandoffPauseTables>;

/** Plain words a test can look for in every log line. */
const REASON = 'INC-2026/0042';

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffPauseTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
  mounted.remove();
});

/** A new organisation, made by the operator. */
async function organization(): Promise<string> {
  const orgId = uuidV7Ids.next();
  await createOrganizationAsOperator(
    app,
    { keys, ids: uuidV7Ids, logger: testLogger() },
    { orgId, name: `Pause Test ${orgId.slice(-6)}`, release: 'r-test', run: null },
  );
  return orgId;
}

const asked = (paused: boolean, eventId = uuidV7Ids.next()): HandoffPauseRequest => ({
  paused,
  reason: REASON,
  eventId,
  release: 'r-test',
  run: null,
});

/** Runs the change and its telling, its log captured. */
async function changed(request: HandoffPauseRequest) {
  const capture = new LogCapture();
  const code = await changeHandoffPauseAsOperator(app, { keys, ids: uuidV7Ids, logger: testLogger(capture) }, request);
  const lines = capture.lines();
  return {
    code,
    text: capture.text,
    events: lines.map((line) => String(line.event)),
    line: (event: string) => lines.find((line) => line.event === event),
    lines,
  };
}

/** How many organisations the directory lists: every one is told. */
const listed = async (): Promise<number> =>
  Number(
    (await database.as('owner').query<{ n: string }>('select pg_catalog.count(*) as n from directory.orgs'))[0]?.n,
  );

/** The organisation's records of pauses and resumes, in chain order. */
const toldOf = (orgId: string) =>
  withTenant(app, orgId, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['id', 'actor_type', 'actor_id', 'action', 'subject_type', 'subject_id', 'details'])
      .where('subject_type', '=', 'handoff_pause')
      .orderBy('seq')
      .execute(),
  );

/** Its admins' notices about them. */
const noticesOf = (orgId: string) =>
  withTenant(app, orgId, (tx) =>
    tx
      .selectFrom('notifications.outbox')
      .select(['kind', 'about_id', 'recipient_user_id'])
      .where('org_id', '=', orgId)
      .where('kind', 'in', ['handoff_paused', 'handoff_resumed'])
      .orderBy('created_at')
      .execute(),
  );

/** The platform chain's pauses and resumes, in order. */
const platformEvents = () =>
  database
    .as('owner')
    .query<{ id: string; action: string; actor_id: string; details: string }>(
      'select id, action, actor_id, details from platform_controls.audit_events where action = any($1) order by seq',
      [[HANDOFF_PAUSED, HANDOFF_RESUMED]],
    );

/** The pause row as stored. */
const pauseRow = async () =>
  (
    await database
      .as('owner')
      .query<{ paused: boolean; event_id: string | null }>(
        'select paused, event_id from platform_controls.handoff_pause',
      )
  )[0];

describe(`B1 the operator pauses and resumes every hand-off (SEC-OPS-03; Postgres ${server.version})`, () => {
  it('finds a pause asked for while born paused already as asked: nothing recorded, nobody told', async () => {
    await organization();
    const { code, events, line } = await changed(asked(true));

    expect(code).toBe(0);
    expect(events).toEqual(['operator.handoff_unchanged']);
    expect(line('operator.handoff_unchanged')).toMatchObject({ paused: true, inForce: null, since: null });
    expect(await platformEvents()).toEqual([]);
  });

  it('resumes on the platform chain, then tells every organisation on its own chain and its admins, never logging the reason', async () => {
    const [first, second] = [await organization(), await organization()];
    const request = asked(false);

    const { code, events, line, text } = await changed(request);

    expect(code).toBe(0);
    expect(events).toEqual(['operator.handoff_resumed', 'operator.handoff_told']);
    expect(line('operator.handoff_told')).toMatchObject({
      platformEventId: request.eventId,
      organizations: await listed(),
      told: await listed(),
      toldBefore: 0,
      failed: 0,
    });
    const [platform] = await platformEvents();
    expect(platform).toMatchObject({ id: request.eventId, action: HANDOFF_RESUMED, actor_id: 'operator' });
    expect(JSON.parse(String(platform?.details))).toEqual({ reason: REASON, release: 'r-test', run: null });
    expect(await pauseRow()).toEqual({ paused: false, event_id: request.eventId });
    for (const orgId of [first, second]) {
      const [told, ...more] = await toldOf(orgId);
      expect(more).toEqual([]);
      expect(told).toMatchObject({
        actor_type: 'system',
        actor_id: 'operator',
        action: 'handoff.resumed',
        subject_id: request.eventId,
      });
      expect(JSON.parse(String(told?.details))).toEqual({ reason: REASON, platformEventId: request.eventId });
      expect(await noticesOf(orgId)).toEqual([
        { kind: 'handoff_resumed', about_id: told?.id, recipient_user_id: null },
      ]);
    }
    expect(text).not.toContain(REASON);
  });

  it('run again, records nothing and tells nobody twice, but tells an organisation made since', async () => {
    const request = asked(true);
    await changed(request);
    const later = await organization();

    const { code, events, line } = await changed(request);

    expect(code).toBe(0);
    expect(events).toEqual(['operator.handoff_unchanged', 'operator.handoff_told']);
    expect(line('operator.handoff_unchanged')).toMatchObject({ paused: true, inForce: request.eventId });
    expect(line('operator.handoff_told')).toMatchObject({ told: 1, toldBefore: (await listed()) - 1, failed: 0 });
    expect((await platformEvents()).filter((event) => event.id === request.eventId)).toHaveLength(1);
    expect((await toldOf(later)).map((event) => event.action)).toEqual(['handoff.paused']);
    expect(await noticesOf(later)).toHaveLength(1);
  });

  it('tells every other organisation when one fails, exits 1, and a run again tells only that one', async () => {
    const [broken, fine] = [await organization(), await organization()];
    const owner = await tamperAsOwner(database, ORGANIZATIONS, broken);
    const [head] = await owner.query<{ mac: Buffer }>('select mac from audit.heads where org_id = $1', [broken]);
    const request = asked(false);
    try {
      await owner.query(`update audit.heads set mac = '\\x00'::bytea where org_id = $1`, [broken]);

      const failing = await changed(request);

      expect(failing.code).toBe(1);
      expect(failing.lines).toEqual(
        expect.arrayContaining([expect.objectContaining({ event: 'operator.handoff_notice_failed', orgId: broken })]),
      );
      expect(failing.line('operator.handoff_told')).toMatchObject({ told: (await listed()) - 1, failed: 1 });
      expect(await toldOf(broken)).toEqual([]);
      expect((await toldOf(fine)).map((event) => event.action)).toEqual(['handoff.resumed']);
    } finally {
      await owner.query('update audit.heads set mac = $2 where org_id = $1', [broken, head?.mac]);
      await owner.end();
    }

    const again = await changed(request);

    expect(again.code).toBe(0);
    expect(again.line('operator.handoff_told')).toMatchObject({ told: 1, toldBefore: (await listed()) - 1, failed: 0 });
    expect((await toldOf(broken)).map((event) => event.action)).toEqual(['handoff.resumed']);
    expect(await toldOf(fine)).toHaveLength(1);
  });
});

describe('B1 what the operator refuses, recording nothing', () => {
  it('a pause row that can’t be believed: refused, the alarm raised, nobody told', async () => {
    const orgId = await organization();
    const before = await platformEvents();
    const { paused } = (await pauseRow()) ?? { paused: true };
    await database.as('owner').query('update platform_controls.handoff_pause set paused = $1', [!paused]);
    try {
      const { code, events, line } = await changed(asked(paused));

      expect(code).toBe(1);
      expect(events).toEqual(['audit.integrity_failed', 'operator.refused']);
      expect(line('audit.integrity_failed')).toMatchObject({ chain: 'platform', check: 'handoff_pause' });
      expect(line('operator.refused')?.problems).toEqual([
        "the hand-off pause's record can't be verified, so nothing was changed",
      ]);
      expect(await platformEvents()).toEqual(before);
      expect(await toldOf(orgId)).toEqual([]);
    } finally {
      await database.as('owner').query('update platform_controls.handoff_pause set paused = $1', [paused]);
    }
  });

  it('a request whose ID names a change overtaken since', async () => {
    const pause = asked(true);
    await changed(asked(false));
    await changed(pause);
    await changed(asked(false));
    const before = await platformEvents();

    const { code, events, line } = await changed(pause);

    expect(code).toBe(1);
    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')).toMatchObject({
      platformEventId: pause.eventId,
      problems: ['the ID names another platform event, or a change overtaken since: write a new request'],
    });
    expect(await platformEvents()).toEqual(before);
  });

  it('finds a pause as asked by another request’s change: telling is that one’s, so nobody is told', async () => {
    const first = asked(true);
    await changed(first);
    const orgId = await organization();

    const { code, events, line } = await changed(asked(true));

    expect(code).toBe(0);
    expect(events).toEqual(['operator.handoff_unchanged']);
    expect(line('operator.handoff_unchanged')).toMatchObject({ inForce: first.eventId });
    expect(await toldOf(orgId)).toEqual([]);
  });
});

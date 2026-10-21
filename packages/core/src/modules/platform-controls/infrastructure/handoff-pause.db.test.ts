// The platform hand-off pause on the real migrated schema, as the app role
// (Phase 4 B1; SEC-OPS-03; ADR-006 §6 level 1; ADR-014 §4): born paused,
// resumed and paused again each with its signed platform event, a change to
// the state it is in already recording nothing, a row changed past the app
// read as tampered (the alarm raised, nothing recorded), and a hand-off's
// FOR SHARE read waiting for a change in flight, then seeing it whole.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { PlatformEventRefused } from '../domain/event.ts';
import {
  changeHandoffPause,
  HANDOFF_PAUSED,
  HANDOFF_RESUMED,
  type HandoffPauseChange,
  type HandoffPauseLock,
  handoffPauseOf,
} from './handoff-pause.ts';
import { createPlatformChain } from './platform-chain.ts';
import type { PlatformControlsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<PlatformControlsTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xb1) });

const OPERATOR = { type: 'system', id: 'operator' } as const;
const asked = (paused: boolean, overrides: Partial<HandoffPauseChange> = {}): HandoffPauseChange => ({
  paused,
  reason: 'INC-2026/0042',
  actor: OPERATOR,
  release: 'r-test',
  run: null,
  ...overrides,
});

/** Pauses or resumes in a transaction of its own, the log captured. */
async function change(paused: boolean, overrides: Partial<HandoffPauseChange> = {}) {
  const capture = new LogCapture();
  const done = await app
    .transaction()
    .execute((tx) => changeHandoffPause(tx, { chain, logger: testLogger(capture) }, asked(paused, overrides)));
  return { done, lines: capture.lines() };
}

/** The pause as a hand-off reads it, the log captured. */
async function pauseNow(lock: HandoffPauseLock = 'share') {
  const capture = new LogCapture();
  const pause = await app.transaction().execute((tx) => handoffPauseOf(tx, lock, testLogger(capture)));
  return { pause, lines: capture.lines() };
}

/** The pause and resume events on the platform chain, in order. */
const pauseEvents = async () =>
  database.as('owner').query<{
    seq: string;
    id: string;
    action: string;
    actor_id: string;
    details: string;
  }>('select seq, id, action, actor_id, details from platform_controls.audit_events where action = any($1) order by seq', [[HANDOFF_PAUSED, HANDOFF_RESUMED]]);

/** The row as stored. */
const row = async () =>
  (
    await database
      .as('owner')
      .query<{ paused: boolean; event_seq: string | null; event_id: string | null }>(
        'select paused, event_seq, event_id from platform_controls.handoff_pause',
      )
  )[0];

/** Changes the row past the app, as its owner can. */
const tamper = async (statement: string, values: unknown[] = []): Promise<void> => {
  const owner = await database.connect('owner');
  try {
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
    await owner.query(statement, values);
  } finally {
    await owner.end();
  }
};

const ALARM = { event: 'audit.integrity_failed', chain: 'platform', check: 'handoff_pause' };

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<PlatformControlsTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

// One pause for the whole platform: every test starts from it as born, on a chain never started.
beforeEach(async () => {
  await tamper('truncate platform_controls.audit_events, platform_controls.audit_head');
  await tamper('delete from platform_controls.handoff_pause');
  await tamper('insert into platform_controls.handoff_pause (paused, event_seq, event_id) values (true, null, null)');
});

describe(`B1 the platform hand-off pause (SEC-OPS-03; Postgres ${server.version})`, () => {
  it('is born paused, by no event, so a new environment hands nothing off until resumed (ADR-014 §4)', async () => {
    expect(await pauseNow()).toEqual({ pause: { outcome: 'paused', since: null, eventId: null }, lines: [] });
    expect(await pauseNow('change')).toMatchObject({ pause: { outcome: 'paused' } });
  });

  it('resumes with a signed platform event, its reason, release and run sealed, the row pointing at it', async () => {
    const { done, lines } = await change(false, { run: 'operator-run-1' });

    expect(done).toMatchObject({ outcome: 'changed', seq: 1n });
    expect(lines).toEqual([]);
    const [event] = await pauseEvents();
    expect(event).toMatchObject({ seq: '1', action: HANDOFF_RESUMED, actor_id: 'operator' });
    expect(JSON.parse(String(event?.details))).toEqual({
      reason: 'INC-2026/0042',
      release: 'r-test',
      run: 'operator-run-1',
    });
    expect(await row()).toEqual({ paused: false, event_seq: '1', event_id: event?.id });
    const recordedAt = done.outcome === 'changed' ? done.recordedAt : undefined;
    expect((await pauseNow()).pause).toEqual({ outcome: 'running', since: recordedAt, eventId: event?.id });
    expect(await chain.verifyAlone(app, undefined)).toMatchObject({ ok: true, seq: 1n });
  });

  it('pauses again, and resumes again, each its own event', async () => {
    await change(false);
    const paused = await change(true);
    const resumed = await change(false);

    expect([paused.done.outcome, resumed.done.outcome]).toEqual(['changed', 'changed']);
    expect((await pauseEvents()).map((event) => event.action)).toEqual([
      HANDOFF_RESUMED,
      HANDOFF_PAUSED,
      HANDOFF_RESUMED,
    ]);
    expect((await pauseNow()).pause).toMatchObject({ outcome: 'running', eventId: (await row())?.event_id });
  });

  it('records nothing for a pause when paused, as born or by an event, nor for a resume when running', async () => {
    expect((await change(true)).done).toEqual({ outcome: 'unchanged', paused: true, since: null, eventId: null });
    const resumed = await change(false);
    const again = await change(false);
    const resumedId = resumed.done.outcome === 'changed' ? resumed.done.eventId : undefined;
    expect(again.done).toMatchObject({ outcome: 'unchanged', paused: false, eventId: resumedId });
    await change(true);
    expect((await change(true)).done).toMatchObject({ outcome: 'unchanged', paused: true });

    expect(await pauseEvents()).toHaveLength(2);
  });

  it('refuses a reason left blank, recording nothing (a resume needs a reason)', async () => {
    await expect(change(false, { reason: '  ' })).rejects.toThrow(PlatformEventRefused);

    expect(await pauseEvents()).toEqual([]);
    expect((await pauseNow()).pause).toMatchObject({ outcome: 'paused' });
  });
});

describe('B1 a pause row changed past the app (FX-TAMPER): read as tampered, the alarm raised, nothing recorded', () => {
  /** Two events recorded, the row then changed as the owner can; the read and a change both refused. */
  async function readAfter(changeRow: (events: { seq: string; id: string }[]) => Promise<void>) {
    await change(false);
    await change(true);
    await changeRow(await pauseEvents());
    const read = await pauseNow();
    const changed = await change(false);
    return { read, changed, events: await pauseEvents() };
  }

  it.each([
    ['flipped to running', () => tamper('update platform_controls.handoff_pause set paused = false'), 'mismatch'],
    [
      'pointed back at the older resume',
      (events: { seq: string; id: string }[]) =>
        tamper('update platform_controls.handoff_pause set paused = false, event_seq = $1, event_id = $2', [
          events[0]?.seq,
          events[0]?.id,
        ]),
      'mismatch',
    ],
    [
      'pointing at the newest event by seq, another by ID',
      (events: { seq: string; id: string }[]) =>
        tamper('update platform_controls.handoff_pause set event_id = $1', [events[0]?.id]),
      'mismatch',
    ],
    [
      'its pointers cleared once an event exists, as if born',
      () => tamper('update platform_controls.handoff_pause set event_seq = null, event_id = null'),
      'mismatch',
    ],
    ['deleted', () => tamper('delete from platform_controls.handoff_pause'), 'missing'],
  ])('%s', async (_, changeRow, reason) => {
    const { read, changed, events } = await readAfter(changeRow);

    expect(read).toEqual({ pause: { outcome: 'tampered' }, lines: [expect.objectContaining({ ...ALARM, reason })] });
    expect(changed.done).toEqual({ outcome: 'tampered' });
    expect(changed.lines).toEqual([expect.objectContaining(ALARM)]);
    expect(events).toHaveLength(2);
  });

  it('a row as born is believed only while no pause or resume was ever recorded', async () => {
    await change(false);
    await tamper('update platform_controls.handoff_pause set paused = true, event_seq = null, event_id = null');

    expect((await pauseNow()).pause).toEqual({ outcome: 'tampered' });
  });

  it('a row resumed with no event behind it is tampering', async () => {
    await tamper('update platform_controls.handoff_pause set paused = false');

    expect((await pauseNow()).pause).toEqual({ outcome: 'tampered' });
  });

  it('a second row, the key dropped, believes neither', async () => {
    await tamper('alter table platform_controls.handoff_pause drop constraint handoff_pause_pkey');
    try {
      await tamper(
        'insert into platform_controls.handoff_pause (paused, event_seq, event_id) values (true, null, null)',
      );

      expect(await pauseNow()).toEqual({
        pause: { outcome: 'tampered' },
        lines: [expect.objectContaining({ ...ALARM, reason: 'unreadable' })],
      });
    } finally {
      await tamper('delete from platform_controls.handoff_pause');
      await tamper('alter table platform_controls.handoff_pause add primary key (only_row)');
    }
  });
});

describe('B1 the pause row is the first lock (ADR-006 §6 level 1)', () => {
  it("a hand-off's FOR SHARE read waits for a change in flight, then sees it whole, never tampered", async () => {
    let changed: (value: undefined) => void = () => undefined;
    const held = new Promise<undefined>((resolve) => {
      changed = resolve;
    });
    let release: (value: undefined) => void = () => undefined;
    const gate = new Promise<undefined>((resolve) => {
      release = resolve;
    });
    const resuming = app.transaction().execute(async (tx) => {
      const done = await changeHandoffPause(tx, { chain, logger: testLogger() }, asked(false));
      changed(undefined);
      await gate;
      return done;
    });
    await held;
    const reading = within(20_000, pauseNow(), 'the hand-off’s read');
    await waitUntilQueued(database.as('admin'), 1);
    release(undefined);

    const resumed = await resuming;
    const { pause, lines } = await reading;
    expect(lines).toEqual([]);
    expect(pause).toMatchObject({ outcome: 'running', eventId: resumed.outcome === 'changed' ? resumed.eventId : '' });
  });
});

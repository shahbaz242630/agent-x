// AT13h's gentler path (S208, the partner's decision): a platform chain cut back below the head a copy holds its console
// sessions to is answered by every session ended once, signed (sessions-all-ended.ts), and people sign in again on the
// same copy with no operator and no restart. As the database's owner (agentx_owner, none of the app's keys) cutting the
// chain's end off and putting back an earlier sealed head, and a session's row. Each its own database: an answer ends
// every session there is, and its record stands for every later one signed in before it.
//
// Each attack has its control beside it: honest traffic answers nothing, and a rebase clears the hold as before.
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { checkStatesWith, createDigestLog } from '../../audit/index.ts';
import { createPlatformChain, type PlatformControlsTables } from '../../platform-controls/index.ts';
import {
  createSessions,
  sessionEndedEvent,
  sessionRotatedEvent,
  sessionsEndedAt,
  sessionsEndedEvent,
} from './sessions.ts';
import { ANSWER_EVERY_MS } from './sessions-all-ended.ts';
import { createSignedEnds, SESSIONS_ALL_ENDED, sessionsAllEndedEvent } from './signed-ends.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables & PlatformControlsTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x5208_0000);
const clock = new FixedClock(new Date('2026-11-21T09:00:00Z'));
const TIMEOUTS = { idleSeconds: 1800, absoluteSeconds: 43_200 };
const PLATFORM = { kind: 'platform' } as const;
const platform = createPlatformChain({ keys, ids });

let capture: LogCapture;
const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const alarms = () => lines('audit.integrity_failed');
const answers = () => lines('identity.sessions_all_ended');

/** The signed states' digest as a copy keeps one, its heads in memory: a copy of the API, as far as these reads go. */
async function newDigest(anchors?: Parameters<typeof createDigestLog>[0]['anchors']) {
  const made = createDigestLog({
    anchors,
    keys,
    logger: testLogger(capture),
    now: () => clock.now(),
    epoch: 1,
    alertAfterMs: 60_000,
    mostBytes: 64 * 1024 * 1024,
  });
  await made.read();
  return made;
}
type Digest = Awaited<ReturnType<typeof newDigest>>;

/** A copy's sessions, held to its digest, answering a cut in the database unless told otherwise. */
const copy = (digest: Digest, answering = true) =>
  createSessions({
    ids,
    clock,
    timeouts: TIMEOUTS,
    keys,
    logger: testLogger(capture),
    digest: () => digest,
    ...(answering ? { database: app } : {}),
  });

const seenOf = (digest: Digest) => digest.heads(PLATFORM)?.seen?.seq;

let people = 0;
/** Someone signed in now: their user, session and cookie. */
async function signedIn(): Promise<{ userId: string; sessionId: string; cookie: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `sessions-cut-${String(people)}` },
    { ids, clock, keys, logger: testLogger() },
  );
  const opened = await copy(await newDigest(), false).open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
  });
  return { userId, ...opened };
}

/** Runs one statement as agentx_owner, on a connection of its own, and gives its rows. */
async function asOwner(text: string, values: readonly unknown[]): Promise<Record<string, unknown>[]> {
  const owner = await database.connect('owner');
  try {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text; every value is bound.
    return await owner.query(text, values);
  } finally {
    await owner.end();
  }
}

/** The session's row as the owner reads it, to put back later. */
async function keep(sessionId: string): Promise<unknown> {
  const [kept] = await asOwner('select pg_catalog.row_to_json(s) as kept from identity.sessions s where s.id = $1', [
    sessionId,
  ]);
  return kept?.kept;
}

/** The owner puts the session's row back as it kept it, MACs and all. */
async function putBack(sessionId: string, kept: unknown): Promise<void> {
  await asOwner('delete from identity.sessions where id = $1', [sessionId]);
  await asOwner(
    'insert into identity.sessions select * from pg_catalog.json_populate_record(null::identity.sessions, $1::json)',
    [JSON.stringify(kept)],
  );
}

/** The session this cookie holds signed out, as the console does: its row deleted, its end signed. */
const signOut = (cookie: string) =>
  app.transaction().execute(async (tx) => {
    const ended = await copy(await newDigest(), false).end(tx as unknown as Kysely<IdentityTables>, cookie);
    if (ended === undefined) throw new Error('the session did not end');
    await platform.record(tx, sessionEndedEvent(ended, clock.now()));
  });

/** The platform chain's head as the owner reads it: the row, to put back. */
async function headRow(): Promise<{ seq: bigint; kept: unknown }> {
  const [row] = await asOwner(
    'select h.seq::text as seq, pg_catalog.row_to_json(h) as kept from platform_controls.audit_head h',
    [],
  );
  return { seq: BigInt(String(row?.seq)), kept: row?.kept };
}

/** The owner puts back the head row it kept, MAC and all. */
const headBack = (kept: unknown) =>
  asOwner(
    `update platform_controls.audit_head h set (seq, hash, mac, mac_key_version) =
       (select r.seq, r.hash, r.mac, r.mac_key_version
        from pg_catalog.json_populate_record(null::platform_controls.audit_head, $1::json) r)`,
    [JSON.stringify(kept)],
  );

/** The owner cuts the platform chain's end off past `to` (a head row it kept) and puts that head back: every seal true. */
async function cutBackTo(to: { seq: bigint; kept: unknown }): Promise<void> {
  await asOwner('delete from platform_controls.audit_events where seq > $1::bigint', [to.seq.toString()]);
  await headBack(to.kept);
}

/** How many records of every session's end the chain holds. */
async function allEndedRecords(): Promise<number> {
  const { rows } = await sql<{ n: string }>`
    select pg_catalog.count(*)::text as n from platform_controls.audit_events where action = ${SESSIONS_ALL_ENDED}
  `.execute(app);
  return Number(rows[0]?.n);
}

/** How many sessions' rows there are. */
async function sessionsLeft(): Promise<number> {
  const { rows } = await sql<{ n: string }>`select pg_catalog.count(*)::text as n from identity.sessions`.execute(app);
  return Number(rows[0]?.n);
}

const cutAt = (seq: bigint, sessionId: string): unknown =>
  expect.objectContaining({
    event: 'audit.integrity_failed',
    check: 'platform_chain',
    reason: 'cut_back',
    seq: String(seq),
    rowId: sessionId,
  });

/**
 * A copy that read a session after another signed out (the head seen past the sign-out), then the owner cuts the
 * sign-out off and puts back the head before it and the signed-out session's row: the AT13h attack.
 */
async function signedOutThenCut(...digests: Digest[]) {
  const signed = await signedIn();
  const bystander = await signedIn();
  const before = await headRow();
  const kept = await keep(signed.sessionId);
  await signOut(signed.cookie);
  for (const digest of digests) expect(await copy(digest, false).use(app, bystander.cookie)).toBeDefined();
  const written = (await headRow()).seq;
  await cutBackTo(before);
  await putBack(signed.sessionId, kept);
  return { signed, bystander, before, written };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables & PlatformControlsTables>(
    { ...database.connection('app'), maxConnections: 4 },
    testLogger(),
  );
  // The platform chain started, so it has a head to cut back to.
  await platform.recordAlone(app, sessionsEndedEvent('0199a0f0-0000-7000-8000-000000000208', clock.now()));
});

beforeEach(() => {
  capture = new LogCapture();
  // Each test's people sign in after any answer an earlier one left on the chain.
  clock.advanceBy(60 * 60 * 1000);
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`AT13h, S208: a cut platform chain signs everyone out once, signed, instead of locking the console (Postgres ${server.version})`, () => {
  it('found: the alarm, every session ended with one signed record, the read refused; then a new sign-in works on the same copy', async () => {
    const digest = await newDigest();
    const at = copy(digest);
    const { signed, bystander, written } = await signedOutThenCut(digest);
    const bystanderRow = await keep(bystander.sessionId);
    const signedRow = await keep(signed.sessionId);
    const records = await allEndedRecords();

    expect(await at.use(app, signed.cookie)).toBeUndefined();
    expect(alarms()).toEqual([cutAt(written, signed.sessionId)]);
    expect(answers()).toEqual([
      expect.objectContaining({ level: 'error', check: 'platform_chain', reason: 'cut_back', seen: String(written) }),
    ]);
    expect(await allEndedRecords()).toBe(records + 1);
    expect(await sessionsLeft()).toBe(0);
    // The head seen never lowered: the hand-off pause stays held to it. The sessions' reads are taken from the answer.
    expect(seenOf(digest)).toBe(written);
    const answered = await headRow();
    expect(digest.heads(PLATFORM)?.accepted?.seen?.seq).toBe(answered.seq);

    // Someone signs in again: on this copy, with no restart, every read lets them in, and no further alarm.
    clock.advanceBy(1000);
    const again = await signedIn();
    expect(await at.use(app, again.cookie)).toMatchObject({ sessionId: again.sessionId });
    expect(await at.holder(app, again.cookie)).toBe(again.userId);
    expect(await at.rotate(app, again.sessionId)).toBeDefined();

    // The sessions from before, put back by the owner: no session here, nor on a copy just started, and quietly.
    await putBack(bystander.sessionId, bystanderRow);
    await putBack(signed.sessionId, signedRow);
    expect(await at.use(app, bystander.cookie)).toBeUndefined();
    expect(await at.holder(app, signed.cookie)).toBeUndefined();
    const restarted = copy(await newDigest());
    expect(await restarted.use(app, bystander.cookie)).toBeUndefined();
    expect(await restarted.rotate(app, signed.sessionId)).toBeUndefined();
    expect(alarms()).toHaveLength(1);
    expect(answers()).toHaveLength(1);
  });

  it('positive control: a copy given no database refuses every session as AT13h did, and answers nothing', async () => {
    const digest = await newDigest();
    const { signed, bystander, written } = await signedOutThenCut(digest);
    const records = await allEndedRecords();
    expect(await copy(digest, false).use(app, bystander.cookie)).toBeUndefined();
    expect(await copy(digest, false).holder(app, signed.cookie)).toBeUndefined();
    expect(alarms()).toEqual([cutAt(written, bystander.sessionId), cutAt(written, signed.sessionId)]);
    expect(await allEndedRecords()).toBe(records);
    expect(answers()).toEqual([]);
    // Answered by a copy that can: the cut stands no longer for anyone signing in after.
    expect(await copy(digest).holder(app, signed.cookie)).toBeUndefined();
    expect(await allEndedRecords()).toBe(records + 1);
  });

  it('forced order: two copies find the same cut at once: one record, the other copy takes it, each lets the next sign-in in', async () => {
    const [one, two] = [await newDigest(), await newDigest()];
    const { signed, bystander } = await signedOutThenCut(one, two);
    const records = await allEndedRecords();
    const holder = await database.connect('owner');
    try {
      await holder.query('begin');
      await holder.query('select 1 from platform_controls.audit_head for update');
      // The first copy's answer holds its own lock and waits for the head's, to record.
      const first = copy(one).use(app, bystander.cookie);
      await waitUntilQueued(database.as('admin'), 1);
      // The second finds the cut (a read that takes no row lock) and waits for the first's answer.
      const second = copy(two).holder(app, signed.cookie);
      await waitUntilQueued(database.as('admin'), 2);
      await holder.query('rollback');
      expect(await first).toBeUndefined();
      expect(await second).toBeUndefined();
    } finally {
      await holder.end();
    }
    expect(await allEndedRecords()).toBe(records + 1);
    expect(answers()).toHaveLength(1);
    expect(lines('identity.sessions_all_ended_found')).toHaveLength(1);
    clock.advanceBy(1000);
    const again = await signedIn();
    expect(await copy(one).use(app, again.cookie)).toBeDefined();
    expect(await copy(two).holder(app, again.cookie)).toBe(again.userId);
    expect(answers()).toHaveLength(1);
  });

  it('a copy finding the cut after another answered: held to the same head it takes that answer; to another, it answers again', async () => {
    const [behind, one, two] = [await newDigest(), await newDigest(), await newDigest()];
    const first = await signedIn();
    const before = await headRow();
    await signOut((await signedIn()).cookie);
    // One copy saw the chain after the first sign-out only, the other two after a second.
    expect(await copy(behind, false).use(app, first.cookie)).toBeDefined();
    await signOut((await signedIn()).cookie);
    expect(await copy(one, false).use(app, first.cookie)).toBeDefined();
    expect(await copy(two, false).use(app, first.cookie)).toBeDefined();
    await cutBackTo(before);
    const records = await allEndedRecords();

    expect(await copy(one).use(app, first.cookie)).toBeUndefined();
    expect(await allEndedRecords()).toBe(records + 1);
    // Someone signs in again; the other copies find the cut as they read that session.
    clock.advanceBy(1000);
    const again = await signedIn();
    // Found after that committed, at or above it, held to the same head: the record names it, so it is taken.
    expect(await copy(two).holder(app, again.cookie)).toBeUndefined();
    expect(await allEndedRecords()).toBe(records + 1);
    expect(lines('identity.sessions_all_ended_found')).toHaveLength(1);
    expect(await copy(two).holder(app, again.cookie)).toBe(again.userId);
    // Held to another head: the record can't be shown to come after the cut it found, so it answers again.
    expect(await copy(behind).holder(app, again.cookie)).toBeUndefined();
    expect(await allEndedRecords()).toBe(records + 2);
    expect(answers()).toHaveLength(2);
  });

  it('the answer cut off too: found again and answered again, but once a copy a minute at most, refusing meanwhile', async () => {
    const digest = await newDigest();
    const at = copy(digest);
    const { bystander, before } = await signedOutThenCut(digest);
    expect(await at.use(app, bystander.cookie)).toBeUndefined();
    expect(answers()).toHaveLength(1);
    clock.advanceBy(1000);
    const again = await signedIn();
    // Read after the answer: held to it.
    expect(await at.use(app, again.cookie)).toBeDefined();
    const records = await allEndedRecords();

    // The owner cuts the answer off as well, back to the head before it.
    await cutBackTo(before);
    expect(await at.use(app, again.cookie)).toBeUndefined();
    expect(await at.holder(app, again.cookie)).toBeUndefined();
    expect(await allEndedRecords()).toBe(records - 1);
    expect(alarms()).toHaveLength(3);
    expect(answers()).toHaveLength(1);

    clock.advanceBy(ANSWER_EVERY_MS);
    expect(await at.holder(app, again.cookie)).toBeUndefined();
    expect(await allEndedRecords()).toBe(records);
    expect(answers()).toHaveLength(2);
    clock.advanceBy(1000);
    const later = await signedIn();
    expect(await at.use(app, later.cookie)).toBeDefined();
    expect(alarms()).toHaveLength(4);
  });

  it('an answer that cannot be recorded (the head forged) ends nothing, takes nothing, and the reads go on refusing', async () => {
    const digest = await newDigest();
    const at = copy(digest);
    const { cookie, sessionId } = await signedIn();
    expect(await at.use(app, cookie)).toBeDefined();
    const head = await headRow();
    await asOwner('update platform_controls.audit_head set mac = pg_catalog.decode(pg_catalog.repeat($1, 32), $2)', [
      '00',
      'hex',
    ]);
    const records = await allEndedRecords();
    try {
      expect(await at.use(app, cookie)).toBeUndefined();
      expect(lines('identity.sessions_all_end_failed')).toEqual([
        expect.objectContaining({ level: 'error', error: 'ChainBroken' }),
      ]);
      expect(await allEndedRecords()).toBe(records);
      expect(await sessionsLeft()).toBeGreaterThan(0);
      expect(digest.heads(PLATFORM)?.accepted).toBeUndefined();
      expect(answers()).toEqual([]);
    } finally {
      await headBack(head.kept);
    }
    // The head put back: believed again, nothing was ended.
    expect(await at.use(app, cookie)).toMatchObject({ sessionId });
  });

  it('control: honest sign-ins, sign-outs, rotations and ends across two copies answer nothing', async () => {
    const [one, two] = [await newDigest(), await newDigest()];
    checkStatesWith(one);
    const records = await allEndedRecords();
    try {
      const a = await signedIn();
      const b = await signedIn();
      expect(await copy(one).use(app, a.cookie)).toBeDefined();
      expect(await copy(two).use(app, b.cookie)).toBeDefined();
      await signOut(b.cookie);
      expect(await copy(two).holder(app, a.cookie)).toBe(a.userId);
      const rotated = await copy(one).rotate(app, a.sessionId);
      if (rotated === undefined) throw new Error('the session was not rotated');
      await platform.recordAlone(app, sessionRotatedEvent(rotated.retired, clock.now()));
      expect(await copy(two).use(app, rotated.cookie)).toBeDefined();
      const c = await signedIn();
      await platform.recordAlone(app, sessionsEndedEvent(c.userId, clock.now()));
      expect(await copy(one).use(app, rotated.cookie)).toBeDefined();
      expect(await copy(two).holder(app, rotated.cookie)).toBe(a.userId);
    } finally {
      checkStatesWith(undefined);
    }
    expect(alarms()).toEqual([]);
    expect(answers()).toEqual([]);
    expect(await allEndedRecords()).toBe(records);
  });

  it('a rebase of the platform chain after the head was seen clears it as before: no alarm, no answer', async () => {
    let rebasedAt = new Date(0);
    const digest = await newDigest({ rebasedAfter: (_, at) => rebasedAt > at, holds: () => true });
    const { signed } = await signedOutThenCut(digest);
    const records = await allEndedRecords();
    rebasedAt = new Date(clock.now().getTime() + 1000);
    expect(seenOf(digest)).toBeUndefined();
    expect(await copy(digest).holder(app, signed.cookie)).toBe(signed.userId);
    expect(alarms()).toEqual([]);
    expect(answers()).toEqual([]);
    expect(await allEndedRecords()).toBe(records);
  });

  it('a sign-in held behind the cut by its own check of the chain goes ahead once an answer was recorded after it', async () => {
    // An answer recorded before the check got anywhere: never one to let a later cut pass.
    await platform.recordAlone(
      app,
      sessionsAllEndedEvent({ held: { seq: 1n, hash: Buffer.alloc(32) }, found: 1n }, clock.now()),
    );
    clock.advanceBy(1000);
    const ends = { logger: testLogger(capture), signedEnds: createSignedEnds(keys) };
    const endsAt = (userId: string, signedInAt: Date) =>
      app
        .transaction()
        .execute((tx) => sessionsEndedAt(tx as unknown as Kysely<IdentityTables>, userId, ends, signedInAt));
    const digest = await newDigest();
    const person = await signedIn();
    expect(await endsAt(person.userId, clock.now())).toMatchObject({ kind: 'read' });
    const reached = await headRow();
    await signOut((await signedIn()).cookie);
    // The sign-in's check, and a session's read, get past the sign-out; then the owner cuts it off.
    expect(await endsAt(person.userId, clock.now())).toMatchObject({ kind: 'read' });
    expect(await copy(digest, false).use(app, person.cookie)).toBeDefined();
    await cutBackTo(reached);
    // Refused, with the alarm, as before: the answer recorded at the start came before where the check got to.
    expect(await endsAt(person.userId, clock.now())).toEqual({ kind: 'tampered' });
    expect(alarms()).toEqual([expect.objectContaining({ check: 'platform_chain', reason: 'head' })]);

    // A session read finds the cut and answers it: every session ended at its time.
    expect(await copy(digest).use(app, person.cookie)).toBeUndefined();
    const answeredAt = clock.now();
    // A sign-in made before the answer is stale; one made after goes ahead, on the same copy's check.
    expect(await endsAt(person.userId, new Date(answeredAt.getTime() - 1))).toEqual({
      kind: 'read',
      endedAt: answeredAt,
    });
    clock.advanceBy(1000);
    const after = await endsAt(person.userId, clock.now());
    expect(after).toEqual({ kind: 'read', endedAt: answeredAt });
  });
});

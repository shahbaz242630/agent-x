// FX-TAMPER on sessions and step-up challenges (S205 tamper pass), as the
// database's owner: agentx_owner, the role the migration job logs in as,
// holding none of the app's keys. Both tables are global (no organisation), so
// no row wall stands in its way: it can insert or update any row.
//
// Before 0100 a session was found by its cookie's hash alone, and a
// challenge's evidence was whatever its row said: a planted session signed the
// owner in as any admin, and a challenge moved to verified, with a passkey,
// had the app sign an admin's change itself (Threat-Model row 13: operators
// can stop money, not grant authority). Now each row's `session-mac` MAC must
// hold: a row the owner wrote is no session and no challenge, and raises the
// integrity alarm. Each attack has its control beside it, the same steps
// without the owner's edit, so a check that refuses everything can't pass.
import { createHash, randomBytes } from 'node:crypto';

import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { createDigestLog } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, type KeyProvider, PURPOSES } from '@agentx/platform/keys';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  type AuditTables,
  ChainBroken,
  checkStatesWith,
  createAuditTrail,
  type StateDigest,
} from '../../audit/index.ts';
import {
  createPlatformChain,
  type PlatformControlsTables,
  type PlatformTransaction,
} from '../../platform-controls/index.ts';
import {
  createSessions,
  endSessionsOf,
  LONGEST_ABSOLUTE_SECONDS,
  lockSessionsOf,
  sessionEndedEvent,
  sessionRotatedEvent,
  sessionsEndedEvent,
} from './sessions.ts';
import {
  createStepUpChallenges,
  type StepUpBinding,
  type StepUpEvidence,
  stepUpDetails,
} from './step-up-challenges.ts';
import { SESSION_ENDED, signedEndKey, signedEndSubjectOf } from './signed-ends.ts';
import type { IdentityTables } from './tables.ts';
import { subjectOfUser, userForSubject, userOfSubject, UserUnbelieved } from './users.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables & AuditTables>;

/** The app's keys, `session-mac` at version `current` with every version up to it held. The owner has none. */
const keysAt = (current: number): KeyProvider =>
  createKeyProvider(
    Object.fromEntries(
      PURPOSES.map((purpose, index) => {
        const versions = purpose === 'session-mac' ? current : 1;
        return [
          purpose,
          {
            current: versions,
            versions: new Map(Array.from({ length: versions }, (_, v) => [v + 1, Buffer.alloc(32, index * 8 + v + 1)])),
          },
        ];
      }),
    ),
  );
const keys = keysAt(1);

const START = new Date('2026-11-19T09:00:00Z');
const ids = new SequentialIds(0x5205_0000);
const clock = new FixedClock(START);
const TIMEOUTS = { idleSeconds: 1800, absoluteSeconds: 43_200 };
const PASSKEY = ['pwd', 'user', 'mfa'];
const EVIDENCE: StepUpEvidence = {
  authTime: START,
  amr: PASSKEY,
  idpSessionId: 'V1_2',
  idTokenHash: createHash('sha256').update('the ID token').digest(),
};

const sha256 = (value: string): Buffer => createHash('sha256').update(value, 'ascii').digest();

let capture: LogCapture;
const sessions = (with_: KeyProvider = keys) =>
  createSessions({ ids, clock, timeouts: TIMEOUTS, keys: with_, logger: testLogger(capture) });
const challenges = (with_: KeyProvider = keys) =>
  createStepUpChallenges({ ids, clock, keys: with_, logger: testLogger(capture) });

/** The integrity alarms raised since the test began. */
const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

let people = 0;
const ISSUER = 'https://auth.example.test';
async function person(): Promise<string> {
  people += 1;
  return userForSubject(
    app,
    { issuer: ISSUER, subject: `session-tamper-${String(people)}` },
    { ids, clock, keys, logger: testLogger() },
  );
}

/** A person made through the app, with the subject they sign in as. */
async function personAs(subject: string): Promise<string> {
  return userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger(capture) });
}

const macs = () => ({ keys, logger: testLogger(capture) });

/** An admin signed in with a passkey: their user, session and cookie. */
async function signedIn(): Promise<{ userId: string; sessionId: string; cookie: string }> {
  const userId = await person();
  const opened = await sessions().open(app, userId, { idpSessionId: 'V1_1', authTime: START, amr: PASSKEY });
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

/** The person's sessions all ended at `at`, as a role change does (membership-changes.ts), the end signed. */
const allEnded = (userId: string, at: Date) =>
  app.transaction().execute(async (tx) => {
    await lockSessionsOf(tx, [userId]);
    await endSessionsOf(tx, userId, at);
    await createPlatformChain({ keys, ids }).record(
      tx as unknown as PlatformTransaction,
      sessionsEndedEvent(userId, at),
    );
  });

/** The session this cookie holds signed out, as the console does: its row deleted and its end signed on `chain`. */
const signedOutOn = (chain: ReturnType<typeof createPlatformChain>, cookie: string) =>
  app.transaction().execute(async (tx) => {
    const ended = await sessions().end(tx as unknown as Kysely<IdentityTables>, cookie);
    if (ended === undefined) throw new Error('the session did not end');
    await chain.record(tx as unknown as PlatformTransaction, sessionEndedEvent(ended, clock.now()));
  });

/** The owner swaps the session's row for the one it kept, MACs and all. */
async function swapRow(sessionId: string, kept: unknown): Promise<void> {
  await asOwner('delete from identity.sessions where id = $1', [sessionId]);
  await asOwner(
    `insert into identity.sessions
       select * from pg_catalog.json_populate_record(null::identity.sessions, $1::json)`,
    [JSON.stringify(kept)],
  );
}

/** A person's MAC and its key version as the database holds them. */
const sealOf = (userId: string) =>
  app.selectFrom('identity.users').select(['mac', 'mac_key_version']).where('id', '=', userId).executeTakeFirst();

/** Holds the session's challenges and consumes one, in a transaction, as an admin's change does. */
const consumeFor = (binding: StepUpBinding, challengeId: string) =>
  withTenant(app, '0199a0f0-0000-7000-8000-000000000205', async (tx) => {
    const held = await challenges().hold(tx, binding.sessionId);
    return challenges().consume(tx, held, challengeId, binding, { passkeyRequired: true });
  });

const challengeRow = (id: string) =>
  app.selectFrom('identity.step_up_challenges').select(['id', 'verified_at']).where('id', '=', id).executeTakeFirst();

/** An open challenge for an admin's role change in the session. */
async function opened(sessionId: string): Promise<{ binding: StepUpBinding; challengeId: string }> {
  const binding: StepUpBinding = { sessionId, action: 'members.change-role', changeHash: sha256(ids.next()) };
  const challenge = await challenges().open(app, binding);
  if (challenge === undefined) throw new Error('the challenge did not open');
  return { binding, challengeId: challenge.challengeId };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables & AuditTables>(
    { ...database.connection('app'), maxConnections: 2 },
    testLogger(),
  );
});

beforeEach(() => {
  capture = new LogCapture();
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the owner can't sign in as a person (Postgres ${server.version})`, () => {
  it("control: the app's own session is found by its cookie, with no alarm", async () => {
    const { userId, sessionId, cookie } = await signedIn();

    expect(await sessions().use(app, cookie)).toMatchObject({ sessionId, userId, amr: PASSKEY });
    expect(await sessions().holder(app, cookie)).toBe(userId);
    expect(alarms()).toEqual([]);
  });

  it('a session row the owner plants, with a cookie of its own choosing, signs no one in, and raises the alarm', async () => {
    const admin = await person();
    const cookie = randomBytes(32).toString('base64url');
    const rowId = ids.next();
    await asOwner(
      `insert into identity.sessions
         (id, user_id, cookie_hash, auth_time, amr, created_at, last_seen_at, ends_at, mac, mac_key_version)
       values ($1, $2, $3, $4, '{pwd,user,mfa}', $4, $4, $5, $6, 1)`,
      [rowId, admin, sha256(cookie), START, new Date(START.getTime() + 3_600_000), randomBytes(32)],
    );

    expect(await sessions().use(app, cookie)).toBeUndefined();
    expect(await sessions().holder(app, cookie)).toBeUndefined();
    expect(await sessions().rotate(app, rowId)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'session', reason: 'mac', rowId, userId: admin }),
      expect.objectContaining({ check: 'session', rowId }),
      expect.objectContaining({ check: 'session', rowId }),
    ]);
  });

  it.each([
    ['its cookie hash, for one of its own', 'cookie_hash'],
    ['its person, to another', 'user_id'],
    ['its methods, to a passkey', 'amr'],
    ['its absolute end, a day later', 'ends_at'],
    ['its MAC, to another row’s', 'mac'],
    ['its key version, to one never made', 'mac_key_version'],
  ])('a real session with %s changed by the owner is no session, and raises the alarm', async (_, column) => {
    const victim = await signedIn();
    const other = await signedIn();
    const theirs = randomBytes(32).toString('base64url');
    const values: Record<string, unknown> = {
      cookie_hash: sha256(theirs),
      user_id: other.userId,
      amr: ['pwd', 'user', 'mfa', 'hwk'],
      ends_at: new Date(START.getTime() + 36 * 3_600_000),
      mac_key_version: 7,
    };
    if (column === 'mac') {
      await asOwner(
        'update identity.sessions set mac = (select mac from identity.sessions where id = $2) where id = $1',
        [victim.sessionId, other.sessionId],
      );
    } else {
      const statements: Record<string, string> = {
        cookie_hash: 'update identity.sessions set cookie_hash = $2 where id = $1',
        user_id: 'update identity.sessions set user_id = $2 where id = $1',
        amr: 'update identity.sessions set amr = $2 where id = $1',
        ends_at: 'update identity.sessions set ends_at = $2 where id = $1',
        mac_key_version: 'update identity.sessions set mac_key_version = $2 where id = $1',
      };
      await asOwner(String(statements[column]), [victim.sessionId, values[column]]);
    }

    expect(await sessions().use(app, column === 'cookie_hash' ? theirs : victim.cookie)).toBeUndefined();
    expect(alarms()).toEqual([expect.objectContaining({ check: 'session', reason: 'mac', rowId: victim.sessionId })]);
    // The other person's own session, untouched, is still theirs.
    expect(await sessions().use(app, other.cookie)).toMatchObject({ sessionId: other.sessionId });
  });

  it("a session's rotation makes its MAC again, and a session made with an older key version still holds", async () => {
    const { sessionId, cookie } = await signedIn();
    const rotated = await sessions().rotate(app, sessionId);
    if (rotated === undefined) throw new Error('the session did not rotate');

    expect(await sessions().use(app, cookie)).toBeUndefined();
    const later = keysAt(2);
    expect(await sessions(later).use(app, rotated.cookie)).toMatchObject({ sessionId });
    // Rotated again under version 2: the row now names it, for both its MACs.
    const again = await sessions(later).rotate(app, sessionId);
    if (again === undefined) throw new Error('the session did not rotate');
    expect(
      await app
        .selectFrom('identity.sessions')
        .select(['mac_key_version', 'last_use_mac_key_version'])
        .where('id', '=', sessionId)
        .executeTakeFirst(),
    ).toEqual({ mac_key_version: 2, last_use_mac_key_version: 2 });
    expect(await sessions(later).use(app, again.cookie)).toMatchObject({ sessionId });
    expect(alarms()).toEqual([]);
  });
});

describe(`SEC-DB-14 R-15 the owner can't put back a session that was ended (S207; Postgres ${server.version})`, () => {
  const platform = createPlatformChain({ keys, ids });

  /** The owner puts the row back exactly as it was, its MAC and all. */
  const putBack = (kept: unknown) =>
    asOwner(
      `insert into identity.sessions
         select * from pg_catalog.json_populate_record(null::identity.sessions, $1::json)`,
      [JSON.stringify(kept)],
    );

  /** A sign-out as the app makes one (sign-in-flow.ts): the session deleted and its end signed, in one transaction. */
  const signOut = (cookie: string) =>
    app.transaction().execute(async (tx) => {
      // As the sign-in flow holds it: a transaction on the identity tables alone.
      const ended = await sessions().end(tx as unknown as Kysely<IdentityTables>, cookie);
      if (ended !== undefined) {
        await platform.record(tx as unknown as PlatformTransaction, sessionEndedEvent(ended, clock.now()));
      }
      return ended;
    });

  const endAll = allEnded;

  const rowOf = (sessionId: string) =>
    app.selectFrom('identity.sessions').select('id').where('id', '=', sessionId).executeTakeFirst();

  it('control: a session never ended, deleted and put back by the owner, is still found, with no alarm', async () => {
    const { userId, sessionId, cookie } = await signedIn();
    const kept = await keep(sessionId);
    await asOwner('delete from identity.sessions where id = $1', [sessionId]);
    await putBack(kept);

    expect(await sessions().use(app, cookie)).toMatchObject({ sessionId, userId });
    expect(await sessions().holder(app, cookie)).toBe(userId);
    expect(await sessions().rotate(app, sessionId)).toBeDefined();
    expect(alarms()).toEqual([]);
  });

  it('a session signed out of, put back byte for byte, is no session, and raises the alarm', async () => {
    const { userId, sessionId, cookie } = await signedIn();
    const other = await sessions().open(app, userId, { idpSessionId: 'V1_3', authTime: START, amr: PASSKEY });
    const kept = await keep(sessionId);
    expect(await signOut(cookie)).toEqual({ userId, sessionId });
    expect(await rowOf(sessionId)).toBeUndefined();

    await putBack(kept);
    expect(await rowOf(sessionId)).toEqual({ id: sessionId });
    expect(await sessions().use(app, cookie)).toBeUndefined();
    expect(await sessions().holder(app, cookie)).toBeUndefined();
    expect(await sessions().rotate(app, sessionId)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'session', reason: 'ended', rowId: sessionId, userId }),
      expect.objectContaining({ check: 'session', reason: 'ended', rowId: sessionId }),
      expect.objectContaining({ check: 'session', reason: 'ended', rowId: sessionId }),
    ]);
    // The person's other session, never signed out of, is still theirs.
    expect(await sessions().use(app, other.cookie)).toMatchObject({ sessionId: other.sessionId });
    expect(alarms()).toHaveLength(3);
  });

  it("a session ended with all its person's, put back, is no session; one signed in after the end is", async () => {
    const { userId, sessionId, cookie } = await signedIn();
    const kept = await keep(sessionId);
    const at = new Date(START.getTime() + 1000);
    await endAll(userId, at);
    expect(await rowOf(sessionId)).toBeUndefined();

    await putBack(kept);
    expect(await sessions().use(app, cookie)).toBeUndefined();
    expect(await sessions().holder(app, cookie)).toBeUndefined();
    expect(await sessions().rotate(app, sessionId)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ check: 'session', reason: 'ended', rowId: sessionId, userId }),
      expect.objectContaining({ check: 'session', reason: 'ended', rowId: sessionId }),
      expect.objectContaining({ check: 'session', reason: 'ended', rowId: sessionId }),
    ]);
    // A sign-in made at the end's moment is not before it (the sign-in's own rule): its session is found.
    const after = await sessions().open(app, userId, { idpSessionId: 'V1_4', authTime: at, amr: PASSKEY });
    expect(await sessions().use(app, after.cookie)).toMatchObject({ sessionId: after.sessionId });
    expect(alarms()).toHaveLength(3);
  });

  it("another person's ends don't touch this person's session", async () => {
    const mine = await signedIn();
    const theirs = await signedIn();
    await signOut(theirs.cookie);
    await endAll(theirs.userId, new Date(START.getTime() + 1000));

    expect(await sessions().use(app, mine.cookie)).toMatchObject({ sessionId: mine.sessionId });
    expect(alarms()).toEqual([]);
  });
});

describe(`the owner can't verify a person's step-up (Postgres ${server.version})`, () => {
  it("control: the app's own verified challenge is consumed for the change, with no alarm", async () => {
    const { sessionId } = await signedIn();
    const { binding, challengeId } = await opened(sessionId);
    expect(await challenges().pending(app, challengeId, sessionId)).toMatchObject({ challengeId });
    expect(await challenges().recordEvidence(app, challengeId, sessionId, EVIDENCE)).toBe(true);

    expect(await consumeFor(binding, challengeId)).toMatchObject({ challengeId, evidence: { amr: PASSKEY } });
    expect(await challengeRow(challengeId)).toBeUndefined();
    expect(alarms()).toEqual([]);
  });

  it('a challenge the owner moves to verified, with a passkey, is never consumed, and raises the alarm', async () => {
    const { userId, sessionId } = await signedIn();
    const { binding, challengeId } = await opened(sessionId);
    await asOwner(
      `update identity.step_up_challenges
       set verified_at = $2, auth_time = $2, amr = '{pwd,user,mfa}', id_token_hash = $3
       where id = $1`,
      [challengeId, START, sha256('no ID token at all')],
    );

    expect(await consumeFor(binding, challengeId)).toBeUndefined();
    // Left as it was, for the incident to find.
    expect(await challengeRow(challengeId)).toMatchObject({ id: challengeId });
    expect(alarms()).toEqual([
      expect.objectContaining({ check: 'step_up_challenge', reason: 'mac', rowId: challengeId, userId }),
    ]);
  });

  it('a verified challenge the owner leaves with part of its evidence missing is never consumed', async () => {
    const { sessionId } = await signedIn();
    const { binding, challengeId } = await opened(sessionId);
    expect(await challenges().recordEvidence(app, challengeId, sessionId, EVIDENCE)).toBe(true);
    await asOwner('alter table identity.step_up_challenges drop constraint evidence_whole', []);
    try {
      await asOwner('update identity.step_up_challenges set id_token_hash = null where id = $1', [challengeId]);

      expect(await consumeFor(binding, challengeId)).toBeUndefined();
      expect(alarms()).toEqual([expect.objectContaining({ check: 'step_up_challenge', rowId: challengeId })]);
    } finally {
      await asOwner('delete from identity.step_up_challenges where id = $1', [challengeId]);
      await asOwner(
        `alter table identity.step_up_challenges add constraint evidence_whole check (
           (verified_at is null and auth_time is null and amr is null and idp_session_id is null and id_token_hash is null)
           or (verified_at is not null and auth_time is not null and amr is not null and id_token_hash is not null))`,
        [],
      );
    }
  });

  it('a challenge genuinely verified with an app code, which the owner says was a passkey, is never consumed (S205 mutation pass)', async () => {
    const { sessionId } = await signedIn();
    const { binding, challengeId } = await opened(sessionId);
    expect(
      await challenges().recordEvidence(app, challengeId, sessionId, { ...EVIDENCE, amr: ['pwd', 'otp', 'mfa'] }),
    ).toBe(true);
    await asOwner("update identity.step_up_challenges set amr = '{pwd,user,mfa}' where id = $1", [challengeId]);

    expect(await consumeFor(binding, challengeId)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ check: 'step_up_challenge', reason: 'mac', rowId: challengeId }),
    ]);
  });

  it('a genuinely verified challenge the owner points at another change is never consumed for it', async () => {
    const { sessionId } = await signedIn();
    const { binding, challengeId } = await opened(sessionId);
    expect(await challenges().recordEvidence(app, challengeId, sessionId, EVIDENCE)).toBe(true);
    const other = { ...binding, changeHash: sha256('the owner’s change') };
    await asOwner('update identity.step_up_challenges set change_hash = $2 where id = $1', [
      challengeId,
      other.changeHash,
    ]);

    expect(await consumeFor(other, challengeId)).toBeUndefined();
    expect(await consumeFor(binding, challengeId)).toBeUndefined();
    expect(alarms()).toHaveLength(1);
  });

  it('a challenge the owner points at another change before it is verified is never pending, nor verified', async () => {
    const { sessionId } = await signedIn();
    const { challengeId } = await opened(sessionId);
    await asOwner('update identity.step_up_challenges set action = $2 where id = $1', [
      challengeId,
      'agents.keys-rotate',
    ]);

    expect(await challenges().pending(app, challengeId, sessionId)).toBeUndefined();
    expect(await challenges().recordEvidence(app, challengeId, sessionId, EVIDENCE)).toBe(false);
    expect(await challengeRow(challengeId)).toEqual({ id: challengeId, verified_at: null });
    expect(alarms()).toHaveLength(2);
  });

  it('a challenge the owner plants for a real session, already verified, is never consumed', async () => {
    const { userId, sessionId } = await signedIn();
    const binding: StepUpBinding = { sessionId, action: 'members.change-role', changeHash: sha256('planted') };
    const challengeId = ids.next();
    await asOwner(
      `insert into identity.step_up_challenges
         (id, session_id, user_id, action, change_hash, nonce, created_at, ends_at,
          verified_at, auth_time, amr, id_token_hash, mac, mac_key_version)
       values ($1, $2, $3, $4, $5, 'n', $6, $7, $6, $6, '{pwd,user,mfa}', $8, $9, 1)`,
      [
        challengeId,
        sessionId,
        userId,
        binding.action,
        binding.changeHash,
        START,
        new Date(START.getTime() + 300_000),
        sha256('no token'),
        randomBytes(32),
      ],
    );

    expect(await consumeFor(binding, challengeId)).toBeUndefined();
    expect(alarms()).toEqual([expect.objectContaining({ check: 'step_up_challenge', rowId: challengeId })]);
  });
});

describe(`SEC-DB-15 the owner can't use a step-up twice by putting its challenge back (R-15, S206; Postgres ${server.version})`, () => {
  const trail = createAuditTrail({ keys, ids });
  const ORG = '0199a0f0-0000-7000-8000-000000005206';

  /**
   * An admin's change in the organisation, as every change consumes one: the
   * challenge consumed and the change's event, with the step-up's evidence,
   * recorded in the same transaction. Undefined, and nothing recorded, if the
   * challenge is refused.
   */
  const changeWith = (userId: string, binding: StepUpBinding, challengeId: string, org = ORG, made = challenges()) =>
    withTenant(app, org, async (tx) => {
      const held = await made.hold(tx, binding.sessionId);
      const consumed = await made.consume(tx, held, challengeId, binding, { passkeyRequired: true });
      if (consumed === undefined) return undefined;
      await trail.record(tx, org, {
        actor: { type: 'user', id: userId },
        action: 'probe.changed',
        subject: { type: 'probe', id: binding.sessionId, version: 1 },
        details: stepUpDetails(consumed),
      });
      return consumed;
    });

  /** A verified challenge, and the row as the owner reads it before its change deletes it. */
  async function verified(sessionId: string) {
    const { binding, challengeId } = await opened(sessionId);
    expect(await challenges().recordEvidence(app, challengeId, sessionId, EVIDENCE)).toBe(true);
    const [kept] = await asOwner(
      'select pg_catalog.row_to_json(c) as kept from identity.step_up_challenges c where c.id = $1',
      [challengeId],
    );
    return { binding, challengeId, kept: kept?.kept };
  }

  /** The owner puts the row back exactly as it was, its MAC and all. */
  const putBack = (kept: unknown) =>
    asOwner(
      `insert into identity.step_up_challenges
         select * from pg_catalog.json_populate_record(null::identity.step_up_challenges, $1::json)`,
      [JSON.stringify(kept)],
    );

  it('control: a challenge never used, put back by the owner, is consumed with no alarm', async () => {
    const { userId, sessionId } = await signedIn();
    const { binding, challengeId, kept } = await verified(sessionId);
    await asOwner('delete from identity.step_up_challenges where id = $1', [challengeId]);
    await putBack(kept);

    expect(await changeWith(userId, binding, challengeId)).toMatchObject({ challengeId });
    expect(alarms()).toEqual([]);
  });

  it('a used challenge the owner puts back, byte for byte, is never consumed again, and raises the alarm', async () => {
    const { userId, sessionId } = await signedIn();
    const { binding, challengeId, kept } = await verified(sessionId);
    expect(await changeWith(userId, binding, challengeId)).toMatchObject({ challengeId });
    expect(await challengeRow(challengeId)).toBeUndefined();
    // The organisation goes on working meanwhile: the change's event is no longer its newest.
    const other = await signedIn();
    const next = await verified(other.sessionId);
    expect(await changeWith(other.userId, next.binding, next.challengeId)).toMatchObject({
      challengeId: next.challengeId,
    });

    await putBack(kept);
    expect(await challengeRow(challengeId)).toMatchObject({ id: challengeId });
    expect(await changeWith(userId, binding, challengeId)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ check: 'step_up_challenge', reason: 'already_used', rowId: challengeId, userId }),
    ]);
    // Left as it was, for the sweep: the change and its event were never made again.
    expect(await challengeRow(challengeId)).toMatchObject({ id: challengeId });
    const made = await withTenant(app, ORG, (tx) =>
      tx
        .selectFrom('audit.events')
        .select('seq')
        .where('action', '=', 'probe.changed')
        .where('actor_id', '=', userId)
        .execute(),
    );
    expect(made).toHaveLength(1);

    // The person's next step-up, a fresh challenge, still works.
    const fresh = await verified(sessionId);
    expect(await changeWith(userId, fresh.binding, fresh.challengeId)).toMatchObject({
      challengeId: fresh.challengeId,
    });
    expect(alarms()).toHaveLength(1);
  });

  it("a used challenge put back is refused when its change was the organisation's first event in the window too", async () => {
    const { userId, sessionId } = await signedIn();
    const { binding, challengeId, kept } = await verified(sessionId);
    const fresh = '0199a0f0-0000-7000-8000-000000015206';
    expect(await changeWith(userId, binding, challengeId, fresh)).toMatchObject({ challengeId });

    await putBack(kept);
    expect(await changeWith(userId, binding, challengeId, fresh)).toBeUndefined();
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'already_used', rowId: challengeId })]);
  });

  /** Runs one statement as agentx_owner inside the organisation, as the wall binds the owner too. */
  async function asOwnerIn(org: string, text: string, values: readonly unknown[]): Promise<void> {
    const owner = await database.connect('owner');
    try {
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [org]);
      // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text; every value is bound.
      await owner.query(text, values);
    } finally {
      await owner.end();
    }
  }

  it.each([
    ['deletes', 'delete from audit.events where org_id = $1 and seq = $2'],
    [
      'moves to another person',
      "update audit.events set actor_id = '0199a0f0-0000-7000-8000-0000000000ff' where org_id = $1 and seq = $2",
    ],
    ['empties the details of', "update audit.events set details = '{}' where org_id = $1 and seq = $2"],
  ])(
    "the owner who %s the change's event to put the used challenge back finds the chain refuses the replay, and the alarm",
    async (_what, hide) => {
      const { userId, sessionId } = await signedIn();
      const { binding, challengeId, kept } = await verified(sessionId);
      const org = ids.next();
      expect(await changeWith(userId, binding, challengeId, org)).toMatchObject({ challengeId });
      // The organisation goes on working: the change's event is mid-chain, as the owner would find it.
      const other = await signedIn();
      const next = await verified(other.sessionId);
      expect(await changeWith(other.userId, next.binding, next.challengeId, org)).toBeDefined();

      await asOwnerIn(org, hide, [org, 1]);
      await putBack(kept);
      await expect(changeWith(userId, binding, challengeId, org)).rejects.toThrow(ChainBroken);
      expect(alarms()).toEqual([
        expect.objectContaining({ check: 'step_up_challenge', reason: 'chain_unverified', rowId: challengeId }),
      ]);
      // Refused whole: the challenge is left where the owner put it, and no new event was sealed.
      expect(await challengeRow(challengeId)).toMatchObject({ id: challengeId });
    },
  );

  it('a challenge consumed outside any organisation is refused outright: there is no trail to tell its use', async () => {
    const { sessionId } = await signedIn();
    const { binding, challengeId } = await verified(sessionId);
    await expect(
      app.transaction().execute(async (tx) => {
        const held = await challenges().hold(tx, sessionId);
        return challenges().consume(tx, held, challengeId, binding, { passkeyRequired: true });
      }),
    ).rejects.toThrow(/only in an organisation's transaction/);
    expect(alarms()).toEqual([]);
  });

  it("reads from just before the challenge opened by the app's clock, so a use right after it still counts", async () => {
    // A clock on the database's own time, as in production: the use's event is recorded seconds after the challenge opens.
    const [now] = await asOwner('select pg_catalog.clock_timestamp() as now', []);
    const live = new FixedClock(now?.now as Date);
    const made = createStepUpChallenges({ ids, clock: live, keys, logger: testLogger(capture) });
    const userId = await person();
    const { sessionId } = await createSessions({
      ids,
      clock: live,
      timeouts: TIMEOUTS,
      keys,
      logger: testLogger(capture),
    }).open(app, userId, { idpSessionId: 'V1_1', authTime: live.now(), amr: PASSKEY });
    const binding: StepUpBinding = { sessionId, action: 'members.change-role', changeHash: sha256(ids.next()) };
    const challenge = await made.open(app, binding);
    if (challenge === undefined) throw new Error('the challenge did not open');
    const { challengeId } = challenge;
    expect(await made.recordEvidence(app, challengeId, sessionId, { ...EVIDENCE, authTime: live.now() })).toBe(true);
    const [kept] = await asOwner(
      'select pg_catalog.row_to_json(c) as kept from identity.step_up_challenges c where c.id = $1',
      [challengeId],
    );
    expect(await changeWith(userId, binding, challengeId, ORG, made)).toMatchObject({ challengeId });

    await putBack(kept?.kept);
    expect(await changeWith(userId, binding, challengeId, ORG, made)).toBeUndefined();
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'already_used', rowId: challengeId })]);
  });

  it("another person's use of a challenge with the same ID in their details doesn't count as this one's", async () => {
    const { userId, sessionId } = await signedIn();
    const other = await signedIn();
    const { binding, challengeId } = await verified(sessionId);
    // The other person's event names this challenge: only the challenge's own person's events are read.
    await withTenant(app, ORG, (tx) =>
      trail.record(tx, ORG, {
        actor: { type: 'user', id: other.userId },
        action: 'probe.changed',
        subject: { type: 'probe', id: other.sessionId, version: 1 },
        details: { stepUpChallengeId: challengeId },
      }),
    );

    expect(await changeWith(userId, binding, challengeId)).toMatchObject({ challengeId });
    expect(alarms()).toEqual([]);
  });
});

describe(`the owner can't move a person to its own login account (Postgres ${server.version})`, () => {
  it('control: a person is found by their own subject, and theirs by their ID, with no alarm', async () => {
    const admin = await personAs('admin-control');

    expect(await personAs('admin-control')).toBe(admin);
    expect(await userOfSubject(app, { issuer: ISSUER, subject: 'admin-control' }, macs())).toBe(admin);
    expect(await subjectOfUser(app, admin, macs())).toEqual({ issuer: ISSUER, subject: 'admin-control' });
    expect(alarms()).toEqual([]);
  });

  it("an admin's subject moved to the owner's own login account signs no one in as the admin, and raises the alarm", async () => {
    const admin = await personAs('admin-x');
    const theirs = await personAs('owner-own');
    // The owner's own row out of the way of the unique key first, then the admin's moved onto its subject.
    await asOwner('update identity.users set subject = $2 where id = $1', [theirs, 'owner-parked']);
    await asOwner('update identity.users set subject = $2 where id = $1', [admin, 'owner-own']);

    // The sign-in (made, or found), the step-up's person, and the address book's subject: none is the admin.
    await expect(personAs('owner-own')).rejects.toBeInstanceOf(UserUnbelieved);
    expect(await userOfSubject(app, { issuer: ISSUER, subject: 'owner-own' }, macs())).toBeUndefined();
    expect(await subjectOfUser(app, admin, macs())).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'user', reason: 'mac', rowId: admin, userId: admin }),
      expect.objectContaining({ check: 'user', rowId: admin }),
      expect.objectContaining({ check: 'user', rowId: admin }),
    ]);
  });

  it('SEC-DB-10 R-15 a person whose MAC the owner nulled is never believed, and nothing gives them one again', async () => {
    const late = await personAs('no-mac');
    await asOwner('update identity.users set mac = null, mac_key_version = null where id = $1', [late]);

    await expect(personAs('no-mac')).rejects.toBeInstanceOf(UserUnbelieved);
    expect(await userOfSubject(app, { issuer: ISSUER, subject: 'no-mac' }, macs())).toBeUndefined();
    expect(await subjectOfUser(app, late, macs())).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ check: 'user', rowId: late }),
      expect.objectContaining({ check: 'user', rowId: late }),
      expect.objectContaining({ check: 'user', rowId: late }),
    ]);
    expect(await sealOf(late)).toEqual({ mac: null, mac_key_version: null });
  });

  it("SEC-DB-10 R-15 an admin's MAC nulled and subject moved to the owner's own login account signs no one in as the admin", async () => {
    // The S207 attack on the deleted start-up backfill: a row with no MAC used to be sealed at the API's next start.
    const admin = await personAs('admin-unsealed');
    await asOwner('update identity.users set mac = null, mac_key_version = null, subject = $2 where id = $1', [
      admin,
      'owner-login',
    ]);

    await expect(personAs('owner-login')).rejects.toBeInstanceOf(UserUnbelieved);
    expect(await userOfSubject(app, { issuer: ISSUER, subject: 'owner-login' }, macs())).toBeUndefined();
    expect(await subjectOfUser(app, admin, macs())).toBeUndefined();
    // Nor did any of it seal the row, and no second person was made for the owner's subject.
    expect(await sealOf(admin)).toEqual({ mac: null, mac_key_version: null });
    const [count] = await asOwner('select count(*)::int as n from identity.users where subject = $1', ['owner-login']);
    expect(count?.n).toBe(1);
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'user', reason: 'mac', rowId: admin, userId: admin }),
      expect.objectContaining({ check: 'user', rowId: admin }),
      expect.objectContaining({ check: 'user', rowId: admin }),
    ]);
  });
});

describe(`the owner can't end someone else's login sessions, nor open a challenge on a forged session (Postgres ${server.version})`, () => {
  it("control: a sign-out of the app's own session names its person", async () => {
    const { userId, sessionId, cookie } = await signedIn();

    expect(await sessions().end(app, cookie)).toEqual({ userId, sessionId });
    expect(
      await app.selectFrom('identity.sessions').select('id').where('id', '=', sessionId).executeTakeFirst(),
    ).toBeUndefined();
    expect(alarms()).toEqual([]);
  });

  it('a sign-out of a session the owner planted for an admin names no one, deletes it, and raises the alarm', async () => {
    const admin = await person();
    const cookie = randomBytes(32).toString('base64url');
    const rowId = ids.next();
    await asOwner(
      `insert into identity.sessions
         (id, user_id, cookie_hash, auth_time, amr, created_at, last_seen_at, ends_at, mac, mac_key_version)
       values ($1, $2, $3, $4, '{pwd,user,mfa}', $4, $4, $5, $6, 1)`,
      [rowId, admin, sha256(cookie), START, new Date(START.getTime() + 3_600_000), randomBytes(32)],
    );

    expect(await sessions().end(app, cookie)).toBeUndefined();
    expect(
      await app.selectFrom('identity.sessions').select('id').where('id', '=', rowId).executeTakeFirst(),
    ).toBeUndefined();
    expect(alarms()).toEqual([expect.objectContaining({ check: 'session', rowId, userId: admin })]);
  });

  it('a challenge is never opened on a session whose MAC fails, so it binds no one', async () => {
    const victim = await signedIn();
    const other = await signedIn();
    await asOwner('update identity.sessions set user_id = $2 where id = $1', [victim.sessionId, other.userId]);

    expect(
      await challenges().open(app, {
        sessionId: victim.sessionId,
        action: 'members.change-role',
        changeHash: sha256('bound to the wrong person'),
      }),
    ).toBeUndefined();
    expect(alarms()).toEqual([expect.objectContaining({ check: 'session', rowId: victim.sessionId })]);
  });
});

describe(`SEC-DB-16 R-15 the owner can't bring back an idle session, nor one from before a step-up (S207 GM-4; Postgres ${server.version})`, () => {
  const platform = createPlatformChain({ keys, ids });
  const IDLE_MS = TIMEOUTS.idleSeconds * 1000;

  /** Sessions on a clock of the test's own, from where the file's stands, so moving it touches no other test. */
  function onOwnClock(): { clock: FixedClock; at: ReturnType<typeof sessions> } {
    const own = new FixedClock(clock.now());
    return {
      clock: own,
      at: createSessions({ ids, clock: own, timeouts: TIMEOUTS, keys, logger: testLogger(capture) }),
    };
  }

  async function opened(
    at: ReturnType<typeof sessions>,
  ): Promise<{ userId: string; sessionId: string; cookie: string }> {
    const userId = await person();
    return { userId, ...(await at.open(app, userId, { idpSessionId: 'V1_1', authTime: START, amr: PASSKEY })) };
  }

  /** A step-up's new cookie ID as the sign-in flow makes it: rotated, and the rotation signed, in one transaction. */
  const rotateSigned = (at: ReturnType<typeof sessions>, sessionId: string) =>
    app.transaction().execute(async (tx) => {
      const rotated = await at.rotate(tx as unknown as Kysely<IdentityTables>, sessionId);
      if (rotated === undefined) throw new Error('the session did not rotate');
      await platform.record(tx as unknown as PlatformTransaction, sessionRotatedEvent(rotated.retired, clock.now()));
      return rotated.cookie;
    });

  /** A request's use, in a transaction of its own, as the sign-in flow makes it. */
  const useIn = (at: ReturnType<typeof sessions>, cookie: string) =>
    app.transaction().execute((tx) => at.use(tx as unknown as Kysely<IdentityTables>, cookie));

  const putBack = swapRow;

  const rowOf = (sessionId: string) =>
    app.selectFrom('identity.sessions').select(['id', 'last_seen_at']).where('id', '=', sessionId).executeTakeFirst();

  it('control: a session used within its idle timeout lives on, each use moving it, and goes for good once idle', async () => {
    const { clock: own, at } = onOwnClock();
    const { sessionId, cookie } = await opened(at);
    for (let use = 0; use < 3; use += 1) {
      own.advanceBy(IDLE_MS - 1000);
      expect(await useIn(at, cookie)).toMatchObject({ sessionId, lastSeenAt: own.now() });
    }
    expect(await at.holder(app, cookie)).toBeDefined();
    own.advanceBy(IDLE_MS);

    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([]);
  });

  it('a live session whose last use was moved on with no MAC made again, as the release before 0111 would, ends with the alarm: no grace (S208)', async () => {
    const { clock: own, at } = onOwnClock();
    const { userId, sessionId, cookie } = await opened(at);
    own.advanceBy(IDLE_MS / 2);
    await asOwner('update identity.sessions set last_seen_at = $2 where id = $1', [sessionId, own.now()]);

    expect(await at.holder(app, cookie)).toBeUndefined();
    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'session', reason: 'last_use', rowId: sessionId, userId }),
      expect.objectContaining({ check: 'session', reason: 'last_use', rowId: sessionId }),
    ]);
    expect(capture.lines().filter((line) => line.level === 'warn')).toEqual([]);
    expect(await rowOf(sessionId)).toBeUndefined();
  });

  it('an idle session whose last use the owner moves on is ended, not found, and raises the alarm', async () => {
    const { clock: own, at } = onOwnClock();
    const { userId, sessionId, cookie } = await opened(at);
    own.advanceBy(IDLE_MS + 60_000);
    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([]);

    await asOwner('update identity.sessions set last_seen_at = $2 where id = $1', [sessionId, own.now()]);
    expect(await at.holder(app, cookie)).toBeUndefined();
    expect(await at.rotate(app, sessionId)).toBeUndefined();
    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'session', reason: 'last_use', rowId: sessionId, userId }),
      expect.objectContaining({ check: 'session', reason: 'last_use', rowId: sessionId }),
      expect.objectContaining({ check: 'session', reason: 'last_use', rowId: sessionId }),
    ]);
    // The last use the refused request wrote made the row whole again: so it was ended with it, and the cookie, asked
    // again, finds nothing.
    expect(await rowOf(sessionId)).toBeUndefined();
    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toHaveLength(3);
  });

  it("a last use moved on with another session's MAC, or one the same session had before, is no use of it", async () => {
    const { clock: own, at } = onOwnClock();
    const victim = await opened(at);
    own.advanceBy(IDLE_MS + 60_000);
    const other = await opened(at);
    // The other session used now: its last use and MAC are the app's, for its own cookie's hash.
    expect(await useIn(at, other.cookie)).toMatchObject({ sessionId: other.sessionId });
    await asOwner(
      `update identity.sessions s set last_seen_at = o.last_seen_at, last_use_mac = o.last_use_mac,
         last_use_mac_key_version = o.last_use_mac_key_version
       from identity.sessions o where s.id = $1 and o.id = $2`,
      [victim.sessionId, other.sessionId],
    );

    expect(await useIn(at, victim.cookie)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ check: 'session', reason: 'last_use', rowId: victim.sessionId }),
    ]);
    expect(await useIn(at, other.cookie)).toMatchObject({ sessionId: other.sessionId });
    expect(alarms()).toHaveLength(1);
  });

  it('a last use moved on while a request waits for the row is checked by the next one, which ends the session', async () => {
    const { clock: own, at } = onOwnClock();
    const { sessionId, cookie } = await opened(at);
    own.advanceBy(IDLE_MS - 60_000);
    const ahead = new Date(own.now().getTime() + IDLE_MS);
    // The owner's move held open, uncommitted: the request's statement starts on the row as it was (live, its last
    // use the app's), waits for the owner's lock, then writes over the moved row. The last use it checks is the one
    // on its own snapshot, the app's and live: it is let in, as the session was live. Its last use is not moved
    // back, so the owner's stays, and the next request checks that one.
    const owner = await database.connect('owner');
    try {
      await owner.query('begin');
      await owner.query('update identity.sessions set last_seen_at = $2 where id = $1', [sessionId, ahead]);
      const request = within(20_000, useIn(at, cookie), 'the request');
      await waitUntilQueued(database.as('admin'), 1);
      await owner.query('commit');

      expect(await request).toMatchObject({ sessionId, lastSeenAt: ahead });
    } finally {
      await owner.end();
    }
    expect(alarms()).toEqual([]);

    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([expect.objectContaining({ check: 'session', reason: 'last_use', rowId: sessionId })]);
    expect(await rowOf(sessionId)).toBeUndefined();
  });

  it('an older last use the app wrote, put back by the owner, only ends the session sooner', async () => {
    const { clock: own, at } = onOwnClock();
    const { sessionId, cookie } = await opened(at);
    const opening = await keep(sessionId);
    own.advanceBy(IDLE_MS - 1000);
    expect(await useIn(at, cookie)).toMatchObject({ sessionId });
    own.advanceBy(2000);
    await putBack(sessionId, opening);

    // Its own last use and MAC, the app's, but past the idle timeout: no session, and nothing tampered with to say.
    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([]);
  });

  it('a session whose last use has no MAC, as the release before 0111 left it, is ended at its next use, with the alarm (S208)', async () => {
    const { at } = onOwnClock();
    const { userId, sessionId, cookie } = await opened(at);
    await asOwner('update identity.sessions set last_use_mac = null, last_use_mac_key_version = null where id = $1', [
      sessionId,
    ]);

    expect(await at.holder(app, cookie)).toBeUndefined();
    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'session', reason: 'last_use', rowId: sessionId, userId }),
      expect.objectContaining({ check: 'session', reason: 'last_use', rowId: sessionId }),
    ]);
    expect(capture.lines().filter((line) => line.level === 'warn')).toEqual([]);
    expect(await rowOf(sessionId)).toBeUndefined();
  });

  it('control: two tabs using one session at once, one waiting for the other, are both let in, with no alarm', async () => {
    const { clock: own, at } = onOwnClock();
    const { sessionId, cookie } = await opened(at);
    own.advanceBy(60_000);
    // The first tab's use holds the row, uncommitted, while the second's queues behind it: the second then finds the
    // row the first wrote, and checks the last use it replaced on its own snapshot.
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let holding: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      holding = resolve;
    });
    const first = app.transaction().execute(async (tx) => {
      const found = await at.use(tx as unknown as Kysely<IdentityTables>, cookie);
      holding();
      await gate;
      return found;
    });
    await held;
    own.advanceBy(1000);
    const second = within(20_000, useIn(at, cookie), 'the second tab');
    await waitUntilQueued(database.as('admin'), 1);
    release();

    expect(await first).toMatchObject({ sessionId });
    expect(await second).toMatchObject({ sessionId, lastSeenAt: own.now() });
    expect(await Promise.all([useIn(at, cookie), useIn(at, cookie), at.holder(app, cookie)])).toEqual([
      expect.objectContaining({ sessionId }),
      expect.objectContaining({ sessionId }),
      expect.any(String),
    ]);
    expect(alarms()).toEqual([]);
  });

  it('control: a step-up gives a new cookie ID that is used as before, its old one finding nothing, with no alarm', async () => {
    const { clock: own, at } = onOwnClock();
    const { sessionId, cookie } = await opened(at);
    own.advanceBy(60_000);
    const rotated = await rotateSigned(at, sessionId);
    own.advanceBy(IDLE_MS - 1000);

    expect(await useIn(at, rotated)).toMatchObject({ sessionId });
    expect(await at.holder(app, rotated)).toBeDefined();
    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([]);
  });

  it('control: without its signed rotation, a row put back as it was before would sign the old cookie in', async () => {
    const { at } = onOwnClock();
    const { sessionId, cookie } = await opened(at);
    const before = await keep(sessionId);
    // Rotated with nothing signed: the guard below is the signature, not anything else about the row.
    expect(await at.rotate(app, sessionId)).toBeDefined();
    await putBack(sessionId, before);

    expect(await useIn(at, cookie)).toMatchObject({ sessionId });
    expect(alarms()).toEqual([]);
  });

  it('a row put back as it was before a step-up finds nothing for the old cookie, and raises the alarm', async () => {
    const { clock: own, at } = onOwnClock();
    const { userId, sessionId, cookie } = await opened(at);
    const before = await keep(sessionId);
    own.advanceBy(60_000);
    const rotated = await rotateSigned(at, sessionId);
    const after = await keep(sessionId);
    await putBack(sessionId, before);

    expect(await at.holder(app, cookie)).toBeUndefined();
    expect(await at.rotate(app, sessionId)).toBeUndefined();
    expect(await useIn(at, cookie)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'session', reason: 'rotated', rowId: sessionId, userId }),
      expect.objectContaining({ check: 'session', reason: 'rotated', rowId: sessionId }),
      expect.objectContaining({ check: 'session', reason: 'rotated', rowId: sessionId }),
    ]);
    // The row as the rotation left it, put back in turn, is the session again for its own cookie.
    await putBack(sessionId, after);
    expect(await useIn(at, rotated)).toMatchObject({ sessionId });
    expect(alarms()).toHaveLength(3);
  });

  it('a row from two step-ups before is refused too, while the latest cookie is still let in', async () => {
    const { clock: own, at } = onOwnClock();
    const { sessionId, cookie } = await opened(at);
    const first = await keep(sessionId);
    own.advanceBy(60_000);
    const middle = await rotateSigned(at, sessionId);
    const second = await keep(sessionId);
    own.advanceBy(60_000);
    const latest = await rotateSigned(at, sessionId);
    const current = await keep(sessionId);

    await putBack(sessionId, first);
    expect(await useIn(at, cookie)).toBeUndefined();
    await putBack(sessionId, second);
    expect(await useIn(at, middle)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ reason: 'rotated', rowId: sessionId }),
      expect.objectContaining({ reason: 'rotated', rowId: sessionId }),
    ]);
    await putBack(sessionId, current);
    expect(await useIn(at, latest)).toMatchObject({ sessionId });
    expect(alarms()).toHaveLength(2);
  });

  it("another session's rotations don't touch this one", async () => {
    const { at } = onOwnClock();
    const mine = await opened(at);
    const theirs = await opened(at);
    await rotateSigned(at, theirs.sessionId);

    expect(await useIn(at, mine.cookie)).toMatchObject({ sessionId: mine.sessionId });
    expect(alarms()).toEqual([]);
  });

  it('costs a request no statement more: one to use or name the holder, two to rotate', async () => {
    const { at } = onOwnClock();
    const { sessionId, cookie } = await opened(at);
    let statements = 0;
    // Counted as each comes back from the server: a subquery is built as a query of its own, but runs in its statement.
    const counted = app.withPlugin({
      transformQuery: (args) => args.node,
      transformResult: (args) => {
        statements += 1;
        return Promise.resolve(args.result);
      },
    }) as unknown as Kysely<IdentityTables>;

    expect(await at.use(counted, cookie)).toMatchObject({ sessionId });
    expect(statements).toBe(1);
    expect(await at.holder(counted, cookie)).toBeDefined();
    expect(statements).toBe(2);
    expect(await at.rotate(counted, sessionId)).toBeDefined();
    expect(statements).toBe(4);
  });
});

describe(`AT13c R-15 a signed end deleted below the platform chain's anchor, its session put back (Postgres ${server.version})`, () => {
  const platform = createPlatformChain({ keys, ids });
  /** The anchor check's platform chain: its walks say where each signed end is. */
  const walking = createPlatformChain({ keys, ids, subjectOf: signedEndSubjectOf });

  /** Sessions held to `digest`, as a process that keeps one makes them (boot.ts). */
  const heldTo = (digest: Pick<StateDigest, 'latest'> | undefined) =>
    createSessions({ ids, clock, timeouts: TIMEOUTS, keys, logger: testLogger(capture), digest: () => digest });

  /** The platform chain walked whole, as the anchor check does after a start: what it read, as the digest keeps it. */
  async function digested(): Promise<Pick<StateDigest, 'latest'>> {
    const report = await walking.verifyAlone(app as unknown as Kysely<PlatformControlsTables>, undefined);
    if (!report.ok) throw new Error('The platform chain should have checked out');
    const seen = report.signed ?? new Map<string, bigint>();
    return { latest: (_chain, type, id) => seen.get(`${type}\n${id.toLowerCase()}`) };
  }

  /**
   * The newest platform event of `action` naming `value` as `fact`, deleted by the owner: below the anchor, so no check
   * of the chain each run sees it. Gives back how to put it back as it was, so the chain holds for the next test.
   */
  async function deletedEnd(action: string, fact: string, value: string): Promise<() => Promise<void>> {
    const [found] = await asOwner(
      `select e.seq, pg_catalog.row_to_json(e) as kept from platform_controls.audit_events e
       where e.action = $1 and (e.details::jsonb ->> $2) = $3 order by e.seq desc limit 1`,
      [action, fact, value],
    );
    if (found === undefined) throw new Error(`no ${action} for ${value}`);
    await asOwner('delete from platform_controls.audit_events where seq = $1', [found.seq]);
    return async () => {
      await asOwner(
        `insert into platform_controls.audit_events
           select * from pg_catalog.json_populate_record(null::platform_controls.audit_events, $1::json)`,
        [JSON.stringify(found.kept)],
      );
    };
  }

  const putBack = swapRow;

  const signOut = (cookie: string) => signedOutOn(platform, cookie);

  /** Each of the three reads refused, each with the alarm for the session as `reason` says. */
  async function refusedWithTheAlarm(
    at: ReturnType<typeof heldTo>,
    { sessionId, cookie, userId }: { sessionId: string; cookie: string; userId: string },
    reason: string,
  ) {
    expect(await at.use(app, cookie)).toBeUndefined();
    expect(await at.holder(app, cookie)).toBeUndefined();
    expect(await at.rotate(app, sessionId)).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', check: 'session', reason, rowId: sessionId, userId }),
      expect.objectContaining({ check: 'session', reason, rowId: sessionId }),
      expect.objectContaining({ check: 'session', reason, rowId: sessionId }),
    ]);
  }

  it('the positive control: without the digest, a sign-out deleted with its session put back signs in again', async () => {
    const { userId, sessionId, cookie } = await signedIn();
    const kept = await keep(sessionId);
    await signOut(cookie);
    const restore = await deletedEnd(SESSION_ENDED, 'record', sessionId);
    try {
      await putBack(sessionId, kept);
      expect(await heldTo(undefined).use(app, cookie)).toMatchObject({ sessionId, userId });
      expect(alarms()).toEqual([]);
    } finally {
      await restore();
    }
  });

  it('held to the digest: the sign-out the walk read is missing, so the session put back is none, with the alarm', async () => {
    const signed = await signedIn();
    const kept = await keep(signed.sessionId);
    await signOut(signed.cookie);
    const digest = await digested();
    const restore = await deletedEnd(SESSION_ENDED, 'record', signed.sessionId);
    try {
      await putBack(signed.sessionId, kept);
      await refusedWithTheAlarm(heldTo(digest), signed, 'ended');
    } finally {
      await restore();
    }
  });

  it('held to the digest: a rotation deleted, the row from before it put back, is none for the old cookie', async () => {
    const signed = await signedIn();
    const before = await keep(signed.sessionId);
    await app.transaction().execute(async (tx) => {
      const rotated = await sessions().rotate(tx as unknown as Kysely<IdentityTables>, signed.sessionId);
      if (rotated === undefined) throw new Error('the session did not rotate');
      await platform.record(tx as unknown as PlatformTransaction, sessionRotatedEvent(rotated.retired, clock.now()));
    });
    const digest = await digested();
    const restore = await deletedEnd('identity.session_rotated', 'record', signed.sessionId);
    try {
      await putBack(signed.sessionId, before);
      expect(await heldTo(undefined).holder(app, signed.cookie)).toBe(signed.userId);
      await refusedWithTheAlarm(heldTo(digest), signed, 'rotated');
    } finally {
      await restore();
    }
  });

  it("held to the digest: the person's newest all-ended deleted, an older one left, a session put back is none", async () => {
    const userId = await person();
    // An end before the session's sign-in, which never touched it, stays: only the newest is taken away.
    await allEnded(userId, new Date(START.getTime() - 1000));
    const opened = await sessions().open(app, userId, { idpSessionId: 'V1_1', authTime: START, amr: PASSKEY });
    const signed = { userId, ...opened };
    const kept = await keep(signed.sessionId);
    await allEnded(userId, new Date(START.getTime() + 1000));
    const digest = await digested();
    const restore = await deletedEnd('identity.sessions_ended', 'person', signed.userId);
    try {
      await putBack(signed.sessionId, kept);
      expect(await heldTo(undefined).holder(app, signed.cookie)).toBe(signed.userId);
      await refusedWithTheAlarm(heldTo(digest), signed, 'ended');
    } finally {
      await restore();
    }
  });

  it('control: held to the digest, sessions never ended, and those of the walk’s people, are found with no alarm', async () => {
    const ended = await signedIn();
    await signOut(ended.cookie);
    const mine = await signedIn();
    const digest = await digested();
    const at = heldTo(digest);
    expect(await at.use(app, mine.cookie)).toMatchObject({ sessionId: mine.sessionId });
    expect(await at.holder(app, mine.cookie)).toBe(mine.userId);
    expect(await at.rotate(app, mine.sessionId)).toBeDefined();
    expect(alarms()).toEqual([]);
  });

  it('a sign-out committed after the read’s snapshot, already in the digest: refused, read again, never the alarm', async () => {
    const { userId, sessionId, cookie } = await signedIn();
    // The digest already knows the end: the anchor check walked it between the read's statement and its judgement.
    const digest: Pick<StateDigest, 'latest'> = {
      latest: (_chain, type, id) =>
        type === SESSION_ENDED && id === signedEndKey.ended(userId, sessionId) ? 99_999n : undefined,
    };
    let commit: (value: undefined) => void = () => undefined;
    const committing = new Promise<undefined>((resolve) => {
      commit = resolve;
    });
    let ended: (value: undefined) => void = () => undefined;
    const endedNow = new Promise<undefined>((resolve) => {
      ended = resolve;
    });
    // The sign-out, its row deleted and its end recorded, waiting to commit.
    const signingOut = app.transaction().execute(async (tx) => {
      const gone = await sessions().end(tx as unknown as Kysely<IdentityTables>, cookie);
      if (gone === undefined) throw new Error('the session did not end');
      await platform.record(tx as unknown as PlatformTransaction, sessionEndedEvent(gone, clock.now()));
      ended(undefined);
      await committing;
    });
    await endedNow;
    let first = true;
    // The read's statement found the row (the sign-out not committed); the sign-out commits before it is judged.
    const ordered = app.withPlugin({
      transformQuery: (args) => args.node,
      transformResult: async (args) => {
        if (first) {
          first = false;
          commit(undefined);
          await signingOut;
        }
        return args.result;
      },
    }) as unknown as Kysely<IdentityTables>;

    expect(await heldTo(digest).holder(ordered, cookie)).toBeUndefined();
    expect(alarms()).toEqual([]);
  });

  it('AT13g: a sign-out the digest forgot past the longest session, deleted with its row put back: past its absolute end, no one', async () => {
    // The longest session there can be, so its absolute end is the latest any setting gives.
    const own = new FixedClock(clock.now());
    const longest = { idleSeconds: 1800, absoluteSeconds: LONGEST_ABSOLUTE_SECONDS };
    const digest = createDigestLog({
      keys,
      logger: testLogger(capture),
      now: () => own.now(),
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 64 * 1024 * 1024,
      forgetSessionEndsAfterMs: LONGEST_ABSOLUTE_SECONDS * 1000,
    });
    const at = (on: FixedClock) =>
      createSessions({ ids, clock: on, timeouts: longest, keys, logger: testLogger(capture), digest: () => digest });
    const userId = await person();
    const { sessionId, cookie } = await at(own).open(app, userId, {
      idpSessionId: 'V1_1',
      authTime: own.now(),
      amr: PASSKEY,
    });
    const kept = await keep(sessionId);
    await app.transaction().execute(async (tx) => {
      const ended = await at(own).end(tx as unknown as Kysely<IdentityTables>, cookie);
      if (ended === undefined) throw new Error('the session did not end');
      await platform.record(tx as unknown as PlatformTransaction, sessionEndedEvent(ended, own.now()));
    });
    // The anchor check's walk, recorded as it keeps one: the digest knows the sign-out from now.
    const report = await walking.verifyAlone(app as unknown as Kysely<PlatformControlsTables>, undefined);
    if (!report.ok) throw new Error('The platform chain should have checked out');
    digest.record({ kind: 'platform' }, report.signed ?? new Map<string, bigint>(), own.now());
    const endKey = signedEndKey.ended(userId, sessionId);
    expect(digest.latest({ kind: 'platform' }, SESSION_ENDED, endKey)).toBeDefined();

    const restore = await deletedEnd(SESSION_ENDED, 'record', sessionId);
    try {
      await putBack(sessionId, kept);
      // Within its absolute end the digest is what refuses it (AT13c), with the alarm.
      expect(await at(own).use(app, cookie)).toBeUndefined();
      expect(alarms()).toEqual([expect.objectContaining({ check: 'session', reason: 'ended', rowId: sessionId })]);

      // Past the longest session and the digest's day of margin: the sign-out's fact is let go.
      own.advanceBy(LONGEST_ABSOLUTE_SECONDS * 1000 + 24 * 3_600_000 + 60_000);
      digest.record({ kind: 'platform' }, new Map(), own.now());
      expect(digest.latest({ kind: 'platform' }, SESSION_ENDED, endKey)).toBeUndefined();
      expect(capture.lines().filter((line) => line.event === 'audit.state_digest_session_ends_forgotten')).toEqual([
        // Every end the walk read, this file's other sessions' too, all known by the same moment.
        expect.objectContaining({
          level: 'info',
          objects: [...(report.signed ?? new Map<string, bigint>()).keys()].filter((key) => key.startsWith('identity.'))
            .length,
        }),
      ]);
      // The row put back is past its absolute end, held by its MAC: no read finds it, and no alarm is needed.
      expect(await at(own).use(app, cookie)).toBeUndefined();
      expect(await at(own).holder(app, cookie)).toBeUndefined();
      expect(await at(own).rotate(app, sessionId)).toBeUndefined();
      expect(alarms()).toHaveLength(1);

      // The positive control: the same row is a session of the app's to a clock still within its end, so its end is
      // all that stops it once the digest has forgotten (the reason the horizon is the longest session there can be).
      // Held to the digest's places alone: its heads (AT13h) would refuse the chain, whose newest event is gone.
      const within = new FixedClock(new Date(clock.now().getTime() + 60_000));
      const placesOnly = createSessions({
        ids,
        clock: within,
        timeouts: longest,
        keys,
        logger: testLogger(capture),
        digest: () => ({ latest: (...asked) => digest.latest(...asked) }),
      });
      expect(await placesOnly.holder(app, cookie)).toBe(userId);
    } finally {
      await restore();
    }
  });
});

/** The signed states' digest, and what it learns of rebases from, as createDigestLog makes and takes them. */
type DigestLog = ReturnType<typeof createDigestLog>;
type DigestAnchors = NonNullable<Parameters<typeof createDigestLog>[0]['anchors']>;

describe(`AT13h R-15 the platform chain cut back below the head this process saw, a session put back (Postgres ${server.version})`, () => {
  const platform = createPlatformChain({ keys, ids });
  const PLATFORM = { kind: 'platform' } as const;

  /** The signed states' digest as a process keeps one, its heads in memory, read whole first. */
  async function newDigest(anchors?: DigestAnchors): Promise<DigestLog> {
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

  const heldTo = (digest: Pick<StateDigest, 'latest'> & Partial<Pick<StateDigest, 'heads'>>) =>
    createSessions({ ids, clock, timeouts: TIMEOUTS, keys, logger: testLogger(capture), digest: () => digest });

  const seenOf = (digest: DigestLog) => digest.heads(PLATFORM)?.seen?.seq;

  /** The platform chain's head as the owner reads it: the row, to put back. */
  const headRow = async (): Promise<{ seq: string; kept: unknown }> => {
    const [row] = await asOwner(
      'select h.seq::text as seq, pg_catalog.row_to_json(h) as kept from platform_controls.audit_head h',
      [],
    );
    return { seq: String(row?.seq), kept: row?.kept };
  };

  /** The owner puts back the head row it kept, MAC and all. */
  const headBack = (kept: unknown) =>
    asOwner(
      `update platform_controls.audit_head h set (seq, hash, mac, mac_key_version) =
         (select r.seq, r.hash, r.mac, r.mac_key_version
          from pg_catalog.json_populate_record(null::platform_controls.audit_head, $1::json) r)`,
      [JSON.stringify(kept)],
    );

  /**
   * The owner cuts the platform chain's end off past `to` (a head row it kept), and puts that head back: every seal left
   * true, no gap for the next walk. Gives back how to put the end back as it was.
   */
  async function cutBackTo(to: { seq: string; kept: unknown }): Promise<() => Promise<void>> {
    const now = await headRow();
    const gone = await asOwner(
      'select pg_catalog.row_to_json(e) as kept from platform_controls.audit_events e where e.seq > $1::bigint order by e.seq',
      [to.seq],
    );
    await asOwner('delete from platform_controls.audit_events where seq > $1::bigint', [to.seq]);
    await headBack(to.kept);
    return async () => {
      for (const { kept } of gone) {
        await asOwner(
          `insert into platform_controls.audit_events
             select * from pg_catalog.json_populate_record(null::platform_controls.audit_events, $1::json)`,
          [JSON.stringify(kept)],
        );
      }
      await headBack(now.kept);
    };
  }

  const signOut = (cookie: string) => signedOutOn(platform, cookie);

  /**
   * A session read (the head seen there), then another signed out, its row kept; the owner cuts the sign-out off with
   * the chain's end, puts back the head from before it and the session's row. `between` runs after the sign-out.
   */
  async function signedOutThenCut(
    digest: DigestLog,
    between: () => Promise<unknown> = () => Promise.resolve(undefined),
  ) {
    const signed = await signedIn();
    const bystander = await signedIn();
    expect(await heldTo(digest).use(app, bystander.cookie)).toMatchObject({ sessionId: bystander.sessionId });
    const before = await headRow();
    const kept = await keep(signed.sessionId);
    await signOut(signed.cookie);
    await between();
    const written = (await headRow()).seq;
    const restore = await cutBackTo(before);
    await swapRow(signed.sessionId, kept);
    return { signed, bystander, before: BigInt(before.seq), written: BigInt(written), restore };
  }

  const cutAt = (seq: bigint, sessionId: string): unknown =>
    expect.objectContaining({
      level: 'error',
      event: 'audit.integrity_failed',
      check: 'platform_chain',
      reason: 'cut_back',
      seq: String(seq),
      rowId: sessionId,
    });

  /** A fresh session read through `digest`: a read after the sign-out, raising the head seen there. */
  const readAfter = (digest: DigestLog) => async () => {
    const { cookie } = await signedIn();
    return heldTo(digest).use(app, cookie);
  };

  it('the positive control: held to places alone, or read only before the sign-out, the session put back signs in again', async () => {
    const digest = await newDigest();
    const { signed, before, restore } = await signedOutThenCut(digest);
    try {
      // No walk read the sign-out (above the anchor), and the read before it saw only the head before it.
      expect(await heldTo({ latest: () => undefined }).use(app, signed.cookie)).toMatchObject({
        sessionId: signed.sessionId,
      });
      expect(seenOf(digest)).toBe(before);
      expect(await heldTo(digest).holder(app, signed.cookie)).toBe(signed.userId);
      expect(alarms()).toEqual([]);
    } finally {
      await restore();
    }
  });

  it('a read after the sign-out raised the head seen: cut back below it, each read refuses the session, with the alarm', async () => {
    const digest = await newDigest();
    const { signed, bystander, written, restore } = await signedOutThenCut(digest, readAfter(digest));
    try {
      expect(seenOf(digest)).toBe(written);
      const at = heldTo(digest);
      expect(await at.use(app, signed.cookie)).toBeUndefined();
      expect(await at.holder(app, signed.cookie)).toBeUndefined();
      expect(await at.rotate(app, signed.sessionId)).toBeUndefined();
      // The chain is cut: no session it judges is believed, the bystander's too, each with the alarm.
      expect(await at.use(app, bystander.cookie)).toBeUndefined();
      expect(alarms()).toEqual([
        cutAt(written, signed.sessionId),
        cutAt(written, signed.sessionId),
        cutAt(written, signed.sessionId),
        cutAt(written, bystander.sessionId),
      ]);
      // Never lowered by what it read cut back.
      expect(seenOf(digest)).toBe(written);
    } finally {
      await restore();
    }
    // The end put back: believed again, the signed-out session no one's, and no further alarm.
    expect(await heldTo(digest).use(app, bystander.cookie)).toMatchObject({ sessionId: bystander.sessionId });
    expect(await heldTo(digest).use(app, signed.cookie)).toBeUndefined();
    expect(alarms()).toHaveLength(5);
  });

  it('the sign-out itself raised the head seen once it committed, before any read: cut back below it, refused', async () => {
    const digest = await newDigest();
    checkStatesWith(digest);
    try {
      const { signed, written, restore } = await signedOutThenCut(digest);
      try {
        expect(seenOf(digest)).toBe(written);
        expect(await heldTo(digest).use(app, signed.cookie)).toBeUndefined();
        expect(alarms()).toEqual([cutAt(written, signed.sessionId)]);
      } finally {
        await restore();
      }
    } finally {
      checkStatesWith(undefined);
    }
  });

  it('forced order: a record rolled back to a savepoint after it, its transaction committed, is never raised', async () => {
    const digest = await newDigest();
    const { cookie, sessionId, userId } = await signedIn();
    expect(await heldTo(digest).use(app, cookie)).toMatchObject({ sessionId });
    const seen = seenOf(digest);
    checkStatesWith(digest);
    try {
      await app.transaction().execute(async (tx) => {
        await sql`savepoint probe_record`.execute(tx);
        await platform.record(tx as unknown as PlatformTransaction, sessionsEndedEvent(userId, clock.now()));
        await sql`rollback to savepoint probe_record`.execute(tx);
      });
    } finally {
      checkStatesWith(undefined);
    }
    expect(seenOf(digest)).toBe(seen);
    expect(await heldTo(digest).use(app, cookie)).toMatchObject({ sessionId });
    expect(alarms()).toEqual([]);
  });

  it('a transaction that has recorded on the chain never raises the head seen from its own reads', async () => {
    const digest = await newDigest();
    const signed = await signedIn();
    const other = await signedIn();
    expect(await heldTo(digest).use(app, other.cookie)).toMatchObject({ sessionId: other.sessionId });
    const seen = seenOf(digest);
    await expect(
      app.transaction().execute(async (tx) => {
        const ended = await sessions().end(tx as unknown as Kysely<IdentityTables>, signed.cookie);
        if (ended === undefined) throw new Error('the session did not end');
        await platform.record(tx as unknown as PlatformTransaction, sessionEndedEvent(ended, clock.now()));
        // Its own read sees the end it recorded, never committed.
        expect(await heldTo(digest).holder(tx as unknown as Kysely<IdentityTables>, other.cookie)).toBe(other.userId);
        throw new Error('rolled back');
      }),
    ).rejects.toThrow('rolled back');
    expect(seenOf(digest)).toBe(seen);
    expect(await heldTo(digest).use(app, signed.cookie)).toMatchObject({ sessionId: signed.sessionId });
    expect(alarms()).toEqual([]);
  });

  it('control: the chain grown honestly, reads and records raise the head seen with no alarm', async () => {
    const digest = await newDigest();
    checkStatesWith(digest);
    try {
      const one = await signedIn();
      const two = await signedIn();
      expect(await heldTo(digest).use(app, one.cookie)).toBeDefined();
      const first = seenOf(digest) ?? 0n;
      await signOut(two.cookie);
      expect(seenOf(digest)).toBe(first + 1n);
      expect(await heldTo(digest).use(app, one.cookie)).toBeDefined();
      expect(await heldTo(digest).holder(app, one.cookie)).toBe(one.userId);
      expect(await heldTo(digest).rotate(app, one.sessionId)).toBeDefined();
      expect(alarms()).toEqual([]);
    } finally {
      checkStatesWith(undefined);
    }
  });

  it('a head whose MAC the app did not write is no head to hold to: refused, and never raised from', async () => {
    const digest = await newDigest();
    const { cookie, sessionId } = await signedIn();
    expect(await heldTo(digest).use(app, cookie)).toMatchObject({ sessionId });
    const seen = seenOf(digest) ?? 0n;
    const head = await headRow();
    await asOwner('update platform_controls.audit_head set mac = pg_catalog.decode(pg_catalog.repeat($1, 32), $2)', [
      '00',
      'hex',
    ]);
    try {
      expect(await heldTo(digest).use(app, cookie)).toBeUndefined();
      expect(alarms()).toEqual([cutAt(seen, sessionId)]);
      // A digest that has seen nothing has nothing to hold to, and raises nothing from a head not sealed.
      const fresh = await newDigest();
      expect(await heldTo(fresh).holder(app, cookie)).toBeDefined();
      expect(seenOf(fresh)).toBeUndefined();
    } finally {
      await headBack(head.kept);
    }
  });

  it('a second head row beside the first, the key dropped: no head to hold to, refused', async () => {
    const digest = await newDigest();
    const { cookie, sessionId } = await signedIn();
    expect(await heldTo(digest).use(app, cookie)).toMatchObject({ sessionId });
    const seen = seenOf(digest) ?? 0n;
    await asOwner('alter table platform_controls.audit_head drop constraint audit_head_pkey', []);
    // The same row twice: whichever a read takes is sealed, so only the count tells.
    await asOwner('insert into platform_controls.audit_head select * from platform_controls.audit_head', []);
    try {
      expect(await heldTo(digest).holder(app, cookie)).toBeUndefined();
      expect(alarms()).toEqual([cutAt(seen, sessionId)]);
    } finally {
      await asOwner(
        'delete from platform_controls.audit_head h where h.ctid <> (select pg_catalog.min(o.ctid) from platform_controls.audit_head o)',
        [],
      );
      await asOwner(
        'alter table platform_controls.audit_head add constraint audit_head_pkey primary key (only_row)',
        [],
      );
    }
  });

  it('a rebase of the platform chain after the head was seen sets it aside: the chain as rebased reads as before', async () => {
    let rebasedAt = new Date(0);
    const digest = await newDigest({ rebasedAfter: (_, at) => rebasedAt > at, holds: () => true });
    const { signed, restore } = await signedOutThenCut(digest, readAfter(digest));
    try {
      // The operator rebases the platform chain where it now stands (E11): the head seen before no longer holds.
      rebasedAt = new Date(clock.now().getTime() + 1000);
      expect(seenOf(digest)).toBeUndefined();
      expect(await heldTo(digest).holder(app, signed.cookie)).toBe(signed.userId);
      expect(alarms()).toEqual([]);
    } finally {
      await restore();
    }
  });
});

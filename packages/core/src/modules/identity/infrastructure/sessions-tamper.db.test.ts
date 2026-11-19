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
} from '@agentx/testing';
import { ChainBroken } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, type KeyProvider, PURPOSES } from '@agentx/platform/keys';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, createAuditTrail } from '../../audit/index.ts';
import { createSessions } from './sessions.ts';
import {
  createStepUpChallenges,
  type StepUpBinding,
  type StepUpEvidence,
  stepUpDetails,
} from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import {
  backfillUserMacs,
  subjectOfUser,
  USER_MAC_BACKFILL_UNTIL,
  userForSubject,
  userOfSubject,
  UserUnbelieved,
} from './users.ts';

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
    expect(await sessions(later).use(app, rotated)).toMatchObject({ sessionId });
    // Rotated again under version 2: the row now names it.
    const again = await sessions(later).rotate(app, sessionId);
    if (again === undefined) throw new Error('the session did not rotate');
    expect(
      await app
        .selectFrom('identity.sessions')
        .select('mac_key_version')
        .where('id', '=', sessionId)
        .executeTakeFirst(),
    ).toEqual({ mac_key_version: 2 });
    expect(await sessions(later).use(app, again)).toMatchObject({ sessionId });
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

describe(`the owner can't use a step-up twice by putting its challenge back (R-15, S206; Postgres ${server.version})`, () => {
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
    // Nor is the backfill ever a way to make it genuine: it gives a MAC only to a row with none.
    expect(await backfillUserMacs(app, { keys, clock })).toBe(0);
    expect(await userOfSubject(app, { issuer: ISSUER, subject: 'owner-own' }, macs())).toBeUndefined();
  });

  it('a person made before 0100 is given their MAC at a start before the cutoff, and then signs in', async () => {
    const earlier = await personAs('made-before-0100');
    await asOwner('update identity.users set mac = null, mac_key_version = null where id = $1', [earlier]);
    expect(await userOfSubject(app, { issuer: ISSUER, subject: 'made-before-0100' }, macs())).toBeUndefined();

    expect(await backfillUserMacs(app, { keys, clock })).toBe(1);
    expect(await userOfSubject(app, { issuer: ISSUER, subject: 'made-before-0100' }, macs())).toBe(earlier);
    expect(await personAs('made-before-0100')).toBe(earlier);
  });

  it('a person with no MAC is never believed once the cutoff has passed, and none is given', async () => {
    const late = await personAs('no-mac-after-cutoff');
    await asOwner('update identity.users set mac = null, mac_key_version = null where id = $1', [late]);
    const after = new FixedClock(new Date(USER_MAC_BACKFILL_UNTIL.getTime() + 1000));

    expect(await backfillUserMacs(app, { keys, clock: after })).toBe(0);
    await expect(personAs('no-mac-after-cutoff')).rejects.toBeInstanceOf(UserUnbelieved);
    expect(await userOfSubject(app, { issuer: ISSUER, subject: 'no-mac-after-cutoff' }, macs())).toBeUndefined();
    expect(alarms()).toEqual([
      expect.objectContaining({ check: 'user', rowId: late }),
      expect.objectContaining({ check: 'user', rowId: late }),
    ]);
  });
});

describe(`the owner can't end someone else's login sessions, nor open a challenge on a forged session (Postgres ${server.version})`, () => {
  it("control: a sign-out of the app's own session names its person", async () => {
    const { userId, sessionId, cookie } = await signedIn();

    expect(await sessions().end(app, cookie)).toBe(userId);
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

// B3-1: step-up challenges (0013), on the real migrated schema, as the app
// role: opened for one change in one session, verified once, and consumed
// once, inside a transaction, only for that change (SEC-HA-03, 04).
import { createHash } from 'node:crypto';

import {
  createTestDatabase,
  FixedClock,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createSessions } from './sessions.ts';
import {
  createStepUpChallenges,
  STEP_UP_SECONDS,
  type StepUpBinding,
  type StepUpChallenges,
  type StepUpEvidence,
} from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const SECOND = 1000;
const START = new Date('2026-09-24T09:00:00Z');
const ids = new SequentialIds(0x300);

const hashOf = (text: string): Buffer => createHash('sha256').update(text).digest();

const EVIDENCE: StepUpEvidence = {
  authTime: new Date('2026-09-24T09:01:00Z'),
  amr: ['pwd', 'user', 'mfa'],
  idpSessionId: 'V1_338719472394810099',
  idTokenHash: hashOf('the ID token'),
};

/** An admin's change: its step-up must be proved with a passkey (SEC-HA-12). */
const NEED = { passkeyRequired: true };

/** Holds the session's challenges, then consumes one, as a change's confirmation does (ADR-006 §6, level 0b). */
const used = async (
  challenges: StepUpChallenges,
  db: Parameters<StepUpChallenges['consume']>[0],
  challengeId: string,
  binding: StepUpBinding,
  need: { readonly passkeyRequired: boolean },
) => challenges.consume(db, await challenges.hold(db, binding.sessionId), challengeId, binding, need);

let people = 0;
/** A person no other test has, with a live session, and challenges on a clock of the test's own. */
async function setUp(): Promise<{
  userId: string;
  sessionId: string;
  cookie: string;
  clock: FixedClock;
  challenges: StepUpChallenges;
  binding: StepUpBinding;
}> {
  people += 1;
  const clock = new FixedClock(START);
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `step-up-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId, cookie } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: START,
    amr: ['pwd', 'otp', 'mfa'],
  });
  return {
    userId,
    sessionId,
    cookie,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    binding: { sessionId, action: 'members.invite', changeHash: hashOf(`invite ${String(people)}`) },
  };
}

const rowsFor = (sessionId: string) =>
  app.selectFrom('identity.step_up_challenges').selectAll().where('session_id', '=', sessionId).execute();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`step-up challenges (Postgres ${server.version})`, () => {
  it("opens a challenge for the session's own person, with a fresh nonce and five minutes", async () => {
    const { userId, sessionId, challenges, binding } = await setUp();
    const opened = await challenges.open(app, binding);

    expect(opened).toEqual({
      challengeId: expect.stringMatching(/^[0-9a-f-]{36}$/) as string,
      sessionId,
      userId,
      action: 'members.invite',
      changeHash: binding.changeHash,
      nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) as string,
      createdAt: START,
      endsAt: new Date(START.getTime() + STEP_UP_SECONDS * SECOND),
    });
    const again = await challenges.open(app, binding);
    expect(again?.nonce).not.toBe(opened?.nonce);
    expect(again?.challengeId).not.toBe(opened?.challengeId);
  });

  it('opens nothing for a session that is gone or past its absolute end', async () => {
    const { clock, challenges, binding } = await setUp();
    expect(
      await challenges.open(app, { ...binding, sessionId: '0199a0f0-0000-7000-8000-00000000dead' }),
    ).toBeUndefined();
    clock.advanceBy(43_200 * SECOND);
    expect(await challenges.open(app, binding)).toBeUndefined();
  });

  it('gives back a pending challenge to its own session alone, until verified or out of time', async () => {
    const { clock, challenges, binding } = await setUp();
    const other = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');

    expect(await challenges.pending(app, opened.challengeId, binding.sessionId)).toEqual(opened);
    expect(await challenges.pending(app, opened.challengeId, other.sessionId)).toBeUndefined();
    clock.advanceBy(STEP_UP_SECONDS * SECOND - 1);
    expect(await challenges.pending(app, opened.challengeId, binding.sessionId)).toEqual(opened);
    clock.advanceBy(1);
    expect(await challenges.pending(app, opened.challengeId, binding.sessionId)).toBeUndefined();

    const verified = await other.challenges.open(app, other.binding);
    if (verified === undefined) throw new Error('no challenge');
    expect(await other.challenges.recordEvidence(app, verified.challengeId, other.sessionId, EVIDENCE)).toBe(true);
    expect(await other.challenges.pending(app, verified.challengeId, other.sessionId)).toBeUndefined();
  });

  it('records the evidence once, for its own session, in time', async () => {
    const { clock, challenges, binding } = await setUp();
    const other = await setUp();
    const first = await challenges.open(app, binding);
    const late = await challenges.open(app, binding);
    if (first === undefined || late === undefined) throw new Error('no challenge');

    expect(await challenges.recordEvidence(app, first.challengeId, other.sessionId, EVIDENCE)).toBe(false);
    expect(await challenges.recordEvidence(app, first.challengeId, binding.sessionId, EVIDENCE)).toBe(true);
    expect(
      await challenges.recordEvidence(app, first.challengeId, binding.sessionId, { ...EVIDENCE, amr: ['pwd'] }),
    ).toBe(false);
    clock.advanceBy(STEP_UP_SECONDS * SECOND);
    expect(await challenges.recordEvidence(app, late.challengeId, binding.sessionId, EVIDENCE)).toBe(false);

    const rows = await rowsFor(binding.sessionId);
    expect(rows.find((row) => row.id === first.challengeId)).toMatchObject({
      verified_at: START,
      auth_time: EVIDENCE.authTime,
      amr: ['pwd', 'user', 'mfa'],
      idp_session_id: EVIDENCE.idpSessionId,
      id_token_hash: EVIDENCE.idTokenHash,
    });
    expect(rows.find((row) => row.id === late.challengeId)).toMatchObject({ verified_at: null, amr: null });
  });

  it('SEC-HA-03 is consumed once, in the transaction that makes the change, with its evidence', async () => {
    const { userId, clock, challenges, binding } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    clock.advanceBy(30 * SECOND);
    await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, EVIDENCE);

    const consumed = await app.transaction().execute((tx) => used(challenges, tx, opened.challengeId, binding, NEED));
    expect(consumed).toEqual({
      ...opened,
      userId,
      verifiedAt: new Date(START.getTime() + 30 * SECOND),
      evidence: EVIDENCE,
    });
    expect(await used(challenges, app, opened.challengeId, binding, NEED)).toBeUndefined();
    expect(await rowsFor(binding.sessionId)).toEqual([]);
  });

  it('SEC-HA-12 is left unused where a passkey is needed and an authenticator app proved it, and used where one is not', async () => {
    const { challenges, binding } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    const withApp = { ...EVIDENCE, amr: ['pwd', 'otp', 'mfa'] };
    await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, withApp);

    expect(await used(challenges, app, opened.challengeId, binding, NEED)).toBeUndefined();
    expect(await rowsFor(binding.sessionId)).toHaveLength(1);
    const consumed = await used(challenges, app, opened.challengeId, binding, { passkeyRequired: false });
    expect(consumed?.evidence).toEqual(withApp);
  });

  it.each([
    ['commits', true],
    ['rolls back', false],
  ])(
    'FX-RACE SEC-HA-03 two changes consuming it at once: the second waits, and gets it only if the first rolls back (the first %s)',
    async (_what, commits) => {
      const { challenges, binding } = await setUp();
      const opened = await challenges.open(app, binding);
      if (opened === undefined) throw new Error('no challenge');
      await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, EVIDENCE);

      let letGo = (): void => undefined;
      const released = new Promise<void>((resolve) => {
        letGo = resolve;
      });
      let consumed = (): void => undefined;
      const hasConsumed = new Promise<void>((resolve) => {
        consumed = resolve;
      });
      const refusal = new Error('the first change was refused');
      const first = app.transaction().execute(async (tx) => {
        const got = await used(challenges, tx, opened.challengeId, binding, NEED);
        consumed();
        await released;
        if (!commits) throw refusal;
        return got;
      });
      await hasConsumed;
      const second = app.transaction().execute((tx) => used(challenges, tx, opened.challengeId, binding, NEED));
      await waitUntilQueued(database.as('admin'), 1);
      letGo();

      if (commits) {
        expect(await first).toBeDefined();
        expect(await within(10_000, second, 'the second consume')).toBeUndefined();
      } else {
        await expect(first).rejects.toBe(refusal);
        expect(await within(10_000, second, 'the second consume')).toBeDefined();
      }
      expect(await rowsFor(binding.sessionId)).toEqual([]);
    },
  );

  it('SEC-HA-03 is not used up by a change that rolls back', async () => {
    const { challenges, binding } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, EVIDENCE);

    const refusal = new Error('the change was refused');
    await expect(
      app.transaction().execute(async (tx) => {
        expect(await used(challenges, tx, opened.challengeId, binding, NEED)).toBeDefined();
        throw refusal;
      }),
    ).rejects.toBe(refusal);
    expect(await used(challenges, app, opened.challengeId, binding, NEED)).toBeDefined();
  });

  it.each<[string, (binding: StepUpBinding, otherSessionId: string) => StepUpBinding]>([
    ['another change', (binding) => ({ ...binding, changeHash: hashOf('another change') })],
    ['another action', (binding) => ({ ...binding, action: 'members.remove' })],
    ['another session', (binding, otherSessionId) => ({ ...binding, sessionId: otherSessionId })],
  ])('SEC-HA-04 confirms nothing for %s, and stays usable for its own', async (_what, change) => {
    const { challenges, binding } = await setUp();
    const other = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, EVIDENCE);

    expect(await used(challenges, app, opened.challengeId, change(binding, other.sessionId), NEED)).toBeUndefined();
    expect(await used(challenges, app, opened.challengeId, binding, NEED)).toBeDefined();
  });

  it('confirms nothing before its evidence is recorded, or once out of time', async () => {
    const { clock, challenges, binding } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    expect(await used(challenges, app, opened.challengeId, binding, NEED)).toBeUndefined();

    await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, EVIDENCE);
    clock.advanceBy(STEP_UP_SECONDS * SECOND);
    expect(await used(challenges, app, opened.challengeId, binding, NEED)).toBeUndefined();
  });

  it.each(['first', 'second'] as const)(
    "holds every challenge of the session until the change's transaction ends, the %s too, so a demotion's lock waits (ADR-006 §6)",
    async (which) => {
      const { challenges, binding } = await setUp();
      const opened = { first: await challenges.open(app, binding), second: await challenges.open(app, binding) };
      const locked = opened[which];
      if (locked === undefined) throw new Error('it should open');
      const holder = await database.connect('admin');
      await holder.query('begin');
      try {
        let locking: Promise<unknown> = Promise.resolve();
        await app.transaction().execute(async (tx) => {
          await challenges.hold(tx, binding.sessionId);
          // A demotion of the person, locking this one challenge: queued behind this transaction.
          locking = within(
            20_000,
            holder.query('select id from identity.step_up_challenges where id = $1 for update', [locked.challengeId]),
            "the demotion's lock",
          );
          await waitUntilQueued(database.as('admin'), 1);
        });

        // Granted once the change's transaction has ended.
        await locking;
      } finally {
        await holder.query('rollback');
        await holder.end();
      }
    },
  );

  it('sweeps past a challenge another transaction holds, never waiting on it, and leaves it for next time', async () => {
    const { clock, challenges, binding } = await setUp();
    const locked = await challenges.open(app, binding);
    const free = await challenges.open(app, binding);
    if (locked === undefined || free === undefined) throw new Error('both should open');
    clock.advanceBy(STEP_UP_SECONDS * SECOND);
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select id from identity.step_up_challenges where id = $1 for update', [locked.challengeId]);

      await within(5_000, challenges.sweep(app, 1000), 'the sweep');
      expect((await rowsFor(binding.sessionId)).map((row) => row.id)).toEqual([locked.challengeId]);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it("leaves a challenge past its time to the sweep: a hold doesn't lock it", async () => {
    const { clock, challenges, binding } = await setUp();
    const old = await challenges.open(app, binding);
    if (old === undefined) throw new Error('it should open');
    clock.advanceBy(STEP_UP_SECONDS * SECOND);
    await app.transaction().execute(async (tx) => {
      await challenges.hold(tx, binding.sessionId);
      // The sweep skips a locked challenge: this one is gone only if the hold left it.
      await challenges.sweep(app, 1000);

      expect(await rowsFor(binding.sessionId)).toEqual([]);
    });
  });

  it('refuses challenges held in another transaction, whose lock has gone already', async () => {
    const { challenges, binding } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('it should open');
    await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, EVIDENCE);
    const elsewhere = await challenges.hold(app, binding.sessionId);

    await expect(
      app.transaction().execute((tx) => challenges.consume(tx, elsewhere, opened.challengeId, binding, NEED)),
    ).rejects.toThrow(RangeError);
    expect(await rowsFor(binding.sessionId)).toHaveLength(1);
  });

  it("refuses challenges held for another session: a change can't use a hold that isn't its own", async () => {
    const { challenges, binding } = await setUp();
    const other = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('it should open');
    await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, EVIDENCE);

    await expect(
      challenges.consume(app, await challenges.hold(app, other.binding.sessionId), opened.challengeId, binding, NEED),
    ).rejects.toThrow(RangeError);
    expect(await rowsFor(binding.sessionId)).toHaveLength(1);
  });

  it('goes with its session, which ends by being deleted', async () => {
    const { cookie, clock, challenges, binding } = await setUp();
    await challenges.open(app, binding);
    const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
    expect(await sessions.end(app, cookie)).toBe(true);
    expect(await rowsFor(binding.sessionId)).toEqual([]);
  });

  it('sweeps challenges out of time, a batch at a time, and leaves the rest', async () => {
    const { clock, challenges, binding } = await setUp();
    const old = await Promise.all([1, 2, 3].map(() => challenges.open(app, binding)));
    clock.advanceBy(STEP_UP_SECONDS * SECOND);
    const fresh = await challenges.open(app, binding);

    const before = await challenges.sweep(app, 2);
    const after = await challenges.sweep(app, 10_000);
    expect(before).toBe(2);
    expect(after).toBeGreaterThanOrEqual(1);
    const left = (await rowsFor(binding.sessionId)).map((row) => row.id);
    expect(left).toEqual([fresh?.challengeId]);
    expect(old.every((challenge) => challenge !== undefined)).toBe(true);
    await expect(challenges.sweep(app, 0)).rejects.toThrow(RangeError);
  });

  it.each<[string, Partial<StepUpBinding>]>([
    ['a session ID that is not a UUID', { sessionId: 'not-a-uuid' }],
    ['an action in capitals', { action: 'Members.Invite' }],
    ['an action of 65 characters', { action: `a${'b'.repeat(64)}` }],
    ['a change hash of 31 bytes', { changeHash: Buffer.alloc(31) }],
    ['a change hash that is text', { changeHash: 'x'.repeat(32) as unknown as Buffer }],
  ])('refuses to open or consume for %s', async (_what, changes) => {
    const { challenges, binding } = await setUp();
    await expect(challenges.open(app, { ...binding, ...changes })).rejects.toThrow(RangeError);
    await expect(
      used(challenges, app, '0199a0f0-0000-7000-8000-000000000001', { ...binding, ...changes }, NEED),
    ).rejects.toThrow(RangeError);
  });

  it.each<[string, Partial<StepUpEvidence>]>([
    ['a time that is not a time', { authTime: new Date(Number.NaN) }],
    ['no methods', { amr: [] }],
    ['17 methods', { amr: Array.from({ length: 17 }, () => 'pwd') }],
    ['an empty method', { amr: [''] }],
    ['an empty Zitadel session ID', { idpSessionId: '' }],
    ['an ID token hash of 16 bytes', { idTokenHash: Buffer.alloc(16) }],
  ])('refuses to record evidence with %s', async (_what, changes) => {
    const { challenges, binding } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    await expect(
      challenges.recordEvidence(app, opened.challengeId, binding.sessionId, { ...EVIDENCE, ...changes }),
    ).rejects.toThrow(RangeError);
  });

  it('records evidence without a Zitadel session ID', async () => {
    const { challenges, binding } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    await challenges.recordEvidence(app, opened.challengeId, binding.sessionId, { ...EVIDENCE, idpSessionId: null });
    expect((await used(challenges, app, opened.challengeId, binding, NEED))?.evidence.idpSessionId).toBeNull();
  });

  it('finds nothing for IDs that are not UUIDs, asking the database nothing', async () => {
    const { challenges, binding } = await setUp();
    expect(await challenges.pending(app, 'nope', binding.sessionId)).toBeUndefined();
    expect(await challenges.pending(app, '0199a0f0-0000-7000-8000-000000000001', 'nope')).toBeUndefined();
    expect(await challenges.recordEvidence(app, 'nope', binding.sessionId, EVIDENCE)).toBe(false);
    expect(await challenges.recordEvidence(app, '0199a0f0-0000-7000-8000-000000000001', 'nope', EVIDENCE)).toBe(false);
    expect(await used(challenges, app, 'nope', binding, NEED)).toBeUndefined();
  });
});

describe(`the table holds a challenge to what it is for (Postgres ${server.version})`, () => {
  it("lets the app record evidence, but not change a challenge's session, person, action or change", async () => {
    const { binding, challenges } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    const app2 = database.as('app');
    const id = [opened.challengeId];
    await expect(
      app2.query('update identity.step_up_challenges set session_id = session_id where id = $1', id),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app2.query('update identity.step_up_challenges set user_id = user_id where id = $1', id),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app2.query('update identity.step_up_challenges set action = action where id = $1', id),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app2.query('update identity.step_up_challenges set change_hash = change_hash where id = $1', id),
    ).rejects.toThrow(/permission denied/);
    await expect(app2.query('update identity.step_up_challenges set nonce = nonce where id = $1', id)).rejects.toThrow(
      /permission denied/,
    );
    await expect(
      app2.query('update identity.step_up_challenges set created_at = created_at where id = $1', id),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app2.query('update identity.step_up_challenges set ends_at = ends_at where id = $1', id),
    ).rejects.toThrow(/permission denied/);
  });

  it('refuses evidence recorded in part', async () => {
    const { binding, challenges } = await setUp();
    const opened = await challenges.open(app, binding);
    if (opened === undefined) throw new Error('no challenge');
    await expect(
      database
        .as('app')
        .query('update identity.step_up_challenges set verified_at = now() where id = $1', [opened.challengeId]),
    ).rejects.toThrow(/evidence_whole/);
  });
});

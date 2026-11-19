// B2-3a-1: a sign-in from end to end, on the real migrated schema, as the app
// role, with a stand-in OIDC client (the client itself: oidc-client.test.ts).
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
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import type { Kysely } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createPlatformChain,
  type PlatformControlsTables,
  type PlatformTransaction,
} from '../../platform-controls/index.ts';
import type { SignInEvidence, Subject } from '../domain/sign-in.ts';
import { createLoginFlows } from './login-flows.ts';
import { type LoginFlow, type OidcClient, SignInFailed } from './oidc-client.ts';
import { openField } from './sealed-fields.ts';
import { sessionEmailOf, SessionEmailUnreadable } from './session-emails.ts';
import {
  createSessions,
  endSessionsOf,
  lockSessionsOf,
  type Sessions,
  SESSIONS_ENDED,
  sessionsEndedAt,
  sessionsEndedEvent,
} from './sessions.ts';
import { createSignIn, type SignIn, StepUpFailed } from './sign-in-flow.ts';
import { createStepUpChallenges, type StepUpBinding, type StepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { contactData } from './user-contacts.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const START = new Date('2026-09-24T09:00:00Z');
const ISSUER = 'https://auth.example.test';
const evidence: SignInEvidence = {
  idpSessionId: 'V1_338719472394810051',
  // As the flow begins: every sign-in asks for a fresh one (the S68 audit).
  authTime: new Date('2026-09-24T09:00:00Z'),
  amr: ['pwd', 'otp', 'mfa'],
};

/** Every flow any stand-in made, so each has its own values. */
let flowsMade = 0;

/** Stand-in keys, one per purpose. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);

/** The stand-in client: flows it started, and what `finish` does with each. */
class StandInClient implements OidcClient {
  started = 0;
  finished: { flow: LoginFlow; code: string; state: string }[] = [];
  subject = '338719472394810051';
  failWith: SignInFailed | undefined;

  /** What each start was asked for. */
  startedWith: ({ prompt?: 'login'; nonce?: string } | undefined)[] = [];
  /** What the next sign-in proves: the usual evidence unless a test says otherwise. */
  proves: SignInEvidence = evidence;
  /** The verified address the next sign-in gives, if any. */
  verifiedEmail: string | undefined = undefined;
  /** The name the next sign-in gives, if any. */
  name: string | undefined = undefined;

  start(options?: { prompt?: 'login'; nonce?: string }) {
    this.started += 1;
    this.startedWith.push(options);
    flowsMade += 1;
    const mark = String(flowsMade).padStart(6, '0');
    const flow: LoginFlow = {
      state: `s${mark}`.padEnd(43, 'S'),
      nonce: options?.nonce ?? `n${mark}`.padEnd(43, 'N'),
      verifier: `v${mark}`.padEnd(43, 'V'),
    };
    return Promise.resolve({ url: `${ISSUER}/oauth/v2/authorize?state=${flow.state}`, flow });
  }

  /** Run as the code is traded: the time the person spends at the login service, say. */
  whileFinishing: (() => unknown) | undefined;

  async finish(flow: LoginFlow, returned: { code: string; state: string }) {
    this.finished.push({ flow, ...returned });
    await this.whileFinishing?.();
    if (this.failWith !== undefined) throw this.failWith;
    if (returned.state !== flow.state) throw new SignInFailed('state_mismatch', 'test');
    const subject: Subject = { issuer: ISSUER, subject: this.subject };
    return {
      subject,
      evidence: this.proves,
      idTokenHash: Buffer.alloc(32, 7),
      verifiedEmail: this.verifiedEmail,
      name: this.name,
    };
  }
}

let client: StandInClient;
let sessions: Sessions;
let signIn: SignIn;
let challenges: StepUpChallenges;

/** Holds the session's challenges, then consumes one, as a change's confirmation does (ADR-006 §6, level 0b). */
const used = async (
  challenges: StepUpChallenges,
  db: Parameters<StepUpChallenges['consume']>[0],
  challengeId: string,
  binding: StepUpBinding,
  need: { readonly passkeyRequired: boolean },
) => challenges.consume(db, await challenges.hold(db, binding.sessionId), challengeId, binding, need);
let clock: FixedClock;
let subjects = 0;
/** What the sign-in logged since the test began. */
let capture: LogCapture;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  subjects += 1;
  client = new StandInClient();
  client.subject = `sign-in-${String(subjects)}`;
  clock = new FixedClock(START);
  capture = new LogCapture();
  const ids = new SequentialIds(0x5000 + subjects * 0x100);
  challenges = createStepUpChallenges({ ids, clock, keys, logger: testLogger() });
  sessions = createSessions({
    ids,
    clock,
    timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
    keys,
    logger: testLogger(),
  });
  signIn = createSignIn({
    db: app,
    oidc: client,
    flows: createLoginFlows({ clock }),
    sessions,
    challenges,
    ids,
    clock,
    keys,
    logger: testLogger(capture),
  });
});

/** Begins a sign-in and comes back with the flow's own state. */
async function roundTrip(returnTo?: string, previousCookie?: string) {
  const { url, flowId } = await signIn.begin(returnTo);
  const state = new URL(url).searchParams.get('state') ?? '';
  return signIn.complete({ flowId, code: 'a-code', state, previousCookie });
}

const sessionsOf = (userId: string) =>
  app.selectFrom('identity.sessions').select('id').where('user_id', '=', userId).execute();

describe(`a sign-in from end to end (Postgres ${server.version})`, () => {
  it('sends the browser to the login service, then opens a session for the person who signed in', async () => {
    const done = await roundTrip('/agents');

    expect(done.returnTo).toBe('/agents');
    expect(await sessions.use(app, done.cookie)).toMatchObject({
      sessionId: done.sessionId,
      userId: done.userId,
      ...evidence,
    });
    const [user] = await app.selectFrom('identity.users').selectAll().where('id', '=', done.userId).execute();
    expect(user).toMatchObject({ issuer: ISSUER, subject: client.subject });
    expect(client.finished).toEqual([expect.objectContaining({ code: 'a-code' })]);
  });

  it('asks the login service for a fresh sign-in every time, so one it kept never signs anyone in (the S68 audit)', async () => {
    await roundTrip();
    await roundTrip();

    expect(client.startedWith).toEqual([{ prompt: 'login' }, { prompt: 'login' }]);
  });

  it('refuses a sign-in made before the flow began, beyond 5 seconds, opening no session (the S68 audit)', async () => {
    const { url, flowId } = await signIn.begin();
    const state = new URL(url).searchParams.get('state') ?? '';
    client.proves = { ...evidence, authTime: new Date(START.getTime() - 5_001) };

    await expect(signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined })).rejects.toThrow(
      expect.objectContaining({ failure: 'stale_authentication' }),
    );
    const users = await app.selectFrom('identity.users').select('id').where('subject', '=', client.subject).execute();
    expect(users).toEqual([]);
  });

  it("S205 refuses a sign-in as a person whose row the owner moved to the signer's subject, opening no session", async () => {
    // The admin first signs in as themselves; then the owner moves their row onto the subject the next sign-in proves.
    const admin = await roundTrip();
    client.subject = `${client.subject}-owner`;
    const owner = await database.connect('owner');
    try {
      await owner.query('update identity.users set subject = $2 where id = $1', [admin.userId, client.subject]);
    } finally {
      await owner.end();
    }

    await expect(roundTrip()).rejects.toThrow(expect.objectContaining({ failure: 'account_unbelieved' }));
    expect(await sessionsOf(admin.userId)).toHaveLength(1);
  });

  it('AG10 refuses a sign-in made before the person’s sessions were last ended, opening none; a later one is taken', async () => {
    const first = await roundTrip();
    const { url, flowId } = await signIn.begin();
    const state = new URL(url).searchParams.get('state') ?? '';
    // At the login service, the person signs in as the flow begins; before they are back, every session of theirs is
    // ended (a removal, a factor reset, a change at the login service), a minute on.
    client.whileFinishing = async () => {
      clock.advanceBy(60_000);
      await app.transaction().execute(async (tx) => {
        await lockSessionsOf(tx, [first.userId]);
        await endSessionsOf(tx, first.userId, clock.now());
      });
    };

    await expect(signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined })).rejects.toThrow(
      expect.objectContaining({ failure: 'stale_authentication' }),
    );
    expect(await sessionsOf(first.userId)).toEqual([]);

    // A sign-in made after the end, at the moment of it or later, is taken.
    client.whileFinishing = undefined;
    client.proves = { ...evidence, authTime: clock.now() };
    const again = await roundTrip();
    expect(again.userId).toBe(first.userId);
    expect(await sessionsOf(first.userId)).toEqual([{ id: again.sessionId }]);
  });

  it('AG10 waits for an end committing as it signs in, then reads it: no session opened past it (ADR-006 §6)', async () => {
    const first = await roundTrip();
    const { url, flowId } = await signIn.begin();
    const state = new URL(url).searchParams.get('state') ?? '';
    // The end, its row written, held open before it commits.
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('update identity.users set sessions_ended_at = $2 where id = $1', [
      first.userId,
      new Date(START.getTime() + 60_000),
    ]);
    const completing = within(
      20_000,
      signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined }),
      'the sign-in',
    );
    const settled = completing.then(
      () => 'opened',
      (error: unknown) => (error instanceof SignInFailed ? error.failure : 'other'),
    );
    await waitUntilQueued(database.as('admin'), 1);
    await holder.query('commit');
    await holder.end();

    expect(await settled).toBe('stale_authentication');
    expect(await sessionsOf(first.userId)).toEqual([{ id: first.sessionId }]);
  });

  it('AG10 keeps the latest end, never moved back by an earlier one, and waits for one committing as it is read', async () => {
    const { userId } = await roundTrip();
    const [earlier, later] = [new Date(START.getTime() + 60_000), new Date(START.getTime() + 120_000)];
    for (const at of [later, earlier]) await app.transaction().execute((tx) => endSessionsOf(tx, userId, at));
    expect(
      await app.transaction().execute((tx) => sessionsEndedAt(tx, userId, { keys, logger: testLogger() }, START)),
    ).toEqual({
      kind: 'read',
      endedAt: later,
    });

    const latest = new Date(START.getTime() + 180_000);
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('update identity.users set sessions_ended_at = $2 where id = $1', [userId, latest]);
    const reading = within(
      20_000,
      app.transaction().execute((tx) => sessionsEndedAt(tx, userId, { keys, logger: testLogger() }, START)),
      'the read',
    );
    await waitUntilQueued(database.as('admin'), 1);
    await holder.query('commit');
    await holder.end();

    expect(await reading).toEqual({ kind: 'read', endedAt: latest });
  });

  it('AG10 an end waits for a sign-in that has read the last end, then ends the session it opened (ADR-006 §6)', async () => {
    const { userId } = await roundTrip();
    const { promise: read, resolve: hasRead } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The sign-in, its read of the last end taken (FOR SHARE), held before it opens its session.
    const signingIn = app.transaction().execute(async (tx) => {
      await sessionsEndedAt(tx, userId, { keys, logger: testLogger() }, START);
      hasRead(undefined);
      await gate;
      await sessions.open(tx, userId, evidence);
    });
    await read;
    const ending = within(
      20_000,
      app.transaction().execute(async (tx) => {
        await lockSessionsOf(tx, [userId]);
        return endSessionsOf(tx, userId, new Date(START.getTime() + 60_000));
      }),
      'the end',
    );
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    await signingIn;

    // Its own session and the one the sign-in opened meanwhile, both ended: none outlives the end.
    expect(await ending).toBe(2);
    expect(await sessionsOf(userId)).toEqual([]);
  });

  it('takes a sign-in made within 5 seconds before the flow began, as clocks drift', async () => {
    const { url, flowId } = await signIn.begin();
    const state = new URL(url).searchParams.get('state') ?? '';
    client.proves = { ...evidence, authTime: new Date(START.getTime() - 5_000) };

    const done = await signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined });

    expect(await sessions.use(app, done.cookie)).toMatchObject({ userId: done.userId });
  });

  it('counts the 5 seconds from the start of the flow’s second, as a sign-in’s time is in whole seconds', async () => {
    clock = new FixedClock(new Date(START.getTime() + 900));
    signIn = createSignIn({
      db: app,
      oidc: client,
      flows: createLoginFlows({ clock }),
      sessions,
      challenges,
      ids: new SequentialIds(0x5000 + subjects * 0x100 + 0x80),
      clock,
      keys,
      logger: testLogger(),
    });
    const { url, flowId } = await signIn.begin();
    const state = new URL(url).searchParams.get('state') ?? '';
    client.proves = { ...evidence, authTime: new Date(START.getTime() - 5_000) };

    const done = await signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined });

    expect(done.userId).toEqual(expect.any(String));
  });

  it('sends the browser home when it asked for nowhere', async () => {
    expect((await roundTrip()).returnTo).toBe('/');
  });

  it('refuses to begin one that would send the browser elsewhere, starting no flow', async () => {
    await expect(signIn.begin('//evil.example')).rejects.toThrow(RangeError);
    expect(client.started).toBe(0);
  });

  it('opens a new session each time, for the same person, and ends the one the browser brought', async () => {
    const first = await roundTrip();
    const second = await roundTrip('/', first.cookie);

    expect(second.userId).toBe(first.userId);
    expect(second.sessionId).not.toBe(first.sessionId);
    expect(await sessions.use(app, first.cookie)).toBeUndefined();
    expect(await sessionsOf(first.userId)).toEqual([{ id: second.sessionId }]);
  });

  it('opens a session even when the cookie the browser brought is no session', async () => {
    const done = await roundTrip('/', 'A'.repeat(43));

    expect(await sessions.use(app, done.cookie)).toBeDefined();
  });

  it('uses a flow once: the same callback again finds no flow, and calls the login service no more', async () => {
    const { url, flowId } = await signIn.begin();
    const state = new URL(url).searchParams.get('state') ?? '';
    await signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined });

    await expect(signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined })).rejects.toMatchObject({
      failure: 'flow_missing',
    });
    expect(client.finished).toHaveLength(1);
  });

  it('finds no flow without its cookie, or with another one', async () => {
    await signIn.begin();

    for (const flowId of [undefined, 'A'.repeat(43), 'not-a-flow']) {
      await expect(
        signIn.complete({ flowId, code: 'a-code', state: 'x', previousCookie: undefined }),
      ).rejects.toMatchObject({ failure: 'flow_missing' });
    }
    expect(client.finished).toEqual([]);
  });

  it('opens no session when the login service refuses, and the flow is used up all the same', async () => {
    const { url, flowId } = await signIn.begin();
    const state = new URL(url).searchParams.get('state') ?? '';
    client.failWith = new SignInFailed('code_rejected', 'test');

    await expect(signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined })).rejects.toMatchObject({
      failure: 'code_rejected',
    });
    expect(await app.selectFrom('identity.users').select('id').where('subject', '=', client.subject).execute()).toEqual(
      [],
    );

    client.failWith = undefined;
    await expect(signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined })).rejects.toMatchObject({
      failure: 'flow_missing',
    });
  });

  it('keeps the session the browser brought when the sign-in fails', async () => {
    const first = await roundTrip();
    const { flowId } = await signIn.begin();

    await expect(
      signIn.complete({ flowId, code: 'a-code', state: 'another-state', previousCookie: first.cookie }),
    ).rejects.toMatchObject({ failure: 'state_mismatch' });
    expect(await sessions.use(app, first.cookie)).toBeDefined();
  });

  it('signs out: ends the session its cookie names, saying who signed in with it, and nothing without one', async () => {
    const done = await roundTrip();

    expect(await signIn.signOut(undefined)).toBeUndefined();
    expect(await sessions.use(app, done.cookie)).toBeDefined();
    // Who it was, as the login service knows them: a sign-out ends their sessions there too (S88).
    expect(await signIn.signOut(done.cookie)).toEqual({ issuer: ISSUER, subject: client.subject });
    expect(await sessions.use(app, done.cookie)).toBeUndefined();
    expect(await signIn.signOut(done.cookie)).toBeUndefined();
  });

  it('finds the live session a signed-in request names (B2-4b), and none once it is signed out', async () => {
    const done = await roundTrip();

    expect(await signIn.signedIn(done.cookie)).toMatchObject({
      sessionId: done.sessionId,
      userId: done.userId,
      ...evidence,
      idleEndsAt: new Date(START.getTime() + 1800 * 1000),
    });
    expect(await signIn.signedIn('A'.repeat(43))).toBeUndefined();
    const lastUse = () =>
      app.selectFrom('identity.sessions').select('last_seen_at').where('id', '=', done.sessionId).executeTakeFirst();
    const before = await lastUse();
    clock.advanceBy(600_000);
    expect(await signIn.holderOf(done.cookie)).toBe(done.userId);
    // Who holds it, without that counting as a use (6A2: a browser's error report).
    expect(await lastUse()).toEqual(before);
    expect(await signIn.holderOf('A'.repeat(43))).toBeUndefined();
    await signIn.signOut(done.cookie);
    expect(await signIn.signedIn(done.cookie)).toBeUndefined();
    expect(await signIn.holderOf(done.cookie)).toBeUndefined();
  });

  it('gives up looking a session up after 10 seconds, a wait for a lock included, rather than hang', async () => {
    const done = await roundTrip();
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table identity.sessions in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, signIn.signedIn(done.cookie), 'the lookup')).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it("gives each browser its own flow: one's callback can't finish another's", async () => {
    const mine = await signIn.begin();
    const theirs = await signIn.begin();
    const theirState = new URL(theirs.url).searchParams.get('state') ?? '';

    await expect(
      signIn.complete({ flowId: mine.flowId, code: 'a-code', state: theirState, previousCookie: undefined }),
    ).rejects.toMatchObject({ failure: 'state_mismatch' });
  });
});

describe(`B3-3a a step-up from end to end (Postgres ${server.version})`, () => {
  const CHANGE = Buffer.alloc(32, 9);
  /** Evidence of a fresh sign-in with a security key, ten seconds after the challenge. */
  const FRESH: SignInEvidence = {
    idpSessionId: 'V1_fresh',
    authTime: new Date(START.getTime() + 10_000),
    amr: ['pwd', 'user', 'mfa'],
  };

  /** A signed-in person with a pending challenge for a change; the client will prove a fresh sign-in. */
  async function signedInWithChallenge() {
    const done = await roundTrip();
    const challenge = await challenges.open(app, {
      sessionId: done.sessionId,
      action: 'members.invite',
      changeHash: CHANGE,
    });
    if (challenge === undefined) throw new Error('no challenge');
    client.proves = FRESH;
    return { done, challenge };
  }

  /** Begins the step-up and comes back with its flow's own state, bringing the cookie given. */
  async function stepUp(sessionId: string, challengeId: string, cookie: string | undefined) {
    const { url, flowId } = await signIn.beginStepUp(sessionId, challengeId, '/members/confirm');
    const state = new URL(url).searchParams.get('state') ?? '';
    return signIn.complete({ flowId, code: 'a-code', state, previousCookie: cookie });
  }

  const binding = (sessionId: string) => ({ sessionId, action: 'members.invite', changeHash: CHANGE });
  /** An admin's change: its step-up must be proved with a passkey (SEC-HA-12). */
  const NEED = { passkeyRequired: true };

  it('asks the login service to sign the person in again with the challenge nonce, then records the evidence and rotates the cookie ID', async () => {
    const { done, challenge } = await signedInWithChallenge();

    const stepped = await stepUp(done.sessionId, challenge.challengeId, done.cookie);

    expect(client.startedWith.at(-1)).toEqual({ prompt: 'login', nonce: challenge.nonce });
    expect(stepped).toMatchObject({
      userId: done.userId,
      sessionId: done.sessionId,
      returnTo: '/members/confirm',
      stepUpChallengeId: challenge.challengeId,
    });
    expect(stepped.cookie).not.toBe(done.cookie);
    expect(await sessions.use(app, done.cookie)).toBeUndefined();
    expect(await sessions.use(app, stepped.cookie)).toMatchObject({ sessionId: done.sessionId });
    const consumed = await used(challenges, app, challenge.challengeId, binding(done.sessionId), NEED);
    expect(consumed?.evidence).toEqual({
      authTime: FRESH.authTime,
      amr: ['pwd', 'user', 'mfa'],
      idpSessionId: 'V1_fresh',
      idTokenHash: Buffer.alloc(32, 7),
    });
  });

  it('refuses to begin one for a challenge of another session, starting nothing', async () => {
    const { challenge } = await signedInWithChallenge();
    const other = await roundTrip();
    const started = client.started;

    await expect(signIn.beginStepUp(other.sessionId, challenge.challengeId)).rejects.toMatchObject({
      failure: 'challenge_missing',
      // Refused at the start, the browser is still on the console's page: nowhere to send it back to.
      back: undefined,
    });
    await expect(signIn.beginStepUp(other.sessionId, challenge.challengeId, '//evil.example')).rejects.toThrow(
      RangeError,
    );
    expect(client.started).toBe(started);
  });

  type SetUp = Awaited<ReturnType<typeof signedInWithChallenge>>;

  it.each<[string, (setUp: SetUp) => Promise<unknown>, string]>([
    [
      'no session cookie',
      ({ done, challenge }) => stepUp(done.sessionId, challenge.challengeId, undefined),
      'session_missing',
    ],
    [
      'the cookie of another session',
      async ({ done, challenge }) => {
        const other = await roundTrip();
        const { url, flowId } = await signIn.beginStepUp(done.sessionId, challenge.challengeId);
        const state = new URL(url).searchParams.get('state') ?? '';
        return signIn.complete({ flowId, code: 'a-code', state, previousCookie: other.cookie });
      },
      'challenge_missing',
    ],
    [
      'another person of ours signing in',
      async ({ done, challenge }) => {
        client.subject = `${client.subject}-other`;
        client.proves = evidence;
        await roundTrip();
        client.proves = FRESH;
        return stepUp(done.sessionId, challenge.challengeId, done.cookie);
      },
      'other_person',
    ],
    [
      'someone the login service knows but we do not',
      ({ done, challenge }) => {
        client.subject = 'never-signed-in-here';
        return stepUp(done.sessionId, challenge.challengeId, done.cookie);
      },
      'other_person',
    ],
    [
      'an authentication from before the challenge',
      ({ done, challenge }) => {
        client.proves = { ...evidence, authTime: new Date(START.getTime() - 60_000) };
        return stepUp(done.sessionId, challenge.challengeId, done.cookie);
      },
      'stale_authentication',
    ],
    [
      'no second factor',
      ({ done, challenge }) => {
        client.proves = { ...FRESH, amr: ['pwd'] };
        return stepUp(done.sessionId, challenge.challengeId, done.cookie);
      },
      'no_second_factor',
    ],
    [
      'a challenge that runs out of time while the person is at the login service',
      ({ done, challenge }) => {
        client.whileFinishing = () => {
          clock.advanceBy(300_000);
        };
        return stepUp(done.sessionId, challenge.challengeId, done.cookie);
      },
      'challenge_missing',
    ],
    [
      'a challenge out of time',
      async ({ done, challenge }) => {
        const { url, flowId } = await signIn.beginStepUp(done.sessionId, challenge.challengeId);
        const state = new URL(url).searchParams.get('state') ?? '';
        clock.advanceBy(300_000);
        return signIn.complete({ flowId, code: 'a-code', state, previousCookie: done.cookie });
      },
      'challenge_missing',
    ],
    [
      'a token the client refused',
      ({ done, challenge }) => {
        client.failWith = new SignInFailed('token_invalid', 'test');
        return stepUp(done.sessionId, challenge.challengeId, done.cookie);
      },
      'token_invalid',
    ],
  ])('fails a step-up back with %s, recording nothing and keeping the cookie', async (_what, act, failure) => {
    const setUp = await signedInWithChallenge();
    const { done, challenge } = setUp;

    const failed = act(setUp);
    await expect(failed).rejects.toBeInstanceOf(StepUpFailed);
    // CO2: with the challenge it was for and the page it came from, for the API to send the browser back to.
    await expect(failed).rejects.toMatchObject({
      failure,
      back: {
        challengeId: challenge.challengeId,
        returnTo: expect.stringMatching(/^\/(members\/confirm)?$/) as unknown,
      },
    });
    expect(await sessions.use(app, done.cookie)).toBeDefined();
    expect(await used(challenges, app, challenge.challengeId, binding(done.sessionId), NEED)).toBeUndefined();
    // Still pending, so the person can try again: unless its time ran out, which is the failure.
    if (clock.now().getTime() === START.getTime()) {
      expect(await challenges.pending(app, challenge.challengeId, done.sessionId)).toMatchObject({
        challengeId: challenge.challengeId,
      });
    }
  });

  it('fails a step-up whose session signs out while the person is at the login service, recording nothing', async () => {
    const { done, challenge } = await signedInWithChallenge();
    client.whileFinishing = () => sessions.end(app, done.cookie);

    // The session is given its new cookie ID first (its lock before the challenge's), and is gone.
    await expect(stepUp(done.sessionId, challenge.challengeId, done.cookie)).rejects.toMatchObject({
      name: 'StepUpFailed',
      failure: 'session_missing',
      back: { returnTo: '/members/confirm', challengeId: challenge.challengeId },
    });
    expect(await sessionsOf(done.userId)).toEqual([]);
  });

  it('takes a step-up’s flow when the login service sends the browser back without a sign-in, naming its page (CO2)', async () => {
    const { done, challenge } = await signedInWithChallenge();
    const { flowId } = await signIn.beginStepUp(done.sessionId, challenge.challengeId, '/members/confirm');

    await expect(
      signIn.complete({ flowId, previousCookie: done.cookie, refused: 'provider_refused' }),
    ).rejects.toMatchObject({
      name: 'StepUpFailed',
      failure: 'provider_refused',
      back: { returnTo: '/members/confirm', challengeId: challenge.challengeId },
    });
    // Taken: used once. The session and the challenge are as they were, so the person can ask again.
    await expect(
      signIn.complete({ flowId, code: 'a-code', state: 's', previousCookie: done.cookie }),
    ).rejects.toMatchObject({
      failure: 'flow_missing',
    });
    expect(await sessions.use(app, done.cookie)).toBeDefined();
    expect(await challenges.pending(app, challenge.challengeId, done.sessionId)).toMatchObject({
      challengeId: challenge.challengeId,
    });
  });

  it('refuses a sign-in sent back without one as it always was, its flow taken, nowhere to go back to', async () => {
    const { flowId } = await signIn.begin('/approvals');

    await expect(
      signIn.complete({ flowId, previousCookie: undefined, refused: 'callback_incomplete' }),
    ).rejects.toMatchObject({ name: 'SignInFailed', failure: 'callback_incomplete' });
    await expect(
      signIn.complete({ flowId, code: 'a-code', state: 's', previousCookie: undefined }),
    ).rejects.toMatchObject({
      failure: 'flow_missing',
    });
  });

  it('keeps a login service that cannot be reached a SignInFailed, as a sign-in does', async () => {
    const { done, challenge } = await signedInWithChallenge();
    client.failWith = new SignInFailed('provider_unavailable', 'test');

    await expect(stepUp(done.sessionId, challenge.challengeId, done.cookie)).rejects.toMatchObject({
      name: 'SignInFailed',
      failure: 'provider_unavailable',
    });
  });

  it('uses the flow of a step-up once: its callback replayed finds nothing', async () => {
    const { done, challenge } = await signedInWithChallenge();
    const { url, flowId } = await signIn.beginStepUp(done.sessionId, challenge.challengeId);
    const state = new URL(url).searchParams.get('state') ?? '';
    const back = { flowId, code: 'a-code', state, previousCookie: done.cookie };
    const stepped = await signIn.complete(back);

    await expect(signIn.complete({ ...back, previousCookie: stepped.cookie })).rejects.toMatchObject({
      failure: 'flow_missing',
    });
  });
});

describe(`a sign-in's verified address (B4-4a, Postgres ${server.version})`, () => {
  const emailRow = (sessionId: string) =>
    app.selectFrom('identity.session_emails').selectAll().where('session_id', '=', sessionId).executeTakeFirst();

  it('keeps the address the login service verified, encrypted with the session, in lower case', async () => {
    client.verifiedEmail = 'Sara.Khan@Example.test';

    const done = await roundTrip();

    expect(await sessionEmailOf(app, keys, done.sessionId)).toBe('sara.khan@example.test');
    const row = await emailRow(done.sessionId);
    expect(row?.email_key_version).toBe(1);
    expect(row?.email_ciphertext.toString('latin1').toLowerCase()).not.toContain('sara');
    expect(await sessionEmailOf(app, keys, done.sessionId.toUpperCase())).toBe('sara.khan@example.test');
  });

  it('keeps none when the login service verified none', async () => {
    const done = await roundTrip();

    expect(await emailRow(done.sessionId)).toBeUndefined();
    expect(await sessionEmailOf(app, keys, done.sessionId)).toBeUndefined();
  });

  it('refuses an address that isn’t one, opening no session', async () => {
    client.verifiedEmail = 'not an address';
    const before = await app.selectFrom('identity.sessions').select('id').execute();

    await expect(roundTrip()).rejects.toThrow(RangeError);
    // The session and the address go in one transaction: neither is left.
    expect(await app.selectFrom('identity.sessions').select('id').execute()).toEqual(before);
  });

  it('goes with its session when the person signs out', async () => {
    client.verifiedEmail = 'sara@example.test';
    const done = await roundTrip();

    await signIn.signOut(done.cookie);

    expect(await emailRow(done.sessionId)).toBeUndefined();
  });

  it('keeps the session’s own address through a step-up, whatever the fresh sign-in says', async () => {
    client.verifiedEmail = 'sara@example.test';
    const done = await roundTrip();
    const challenge = await challenges.open(app, {
      sessionId: done.sessionId,
      action: 'members.invite',
      changeHash: Buffer.alloc(32, 1),
    });
    if (challenge === undefined) throw new Error('no challenge');
    const { url, flowId } = await signIn.beginStepUp(done.sessionId, challenge.challengeId);
    client.verifiedEmail = 'mallory@example.test';
    client.proves = { ...evidence, authTime: clock.now() };
    await signIn.complete({
      flowId,
      code: 'a-code',
      state: new URL(url).searchParams.get('state') ?? '',
      previousCookie: done.cookie,
    });

    expect(await sessionEmailOf(app, keys, done.sessionId)).toBe('sara@example.test');
  });

  it('won’t open in another session: the address is bound to its own', async () => {
    client.verifiedEmail = 'sara@example.test';
    const first = await roundTrip();
    client.verifiedEmail = undefined;
    const second = await roundTrip();
    const copied = await emailRow(first.sessionId);
    if (copied === undefined) throw new Error('no address');
    const owner = await database.connect('admin');
    try {
      await owner.query('insert into identity.session_emails values ($1, $2, $3)', [
        second.sessionId,
        copied.email_ciphertext,
        copied.email_key_version,
      ]);
    } finally {
      await owner.end();
    }

    await expect(sessionEmailOf(app, keys, second.sessionId)).rejects.toBeInstanceOf(SessionEmailUnreadable);
  });

  it('takes a sealed address of 29 to 1,024 bytes and key version 1 or later, and nothing else', async () => {
    const done = await roundTrip();
    /** Writes a row past the module, in a transaction rolled back if nothing refuses it. */
    const written = (ciphertext: Buffer, version: number) =>
      app.transaction().execute(async (tx) => {
        await tx
          .insertInto('identity.session_emails')
          .values({ session_id: done.sessionId, email_ciphertext: ciphertext, email_key_version: version })
          .execute();
        throw new Error('rolled back');
      });

    for (const [ciphertext, version] of [
      [Buffer.alloc(29), 1],
      [Buffer.alloc(1024), 1],
    ] as const) {
      await expect(written(ciphertext, version)).rejects.toThrow('rolled back');
    }
    for (const length of [28, 1025]) {
      await expect(written(Buffer.alloc(length), 1)).rejects.toMatchObject({
        code: '23514',
        constraint: 'session_emails_email_ciphertext_check',
      });
    }
    await expect(written(Buffer.alloc(40), 0)).rejects.toMatchObject({
      code: '23514',
      constraint: 'session_emails_email_key_version_check',
    });
  });

  it('can’t be changed or deleted by the app, only added', async () => {
    client.verifiedEmail = 'sara@example.test';
    const done = await roundTrip();

    await expect(
      app
        .updateTable('identity.session_emails')
        .set({ email_key_version: 2 })
        .where('session_id', '=', done.sessionId)
        .execute(),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      app.deleteFrom('identity.session_emails').where('session_id', '=', done.sessionId).execute(),
    ).rejects.toMatchObject({ code: '42501' });
  });
});

describe(`a person's kept name and address (E10d, decision 25, Postgres ${server.version})`, () => {
  /** The person's kept values, opened; a field kept for no one opens as undefined. */
  const keptFor = async (userId: string) => {
    const row = await app
      .selectFrom('identity.user_contacts')
      .selectAll()
      .where('user_id', '=', userId)
      .executeTakeFirst();
    if (row === undefined) return undefined;
    const opened = (ciphertext: Buffer | null, keyVersion: number | null, field: 'name' | 'email') =>
      ciphertext === null || keyVersion === null
        ? undefined
        : openField(
            keys,
            { ciphertext, keyVersion },
            contactData(userId, field),
            (cause) => new Error('unreadable', { cause }),
          );
    return {
      name: opened(row.name_ciphertext, row.name_key_version, 'name'),
      email: opened(row.email_ciphertext, row.email_key_version, 'email'),
      updatedAt: row.updated_at,
    };
  };

  it('keeps the name and verified address, encrypted, as of the sign-in', async () => {
    client.name = 'Sara  Khan';
    client.verifiedEmail = 'Sara.Khan@Example.test';

    const done = await roundTrip();

    expect(await keptFor(done.userId)).toEqual({
      name: 'Sara Khan',
      email: 'sara.khan@example.test',
      updatedAt: clock.now(),
    });
    const row = await app
      .selectFrom('identity.user_contacts')
      .selectAll()
      .where('user_id', '=', done.userId)
      .executeTakeFirstOrThrow();
    expect(row.name_ciphertext?.toString('latin1')).not.toContain('Sara');
    expect(row.email_ciphertext?.toString('latin1').toLowerCase()).not.toContain('sara');
  });

  it('refreshes them at the next sign-in, keeping a value the login service didn’t give this time', async () => {
    client.name = 'Sara Khan';
    client.verifiedEmail = 'sara@example.test';
    const first = await roundTrip();
    clock.advanceBy(60_000);
    client.proves = { ...evidence, authTime: clock.now() };

    client.name = 'Sara Al Mansoori';
    client.verifiedEmail = undefined;
    const second = await roundTrip(undefined, first.cookie);

    expect(second.userId).toBe(first.userId);
    expect(await keptFor(first.userId)).toEqual({
      name: 'Sara Al Mansoori',
      email: 'sara@example.test',
      updatedAt: clock.now(),
    });

    client.name = undefined;
    client.verifiedEmail = 'sara.new@example.test';
    await roundTrip(undefined, second.cookie);
    expect(await keptFor(first.userId)).toMatchObject({ name: 'Sara Al Mansoori', email: 'sara.new@example.test' });
  });

  it('keeps nothing for a person whose sign-in gave neither', async () => {
    const done = await roundTrip();

    expect(await keptFor(done.userId)).toBeUndefined();
  });

  it('keeps a name alone when the address isn’t verified', async () => {
    client.name = 'Omar';

    const done = await roundTrip();

    expect(await keptFor(done.userId)).toMatchObject({ name: 'Omar', email: undefined });
  });

  it('refuses a name that isn’t one, opening no session', async () => {
    client.name = '\u202e';
    const before = await app.selectFrom('identity.sessions').select('id').execute();

    await expect(roundTrip()).rejects.toThrow(RangeError);
    expect(await app.selectFrom('identity.sessions').select('id').execute()).toEqual(before);
  });

  it('won’t open a value copied to another person, or one field as the other', async () => {
    client.name = 'Sara Khan';
    client.verifiedEmail = 'sara@example.test';
    const sara = await roundTrip();
    client.subject = `${client.subject}9`;
    client.name = 'Mallory';
    client.verifiedEmail = undefined;
    const mallory = await roundTrip();
    const row = await app
      .selectFrom('identity.user_contacts')
      .selectAll()
      .where('user_id', '=', sara.userId)
      .executeTakeFirstOrThrow();
    const saraName = row.name_ciphertext;
    if (saraName === null) throw new Error('nothing kept');
    const owner = await database.connect('admin');
    try {
      await owner.query(
        'update identity.user_contacts set name_ciphertext = $2, name_key_version = 1, email_ciphertext = $3, email_key_version = 1 where user_id = $1',
        [mallory.userId, saraName, saraName],
      );
    } finally {
      await owner.end();
    }
    const swapped = await app
      .selectFrom('identity.user_contacts')
      .selectAll()
      .where('user_id', '=', mallory.userId)
      .executeTakeFirstOrThrow();

    for (const [ciphertext, field] of [
      [swapped.name_ciphertext, 'name'],
      [swapped.email_ciphertext, 'email'],
    ] as const) {
      if (ciphertext === null) throw new Error('nothing kept');
      expect(() =>
        keys.decrypt('field-encryption', { ciphertext, keyVersion: 1 }, contactData(mallory.userId, field)),
      ).toThrow();
    }
    expect(() =>
      keys.decrypt('field-encryption', { ciphertext: saraName, keyVersion: 1 }, contactData(sara.userId, 'email')),
    ).toThrow();
  });
});

describe(`R-15 the owner can't set a person's sessions' end back (S206, Postgres ${server.version})`, () => {
  // The end is signed on the platform chain as the column is written, in the same transaction, as every caller does
  // (membership-changes, reset-removals, idp-copier). The owner, holding no key, can set the column back or empty it,
  // but not the signed record: a sign-in begun before the end is still refused, and the alarm raised.
  const platform = createPlatformChain({ keys, ids: new SequentialIds(0x5206_0000) });
  const MINUTE = 60_000;

  /** Ends every session of the person at `at`, signing the end, as the callers do. */
  const endSigned = (userId: string, at: Date) =>
    app.transaction().execute(async (tx) => {
      await lockSessionsOf(tx, [userId]);
      await endSessionsOf(tx, userId, at);
      return platform.record(tx as unknown as PlatformTransaction, sessionsEndedEvent(userId, at));
    });

  /** Runs one statement as agentx_owner, holding none of the app's keys, on a connection of its own. */
  async function asOwner(text: string, values: readonly unknown[]): Promise<void> {
    const owner = await database.connect('owner');
    try {
      // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text; every value is bound.
      await owner.query(text, values);
    } finally {
      await owner.end();
    }
  }

  /**
   * A sign-in made as its flow begins, finished after the person's sessions were ended a minute on, with `meanwhile`
   * done before the person is back: what it came to.
   */
  async function begunBeforeTheEnd(meanwhile: (userId: string, ended: { readonly seq: bigint }) => Promise<void>) {
    const { userId } = await roundTrip();
    const { url, flowId } = await signIn.begin();
    const state = new URL(url).searchParams.get('state') ?? '';
    client.whileFinishing = async () => {
      clock.advanceBy(MINUTE);
      const ended = await endSigned(userId, clock.now());
      await meanwhile(userId, ended);
    };
    const settled = await signIn.complete({ flowId, code: 'a-code', state, previousCookie: undefined }).then(
      () => 'opened',
      (error: unknown) => (error instanceof SignInFailed ? error.failure : 'other'),
    );
    return { userId, settled };
  }

  const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');
  const rolledBack = (userId: string): unknown[] => [
    expect.objectContaining({ check: 'user', reason: 'sessions_ended_rolled_back', userId, rowId: userId }),
  ];

  it('control: an end signed and kept refuses a sign-in begun before it, with no alarm; a later one is taken', async () => {
    const { userId, settled } = await begunBeforeTheEnd(() => Promise.resolve());

    expect(settled).toBe('stale_authentication');
    expect(await sessionsOf(userId)).toEqual([]);
    client.whileFinishing = undefined;
    client.proves = { ...evidence, authTime: clock.now() };
    expect((await roundTrip()).userId).toBe(userId);
    expect(alarms()).toEqual([]);
  });

  it('the column set back by the owner still refuses a sign-in begun before the end, and raises the alarm', async () => {
    const { userId, settled } = await begunBeforeTheEnd((person) =>
      asOwner('update identity.users set sessions_ended_at = $2 where id = $1', [person, START]),
    );

    expect(settled).toBe('stale_authentication');
    expect(await sessionsOf(userId)).toEqual([]);
    expect(alarms()).toEqual(rolledBack(userId));
  });

  it('the column emptied by the owner still refuses it, and raises the alarm', async () => {
    const { userId, settled } = await begunBeforeTheEnd((person) =>
      asOwner('update identity.users set sessions_ended_at = null where id = $1', [person]),
    );

    expect(settled).toBe('stale_authentication');
    expect(await sessionsOf(userId)).toEqual([]);
    expect(alarms()).toEqual(rolledBack(userId));
  });

  it("reads the later of the column and the person's own latest signed end, never another person's", async () => {
    const { userId } = await roundTrip();
    client.subject = `${client.subject}-other`;
    const other = await roundTrip();
    const at = (minutes: number) => new Date(START.getTime() + minutes * MINUTE);
    const [first, second, theirs] = [at(1), at(2), at(3)];
    await endSigned(userId, first);
    await endSigned(userId, second);
    await endSigned(other.userId, theirs);
    // Signed in at the test's clock, long before the database's own: every event since is checked in place. Or an
    // long past the database's clock, when none is: the person's latest end, by the index, all the same.
    const read = async (signedInAt: Date) => {
      const ended = await app
        .transaction()
        .execute((tx) => sessionsEndedAt(tx, userId, { keys, logger: testLogger(capture) }, signedInAt));
      return ended.kind === 'read' ? ended.endedAt : ended.kind;
    };
    const [checked, indexed] = [START, new Date('2100-01-01T00:00:00Z')];

    expect([await read(checked), await read(indexed)]).toEqual([second, second]);
    expect(alarms()).toEqual([]);
    // Ahead of the record (an end timed by another replica's later clock, say): the column, with no alarm.
    const ahead = new Date(START.getTime() + 4 * MINUTE);
    await app.updateTable('identity.users').set({ sessions_ended_at: ahead }).where('id', '=', userId).execute();
    expect([await read(checked), await read(indexed)]).toEqual([ahead, ahead]);
    expect(alarms()).toEqual([]);
    // Behind the latest record, though past an earlier one: the latest record, and the alarm, each way.
    await asOwner('update identity.users set sessions_ended_at = $2 where id = $1', [userId, first]);
    expect([await read(checked), await read(indexed)]).toEqual([second, second]);
    expect(alarms()).toEqual([...rolledBack(userId), ...rolledBack(userId)]);
  });

  it('an end whose record the owner deletes for a moment, with the column set back, is refused, with the alarm', async () => {
    const { userId, settled } = await begunBeforeTheEnd(async (person, ended) => {
      // Another event after it, so it lies inside the chain, not at its top.
      await platform.recordAlone(app as unknown as Kysely<PlatformControlsTables>, {
        actor: { type: 'system', id: 'api' },
        action: 'platform.started',
        details: { release: 'r-206' },
      });
      await database
        .as('admin')
        .query('create table public.held_r15 as select * from platform_controls.audit_events where seq = $1', [
          ended.seq,
        ]);
      await asOwner('delete from platform_controls.audit_events where seq = $1', [ended.seq]);
      await asOwner('update identity.users set sessions_ended_at = null where id = $1', [person]);
    });

    expect(settled).toBe('account_unbelieved');
    expect(await sessionsOf(userId)).toEqual([]);
    expect(alarms()).toEqual([expect.objectContaining({ check: 'platform_chain', reason: 'gap', userId })]);
    // Put back byte for byte, the chain is whole again: only this check, made while the record was gone, found it.
    await database.as('admin').query('insert into platform_controls.audit_events select * from public.held_r15');
    await database.as('admin').query('drop table public.held_r15');
    expect(await platform.verifyAlone(app as unknown as Kysely<PlatformControlsTables>, undefined)).toMatchObject({
      ok: true,
    });
  });

  it('believes the checked stretch, not the index alone: a record put back while the read waits for the row', async () => {
    const { userId } = await roundTrip();
    const ended = await endSigned(userId, new Date(START.getTime() + MINUTE));
    const admin = database.as('admin');
    // The owner deletes the record, then holds the person's row, its column emptied, uncommitted.
    await admin.query('create table public.held_r15 as select * from platform_controls.audit_events where seq = $1', [
      ended.seq,
    ]);
    await admin.query('delete from platform_controls.audit_events where seq = $1', [ended.seq]);
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('update identity.users set sessions_ended_at = null where id = $1', [userId]);
    const reading = within(
      20_000,
      app.transaction().execute((tx) => sessionsEndedAt(tx, userId, { keys, logger: testLogger(capture) }, START)),
      'the read',
    );
    // The read's first statement waits for the row on its snapshot, the record missing; the record is put back.
    await waitUntilQueued(admin, 1);
    await admin.query('insert into platform_controls.audit_events select * from public.held_r15');
    await admin.query('drop table public.held_r15');
    await holder.query('commit');
    await holder.end();

    expect(await reading).toEqual({ kind: 'read', endedAt: new Date(START.getTime() + MINUTE) });
    expect(alarms()).toEqual(rolledBack(userId));
  });

  it(`signs the end as ${SESSIONS_ENDED}, naming the person in lower case and the moment as toISOString writes it`, () => {
    const at = new Date(START.getTime() + MINUTE);
    expect(sessionsEndedEvent('0A0B0C0D-0000-4000-8000-000000000001', at)).toEqual({
      actor: { type: 'system', id: 'api' },
      action: SESSIONS_ENDED,
      details: { person: '0a0b0c0d-0000-4000-8000-000000000001', at: at.toISOString() },
    });
  });
});

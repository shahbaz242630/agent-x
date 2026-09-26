// B2-3a-1: a sign-in from end to end, on the real migrated schema, as the app
// role, with a stand-in OIDC client (the client itself: oidc-client.test.ts).
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase, within } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import type { SignInEvidence, Subject } from '../domain/sign-in.ts';
import { createLoginFlows } from './login-flows.ts';
import { type LoginFlow, type OidcClient, SignInFailed } from './oidc-client.ts';
import { sessionEmailOf, SessionEmailUnreadable } from './session-emails.ts';
import { createSessions, type Sessions } from './sessions.ts';
import { createSignIn, type SignIn, StepUpFailed } from './sign-in-flow.ts';
import { createStepUpChallenges, type StepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const START = new Date('2026-09-24T09:00:00Z');
const ISSUER = 'https://auth.example.test';
const evidence: SignInEvidence = {
  idpSessionId: 'V1_338719472394810051',
  authTime: new Date('2026-09-24T08:59:30Z'),
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
    return { subject, evidence: this.proves, idTokenHash: Buffer.alloc(32, 7), verifiedEmail: this.verifiedEmail };
  }
}

let client: StandInClient;
let sessions: Sessions;
let signIn: SignIn;
let challenges: StepUpChallenges;
let clock: FixedClock;
let subjects = 0;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>(
    { ...database.connection('app'), maxConnections: 2 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
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
  const ids = new SequentialIds(0x5000 + subjects * 0x100);
  challenges = createStepUpChallenges({ ids, clock });
  sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  signIn = createSignIn({
    db: app,
    oidc: client,
    flows: createLoginFlows({ clock }),
    sessions,
    challenges,
    ids,
    clock,
    keys,
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

  it('signs out: ends the session its cookie names, and nothing without one', async () => {
    const done = await roundTrip();

    expect(await signIn.signOut(undefined)).toBe(false);
    expect(await sessions.use(app, done.cookie)).toBeDefined();
    expect(await signIn.signOut(done.cookie)).toBe(true);
    expect(await sessions.use(app, done.cookie)).toBeUndefined();
    expect(await signIn.signOut(done.cookie)).toBe(false);
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
    await signIn.signOut(done.cookie);
    expect(await signIn.signedIn(done.cookie)).toBeUndefined();
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
    const consumed = await challenges.consume(app, challenge.challengeId, binding(done.sessionId), NEED);
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
      'the old authentication of the session',
      ({ done, challenge }) => {
        client.proves = evidence;
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
    await expect(failed).rejects.toMatchObject({ failure });
    expect(await sessions.use(app, done.cookie)).toBeDefined();
    expect(await challenges.consume(app, challenge.challengeId, binding(done.sessionId), NEED)).toBeUndefined();
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
    });
    expect(await sessionsOf(done.userId)).toEqual([]);
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

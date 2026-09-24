// B2-3a-1: a sign-in from end to end, on the real migrated schema, as the app
// role, with a stand-in OIDC client (the client itself: oidc-client.test.ts).
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase, within } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import type { SignInEvidence, Subject } from '../domain/sign-in.ts';
import { createLoginFlows } from './login-flows.ts';
import { type LoginFlow, type OidcClient, SignInFailed } from './oidc-client.ts';
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

  finish(flow: LoginFlow, returned: { code: string; state: string }) {
    this.finished.push({ flow, ...returned });
    if (this.failWith !== undefined) return Promise.reject(this.failWith);
    if (returned.state !== flow.state) return Promise.reject(new SignInFailed('state_mismatch', 'test'));
    const subject: Subject = { issuer: ISSUER, subject: this.subject };
    return Promise.resolve({ subject, evidence: this.proves, idTokenHash: Buffer.alloc(32, 7) });
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
    const consumed = await challenges.consume(app, challenge.challengeId, binding(done.sessionId));
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
    expect(await challenges.consume(app, challenge.challengeId, binding(done.sessionId))).toBeUndefined();
    // Still pending, so the person can try again: unless its time ran out, which is the failure.
    if (clock.now().getTime() === START.getTime()) {
      expect(await challenges.pending(app, challenge.challengeId, done.sessionId)).toMatchObject({
        challengeId: challenge.challengeId,
      });
    }
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

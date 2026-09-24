// B2-3a-1: a sign-in from end to end, on the real migrated schema, as the app
// role, with a stand-in OIDC client (the client itself: oidc-client.test.ts).
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import type { SignInEvidence, Subject } from '../domain/sign-in.ts';
import { createLoginFlows } from './login-flows.ts';
import { type LoginFlow, type OidcClient, SignInFailed } from './oidc-client.ts';
import { createSessions, type Sessions } from './sessions.ts';
import { createSignIn, type SignIn } from './sign-in-flow.ts';
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

  start() {
    this.started += 1;
    flowsMade += 1;
    const mark = String(flowsMade).padStart(6, '0');
    const flow: LoginFlow = {
      state: `s${mark}`.padEnd(43, 'S'),
      nonce: `n${mark}`.padEnd(43, 'N'),
      verifier: `v${mark}`.padEnd(43, 'V'),
    };
    return Promise.resolve({ url: `${ISSUER}/oauth/v2/authorize?state=${flow.state}`, flow });
  }

  finish(flow: LoginFlow, returned: { code: string; state: string }) {
    this.finished.push({ flow, ...returned });
    if (this.failWith !== undefined) return Promise.reject(this.failWith);
    if (returned.state !== flow.state) return Promise.reject(new SignInFailed('state_mismatch', 'test'));
    const subject: Subject = { issuer: ISSUER, subject: this.subject };
    return Promise.resolve({ subject, evidence });
  }
}

let client: StandInClient;
let sessions: Sessions;
let signIn: SignIn;
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
  const clock = new FixedClock(START);
  const ids = new SequentialIds(0x5000 + subjects * 0x100);
  sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  signIn = createSignIn({ db: app, oidc: client, flows: createLoginFlows({ clock }), sessions, ids, clock });
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

  it("gives each browser its own flow: one's callback can't finish another's", async () => {
    const mine = await signIn.begin();
    const theirs = await signIn.begin();
    const theirState = new URL(theirs.url).searchParams.get('state') ?? '';

    await expect(
      signIn.complete({ flowId: mine.flowId, code: 'a-code', state: theirState, previousCookie: undefined }),
    ).rejects.toMatchObject({ failure: 'state_mismatch' });
  });
});

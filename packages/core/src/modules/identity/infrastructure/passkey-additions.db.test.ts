// SA6: a passkey added inside Agent X, from the step-up to the key confirmed (passkey-additions.ts): the ticket bound
// to its session and used once, in time; the passkey's ID on the platform chain before the page has anything to make
// the key with, and nothing handed out when that record fails; the person's token sealed for this addition alone,
// used once and taken back.
import { createDatabase, type Database, type IdempotentRequest } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it, vi } from 'vitest';

import type { AuditTables } from '../../audit/index.ts';
import type { PlatformControlsTables } from '../../platform-controls/index.ts';
import {
  OWN_PASSKEY_REGISTERED,
  PASSKEY_ADD_ACTION,
  REGISTERING_SECONDS,
  STEPPED_UP_SECONDS,
  TICKET_SECONDS,
} from '../domain/passkey-addition.ts';
import type { OwnPasskeys } from './idp-passkeys.ts';
import { createPasskeyAdditions, sweepPasskeyAdditions } from './passkey-additions.ts';
import { createSessions } from './sessions.ts';
import { LoginTokenRefused } from './zitadel-call.ts';
import { createStepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & AuditTables & PlatformControlsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x5a61_0000_0000);
const ISSUER = 'https://auth.example.test';
const PERSON_KEYS = '00000000-0000-0000-0000-000000000000';
/** The person's access token, as a stand-in: built at run time, as every stand-in for a secret. */
const TOKEN = ['person', 'access', 'stand', 'in'].join('-');
const OPTIONS = { publicKey: { challenge: 'Y2hhbGxlbmdl', rp: { id: 'auth.example.test' } } };
let clock: FixedClock;
let counter = 0;

/** The login service as the person: each call kept, its answers as the test sets them. */
function loginService(passkeyId = '400000000000000001') {
  const calls = { register: [] as string[][], confirm: [] as unknown[][] };
  const passkeys: OwnPasskeys & { answer: 'confirmed' | 'refused'; failRegister?: Error } = {
    answer: 'confirmed',
    register: (token, subject) => {
      calls.register.push([token, subject]);
      if (passkeys.failRegister !== undefined) return Promise.reject(passkeys.failRegister);
      return Promise.resolve({ passkeyId, options: OPTIONS });
    },
    confirm: (token, subject, id, credential) => {
      calls.confirm.push([token, subject, id, credential]);
      return Promise.resolve(passkeys.answer);
    },
  };
  return { passkeys, calls };
}

function additionsWith(passkeys: OwnPasskeys, revoke = vi.fn(() => Promise.resolve(true)), capture?: LogCapture) {
  const challenges = createStepUpChallenges({ ids, clock, keys, logger: testLogger() });
  return {
    challenges,
    revoke,
    additions: createPasskeyAdditions({
      database: app,
      challenges,
      passkeys,
      revoke,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    }),
  };
}

/** A person signed in, with a session. */
async function signedIn(): Promise<{ userId: string; subject: string; sessionId: string }> {
  counter += 1;
  const subject = String(314_000_000_000_000_000n + BigInt(counter));
  const userId = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger() });
  const { sessionId } = await createSessions({
    ids,
    clock,
    timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
    keys,
    logger: testLogger(),
  }).open(app, userId, { idpSessionId: 'V1_1', authTime: clock.now(), amr: ['user', 'mfa'] });
  return { userId, subject, sessionId };
}

const keyed = (userId: string, operation: string, key = `key-${String(counter)}-${operation}`): IdempotentRequest => ({
  orgId: PERSON_KEYS,
  client: { kind: 'user', id: userId },
  operation,
  key,
  payload: '{}',
});

/** A person stepped up for an addition: its challenge, with the token kept as the step-up's return keeps it. */
async function steppedUp(passkeys: OwnPasskeys, revoke?: ReturnType<typeof vi.fn>, capture?: LogCapture) {
  const who = await signedIn();
  const parts = additionsWith(passkeys, revoke as never, capture);
  const begun = await parts.additions.begin(who.sessionId, who.userId, keyed(who.userId, 'passkey.add'));
  if (begun.outcome !== 'done') throw new Error('not begun');
  await app.transaction().execute((tx) =>
    parts.additions.steppedUp(tx, {
      challengeId: begun.challengeId,
      sessionId: who.sessionId,
      userId: who.userId,
      accessToken: TOKEN,
    }),
  );
  return { ...who, ...parts, challengeId: begun.challengeId };
}

/** Stepped up and ticketed. */
async function ticketed(passkeys: OwnPasskeys, revoke?: ReturnType<typeof vi.fn>, capture?: LogCapture) {
  const stepped = await steppedUp(passkeys, revoke, capture);
  const issued = await stepped.additions.ticket(
    stepped.sessionId,
    stepped.challengeId,
    keyed(stepped.userId, 'passkey.add.confirm'),
  );
  if (issued.outcome !== 'done') throw new Error('not ticketed');
  return { ...stepped, ticket: issued.ticket };
}

const ownRecords = async () =>
  (
    await app
      .selectFrom('platform_controls.audit_events')
      .select('details')
      .where('action', '=', OWN_PASSKEY_REGISTERED)
      .orderBy('seq')
      .execute()
  ).map((row) => JSON.parse(row.details) as Record<string, unknown>);

const rowOf = (id: string) =>
  app.selectFrom('identity.passkey_additions').selectAll().where('id', '=', id).executeTakeFirst();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date(Date.UTC(2026, 5, 1 + counter, 9)));
});

describe(`SA6: adding a passkey inside Agent X (Postgres ${server.version})`, () => {
  it('opens the session’s step-up for adding a passkey, the same one for a retry of the request', async () => {
    const who = await signedIn();
    const { additions, challenges } = additionsWith(loginService().passkeys);
    const request = keyed(who.userId, 'passkey.add');

    const first = await additions.begin(who.sessionId, who.userId, request);
    const again = await additions.begin(who.sessionId, who.userId, request);

    expect(first).toEqual({ outcome: 'done', challengeId: expect.any(String) as string });
    expect(again).toEqual(first);
    if (first.outcome !== 'done') return;
    expect(await challenges.pending(app, first.challengeId, who.sessionId)).toEqual(
      expect.objectContaining({ action: PASSKEY_ADD_ACTION, userId: who.userId }),
    );
    expect(await additions.begin(who.sessionId, who.userId, { ...request, payload: '{"other":1}' })).toEqual({
      outcome: 'conflict',
    });
  });

  it('refuses to open a step-up for a session that is gone', async () => {
    const who = await signedIn();
    await app.deleteFrom('identity.sessions').where('id', '=', who.sessionId).execute();
    const { additions } = additionsWith(loginService().passkeys);

    expect(await additions.begin(who.sessionId, who.userId, keyed(who.userId, 'passkey.add'))).toEqual({
      outcome: 'refused',
      code: 'UNAUTHENTICATED',
    });
  });

  it('keeps the person’s token sealed, opening for this addition alone', async () => {
    const stepped = await steppedUp(loginService().passkeys);
    const row = await rowOf(stepped.challengeId);

    expect(row).toEqual(expect.objectContaining({ state: 'stepped_up', ticket_hash: null, passkey_id: null }));
    expect(row?.token_ciphertext?.toString('utf8')).not.toContain(TOKEN);
    // Moved to another addition of another person, it won't open there.
    const other = await steppedUp(loginService().passkeys);
    const issued = await other.additions.ticket(
      other.sessionId,
      other.challengeId,
      keyed(other.userId, 'passkey.add.confirm'),
    );
    if (issued.outcome !== 'done') throw new Error('not ticketed');
    await app
      .updateTable('identity.passkey_additions')
      .set({ token_ciphertext: row?.token_ciphertext ?? null, token_key_version: row?.token_key_version ?? null })
      .where('id', '=', other.challengeId)
      .execute();
    await expect(other.additions.options(issued.ticket)).rejects.toThrow("can't be opened");
  });

  it('SEC-HA-02 refuses the ticket before the person signs in again, to another session, or once the step-up ran out', async () => {
    const who = await signedIn();
    const { additions } = additionsWith(loginService().passkeys);
    const begun = await additions.begin(who.sessionId, who.userId, keyed(who.userId, 'passkey.add'));
    if (begun.outcome !== 'done') throw new Error('not begun');
    // Asked for, never signed in again for: nothing waits for its ticket.
    expect(await additions.ticket(who.sessionId, begun.challengeId, keyed(who.userId, 'passkey.add.confirm'))).toEqual({
      outcome: 'refused',
      code: 'STEP_UP_FAILED',
    });
    // Signed in again for, but asked from another session, or after the step-up's minutes.
    const stepped = await steppedUp(loginService().passkeys);
    const stranger = await signedIn();
    expect(
      await stepped.additions.ticket(
        stranger.sessionId,
        stepped.challengeId,
        keyed(stranger.userId, 'passkey.add.confirm'),
      ),
    ).toEqual({ outcome: 'refused', code: 'STEP_UP_FAILED' });
    clock.advanceBy(STEPPED_UP_SECONDS * 1000);
    expect(
      await stepped.additions.ticket(
        stepped.sessionId,
        stepped.challengeId,
        keyed(stepped.userId, 'passkey.add.confirm'),
      ),
    ).toEqual({ outcome: 'refused', code: 'STEP_UP_FAILED' });
  });

  describe('the ticket', () => {
    it('is given once, for the session that stepped up, and its step-up challenge goes', async () => {
      const stepped = await steppedUp(loginService().passkeys);
      const request = keyed(stepped.userId, 'passkey.add.confirm');

      const issued = await stepped.additions.ticket(stepped.sessionId, stepped.challengeId, request);

      expect(issued).toEqual({
        outcome: 'done',
        ticket: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) as string,
        endsAt: new Date(clock.now().getTime() + TICKET_SECONDS * 1000),
      });
      expect(await stepped.challenges.pending(app, stepped.challengeId, stepped.sessionId)).toBeUndefined();
      // The same request again can't be shown the ticket, kept nowhere; another request finds none waiting.
      expect(await stepped.additions.ticket(stepped.sessionId, stepped.challengeId, request)).toEqual({
        outcome: 'refused',
        code: 'PASSKEY_TICKET_ALREADY_ISSUED',
      });
      expect(
        await stepped.additions.ticket(
          stepped.sessionId,
          stepped.challengeId,
          keyed(stepped.userId, 'passkey.add.confirm', 'k2'),
        ),
      ).toEqual({ outcome: 'refused', code: 'STEP_UP_FAILED' });
    });

    it('is never given to another person’s session, nor seen from it', async () => {
      const stepped = await steppedUp(loginService().passkeys);
      const stranger = await signedIn();

      expect(
        await stepped.additions.ticket(
          stranger.sessionId,
          stepped.challengeId,
          keyed(stranger.userId, 'passkey.add.confirm'),
        ),
      ).toEqual({ outcome: 'refused', code: 'STEP_UP_FAILED' });
      expect(await stepped.additions.status(stranger.sessionId, stepped.challengeId)).toBe('GONE');
      expect(await stepped.additions.status(stepped.sessionId, stepped.challengeId)).toBe('STEPPED_UP');
    });

    it('is not given once the step-up’s minutes ran out', async () => {
      const stepped = await steppedUp(loginService().passkeys);
      clock.advanceBy(STEPPED_UP_SECONDS * 1000);

      expect(
        await stepped.additions.ticket(
          stepped.sessionId,
          stepped.challengeId,
          keyed(stepped.userId, 'passkey.add.confirm'),
        ),
      ).toEqual({ outcome: 'refused', code: 'STEP_UP_FAILED' });
    });

    it('redeems nothing once its minutes ran out, used, or not one of ours', async () => {
      const { passkeys, calls } = loginService();
      const late = await ticketed(passkeys);
      clock.advanceBy(TICKET_SECONDS * 1000);
      expect(await late.additions.options(late.ticket)).toEqual({ outcome: 'refused', code: 'PASSKEY_TICKET_INVALID' });

      const used = await ticketed(passkeys);
      expect((await used.additions.options(used.ticket)).outcome).toBe('done');
      expect(await used.additions.options(used.ticket)).toEqual({ outcome: 'refused', code: 'PASSKEY_TICKET_INVALID' });

      expect(await used.additions.options('A'.repeat(43))).toEqual({
        outcome: 'refused',
        code: 'PASSKEY_TICKET_INVALID',
      });
      expect(await used.additions.options('not a ticket')).toEqual({
        outcome: 'refused',
        code: 'PASSKEY_TICKET_INVALID',
      });
      expect(await used.additions.confirm('not a ticket', {})).toEqual({
        outcome: 'refused',
        code: 'PASSKEY_TICKET_INVALID',
      });
      expect(calls.register).toHaveLength(1);
    });
  });

  describe('the options', () => {
    it('SA6 records the passkey as the person’s own on the platform chain before handing anything out', async () => {
      const { passkeys, calls } = loginService('400000000000000777');
      const ready = await ticketed(passkeys);

      const asked = await ready.additions.options(ready.ticket);

      expect(asked).toEqual({ outcome: 'done', options: OPTIONS });
      expect(calls.register).toEqual([[TOKEN, ready.subject]]);
      expect(await ownRecords()).toContainEqual({
        person: ready.userId,
        subject: ready.subject,
        passkey: '400000000000000777',
        at: clock.now().toISOString(),
      });
      expect(await rowOf(ready.challengeId)).toEqual(
        expect.objectContaining({
          state: 'registering',
          passkey_id: '400000000000000777',
          ends_at: new Date(clock.now().getTime() + REGISTERING_SECONDS * 1000),
        }),
      );
      expect(await ready.additions.status(ready.sessionId, ready.challengeId)).toBe('WAITING_FOR_KEY');
    });

    it('SA6 hands nothing out when the record can’t be made, and takes the person’s token back', async () => {
      // A passkey ID the table refuses: the transaction that records it rolls back, record and all.
      const { passkeys } = loginService('9'.repeat(201));
      const revoke = vi.fn(() => Promise.resolve(true));
      const ready = await ticketed(passkeys, revoke);
      const before = (await ownRecords()).length;

      await expect(ready.additions.options(ready.ticket)).rejects.toThrow();

      expect(await ownRecords()).toHaveLength(before);
      expect(revoke).toHaveBeenCalledWith(TOKEN);
      expect(await rowOf(ready.challengeId)).toBeUndefined();
    });

    it('records nothing when the login service fails, takes the token back, and the ticket stays used', async () => {
      const { passkeys } = loginService();
      passkeys.failRegister = new Error('the login service is away');
      const revoke = vi.fn(() => Promise.resolve(true));
      const ready = await ticketed(passkeys, revoke);
      const before = (await ownRecords()).length;

      await expect(ready.additions.options(ready.ticket)).rejects.toThrow('away');

      expect(await ownRecords()).toHaveLength(before);
      expect(revoke).toHaveBeenCalledWith(TOKEN);
      // Its token no longer stored: the row, token and all, is gone.
      expect(await rowOf(ready.challengeId)).toBeUndefined();
      expect(await ready.additions.options(ready.ticket)).toEqual({
        outcome: 'refused',
        code: 'PASSKEY_TICKET_INVALID',
      });
    });

    it('answers the person’s token refused as the key refused, never the login service’s alarm, and lets it go', async () => {
      const { passkeys } = loginService();
      passkeys.failRegister = new LoginTokenRefused('the login service refused the token: it answered 401');
      const revoke = vi.fn(() => Promise.resolve(false));
      const capture = new LogCapture();
      const ready = await ticketed(passkeys, revoke, capture);

      expect(await ready.additions.options(ready.ticket)).toEqual({ outcome: 'refused', code: 'PASSKEY_REFUSED' });

      expect(revoke).toHaveBeenCalledWith(TOKEN);
      expect(await rowOf(ready.challengeId)).toBeUndefined();
      // Revocation refused too: said plainly, never naming the token.
      expect(capture.lines().map((line) => line.event)).toEqual(['identity.passkey_token_kept']);
      expect(JSON.stringify(capture.lines())).not.toContain(TOKEN);
    });
  });

  describe('the key confirmed', () => {
    it('is sent to the login service as the person once, the token taken back, and read as added', async () => {
      const { passkeys, calls } = loginService('400000000000000888');
      const revoke = vi.fn(() => Promise.resolve(true));
      const ready = await ticketed(passkeys, revoke);
      await ready.additions.options(ready.ticket);
      const credential = { id: 'abc', rawId: 'abc', type: 'public-key', response: {} };

      expect(await ready.additions.confirm(ready.ticket, credential)).toEqual({ outcome: 'done' });

      expect(calls.confirm).toEqual([[TOKEN, ready.subject, '400000000000000888', credential]]);
      expect(revoke).toHaveBeenCalledWith(TOKEN);
      expect(await rowOf(ready.challengeId)).toEqual(
        expect.objectContaining({ state: 'confirmed', token_ciphertext: null, token_key_version: null }),
      );
      expect(await ready.additions.status(ready.sessionId, ready.challengeId)).toBe('ADDED');
      expect(await ready.additions.confirm(ready.ticket, credential)).toEqual({
        outcome: 'refused',
        code: 'PASSKEY_TICKET_INVALID',
      });
      expect(calls.confirm).toHaveLength(1);
    });

    it('is refused before the options were asked for, or once its minutes ran out', async () => {
      const { passkeys, calls } = loginService();
      const early = await ticketed(passkeys);
      expect(await early.additions.confirm(early.ticket, {})).toEqual({
        outcome: 'refused',
        code: 'PASSKEY_TICKET_INVALID',
      });

      const late = await ticketed(passkeys);
      await late.additions.options(late.ticket);
      clock.advanceBy(REGISTERING_SECONDS * 1000);
      expect(await late.additions.confirm(late.ticket, {})).toEqual({
        outcome: 'refused',
        code: 'PASSKEY_TICKET_INVALID',
      });
      expect(calls.confirm).toEqual([]);
    });

    it('refused by the login service, is gone, its token taken back, and said so', async () => {
      const { passkeys } = loginService();
      passkeys.answer = 'refused';
      const revoke = vi.fn(() => Promise.resolve(false));
      const ready = await ticketed(passkeys, revoke);
      await ready.additions.options(ready.ticket);

      expect(await ready.additions.confirm(ready.ticket, {})).toEqual({ outcome: 'refused', code: 'PASSKEY_REFUSED' });

      expect(revoke).toHaveBeenCalledWith(TOKEN);
      expect(await rowOf(ready.challengeId)).toBeUndefined();
      expect(await ready.additions.status(ready.sessionId, ready.challengeId)).toBe('GONE');
    });
  });

  it('sweeps additions past their time, taking back each token still held, and leaves the rest', async () => {
    const stale = await steppedUp(loginService().passkeys);
    clock.advanceBy(STEPPED_UP_SECONDS * 1000);
    const fresh = await steppedUp(loginService().passkeys);
    const revoke = vi.fn(() => Promise.resolve(true));
    const capture = new LogCapture();

    const swept = await sweepPasskeyAdditions({ database: app, keys, revoke, clock, logger: testLogger(capture) }, 100);

    expect(swept).toBeGreaterThanOrEqual(1);
    expect(revoke).toHaveBeenCalledWith(TOKEN);
    // Earlier tests' additions go too; only those still holding a token are taken back.
    expect(revoke.mock.calls.length).toBeLessThanOrEqual(swept);
    // Every token taken back: none said kept (an earlier test's token moved to another row is the alarm, as below).
    expect(capture.lines().filter((line) => line.event === 'identity.passkey_token_kept')).toEqual([]);
    expect(await rowOf(stale.challengeId)).toBeUndefined();
    expect(await rowOf(fresh.challengeId)).toBeDefined();
  });

  it('sweeps a token the login service won’t take back, or with no way to, all the same, and says so', async () => {
    for (const revoke of [vi.fn(() => Promise.resolve(false)), undefined]) {
      const stale = await steppedUp(loginService().passkeys);
      clock.advanceBy(STEPPED_UP_SECONDS * 1000);
      const capture = new LogCapture();

      await sweepPasskeyAdditions({ database: app, keys, revoke, clock, logger: testLogger(capture) }, 100);

      expect(await rowOf(stale.challengeId)).toBeUndefined();
      expect(capture.lines().map((line) => line.event)).toContain('identity.passkey_token_kept');
      expect(JSON.stringify(capture.lines())).not.toContain(TOKEN);
    }
  });

  it('sweeps a confirmed addition, which holds no token, taking nothing back', async () => {
    const { passkeys } = loginService();
    const ready = await ticketed(passkeys);
    await ready.additions.options(ready.ticket);
    await ready.additions.confirm(ready.ticket, {});
    clock.advanceBy(60 * 60_000);
    const revoke = vi.fn(() => Promise.resolve(true));

    await sweepPasskeyAdditions({ database: app, keys, revoke, clock, logger: testLogger() }, 100);

    expect(await rowOf(ready.challengeId)).toBeUndefined();
    expect(revoke).not.toHaveBeenCalled();
  });

  it('sweeps a token sealed for another addition with the alarm, never sending it anywhere', async () => {
    const first = await steppedUp(loginService().passkeys);
    const second = await steppedUp(loginService().passkeys);
    const moved = await rowOf(first.challengeId);
    await app
      .updateTable('identity.passkey_additions')
      .set({ token_ciphertext: moved?.token_ciphertext ?? null, token_key_version: moved?.token_key_version ?? null })
      .where('id', '=', second.challengeId)
      .execute();
    await app.deleteFrom('identity.passkey_additions').where('id', '=', first.challengeId).execute();
    clock.advanceBy(STEPPED_UP_SECONDS * 1000);
    const revoke = vi.fn(() => Promise.resolve(true));
    const capture = new LogCapture();

    await sweepPasskeyAdditions({ database: app, keys, revoke, clock, logger: testLogger(capture) }, 100);

    expect(await rowOf(second.challengeId)).toBeUndefined();
    expect(revoke).not.toHaveBeenCalled();
    expect(capture.lines()).toEqual([
      expect.objectContaining({ event: 'audit.integrity_failed', check: 'passkey_addition' }),
    ]);
  });
});

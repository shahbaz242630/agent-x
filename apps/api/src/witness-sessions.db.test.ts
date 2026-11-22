// TR-1 (11), with AT13h (S208): a platform chain cut back below a head another copy wrote and witnessed, found by a copy
// that never read it. W records on the platform chain, its head witnessed; the owner (agentx_owner, none of the app's
// keys) cuts the chain's end off and puts back the head before it. J's console sessions, held to the heads W witnessed,
// find the cut, answer it once by every session ended (signed), and take the chain as it stands: the next sign-in works
// on J with no restart. The head the cut took away, witnessed before the answer, never locks the console again (the
// accepted reads hold only to heads witnessed after it); every other read (the hand-off pause's) stays held to it.
import { checkStatesWith, witnessWith } from '@agentx/core/modules/audit';
import { createSessions, type IdentityTables, userForSubject } from '@agentx/core/modules/identity';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { createDigestLog, createWitnessLog, type DigestLog, WitnessUnconfirmed } from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createFakeWriteOnceStore,
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it } from 'vitest';

import { recordStart } from './start-record.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables & PlatformControlsTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x7c1e_0000);
// Behind the database's clock: signed ends with a time to come decide nothing.
const clock = new FixedClock(new Date('2026-01-01T09:00:00Z'));
const TIMEOUTS = { idleSeconds: 1800, absoluteSeconds: 43_200 };
const PLATFORM = { kind: 'platform' } as const;
const capture = new LogCapture();
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables & PlatformControlsTables>(
    { ...database.connection('app'), maxConnections: 4 },
    testLogger(),
  );
  await started();
});

afterEach(() => {
  checkStatesWith(undefined);
  witnessWith(undefined);
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** A platform event as a start writes one. */
const started = () =>
  recordStart(app, keys, ids, { configHash: `sha256:${'ab'.repeat(32)}`, release: 'r-test', gateRef: undefined });

/** A copy's sessions, held to its digest, answering a cut in the database. */
const sessionsOn = (digest: DigestLog) =>
  createSessions({
    ids,
    clock,
    timeouts: TIMEOUTS,
    keys,
    logger: testLogger(capture),
    digest: () => digest,
    database: app,
  });

let people = 0;
/** Someone signed in now, on no copy's digest. */
async function signedIn(): Promise<{ sessionId: string; cookie: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `witness-sessions-${String(people)}` },
    { ids, clock, keys, logger: testLogger() },
  );
  return createSessions({ ids, clock, timeouts: TIMEOUTS, keys, logger: testLogger() }).open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
  });
}

/** One statement as agentx_owner. */
async function asOwner(text: string, values: readonly unknown[] = []): Promise<Record<string, unknown>[]> {
  const owner = await database.connect('owner');
  try {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text; every value is bound.
    return await owner.query(text, values);
  } finally {
    await owner.end();
  }
}

/**
 * W writes on the platform chain, its head witnessed; the owner cuts it off; J reads the store, its digest held to it.
 * Someone signed in before, and J's sessions.
 */
async function cutWitnessedOnW() {
  const store = createFakeWriteOnceStore();
  const witnessOf = (waitMs?: number) =>
    createWitnessLog({
      store: store.store,
      keys,
      logger: testLogger(capture),
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 1024 * 1024,
      ...(waitMs === undefined ? {} : { waitMs }),
    });
  const bystander = await signedIn();
  const [before] = await asOwner(
    'select h.seq::text as seq, pg_catalog.row_to_json(h) as kept from platform_controls.audit_head h',
  );
  // W writes on the platform chain; its head goes to the store before W's process says it is done.
  const onW = witnessOf();
  witnessWith(onW);
  await started();
  witnessWith(undefined);
  await onW.drained();
  expect(store.files.size).toBe(1);
  // The owner cuts W's event off and puts back the head before it: every seal true.
  await asOwner('delete from platform_controls.audit_events where seq > $1::bigint', [String(before?.seq)]);
  await asOwner(
    `update platform_controls.audit_head h set (seq, hash, mac, mac_key_version) =
         (select r.seq, r.hash, r.mac, r.mac_key_version
          from pg_catalog.json_populate_record(null::platform_controls.audit_head, $1::json) r)`,
    [JSON.stringify(before?.kept)],
  );

  // J never read W's event: only the store tells it.
  const onJ = witnessOf();
  await onJ.refresh();
  const digest = createDigestLog({
    keys,
    logger: testLogger(capture),
    now: () => clock.now(),
    epoch: 1,
    alertAfterMs: 60_000,
    mostBytes: 64 * 1024 * 1024,
    witnessed: (chain) => onJ.heldTo(chain),
  });
  await digest.read();
  expect(digest.heads(PLATFORM)?.seen).toBeUndefined();
  const witnessed = onJ.pending(PLATFORM)[0]?.seq;
  expect(witnessed).toBeGreaterThan(BigInt(String(before?.seq)));
  return { store, witnessOf, bystander, onJ, digest, witnessed, j: sessionsOn(digest) };
}

describe('SEC-DB-20 TR-1 (11): a platform cut below another copy’s witnessed head, answered as AT13h answers it', () => {
  it('found on J from W’s head: the alarm, every session ended once, then a new sign-in works on J; the pause stays held', async () => {
    const { bystander, onJ, digest, witnessed, j } = await cutWitnessedOnW();

    expect(await j.use(app, bystander.cookie)).toBeUndefined();
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ check: 'platform_chain', reason: 'cut_back', seq: String(witnessed) }),
    ]);
    expect(lines('identity.sessions_all_ended')).toHaveLength(1);
    expect(digest.heads(PLATFORM)?.accepted).toBeDefined();

    // Someone signs in again on J, no restart: let in, no further alarm, though W's old head is still witnessed.
    clock.advanceBy(1000);
    const again = await signedIn();
    expect(await j.use(app, again.cookie)).toMatchObject({ sessionId: again.sessionId });
    expect(lines('audit.integrity_failed')).toHaveLength(1);

    // Every other read (the hand-off pause's) stays held to the head the cut took away; the sessions' only to the answer
    // (recorded at that same place, as the chain now stands, another event there).
    const gone = onJ.pending(PLATFORM).find(({ seq }) => seq === witnessed);
    const same = (heads: readonly { seq: bigint; hash: Buffer }[] | undefined) =>
      heads?.some(({ seq, hash }) => seq === gone?.seq && hash.equals(gone.hash));
    expect(same(digest.heads(PLATFORM)?.heldTo)).toBe(true);
    expect(same(digest.heads(PLATFORM)?.accepted?.heldTo)).toBe(false);
  });

  it('PR-1d: the answer’s own head unwitnessed (the store down) is the request’s 503, never a locked console: the next sign-in works', async () => {
    const { store, witnessOf, bystander, j } = await cutWitnessedOnW();
    let down = true;
    store.instead.put = (name, bytes) => (down ? Promise.reject(new Error('store down')) : store.real.put(name, bytes));
    witnessWith(witnessOf(100));
    await expect(j.use(app, bystander.cookie)).rejects.toBeInstanceOf(WitnessUnconfirmed);
    // Answered all the same: every session ended, once.
    expect(lines('identity.sessions_all_ended')).toHaveLength(1);
    expect(lines('identity.sessions_all_end_failed')).toEqual([]);
    // Still down, a new sign-in on J is let in: the cut taken as it stands, nothing more to answer or to wait for.
    clock.advanceBy(1000);
    const again = await signedIn();
    expect(await j.use(app, again.cookie)).toMatchObject({ sessionId: again.sessionId });
    down = false;
    expect(lines('identity.sessions_all_ended')).toHaveLength(1);
  });
});

// Clearing the integrity hold as the organisation's admin does it (B3+-2c-2):
// asked for with the investigation of the hold as it stands, confirmed with a
// step-up bound to exactly that, and cleared only once every record of the
// organisation, the product's own authority tables, is verified whole. What
// the clearing step itself refuses is the audit module's
// (hold-clearing.db.test.ts there).
import { createHash } from 'node:crypto';

import { createDatabase, type Database, type IdempotentRequest } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  confirmedWhileDemoted,
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  type SavedRow,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { type AuditTables, createAuditTrail, pollHoldsWaiting, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import {
  CLEAR_CONFIRM_OPERATION,
  CLEAR_OPERATION,
  type ClearingAdmin,
  createHoldClearings,
  type HoldClearings,
} from './hold-clearing.ts';
import { createHoldInvestigations, INVESTIGATE_OPERATION } from './hold-investigations.ts';
import { addMembership, MEMBERSHIPS } from './memberships.ts';
import { createSessions } from './sessions.ts';
import { createStepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe200_0000_0000);
const clock = new FixedClock(new Date('2026-09-26T09:00:00Z'));
const challenges = () => createStepUpChallenges({ ids, clock });
const sessions = () => createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
let clearings: HoldClearings;
/** What the clearings log. */
const capture = new LogCapture();

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000bb';

const services = () => ({ keys, ids, logger: testLogger() });

let people = 0;
type Member = ClearingAdmin & { membershipId: string; cookie: string };

/** A person in the organisation with this role, signed in. */
async function member(org: string, role: Role): Promise<Member> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `clearing-${String(people)}` },
    { ids, clock },
  );
  const { sessionId, cookie } = await sessions().open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId, cookie };
}

let org: string;
let admin: Member;

/** Runs `work` as the database's owner, inside the organisation. */
async function asOwner(work: (owner: OwnerTamper) => Promise<unknown>): Promise<void> {
  const owner = await tamperAsOwner(database, MEMBERSHIPS, org);
  try {
    await work(owner);
  } finally {
    await owner.end();
  }
}

/** Reads a membership for a decision, as a request would: tampering found there holds the organisation. */
const read = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) =>
    states.verifiedState(tx, MEMBERSHIPS, { orgId: org, id }, 'share'),
  );

/**
 * Another member's role changed past the app and read, then the row put back
 * as it was signed: the organisation held, its cause removed. Gives back how
 * to tamper with the row again, and to put it back again.
 */
async function holdThenRepair(): Promise<{ id: string; tamper: () => Promise<void>; restore: () => Promise<void> }> {
  const { membershipId: id } = await member(org, 'viewer');
  let saved: SavedRow | undefined;
  await asOwner(async (owner) => {
    saved = await owner.saveRow(id);
  });
  const tamper = () => asOwner((owner) => owner.setColumn(id, 'role', 'admin'));
  const restore = () =>
    asOwner(async (owner) => {
      if (saved !== undefined) await owner.restoreRow(saved);
    });
  await tamper();
  await read(id);
  await restore();
  return { id, tamper, restore };
}

const keyed = (who: ClearingAdmin, operation: string, key: string, payload: string): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload,
});

/** Records the investigation of the hold as it stands, as the admin does, and gives back its ID. */
async function investigate(who: ClearingAdmin = admin): Promise<string> {
  const investigations = createHoldInvestigations({ database: app, keys, ids, logger: testLogger() });
  const finding = { conclusion: 'CAUSE_REMOVED', reference: `INC-${ids.next().slice(-6)}` } as const;
  const written = await investigations.record(
    who,
    keyed(who, INVESTIGATE_OPERATION, ids.next(), JSON.stringify(finding)),
    finding,
    CORRELATION,
  );
  if (written.outcome !== 'written') throw new Error(`not recorded: ${JSON.stringify(written)}`);
  return written.investigation.id;
}

const ask = (investigationId: string, who: ClearingAdmin = admin, key = 'ask-1') =>
  clearings.ask(who, keyed(who, CLEAR_OPERATION, key, investigationId), investigationId, CORRELATION);

const confirm = (investigationId: string, challengeId: string, who: ClearingAdmin = admin, key = 'confirm-1') =>
  clearings.confirm(
    who,
    keyed(who, CLEAR_CONFIRM_OPERATION, key, `${investigationId} ${challengeId}`),
    investigationId,
    challengeId,
    CORRELATION,
  );

/** The admin signs in again for the challenge, as the step-up's return records it. */
const stepUp = (who: ClearingAdmin, challengeId: string, amr: readonly string[] = ['pwd', 'user', 'mfa']) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

/** Asks, signs in again, and gives back the challenge. */
/** The API's job's record that the whole history was checked after the investigation (Phase 2 D1c), as it makes it. */
const historyChecked = (investigationId: string) =>
  withSignedStates(app, org, services(), (tx, states) => states.recordHistoryChecked(tx, org, investigationId, 0));

/** Asked and signed in again, the HELD state's history checked meanwhile unless `history` is false. */
async function steppedUp(investigationId: string, who: ClearingAdmin = admin, history = true): Promise<string> {
  const answer = await ask(investigationId, who);
  if (answer.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(answer)}`);
  await stepUp(who, answer.stepUpChallengeId);
  if (history) await historyChecked(investigationId);
  return answer.stepUpChallengeId;
}

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  clearings = createHoldClearings({
    database: app,
    keys,
    ids,
    challenges: challenges(),
    logger: testLogger(capture),
    authorityTables: AUTHORITY_TABLES,
  });
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  admin = await member(org, 'admin');
});

/** Refused and still HELD while the check given what the hold names says not whole; then cleared. */
async function refusedUntilWhole(id: string, investigationId: string, challengeId: string): Promise<void> {
  const asked: string[] = [];
  let whole = false;
  const withTheirs = createHoldClearings({
    database: app,
    keys,
    ids,
    challenges: challenges(),
    logger: testLogger(),
    authorityTables: AUTHORITY_TABLES,
    namedRecordChecks: {
      [MEMBERSHIPS.subject]: (_tx, _states, orgId, objectId) => {
        asked.push(`${orgId} ${objectId}`);
        return Promise.resolve(whole);
      },
    },
  });
  const confirmTheirs = () =>
    withTheirs.confirm(
      admin,
      keyed(admin, CLEAR_CONFIRM_OPERATION, 'confirm-1', `${investigationId} ${challengeId}`),
      investigationId,
      challengeId,
      CORRELATION,
    );

  expect(await confirmTheirs()).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  whole = true;
  expect(await confirmTheirs()).toMatchObject({ outcome: 'cleared' });
  expect(asked).toEqual([`${org} ${id}`, `${org} ${id}`]);
}

describe(`clearing the integrity hold as its admin (Postgres ${server.version})`, () => {
  it('asks, signs in again, and clears: the hold CLEAR, one version on', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);

    const cleared = await confirm(investigationId, challengeId);

    expect(cleared).toMatchObject({ outcome: 'cleared', hold: { outcome: 'clear', version: 3 } });
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 3 });
    // Cleared by the admin, after the investigation, with the step-up they signed in again for.
    const now = await hold();
    const eventId = now.outcome === 'clear' ? now.eventId : ids.next();
    const trail = createAuditTrail({ keys, ids });
    expect(
      await withSignedStates(app, org, services(), (tx) => trail.recordedEvent(tx, org, { eventId })),
    ).toMatchObject({
      kind: 'recorded',
      event: {
        actor: { type: 'user', id: admin.userId },
        action: 'integrity_hold.cleared',
        details: { investigationId, stepUpChallengeId: challengeId },
      },
    });
    // A replay answers the hold as it now stands, clearing nothing more.
    expect(await confirm(investigationId, challengeId)).toEqual(cleared);
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 3 });
  });

  it('answers a replayed ask with the same step-up', async () => {
    await holdThenRepair();
    const investigationId = await investigate();

    const first = await ask(investigationId);

    expect(first).toMatchObject({ outcome: 'asked' });
    expect(await ask(investigationId)).toEqual(first);
  });

  it('refuses to ask while the hold is CLEAR, as NOT_ON_HOLD, keeping nothing', async () => {
    expect(await ask(ids.next())).toEqual({ outcome: 'refused', status: 409, code: 'NOT_ON_HOLD' });
  });

  it('refuses to ask without an investigation of the hold as it stands, as NO_INVESTIGATION', async () => {
    await holdThenRepair();

    expect(await ask(ids.next())).toEqual({ outcome: 'refused', status: 409, code: 'NO_INVESTIGATION' });
  });

  it('refuses an investigation of an earlier HELD state, cleared since and held again', async () => {
    const row = await holdThenRepair();
    const first = await investigate();
    await confirm(first, await steppedUp(first));
    await row.tamper();
    await read(row.id);
    await row.restore();
    expect(await hold()).toMatchObject({ outcome: 'held', version: 4 });

    expect(await ask(first, admin, 'ask-2')).toEqual({ outcome: 'refused', status: 409, code: 'NO_INVESTIGATION' });
  });

  it('SEC-HA-12 refuses a step-up proved with an app code, not a passkey, as STEP_UP_FAILED, leaving it HELD', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const answer = await ask(investigationId);
    if (answer.outcome !== 'asked') throw new Error(`not asked: ${answer.outcome}`);
    await stepUp(admin, answer.stepUpChallengeId, ['pwd', 'otp', 'mfa']);

    expect(await confirm(investigationId, answer.stepUpChallengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('refuses to confirm before the admin has signed in again, as STEP_UP_FAILED, leaving it HELD', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const answer = await ask(investigationId);
    const challengeId = answer.outcome === 'asked' ? answer.stepUpChallengeId : ids.next();

    expect(await confirm(investigationId, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('refuses a step-up signed in again for another investigation, as STEP_UP_FAILED', async () => {
    await holdThenRepair();
    const first = await investigate();
    const challengeId = await steppedUp(first);
    const second = await investigate();

    expect(await confirm(second, challengeId)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it("refuses another admin's step-up, as STEP_UP_FAILED", async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    const other = await member(org, 'admin');

    expect(await confirm(investigationId, challengeId, other)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
  });

  it('refuses while a record is still tampered with, as INTEGRITY_FAILED: every record is checked, and the hold stays', async () => {
    const row = await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    await row.tamper();

    expect(await confirm(investigationId, challengeId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    // Put back as it was signed, the same step-up still clears it: the refusal kept nothing.
    await row.restore();
    expect(await confirm(investigationId, challengeId)).toMatchObject({ outcome: 'cleared' });
  });

  it('refuses while the audit chain is broken, as INTEGRITY_FAILED: an event deleted before the latest signed ones (the S68 audit)', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    // Someone who owns the database deletes an early event: every record's latest signed event is still whole.
    await database.as('admin').query('delete from audit.events where org_id = $1 and seq = 2', [org]);

    expect(await confirm(investigationId, challengeId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
    expect(await hold()).toMatchObject({ outcome: 'held' });
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'integrity_hold.chain_still_broken', reason: 'gap', seq: '2' }),
    );
  });

  it('refuses to confirm once the hold was cleared since, as NOT_ON_HOLD', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    const other = await member(org, 'admin');
    await confirm(investigationId, await steppedUp(investigationId, other), other);

    expect(await confirm(investigationId, challengeId, admin, 'confirm-2')).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'NOT_ON_HOLD',
    });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s at both steps', async (role) => {
    await holdThenRepair();
    const investigationId = await investigate();
    const someone = await member(org, role);

    expect(await ask(investigationId, someone)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await confirm(investigationId, ids.next(), someone)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  it("refuses to ask when the hold can't be believed, as INTEGRITY_FAILED", async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    await asOwner((owner) =>
      owner.query("update audit.events set details = '{}' where org_id = $1 and subject_type = 'integrity_hold'", [
        org,
      ]),
    );

    expect(await ask(investigationId)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('checks every authority table: an organisation with none refused when built', () => {
    expect(() =>
      createHoldClearings({
        database: app,
        keys,
        ids,
        challenges: challenges(),
        logger: testLogger(),
        authorityTables: [],
      }),
    ).toThrow('Clearing checks every authority table first');
  });

  it('refuses an investigation whose event was changed past the app, as INTEGRITY_FAILED, at both steps', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    await asOwner((owner) =>
      owner.query(
        "update audit.events set details = replace(details, 'CAUSE_REMOVED', 'NO_TAMPERING') where org_id = $1 and subject_type = 'hold_investigation'",
        [org],
      ),
    );

    expect(await ask(investigationId, admin, 'ask-2')).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
    expect(await confirm(investigationId, challengeId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('refuses to ask for a session ended since the request was let in, as UNAUTHENTICATED', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    await sessions().end(app, admin.cookie);

    expect(await ask(investigationId)).toEqual({ outcome: 'refused', status: 401, code: 'UNAUTHENTICATED' });
  });

  it('refuses until the HELD state’s whole history is checked, as HISTORY_UNCHECKED, leaving it HELD (Phase 2 D1c)', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId, admin, false);

    expect(await confirm(investigationId, challengeId)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'HISTORY_UNCHECKED',
    });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    // Once the API's job has recorded it, the same step-up clears it.
    await historyChecked(investigationId);
    expect(await confirm(investigationId, challengeId)).toMatchObject({ outcome: 'cleared' });
  });

  it('asks for no history check when no table is a growing one', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId, admin, false);
    const noGrowing = createHoldClearings({
      database: app,
      keys,
      ids,
      challenges: challenges(),
      logger: testLogger(),
      authorityTables: AUTHORITY_TABLES.filter((table) => table.liveStatuses === undefined),
    });

    expect(
      await noGrowing.confirm(
        admin,
        keyed(admin, CLEAR_CONFIRM_OPERATION, 'confirm-1', `${investigationId} ${challengeId}`),
        investigationId,
        challengeId,
        CORRELATION,
      ),
    ).toMatchObject({ outcome: 'cleared' });
  });

  it('refuses at once while the record its hold names is tampered with, though past the newest of a growing table (Phase 2 D1b; 4D2e Stage F)', async () => {
    const row = await holdThenRepair();
    // A newer membership, so the named one is past the newest one verifyAll reads here.
    await member(org, 'viewer');
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    // Memberships checked as a growing table is, in a status none of these has: verifyAll judges the newest alone.
    const liveOnly = createHoldClearings({
      database: app,
      keys,
      ids,
      challenges: challenges(),
      logger: testLogger(),
      authorityTables: AUTHORITY_TABLES.map((table) =>
        table === MEMBERSHIPS ? { ...table, liveStatuses: ['DEACTIVATED'] } : table,
      ),
      objectsChecked: 1,
    });
    const confirmLiveOnly = () =>
      liveOnly.confirm(
        admin,
        keyed(admin, CLEAR_CONFIRM_OPERATION, 'confirm-1', `${investigationId} ${challengeId}`),
        investigationId,
        challengeId,
        CORRELATION,
      );
    await row.tamper();

    expect(await confirmLiveOnly()).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    // Put back as it was signed, it clears.
    await row.restore();
    expect(await confirmLiveOnly()).toMatchObject({ outcome: 'cleared' });
  });

  it('refuses while what the hold names is not whole beyond its signed state, its own check given the record (G1)', async () => {
    const row = await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    await refusedUntilWhole(row.id, investigationId, challengeId);
  });

  it('a hold recorded from a row, by a process that never saw the finding: the same check, and it stays held (D5)', async () => {
    const { membershipId: id } = await member(org, 'viewer');
    await database
      .as('app')
      .query(
        "insert into directory.holds_waiting (org_id, subject_type, object_id, reason) values ($1, $2, $3, 'holding')",
        [org, MEMBERSHIPS.subject, id],
      );
    await pollHoldsWaiting(app, services());
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);

    await refusedUntilWhole(id, investigationId, challengeId);
  });

  describe('a hold naming a record with no row (D5)', () => {
    /** A hold as a forged row sets it: naming this, and nothing else tampered with. */
    const holdFromRow = async (subjectType: string, objectId: string) => {
      await database
        .as('app')
        .query(
          "insert into directory.holds_waiting (org_id, subject_type, object_id, reason) values ($1, $2, $3, 'seal')",
          [org, subjectType, objectId],
        );
      await pollHoldsWaiting(app, services());
      expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    };
    let linesBefore = 0;
    const nothingToRepair = () =>
      capture
        .lines()
        .slice(linesBefore)
        .filter(({ event }) => event === 'integrity_hold.named_record_never_signed');
    /** Memberships checked as a growing table is, in a status none has: only the check of what the hold names reads them. */
    const confirmLiveOnly = (investigationId: string, challengeId: string) =>
      createHoldClearings({
        database: app,
        keys,
        ids,
        challenges: challenges(),
        logger: testLogger(capture),
        authorityTables: AUTHORITY_TABLES.map((table) =>
          table === MEMBERSHIPS ? { ...table, liveStatuses: ['DEACTIVATED'] } : table,
        ),
      }).confirm(
        admin,
        keyed(admin, CLEAR_CONFIRM_OPERATION, 'confirm-1', `${investigationId} ${challengeId}`),
        investigationId,
        challengeId,
        CORRELATION,
      );

    beforeEach(() => {
      linesBefore = capture.lines().length;
    });

    it('a record that never existed has nothing to repair: cleared by the real steps, and said', async () => {
      const never = ids.next();
      await holdFromRow(MEMBERSHIPS.subject, never);
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);

      expect(await confirm(investigationId, challengeId)).toMatchObject({ outcome: 'cleared' });

      expect(await hold()).toMatchObject({ outcome: 'clear', version: 3 });
      expect(nothingToRepair()).toEqual([
        expect.objectContaining({
          level: 'warn',
          orgId: org,
          correlationId: CORRELATION,
          subjectType: MEMBERSHIPS.subject,
          objectId: never,
        }),
      ]);
    });

    it('another organisation’s record reads as none of this one’s: the same way out', async () => {
      const neighbour = ids.next();
      await withSignedStates(app, neighbour, services(), (tx, states) =>
        createOrganization(tx, states, { id: neighbour, name: 'Next Door LLC', actor: OPERATOR }),
      );
      const { membershipId } = await member(neighbour, 'viewer');
      await holdFromRow(MEMBERSHIPS.subject, membershipId);
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);

      expect(await confirm(investigationId, challengeId)).toMatchObject({ outcome: 'cleared' });
      expect(nothingToRepair()).toHaveLength(1);
    });

    it('a subject no table holds has nothing to read: cleared, with no line, as for the chain', async () => {
      await holdFromRow('no_such_subject', ids.next());
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);

      expect(await confirm(investigationId, challengeId)).toMatchObject({ outcome: 'cleared' });
      expect(nothingToRepair()).toEqual([]);
    });

    it('a clear that commits says cleared, though another record waits here to be the next hold, which it then is', async () => {
      await holdFromRow(MEMBERSHIPS.subject, ids.next());
      const next = ids.next();
      await database
        .as('app')
        .query(
          "insert into directory.holds_waiting (org_id, subject_type, object_id, reason) values ($1, $2, $3, 'seal')",
          [org, MEMBERSHIPS.subject, next],
        );
      await pollHoldsWaiting(app, services());
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);

      expect(await confirm(investigationId, challengeId)).toMatchObject({
        outcome: 'cleared',
        hold: { outcome: 'clear', version: 3 },
      });

      // The next hold stands by its own row: set by that same read's end, with no wait.
      expect(await hold()).toMatchObject({ outcome: 'held', version: 4 });
    });

    it('a replay reading the next hold leaves what rests behind it at rest', async () => {
      await holdFromRow(MEMBERSHIPS.subject, ids.next());
      for (const next of [ids.next(), ids.next()]) {
        await database
          .as('app')
          .query(
            "insert into directory.holds_waiting (org_id, subject_type, object_id, reason) values ($1, $2, $3, 'seal')",
            [org, MEMBERSHIPS.subject, next],
          );
      }
      await pollHoldsWaiting(app, services());
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);
      await confirm(investigationId, challengeId);
      // One set as the clear's read ended; the other tried now, and resting behind it.
      await pollHoldsWaiting(app, services());
      expect(await hold()).toMatchObject({ outcome: 'held', version: 4 });
      const seen = capture.lines().length;
      const locker = await database.connect('admin');
      await locker.query('begin');
      await locker.query('select seq from audit.heads where org_id = $1 for no key update', [org]);
      try {
        // Asked again: answered, with no try of what rests, which would wait out the head's lock.
        expect(await within(3_000, confirm(investigationId, challengeId), 'the replay')).toMatchObject({
          outcome: 'cleared',
        });
      } finally {
        await locker.query('rollback');
        await locker.end();
      }
      expect(
        capture
          .lines()
          .slice(seen)
          .filter(({ reason }) => reason === 'not_recorded'),
      ).toEqual([]);
    });

    it('a clear whose commit fails says nothing of a record never signed', async () => {
      await holdFromRow(MEMBERSHIPS.subject, ids.next());
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);
      const owner = database.as('owner');
      await owner.query(
        "create function audit.refuse_at_commit() returns trigger language plpgsql as $$ begin raise exception 'refused at commit'; end $$",
      );
      await owner.query(
        'create constraint trigger refuse_at_commit after update on audit.heads deferrable initially deferred for each row execute function audit.refuse_at_commit()',
      );
      try {
        await expect(confirm(investigationId, challengeId)).rejects.toThrow();
      } finally {
        await owner.query('drop trigger refuse_at_commit on audit.heads');
        await owner.query('drop function audit.refuse_at_commit()');
      }

      expect(nothingToRepair()).toEqual([]);
      expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    });

    it('the way out skips nothing else: no step-up, no history check, and it stays held, with nothing said', async () => {
      await holdFromRow(MEMBERSHIPS.subject, ids.next());
      const investigationId = await investigate();
      const answer = await ask(investigationId);
      if (answer.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(answer)}`);

      // Never signed in again.
      expect(await confirm(investigationId, answer.stepUpChallengeId)).toEqual({
        outcome: 'refused',
        status: 403,
        code: 'STEP_UP_FAILED',
      });
      // Signed in again, the whole history unchecked.
      await stepUp(admin, answer.stepUpChallengeId);
      expect(await confirm(investigationId, answer.stepUpChallengeId)).toEqual({
        outcome: 'refused',
        status: 409,
        code: 'HISTORY_UNCHECKED',
      });

      expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
      expect(nothingToRepair()).toEqual([]);
    });

    it('asked with no investigation of the hold: refused, and no step-up to spend', async () => {
      await holdFromRow(MEMBERSHIPS.subject, ids.next());

      expect(await ask(ids.next())).toEqual({ outcome: 'refused', status: 409, code: 'NO_INVESTIGATION' });
      expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
    });

    it('a signed record deleted past the app: refused, as a whole check finds it', async () => {
      const { membershipId: id } = await member(org, 'viewer');
      await holdFromRow(MEMBERSHIPS.subject, id);
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);
      await asOwner((owner) => owner.deleteRow(id));

      expect(await confirm(investigationId, challengeId)).toEqual({
        outcome: 'refused',
        status: 503,
        code: 'INTEGRITY_FAILED',
      });
      expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
      expect(nothingToRepair()).toEqual([]);
    });

    it('a signed record deleted past the app that no whole check lists: refused by the check of what the hold names', async () => {
      const { membershipId: id } = await member(org, 'viewer');
      await holdFromRow(MEMBERSHIPS.subject, id);
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);
      await asOwner((owner) => owner.deleteRow(id));

      expect(await confirmLiveOnly(investigationId, challengeId)).toEqual({
        outcome: 'refused',
        status: 503,
        code: 'INTEGRITY_FAILED',
      });
      expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
      expect(nothingToRepair()).toEqual([]);
    });

    it('a record with history but no seal and no row: refused, as any history means it once was', async () => {
      const never = ids.next();
      await holdFromRow(MEMBERSHIPS.subject, never);
      await withSignedStates(app, org, services(), (tx) =>
        createAuditTrail({ keys, ids }).record(tx, org, {
          actor: OPERATOR,
          action: 'membership.noted',
          subject: { type: MEMBERSHIPS.subject, id: never, version: 1 },
          details: {},
        }),
      );
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);

      expect(await confirmLiveOnly(investigationId, challengeId)).toEqual({
        outcome: 'refused',
        status: 503,
        code: 'INTEGRITY_FAILED',
      });
      expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
      expect(nothingToRepair()).toEqual([]);
    });

    it('a row there with nothing signed is no record that never was: refused', async () => {
      const id = ids.next();
      const user = await userForSubject(
        app,
        { issuer: 'https://auth.example.test', subject: `planted-${id}` },
        { ids, clock },
      );
      await asOwner(async (owner) => {
        await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
          user,
          org,
          id,
        ]);
        await owner.query(
          "insert into identity.memberships (org_id, id, user_id, role, status, joined_at) values ($1, $2, $3, 'viewer', 'ACTIVE', now())",
          [org, id, user],
        );
      });
      await holdFromRow(MEMBERSHIPS.subject, id);
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);

      expect(await confirmLiveOnly(investigationId, challengeId)).toEqual({
        outcome: 'refused',
        status: 503,
        code: 'INTEGRITY_FAILED',
      });
      expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
      expect(nothingToRepair()).toEqual([]);
    });

    it('the same with no history at all, read only by the check of what the hold names: cleared', async () => {
      await holdFromRow(MEMBERSHIPS.subject, ids.next());
      const investigationId = await investigate();
      const challengeId = await steppedUp(investigationId);

      expect(await confirmLiveOnly(investigationId, challengeId)).toMatchObject({ outcome: 'cleared' });
      expect(nothingToRepair()).toHaveLength(1);
    });
  });

  it('fails rather than judge part of a table past the objects it checks, leaving it HELD', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    const few = createHoldClearings({
      database: app,
      keys,
      ids,
      challenges: challenges(),
      logger: testLogger(),
      authorityTables: AUTHORITY_TABLES,
      objectsChecked: 1,
    });

    await expect(
      few.confirm(
        admin,
        keyed(admin, CLEAR_CONFIRM_OPERATION, 'confirm-1', `${investigationId} ${challengeId}`),
        investigationId,
        challengeId,
        CORRELATION,
      ),
    ).rejects.toThrow('more membership records than clearing checks');
    expect(await hold()).toMatchObject({ outcome: 'held', version: 2 });
  });

  it('refuses as HOLD_CHANGED a hold cleared while the clearing waited at the chain head, which it takes last', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    const now = await hold();
    const holdEventId = now.outcome === 'held' ? now.eventId : ids.next();
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let clearedFirst = (): void => undefined;
    const first = new Promise<void>((resolve) => {
      clearedFirst = resolve;
    });
    // Another clearing holds the chain head, the hold cleared but not yet committed.
    const holder = withSignedStates(app, org, services(), async (tx, states) => {
      await states.verifyAll(tx, org, AUTHORITY_TABLES, 100);
      await states.clearIntegrityHold(tx, org, {
        actor: { type: 'user', id: admin.userId },
        holdEventId,
        investigationId,
        stepUp: { stepUpChallengeId: ids.next() },
      });
      clearedFirst();
      await gate;
    });
    await first;

    const clearing = within(20_000, confirm(investigationId, challengeId), 'the clearing');
    try {
      await waitUntilQueued(database.as('admin'), 1);
    } finally {
      release();
      await holder;
    }

    expect(await clearing).toEqual({ outcome: 'refused', status: 409, code: 'HOLD_CHANGED' });
    expect(await hold()).toMatchObject({ outcome: 'clear', version: 3 });
  });

  it("refuses to ask when the admin's own membership can't be believed, as INTEGRITY_FAILED", async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    await asOwner((owner) => owner.setColumn(admin.membershipId, 'role', 'viewer'));

    expect(await ask(investigationId)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('refuses a step-up begun for a HELD state the hold has since left, as STEP_UP_FAILED: the step-up names the state', async () => {
    const row = await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    // Another admin clears it, and it is held again: a new HELD state.
    const other = await member(org, 'admin');
    await confirm(investigationId, await steppedUp(investigationId, other), other);
    await row.tamper();
    await read(row.id);
    await row.restore();
    expect(await hold()).toMatchObject({ outcome: 'held', version: 4 });

    expect(await confirm(investigationId, challengeId, admin, 'confirm-2')).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await hold()).toMatchObject({ outcome: 'held', version: 4 });
  });

  it("answers a replay as INTEGRITY_FAILED once the hold it would show can't be believed", async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    await confirm(investigationId, challengeId);
    await asOwner((owner) =>
      owner.query("update audit.events set details = '{}' where org_id = $1 and subject_type = 'integrity_hold'", [
        org,
      ]),
    );

    expect(await confirm(investigationId, challengeId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });
});

describe(`the confirmation's lock order against the admin's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('a clearing’s confirmation holds the admin’s step-up challenges before their membership, so their demotion at the same moment waits, never deadlocks', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    const cleared = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: admin.membershipId },
      () => confirm(investigationId, challengeId),
    );

    expect(cleared).toMatchObject({ outcome: 'cleared', hold: { outcome: 'clear', version: 3 } });
  });
});

// Clearing the integrity hold as the organisation's admin does it (B3+-2c-2):
// asked for with the investigation of the hold as it stands, confirmed with a
// step-up bound to exactly that, and cleared only once every record of the
// organisation, the product's own authority tables, is verified whole. What
// the clearing step itself refuses is the audit module's
// (hold-clearing.db.test.ts there).
import { createHash } from 'node:crypto';

import { createDatabase, type Database, type IdempotentRequest } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  type SavedRow,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { type AuditTables, createAuditTrail, withSignedStates } from '../../audit/index.ts';
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

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000bb';

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const services = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

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
  const investigations = createHoldInvestigations({ database: app, keys, ids, logger: loggerFor(new LogCapture()) });
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
const stepUp = (who: ClearingAdmin, challengeId: string) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

/** Asks, signs in again, and gives back the challenge. */
async function steppedUp(investigationId: string, who: ClearingAdmin = admin): Promise<string> {
  const answer = await ask(investigationId, who);
  if (answer.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(answer)}`);
  await stepUp(who, answer.stepUpChallengeId);
  return answer.stepUpChallengeId;
}

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
  clearings = createHoldClearings({
    database: app,
    keys,
    ids,
    challenges: challenges(),
    logger: loggerFor(new LogCapture()),
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
        logger: loggerFor(new LogCapture()),
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

  it('fails rather than judge part of a table past the objects it checks, leaving it HELD', async () => {
    await holdThenRepair();
    const investigationId = await investigate();
    const challengeId = await steppedUp(investigationId);
    const few = createHoldClearings({
      database: app,
      keys,
      ids,
      challenges: challenges(),
      logger: loggerFor(new LogCapture()),
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

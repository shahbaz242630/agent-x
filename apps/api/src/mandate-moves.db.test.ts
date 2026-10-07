// Phase 2 B4: suspending, resuming and revoking a mandate, composed in the
// API, on the real migrated schema as the app role: an admin asks, signs in
// again with a passkey and confirms; each move with the step-up's evidence on
// its event and every admin and approver told; a retry answered as it was;
// every refusal by its code; a step-up that isn't a passkey, was asked for
// another move or for the mandate as it stood before; a tampered mandate; and
// the lock order against the admin's demotion.
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { MANDATES } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { createDatabase, type Database, type IdempotentRequest } from '@agentx/platform/db';
import {
  confirmedWhileDemoted,
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createMandateMoves,
  type MandateMove,
  type MandateMoved,
  type MandateMoves,
  type MoveAsked,
  MOVE_OPERATIONS,
} from './mandate-moves.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import {
  keys,
  type Member,
  mandateWorld,
  type MandateWorldTables,
  PASSKEY,
  refused,
  type World,
} from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xb4a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b4';
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

let clock: FixedClock;
let registry: MandateRegistry;
let moves: MandateMoves;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'mandate-moves' });
const { member, world, keyed, eventsAbout, noticesOf, stepUp, acceptedPastTheUseCase } = shared;

/** A mandate drafted for the world's agent, ending at `endsAt` if given, and accepted: ACTIVE. */
async function active(w: World, endsAt: Date | null = null): Promise<string> {
  const { id } = await shared.drafted(registry, w, { endsAt });
  await acceptedPastTheUseCase(w, id);
  return id;
}

const ask = (who: Member, id: string, move: MandateMove) =>
  moves.ask(who, keyed(who, MOVE_OPERATIONS[move].ask), id, move, CORRELATION);

const confirm = (who: Member, id: string, move: MandateMove, challengeId: string, key?: IdempotentRequest) =>
  moves.confirm(who, key ?? keyed(who, MOVE_OPERATIONS[move].confirm), id, move, challengeId, CORRELATION);

const askedFor = (write: MoveAsked): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

const movedOf = (write: MandateMoved) => {
  if (write.outcome !== 'moved') throw new Error(`not moved: ${JSON.stringify(write)}`);
  return write;
};

/** Asks, signs in again with `amr` and confirms: the confirm's answer. */
async function moved(w: World, id: string, move: MandateMove, amr: readonly string[] = PASSKEY) {
  const challengeId = askedFor(await ask(w.admin, id, move));
  await stepUp(w.admin, challengeId, amr);
  return confirm(w.admin, id, move, challengeId);
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-07T08:00:00Z'));
  const logger = testLogger(new LogCapture());
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  moves = createMandateMoves({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger,
  });
});

describe('suspending, resuming and revoking a mandate (B4)', () => {
  it('an admin suspends, resumes, then revokes, each with a passkey: the evidence on each event, every admin and approver told', async () => {
    const w = await world();
    const id = await active(w);

    expect(movedOf(await moved(w, id, 'suspend')).mandate.status).toBe('SUSPENDED');
    const resumed = movedOf(await moved(w, id, 'resume'));
    expect(resumed.mandate.status).toBe('ACTIVE');
    expect(resumed.current).not.toBeNull();
    expect(movedOf(await moved(w, id, 'revoke')).mandate.status).toBe('REVOKED');

    const events = (await eventsAbout(w.org, id)).slice(-3);
    expect(events.map(({ action, actorType }) => [action, actorType])).toEqual([
      ['mandate.suspended', 'user'],
      ['mandate.resumed', 'user'],
      ['mandate.revoked', 'user'],
    ]);
    for (const { details } of events) expect(details).toMatchObject({ methods: PASSKEY.join(' ') });
    expect(await noticesOf(w.org)).toEqual(
      ['mandate_suspended', 'mandate_resumed', 'mandate_revoked'].map((kind) => ({
        kind,
        about_id: id,
        recipient_user_id: null,
      })),
    );
  });

  it('revokes a suspended mandate, and a draft never accepted', async () => {
    const w = await world();
    const id = await active(w);
    movedOf(await moved(w, id, 'suspend'));
    expect(movedOf(await moved(w, id, 'revoke')).mandate.status).toBe('REVOKED');

    const draft = await shared.drafted(registry, w);
    expect(movedOf(await moved(w, draft.id, 'revoke')).mandate).toMatchObject({
      status: 'REVOKED',
      currentVersionId: null,
    });
  });

  it('answers a confirm sent again from the mandate, moving nothing twice', async () => {
    const w = await world();
    const id = await active(w);
    const challengeId = askedFor(await ask(w.admin, id, 'suspend'));
    await stepUp(w.admin, challengeId);
    const key = keyed(w.admin, MOVE_OPERATIONS.suspend.confirm);
    movedOf(await confirm(w.admin, id, 'suspend', challengeId, key));

    expect(movedOf(await confirm(w.admin, id, 'suspend', challengeId, key)).mandate.status).toBe('SUSPENDED');
    expect((await eventsAbout(w.org, id)).filter(({ action }) => action === 'mandate.suspended')).toHaveLength(1);
  });

  it('refuses each move the mandate can’t make, by its code', async () => {
    const w = await world();
    const draft = await shared.drafted(registry, w);
    expect(await ask(w.admin, draft.id, 'suspend')).toEqual(refused(409, 'MANDATE_NOT_ACTIVE'));
    expect(await ask(w.admin, draft.id, 'resume')).toEqual(refused(409, 'MANDATE_NOT_SUSPENDED'));

    await acceptedPastTheUseCase(w, draft.id);
    expect(await ask(w.admin, draft.id, 'resume')).toEqual(refused(409, 'MANDATE_NOT_SUSPENDED'));

    movedOf(await moved(w, draft.id, 'revoke'));
    expect(await ask(w.admin, draft.id, 'suspend')).toEqual(refused(409, 'MANDATE_NOT_ACTIVE'));
    expect(await ask(w.admin, draft.id, 'resume')).toEqual(refused(409, 'MANDATE_NOT_SUSPENDED'));
    expect(await ask(w.admin, draft.id, 'revoke')).toEqual(refused(409, 'MANDATE_ENDED'));
    expect(await ask(w.admin, ids.next(), 'revoke')).toEqual(refused(404, 'NOT_FOUND'));
  });

  it('won’t resume a mandate whose version in force has reached its end: MANDATE_ENDED, the expiry job’s to end', async () => {
    const w = await world();
    const id = await active(w, new Date(clock.now().getTime() + 3_600_000));
    movedOf(await moved(w, id, 'suspend'));
    const challengeId = askedFor(await ask(w.admin, id, 'resume'));
    await stepUp(w.admin, challengeId);
    clock.advanceBy(3_600_000);

    expect(await confirm(w.admin, id, 'resume', challengeId)).toEqual(refused(409, 'MANDATE_ENDED'));
    expect(await ask(w.admin, id, 'resume')).toEqual(refused(409, 'MANDATE_ENDED'));
    // Still a brake: it can be revoked.
    expect(movedOf(await moved(w, id, 'revoke')).mandate.status).toBe('REVOKED');
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s: FORBIDDEN', async (role) => {
    const w = await world();
    const id = await active(w);
    expect(await ask(await member(w.org, role), id, 'suspend')).toEqual(refused(403, 'FORBIDDEN'));
  });

  it('refuses a step-up signed in with an app code: STEP_UP_FAILED, nothing moved', async () => {
    const w = await world();
    const id = await active(w);
    expect(await moved(w, id, 'suspend', APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect((await eventsAbout(w.org, id)).at(-1)?.action).toBe('mandate.activated');
  });

  it('refuses a step-up asked for another move: STEP_UP_FAILED', async () => {
    const w = await world();
    const id = await active(w);
    const challengeId = askedFor(await ask(w.admin, id, 'suspend'));
    await stepUp(w.admin, challengeId);

    expect(await confirm(w.admin, id, 'revoke', challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
  });

  it('refuses a step-up asked before the mandate changed: STEP_UP_FAILED, for the mandate as it stood', async () => {
    const w = await world();
    const id = await active(w);
    const challengeId = askedFor(await ask(w.admin, id, 'revoke'));
    await stepUp(w.admin, challengeId);
    movedOf(await moved(w, id, 'suspend'));

    expect(await confirm(w.admin, id, 'revoke', challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
  });

  it('a mandate tampered with past the app: INTEGRITY_FAILED (FX-TAMPER: un-revoked)', async () => {
    const w = await world();
    const id = await active(w);
    movedOf(await moved(w, id, 'revoke'));
    const owner = await tamperAsOwner(database, MANDATES, w.org);
    try {
      await owner.withoutStatusGuard(() =>
        owner.query("update mandates.mandates set status = 'ACTIVE' where id = $1", [id]),
      );
    } finally {
      await owner.end();
    }

    expect(await ask(w.admin, id, 'suspend')).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });
});

describe(`the confirm's lock order against the admin's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('holds its step-up challenges before the admin’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const w = await world();
    const id = await active(w);
    const challengeId = askedFor(await ask(w.admin, id, 'suspend'));
    await stepUp(w.admin, challengeId);

    const done = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: w.org, membershipId: w.admin.membershipId },
      () => confirm(w.admin, id, 'suspend', challengeId),
    );

    expect(movedOf(done).mandate.status).toBe('SUSPENDED');
  });
});

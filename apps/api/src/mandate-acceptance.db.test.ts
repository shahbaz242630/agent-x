// Phase 2 B3: accepting a mandate's draft, composed in the API, on the real
// migrated schema as the app role, with a signed agent, a funding source
// linked through the fake partner, signed suppliers and a draft made by the
// registry: an admin asks, signs in again with a passkey and confirms; the
// draft in force, ACTIVE for a first, the next superseding it; the evidence
// on the accept event; every refusal by its code; a step-up that isn't a
// passkey, has run out or was asked for another draft; a tampered mandate of
// the agent; and the lock order against the admin's demotion.
import { AGENTS } from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { MANDATES } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
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
  ACCEPT_CONFIRM_OPERATION,
  ACCEPT_OPERATION,
  createMandateAcceptance,
  type MandateAcceptance,
  type MandateAccepted,
} from './mandate-acceptance.ts';
import {
  createMandateRegistry,
  type MandateDraft,
  type MandateRegistry,
  REDRAFT_OPERATION,
} from './mandate-registry.ts';
import {
  askedFor,
  draftedOf,
  keys,
  type Member,
  mandateWorld,
  type MandateWorldTables,
  OPERATOR,
  PASSKEY,
  refused,
  type World,
} from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xb3a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b3';
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

let clock: FixedClock;
let registry: MandateRegistry;
let acceptance: MandateAcceptance;

const challenges = () => createStepUpChallenges({ ids, clock });
const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'mandate-acceptance' });
const { quiet, member, world, termsOf, keyed, partnerSays, eventsAbout, stepUp, movedPastTheUseCase } = shared;

/** A mandate drafted for the world's agent: its ID and its draft's. */
const drafted = (w: World, overrides: Partial<MandateDraft['terms']> = {}) => shared.drafted(registry, w, overrides);

/** A later draft of the mandate: its ID. */
async function redrafted(w: World, mandateId: string, overrides: Partial<MandateDraft['terms']> = {}) {
  const write = draftedOf(
    await registry.redraft(w.admin, keyed(w.admin, REDRAFT_OPERATION), mandateId, termsOf(w, overrides), CORRELATION),
  );
  return write.pending?.version.id ?? '';
}

const ask = (who: Member, mandateId: string, versionId: string) =>
  acceptance.accept(who, keyed(who, ACCEPT_OPERATION), mandateId, versionId, CORRELATION);

const confirm = (who: Member, mandateId: string, challengeId: string, key?: IdempotentRequest) =>
  acceptance.acceptConfirm(who, key ?? keyed(who, ACCEPT_CONFIRM_OPERATION), mandateId, challengeId, CORRELATION);

const acceptedOf = (write: MandateAccepted) => {
  if (write.outcome !== 'accepted') throw new Error(`not accepted: ${JSON.stringify(write)}`);
  return write;
};

/** Asks, signs in again with `amr` and confirms: the confirm's answer. */
async function accepted(w: World, mandateId: string, versionId: string, amr: readonly string[] = PASSKEY) {
  const challengeId = askedFor(await ask(w.admin, mandateId, versionId));
  await stepUp(w.admin, challengeId, amr);
  return confirm(w.admin, mandateId, challengeId);
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
  acceptance = createMandateAcceptance({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    outbox: createOutbox({ ids, clock }),
    logger,
  });
});

describe('accepting a mandate’s draft (B3)', () => {
  it('an admin accepts the first draft with a passkey: ACTIVE, the draft in force, the evidence on its event', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const challengeId = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, challengeId);
    const done = acceptedOf(await confirm(w.admin, id, challengeId));

    expect(done.mandate).toMatchObject({
      status: 'ACTIVE',
      currentVersionId: versionId,
      pendingVersionId: null,
      acceptedBy: w.admin.membershipId,
      acceptedAt: clock.now(),
    });
    expect(done.current?.version.id).toBe(versionId);
    expect(done.pending).toBeNull();
    const events = await eventsAbout(w.org, id);
    expect(events.map(({ action }) => action)).toEqual(['mandate.drafted', 'mandate.accepted', 'mandate.activated']);
    expect(
      await withTenant(app, w.org, (tx) =>
        tx.selectFrom('notifications.outbox').select(['kind', 'about_id', 'recipient_user_id']).execute(),
      ),
    ).toEqual([{ kind: 'mandate_accepted', about_id: id, recipient_user_id: null }]);
    expect(events[1]?.details).toMatchObject({
      versionId,
      replaced: null,
      termsHash: done.current?.version.termsHash,
      stepUpChallengeId: challengeId,
      methods: 'pwd user mfa',
    });
  });

  it('a later draft accepted supersedes the version in force, the mandate staying ACTIVE', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    acceptedOf(await accepted(w, id, versionId));
    const second = await redrafted(w, id, { purpose: 'Stationery' });
    const done = acceptedOf(await accepted(w, id, second));

    expect(done.mandate).toMatchObject({ status: 'ACTIVE', currentVersionId: second, pendingVersionId: null });
    expect(done.current?.version).toMatchObject({ version: 2, purpose: 'Stationery' });
    const events = await eventsAbout(w.org, id);
    expect(events.at(-1)).toMatchObject({
      action: 'mandate.accepted',
      details: { versionId: second, replaced: versionId },
    });
  });

  it('answers a confirm retried with its key from the mandate, accepting nothing twice', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const challengeId = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, challengeId);
    const key = keyed(w.admin, ACCEPT_CONFIRM_OPERATION);
    acceptedOf(await confirm(w.admin, id, challengeId, key));

    expect(acceptedOf(await confirm(w.admin, id, challengeId, key)).mandate.status).toBe('ACTIVE');
    expect((await eventsAbout(w.org, id)).filter(({ action }) => action === 'mandate.accepted')).toHaveLength(1);
  });
});

describe('the step-up an acceptance needs (B3, SEC-HA-12)', () => {
  it('refuses a step-up signed in again without a passkey, the draft still waiting', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);

    expect(await accepted(w, id, versionId, APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await registry.show(w.org, id, CORRELATION)).toMatchObject({ mandate: { status: 'PENDING_ACCEPTANCE' } });
  });

  it('refuses a step-up never signed in again for, or run out', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const unsigned = askedFor(await ask(w.admin, id, versionId));
    expect(await confirm(w.admin, id, unsigned)).toEqual(refused(403, 'STEP_UP_FAILED'));

    const late = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, late);
    clock.advanceBy(301_000);
    expect(await confirm(w.admin, id, late)).toEqual(refused(403, 'STEP_UP_FAILED'));
  });

  it('refuses a step-up asked for a draft a newer one has replaced, and an ask naming the replaced one', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const challengeId = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, challengeId);
    await redrafted(w, id, { purpose: 'Stationery' });

    expect(await confirm(w.admin, id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_NOT_WAITING'));
  });
});

describe('the step-up bound to the mandate as it stood (B3)', () => {
  it('refuses a step-up asked before the mandate changed, though its draft is the same: suspended and resumed between', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    acceptedOf(await accepted(w, id, versionId));
    const second = await redrafted(w, id);
    const challengeId = askedFor(await ask(w.admin, id, second));
    await stepUp(w.admin, challengeId);
    await movedPastTheUseCase(w, id, 'suspend');
    await movedPastTheUseCase(w, id, 'resume');

    expect(await confirm(w.admin, id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
  });
});

describe('what acceptance refuses (B3)', () => {
  it.each(['approver', 'developer', 'viewer'] as const)('a member who is a %s', async (role) => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    expect(await ask(await member(w.org, role), id, versionId)).toEqual(refused(403, 'FORBIDDEN'));
  });

  it('a mandate none of the organisation’s, or revoked', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    expect(await ask(w.admin, ids.next(), versionId)).toEqual(refused(404, 'NOT_FOUND'));
    await movedPastTheUseCase(w, id, 'revoke');
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_ENDED'));
  });

  it('a suspended mandate’s new draft, until it is resumed', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    acceptedOf(await accepted(w, id, versionId));
    const second = await redrafted(w, id);
    await movedPastTheUseCase(w, id, 'suspend');

    expect(await ask(w.admin, id, second)).toEqual(refused(409, 'MANDATE_SUSPENDED'));
  });

  it('an ACTIVE mandate with no draft waiting', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    acceptedOf(await accepted(w, id, versionId));
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_NOT_WAITING'));
  });

  it('a suspended agent’s mandate', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspend',
        details: {},
      }),
    );
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'AGENT_NOT_ACTIVE'));
  });

  it('a draft whose end has passed since it was drafted', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w, { endsAt: new Date(clock.now().getTime() + 3_600_000) });
    clock.advanceBy(3_600_000);
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_DRAFT_EXPIRED'));
  });

  it('a draft whose source can no longer fund, or whose consent the bank has since lowered past it', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const most = w.state.controls.maxPaymentMinor;
    await partnerSays(w, { controls: { ...w.state.controls, maxPaymentMinor: most - 1n } });
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_PAST_CONSENT'));

    clock.advanceBy(1000);
    await partnerSays(w, { consentExpiresAt: clock.now() });
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'SOURCE_NOT_USABLE'));
  });

  it('a mandate whose agent was changed past the app: INTEGRITY_FAILED', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const owner = await tamperAsOwner(database, AGENTS, w.org);
    try {
      await owner.setColumn(w.agent, 'scopes', 'requests:read requests:write');
    } finally {
      await owner.end();
    }
    expect(await ask(w.admin, id, versionId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });

  it('any mandate of the agent tampered with, though the open-mandate query missed it (FX-TAMPER, S89 review)', async () => {
    const w = await world();
    const first = await drafted(w);
    const owner = await tamperAsOwner(database, MANDATES, w.org);
    try {
      await owner.query("update mandates.mandates set status = 'REVOKED' where id = $1", [first.id]);
    } finally {
      await owner.end();
    }
    const second = await drafted(w);

    expect(await ask(w.admin, second.id, second.versionId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });
});

describe(`the confirm's lock order against the admin's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('holds its step-up challenges before the admin’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const challengeId = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, challengeId);

    const done = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: w.org, membershipId: w.admin.membershipId },
      () => confirm(w.admin, id, challengeId),
    );

    expect(acceptedOf(done).mandate.status).toBe('ACTIVE');
  });
});

// Phase 3 C2b: the brakes void their own pending requests in their own
// transaction, before their signed move (PRD §4.2; ADR-006 §6 "Cascades";
// decisions 4 and 7; SEC-AG-11, SEC-AG-15), on the real migrated schema as the
// app role, through each use case. The agent's suspend on cancel (the kill
// switch), the mandate's suspend on cancel, its revoke, its expiry (the job)
// and its supersede (a new version accepted) each leave the waiting and the
// approved request DENIED as the API's with the brake's cause, their holdings
// released, recorded before the brake's own event, with no request-voids job
// run; another agent's request, under another mandate, stands. A pause voids
// nothing, and a pause made a cancel voids them. A batch stops at its bound,
// in order of ID. A request tampered with is left, its alarm raised, and the
// brake still holds. A brake queued behind an approval holding the request
// (forced) voids it once approved (revoke-, supersede- and
// suspend-during-approval); one queued behind a cancel leaves it cancelled,
// as it does a request ended before it. C3: the source's suspend and the
// supplier's on cancel, its new details and its new payee made current (the
// last two always cancel, decision 7, a paused supplier's requests too) void
// theirs as well, and so does a refresh that ends the source (gone for good,
// or unknown to the partner); a source's brake voids every agent's requests
// it funds. Each void comes before the brake's first event. Decision 8 (C3b):
// a payee registration's choice, cancel or pause, decides what its unverify
// does to the supplier's requests: cancel voids them at the check, before its
// first event; pause holds them while it is unverified, through the
// request-voids job, until the change is confirmed (voided) or withdrawn and
// the supplier verified again (they stand); a start carrying on with one open
// and choosing otherwise is the choice that holds.
import { withSignedStates } from '@agentx/core/modules/audit';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  createFakeRail,
  type FinancialRailAdapter,
  type SourceLookup,
  SANDBOX_ACCOUNTS,
} from '@agentx/core/modules/providers';
import {
  approveRequest,
  cancelRequest,
  checkHoldings,
  type PendingChoice,
  requestOf,
  SPEND_REQUESTS,
  voidPendingOf,
} from '@agentx/core/modules/spend-requests';
import { supplierOf } from '@agentx/core/modules/suppliers';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AgentChanges, createAgentChanges, SUSPEND_OPERATION } from './agent-changes.ts';
import {
  createFundingSourceChanges,
  REFRESH_OPERATION,
  SUSPEND_OPERATION as SOURCE_SUSPEND,
} from './funding-source-changes.ts';
import { ACCEPT_CONFIRM_OPERATION, ACCEPT_OPERATION, createMandateAcceptance } from './mandate-acceptance.ts';
import { createMandateExpiry } from './mandate-expiry.ts';
import { createMandateMoves, type MandateMove, type MandateMoves, MOVE_OPERATIONS } from './mandate-moves.ts';
import { createMandateRegistry, type MandateRegistry, REDRAFT_OPERATION } from './mandate-registry.ts';
import { AED, askedFor, draftedOf, keys, type World } from './mandate-world.helper.test.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { createSpendRequestReads } from './spend-request-reads.ts';
import { createRequestVoids } from './request-voids.ts';
import { spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';
import {
  createSupplierChanges,
  REACTIVATE_CONFIRM_OPERATION as SUPPLIER_REACTIVATE_CONFIRM,
  REACTIVATE_OPERATION as SUPPLIER_REACTIVATE,
  SUSPEND_OPERATION as SUPPLIER_SUSPEND,
} from './supplier-changes.ts';
import { createSupplierDetailsChanges, DETAILS_CONFIRM_OPERATION, DETAILS_OPERATION } from './supplier-details.ts';
import {
  createSupplierPayeeChanges,
  PAYEE_APPROVE_CONFIRM_OPERATION,
  PAYEE_APPROVE_OPERATION,
  PAYEE_WITHDRAW_OPERATION,
} from './supplier-payee-changes.ts';
import {
  createOrganizationChanges,
  FREEZE_OPERATION,
  UNFREEZE_CONFIRM_OPERATION,
  UNFREEZE_OPERATION,
} from './organization-changes.ts';
import { createSupplierPayees, PAYEE_CHECK_OPERATION, PAYEE_START_OPERATION } from './supplier-payees.ts';
import { pausedOf } from './suspensions.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xc2b0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000c2';
const HOUR_MS = 3_600_000;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let agents: AgentChanges;
let moves: MandateMoves;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'brake-voids',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, statusOf, holdingsOf, spentOf, mandateIdOf, signed, keyed, stepUp, termsOf } = shared;

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

const logger = () => testLogger(capture);

/** A world whose agent has a key and a mandate in force (approval above AED 1,000), ending at `endsAt` if given. */
async function ready(endsAt: Date | null = null) {
  const w = await shared.world();
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, { approvalThreshold: AED(100_000n), endsAt });
  return { w, acting: await shared.agentKey(w) };
}

/** What each brake's use case answers once it has made its move. */
const PRESSED = ['changed', 'moved', 'accepted'];

/** A brake's use case, ready to call: its answer. */
type Press = () => Promise<{ readonly outcome: string }>;

/** The agent suspended through its use case, with `choice`. */
const suspended = (w: World, choice: PendingChoice) =>
  agents.suspend(w.admin, keyed(w.admin, SUSPEND_OPERATION), w.agent, choice, CORRELATION);

/** The mandate's move asked, stepped up with a passkey: its confirm, to call. */
async function moving(
  w: World,
  mandateId: string,
  move: MandateMove,
  choice: PendingChoice = 'cancel',
): Promise<Press> {
  const chosen = move === 'suspend' ? { move, pendingRequests: choice } : { move };
  const challengeId = askedFor(
    await moves.ask(w.admin, keyed(w.admin, MOVE_OPERATIONS[move].ask), mandateId, chosen, CORRELATION),
  );
  await stepUp(w.admin, challengeId);
  return () =>
    moves.confirm(w.admin, keyed(w.admin, MOVE_OPERATIONS[move].confirm), mandateId, chosen, challengeId, CORRELATION);
}

/** A new version of the mandate drafted, its acceptance asked and stepped up with a passkey: its confirm, to call. */
async function superseding(w: World, mandateId: string): Promise<Press> {
  const acceptance = createMandateAcceptance({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger: logger(),
  });
  const terms = termsOf(w, { purpose: 'Office supplies, renewed', approvalThreshold: AED(100_000n) });
  const drafted = draftedOf(
    await registry.redraft(w.admin, keyed(w.admin, REDRAFT_OPERATION), mandateId, terms, CORRELATION),
  );
  const versionId = drafted.pending?.version.id ?? '';
  const challengeId = askedFor(
    await acceptance.accept(w.admin, keyed(w.admin, ACCEPT_OPERATION), mandateId, versionId, CORRELATION),
  );
  await stepUp(w.admin, challengeId);
  return () =>
    acceptance.acceptConfirm(w.admin, keyed(w.admin, ACCEPT_CONFIRM_OPERATION), mandateId, challengeId, CORRELATION);
}

/** The services the source's and the supplier's use cases are made with. */
const services = () => ({
  database: app,
  keys,
  ids,
  clock,
  challenges: createStepUpChallenges({ ids, clock }),
  outbox: createOutbox({ ids, clock }),
  logger: logger(),
});

/** The world's source suspended through its use case, with `choice`. */
const sourceSuspended = (w: World, choice: PendingChoice) =>
  createFundingSourceChanges({ ...services(), rail: undefined }).suspend(
    w.admin,
    keyed(w.admin, SOURCE_SUSPEND),
    w.source,
    choice,
    CORRELATION,
  );

/** The world's source refreshed through its use case, the partner answering `answer` of it. */
const refreshed = (w: World, answer: (now: Date) => SourceLookup) => () =>
  createFundingSourceChanges({
    ...services(),
    rail: { ...createFakeRail({ clock, ids }), getSourceState: () => Promise.resolve(answer(clock.now())) },
  }).refresh(w.admin, keyed(w.admin, REFRESH_OPERATION), w.source, CORRELATION);

/** The world's organisation frozen through its use case by its admin, with `choice`. */
const frozen = (w: World, choice: PendingChoice) =>
  createOrganizationChanges(services()).freeze(w.admin, keyed(w.admin, FREEZE_OPERATION), choice, CORRELATION);

/** The world's first supplier suspended through its use case, with `choice`. */
const supplierSuspended = (w: World, choice: PendingChoice) =>
  createSupplierChanges(services()).suspend(
    w.admin,
    keyed(w.admin, SUPPLIER_SUSPEND),
    w.suppliers[0] ?? '',
    choice,
    CORRELATION,
  );

/** New details for the world's first supplier asked, stepped up with a passkey: their confirm, to call. */
async function detailsChanging(w: World): Promise<Press> {
  const changes = createSupplierDetailsChanges(services());
  const supplierId = w.suppliers[0] ?? '';
  const details = {
    displayName: 'Gulf Office Supplies Trading LLC',
    contacts: { phone: '+971501234567', email: null, tradeLicence: null },
    source: { kind: 'registry', ref: 'DED-123456' },
  } as const;
  const challengeId = askedFor(
    await changes.change(w.admin, keyed(w.admin, DETAILS_OPERATION), supplierId, details, CORRELATION),
  );
  await stepUp(w.admin, challengeId);
  return () =>
    changes.changeConfirm(
      w.admin,
      keyed(w.admin, DETAILS_CONFIRM_OPERATION),
      supplierId,
      { details, stepUpChallengeId: challengeId },
      CORRELATION,
    );
}

/** The fake partner the test's payees are registered with: one a test, so a payee key taken is seen as taken. */
let payeeRail: ReturnType<typeof createFakeRail>;

/**
 * A new payee registered for the supplier (the world's first unless named)
 * through the fake partner's form, the admin choosing each of `choices` in
 * turn on a start (a second start carries on with the one open), its form
 * filled in and then checked: the change left waiting. The check, to call.
 */
async function payeeRegistering(
  w: World,
  choices: readonly PendingChoice[],
  supplierId = w.suppliers[0] ?? '',
  rail: FinancialRailAdapter = payeeRail,
): Promise<Press> {
  const payees = createSupplierPayees({ ...services(), rail, partner: 'fake' });
  let started: Awaited<ReturnType<typeof payees.start>> | undefined;
  for (const choice of choices) {
    started = await payees.start(w.admin, keyed(w.admin, PAYEE_START_OPERATION), supplierId, choice, CORRELATION);
  }
  if (started?.outcome !== 'started') throw new Error(`not started: ${JSON.stringify(started)}`);
  const iban = SANDBOX_ACCOUNTS[0]?.AccountIdentifiers.find((each) => each.SchemeName === 'IBAN')?.Identification;
  await payeeRail.bank.fillForm(w.org, started.form?.url ?? '', { name: 'Gulf Office Supplies LLC', iban: iban ?? '' });
  const { id } = started.registration;
  return () => payees.check(w.admin, keyed(w.admin, PAYEE_CHECK_OPERATION), supplierId, id, CORRELATION);
}

/** The change waiting for the supplier (the world's first unless named): its confirmation asked and stepped up with a passkey: its confirm, to call. */
async function payeeConfirming(w: World, supplierId = w.suppliers[0] ?? ''): Promise<Press> {
  const changes = createSupplierPayeeChanges(services());
  const challengeId = askedFor(
    await changes.approve(w.admin, keyed(w.admin, PAYEE_APPROVE_OPERATION), supplierId, CORRELATION),
  );
  await stepUp(w.admin, challengeId);
  return () =>
    changes.approveConfirm(
      w.admin,
      keyed(w.admin, PAYEE_APPROVE_CONFIRM_OPERATION),
      supplierId,
      challengeId,
      CORRELATION,
    );
}

/** The change waiting for the world's first supplier withdrawn by its admin. */
const payeeWithdrawn = (w: World) =>
  createSupplierPayeeChanges(services()).withdraw(
    w.admin,
    keyed(w.admin, PAYEE_WITHDRAW_OPERATION),
    w.suppliers[0] ?? '',
    CORRELATION,
  );

/** A new payee for the world's first supplier, paused first by its suspend and by its registration: its confirm, to call. */
async function payeeChanging(w: World): Promise<Press> {
  await supplierSuspended(w, 'pause');
  expect((await (await payeeRegistering(w, ['pause']))()).outcome).toBe('checked');
  return payeeConfirming(w);
}

/**
 * Each brake, made ready on the world's agent and mandate: its use case's
 * call, the cause it leaves, and what it stops. `spares` says whether a
 * second agent's request under its own mandate, to the second supplier, on
 * the same source, stands.
 */
const BRAKES = {
  'the organisation frozen to cancel (D1)': {
    cause: 'ORG_FROZEN',
    subject: 'organization',
    spares: false,
    ready: (w: World) => Promise.resolve<Press>(() => frozen(w, 'cancel')),
  },
  'the agent suspended to cancel (the kill switch)': {
    cause: 'AGENT_SUSPENDED',
    subject: 'agent',
    spares: true,
    ready: (w: World) => Promise.resolve<Press>(() => suspended(w, 'cancel')),
  },
  'the mandate suspended to cancel': {
    cause: 'MANDATE_NOT_IN_FORCE',
    subject: 'mandate',
    spares: true,
    ready: (w: World, mandateId: string) => moving(w, mandateId, 'suspend'),
  },
  'the mandate revoked': {
    cause: 'MANDATE_NOT_IN_FORCE',
    subject: 'mandate',
    spares: true,
    ready: (w: World, mandateId: string) => moving(w, mandateId, 'revoke'),
  },
  'the mandate superseded': {
    cause: 'MANDATE_NOT_IN_FORCE',
    subject: 'mandate',
    spares: true,
    ready: superseding,
  },
  'the source suspended to cancel': {
    cause: 'SOURCE_NOT_USABLE',
    subject: 'funding_source',
    spares: false,
    ready: (w: World) => Promise.resolve<Press>(() => sourceSuspended(w, 'cancel')),
  },
  'the source ended by the partner (a refresh: consent gone for good)': {
    cause: 'SOURCE_NOT_USABLE',
    subject: 'funding_source',
    spares: false,
    ready: (w: World) =>
      Promise.resolve<Press>(
        refreshed(w, (now) => ({
          kind: 'found',
          source: { ...w.state, availability: 'UNAVAILABLE', consentStatus: 'Revoked', statusChangedAt: now },
        })),
      ),
  },
  'the source unknown to the partner (a refresh)': {
    cause: 'SOURCE_NOT_USABLE',
    subject: 'funding_source',
    spares: false,
    ready: (w: World) => Promise.resolve<Press>(refreshed(w, () => ({ kind: 'not_found' }))),
  },
  'the supplier suspended to cancel': {
    cause: 'SUPPLIER_NOT_VERIFIED',
    subject: 'supplier',
    spares: true,
    ready: (w: World) => Promise.resolve<Press>(() => supplierSuspended(w, 'cancel')),
  },
  'the supplier’s details changed': {
    cause: 'SUPPLIER_CHANGED',
    subject: 'supplier',
    spares: true,
    ready: detailsChanging,
  },
  'the paused supplier’s new payee confirmed': {
    cause: 'SUPPLIER_CHANGED',
    subject: 'supplier',
    spares: true,
    ready: payeeChanging,
  },
} as const;
type Brake = keyof typeof BRAKES;

/** The ID of what the brake stops, in the world. */
const SUBJECT_IDS = {
  organization: (w: World) => w.org,
  agent: (w: World) => w.agent,
  mandate: (_: World, mandateId: string) => mandateId,
  funding_source: (w: World) => w.source,
  supplier: (w: World) => w.suppliers[0] ?? '',
} as const;

/** The sequence of the newest event about the object, in the organisation's chain. */
const newestSeq = (w: World, subjectType: string, subjectId: string) =>
  withTenant(app, w.org, async (tx) => {
    const { seq } = await tx
      .selectFrom('audit.events')
      .select('seq')
      .where('subject_type', '=', subjectType)
      .where('subject_id', '=', subjectId)
      .orderBy('seq', 'desc')
      .executeTakeFirstOrThrow();
    return seq;
  });

/** The sequence of the first event about the object after `after`, in the organisation's chain. */
const firstSeqAfter = (w: World, subjectType: string, subjectId: string, after: bigint) =>
  withTenant(app, w.org, async (tx) => {
    const { seq } = await tx
      .selectFrom('audit.events')
      .select('seq')
      .where('subject_type', '=', subjectType)
      .where('subject_id', '=', subjectId)
      .where('seq', '>', after)
      .orderBy('seq')
      .executeTakeFirstOrThrow();
    return seq;
  });

/** The approved and the waiting request of the world's agent, and one of a second agent's under its own mandate. */
async function pendingOf(w: World, acting: Awaited<ReturnType<typeof shared.agentKey>>) {
  // AED 500, under the approval threshold: asked first, before the supplier's split total passes it.
  const approved = await ask(acting, w, { amount: AED(50_000n), orderReference: 'INV-A' });
  const waiting = await ask(acting, w, { orderReference: 'INV-W' });
  const theirs = await shared.secondAgent(registry, w, { approvalThreshold: AED(100_000n) });
  const elsewhere = await ask(theirs, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
  expect([approved.status, waiting.status, elsewhere.status]).toEqual(['APPROVED', 'APPROVAL_REQUIRED', 'APPROVED']);
  return { approved, waiting, elsewhere };
}

/** Each request DENIED by a void with `cause`, its holdings released, its void signed before `before`. */
async function voidedBefore(
  w: World,
  requests: readonly { readonly id: string; readonly status: string }[],
  cause: string,
  before: bigint,
) {
  for (const request of requests) {
    expect(await statusOf(w, request.id)).toBe('DENIED');
    expect(await holdingsOf(w, request.id)).toEqual({ reservation: 'RELEASED', released: true });
    const events = await shared.eventsAbout(w.org, request.id, SPEND_REQUESTS.subject);
    expect(events.at(-1)).toMatchObject({
      action: 'spend_request.voided',
      actorType: 'system',
      details: { statusFrom: request.status, statusTo: 'DENIED', causes: cause },
    });
    expect(await newestSeq(w, SPEND_REQUESTS.subject, request.id)).toBeLessThan(before);
  }
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // The audit chain seals each event's time by the database's clock, so the tests start from now.
  clock = new FixedClock(new Date());
  capture = new LogCapture();
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger: logger() });
  const outbox = createOutbox({ ids, clock });
  decisions = createSpendRequestDecisions({ database: app, outbox, keys, ids, clock, logger: logger() });
  const challenges = createStepUpChallenges({ ids, clock });
  agents = createAgentChanges({ database: app, keys, ids, clock, challenges, outbox, logger: logger() });
  moves = createMandateMoves({ database: app, keys, ids, clock, challenges, outbox, logger: logger() });
  payeeRail = createFakeRail({ clock, ids });
});

describe('the brakes void their own pending requests in their transaction (C2b)', () => {
  it.each(Object.keys(BRAKES) as Brake[])(
    'voids the waiting and the approved once %s, before its first event: DENIED with its cause, holdings released',
    async (what) => {
      const { w, acting } = await ready();
      const mandateId = await mandateIdOf(w);
      const { approved, waiting, elsewhere } = await pendingOf(w, acting);
      const brake = BRAKES[what];
      const press = await brake.ready(w, mandateId);
      const subjectId = SUBJECT_IDS[brake.subject](w, mandateId);
      const before = await newestSeq(w, brake.subject, subjectId);

      expect(PRESSED).toContain((await press()).outcome);

      const braked = await firstSeqAfter(w, brake.subject, subjectId, before);
      await voidedBefore(w, [approved, waiting], brake.cause, braked);
      expect(await statusOf(w, elsewhere.id)).toBe(brake.spares ? 'APPROVED' : 'DENIED');
      expect(await spentOf(w, acting)).toBe(0n);
      // The holdings check still finds everything as signed.
      const checked = await withSignedStates(app, w.org, shared.quiet(), (tx, states) =>
        checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }),
      );
      expect(checked).toMatchObject({ mismatched: 0, tampered: 0 });
    },
  );

  it('voids them once the mandate expires, in the expiry job’s transaction, before its own event', async () => {
    const { w, acting } = await ready(new Date(clock.now().getTime() + HOUR_MS));
    const mandateId = await mandateIdOf(w);
    const { approved, waiting, elsewhere } = await pendingOf(w, acting);
    clock.advanceBy(HOUR_MS + 1);

    await createMandateExpiry({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      clock,
      outbox: createOutbox({ ids, clock }),
      logger: logger(),
    }).run();

    expect(lines('mandate_expiry.expired')).toHaveLength(1);
    await voidedBefore(w, [approved, waiting], 'MANDATE_NOT_IN_FORCE', await newestSeq(w, 'mandate', mandateId));
    expect(await statusOf(w, elsewhere.id)).toBe('APPROVED');
  });

  it('voids nothing when the agent or the mandate is suspended to pause; a pause made a cancel voids them (decision 7)', async () => {
    const { w, acting } = await ready();
    const mandateId = await mandateIdOf(w);
    const { approved, waiting } = await pendingOf(w, acting);

    await suspended(w, 'pause');
    await (
      await moving(w, mandateId, 'suspend', 'pause')
    )();
    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);

    await (
      await moving(w, mandateId, 'suspend', 'cancel')
    )();
    await voidedBefore(w, [approved, waiting], 'MANDATE_NOT_IN_FORCE', await newestSeq(w, 'mandate', mandateId));
  });

  it('voids them when the agent’s pause is made a cancel, with the agent’s cause', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    await suspended(w, 'pause');

    await suspended(w, 'cancel');

    await voidedBefore(w, [approved, waiting], 'AGENT_SUSPENDED', await newestSeq(w, 'agent', w.agent));
  });

  it('voids nothing when the source or the supplier is suspended to pause; a pause made a cancel voids them', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);

    await sourceSuspended(w, 'pause');
    await supplierSuspended(w, 'pause');
    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);

    await supplierSuspended(w, 'cancel');
    await voidedBefore(
      w,
      [approved, waiting],
      'SUPPLIER_NOT_VERIFIED',
      await newestSeq(w, 'supplier', w.suppliers[0] ?? ''),
    );
  });

  it('voids them when the source’s pause is made a cancel, with the source’s cause', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    await sourceSuspended(w, 'pause');

    await sourceSuspended(w, 'cancel');

    await voidedBefore(w, [approved, waiting], 'SOURCE_NOT_USABLE', await newestSeq(w, 'funding_source', w.source));
  });

  it('voids a paused supplier’s requests once its details change (decision 7: new details always cancel)', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    await supplierSuspended(w, 'pause');

    await (
      await detailsChanging(w)
    )();

    await voidedBefore(
      w,
      [approved, waiting],
      'SUPPLIER_CHANGED',
      await newestSeq(w, 'supplier', w.suppliers[0] ?? ''),
    );
  });

  it('voids at most its bound, the first by ID, leaving the rest standing for the job', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);

    const voided = await signed(w, (tx, states) =>
      voidPendingOf(tx, states, keys, w.org, { agentId: w.agent }, 'AGENT_SUSPENDED', clock.now(), 1),
    );

    expect(voided).toBe(1);
    const [first, second] = [approved, waiting].toSorted((a, b) => a.id.localeCompare(b.id));
    expect(await statusOf(w, first?.id ?? '')).toBe('DENIED');
    expect(await statusOf(w, second?.id ?? '')).toBe(second?.status);
  });

  it('leaves a request tampered with as it is, its alarm raised, and the brake still holds (FX-TAMPER)', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(waiting.id);
    } finally {
      await owner.end();
    }

    expect(await suspended(w, 'cancel')).toMatchObject({ outcome: 'changed' });

    expect(lines('audit.integrity_failed')).not.toEqual([]);
    expect(await statusOf(w, approved.id)).toBe('DENIED');
    const row = await withTenant(app, w.org, (tx) =>
      tx.selectFrom('spend_requests.requests').select('status').where('id', '=', waiting.id).executeTakeFirstOrThrow(),
    );
    expect(row.status).toBe('APPROVAL_REQUIRED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'HELD', released: false });
  });
});

describe('a payee registration’s choice for the supplier’s pending requests (decision 8, C3b)', () => {
  const supplierOfWorld = (w: World) => w.suppliers[0] ?? '';
  const job = (w: World) =>
    createRequestVoids({ list: () => Promise.resolve([w.org]), database: app, keys, ids, clock, logger: logger() });

  it('cancel: the check voids them, before its first event, and unverifies the supplier', async () => {
    const { w, acting } = await ready();
    const { approved, waiting, elsewhere } = await pendingOf(w, acting);
    const before = await newestSeq(w, 'supplier', supplierOfWorld(w));
    const check = await payeeRegistering(w, ['cancel']);

    expect((await check()).outcome).toBe('checked');

    const unverified = await firstSeqAfter(w, 'supplier', supplierOfWorld(w), before);
    await voidedBefore(w, [approved, waiting], 'SUPPLIER_NOT_VERIFIED', unverified);
    expect(await statusOf(w, elsewhere.id)).toBe('APPROVED');
    const events = await shared.eventsAbout(w.org, supplierOfWorld(w), 'supplier');
    expect(events.find(({ action }) => action === 'supplier.unverify')).toMatchObject({
      details: { pendingRequests: 'cancel', pendingStatementVersion: 2 },
    });
  });

  /** Whether the supplier's stop in force, in `status`, still pauses its requests, as the request-voids job reads it. */
  const stillPaused = async (w: World, status: string) =>
    (await signed(w, (tx, states) => pausedOf(tx, states, w.org, [['supplier', supplierOfWorld(w), status]]))).has(
      'supplier',
    );
  const chosen = async (w: World) =>
    (await shared.eventsAbout(w.org, supplierOfWorld(w), 'supplier')).filter(
      ({ action }) => action === 'supplier.pending_requests_chosen',
    );

  it('cancel on a supplier suspended with its requests paused: the check voids them at once, and the cancel holds (C3c)', async () => {
    const { w, acting } = await ready();
    const { approved, waiting, elsewhere } = await pendingOf(w, acting);
    await supplierSuspended(w, 'pause');
    const before = await newestSeq(w, 'supplier', supplierOfWorld(w));

    expect((await (await payeeRegistering(w, ['cancel']))()).outcome).toBe('checked');

    const recorded = await firstSeqAfter(w, 'supplier', supplierOfWorld(w), before);
    await voidedBefore(w, [approved, waiting], 'SUPPLIER_NOT_VERIFIED', recorded);
    expect(await statusOf(w, elsewhere.id)).toBe('APPROVED');
    expect(await chosen(w)).toMatchObject([{ details: { pendingRequests: 'cancel', pendingStatementVersion: 2 } }]);
    // The cancel is the stop in force: the job takes any past the batch, and a pause can't undo it.
    expect(await stillPaused(w, 'SUSPENDED')).toBe(false);
    expect(await supplierSuspended(w, 'pause')).toMatchObject({
      outcome: 'refused',
      code: 'PENDING_REQUESTS_CANCELLED',
    });
  });

  it('cancel on a supplier unverified with its requests paused: the next registration’s check voids them at once (C3c)', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    expect((await (await payeeRegistering(w, ['pause']))()).outcome).toBe('checked');
    expect((await payeeWithdrawn(w)).outcome).toBe('changed');
    expect(await stillPaused(w, 'UNVERIFIED')).toBe(true);
    const before = await newestSeq(w, 'supplier', supplierOfWorld(w));

    expect((await (await payeeRegistering(w, ['cancel']))()).outcome).toBe('checked');

    const recorded = await firstSeqAfter(w, 'supplier', supplierOfWorld(w), before);
    await voidedBefore(w, [approved, waiting], 'SUPPLIER_NOT_VERIFIED', recorded);
    expect(await chosen(w)).toHaveLength(1);
    expect(await stillPaused(w, 'UNVERIFIED')).toBe(false);
  });

  it('pause on a supplier suspended with its requests paused: nothing changes, its suspension’s choice holds (C3c)', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    await supplierSuspended(w, 'pause');

    expect((await (await payeeRegistering(w, ['pause']))()).outcome).toBe('checked');
    await job(w).run();

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
    expect(await chosen(w)).toEqual([]);
    expect(await stillPaused(w, 'SUSPENDED')).toBe(true);
  });

  it('cancel on a supplier suspended to cancel already: its requests stay cancelled, nothing more recorded (C3c)', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    await supplierSuspended(w, 'cancel');

    expect((await (await payeeRegistering(w, ['cancel']))()).outcome).toBe('checked');

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe('DENIED');
    expect(await chosen(w)).toEqual([]);
  });

  it('cancel on a supplier unverified to cancel already: its requests stay cancelled, nothing more recorded (C3c)', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    expect((await (await payeeRegistering(w, ['cancel']))()).outcome).toBe('checked');
    expect((await payeeWithdrawn(w)).outcome).toBe('changed');

    expect((await (await payeeRegistering(w, ['cancel']))()).outcome).toBe('checked');

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe('DENIED');
    expect(await chosen(w)).toEqual([]);
  });

  it('pause: they stand through the job while it is unverified; withdrawn and verified again, they stand', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);

    expect((await (await payeeRegistering(w, ['pause']))()).outcome).toBe('checked');
    await job(w).run();

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
    expect((await payeeWithdrawn(w)).outcome).toBe('changed');
    await job(w).run();
    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
    await shared.verified(w, supplierOfWorld(w));
    await job(w).run();
    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
  });

  it('pause: the change confirmed voids them, as a new payee always does', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    expect((await (await payeeRegistering(w, ['pause']))()).outcome).toBe('checked');
    const confirm = await payeeConfirming(w);
    const before = await newestSeq(w, 'supplier', supplierOfWorld(w));

    expect((await confirm()).outcome).toBe('changed');

    const changed = await firstSeqAfter(w, 'supplier', supplierOfWorld(w), before);
    await voidedBefore(w, [approved, waiting], 'SUPPLIER_CHANGED', changed);
  });

  it('a stop that names no choice (one from before the choice existed) cancels: the job voids them', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    // Suspended past the use case, as before C2a: its event names no choice.
    await shared.STOPS['the supplier suspended'](w);

    await job(w).run();

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe('DENIED');
  });

  it('cancel: a payee key another supplier is paid to unverifies nothing, so voids nothing', async () => {
    const { w, acting } = await ready();
    const [first, second] = w.suppliers;
    // The second supplier paid to the account first.
    expect((await (await payeeRegistering(w, ['cancel'], second))()).outcome).toBe('checked');
    expect((await (await payeeConfirming(w, second))()).outcome).toBe('changed');
    const approved = await ask(acting, w, { amount: AED(50_000n), orderReference: 'INV-A' });
    const waiting = await ask(acting, w, { orderReference: 'INV-W' });

    await (
      await payeeRegistering(w, ['cancel'], first)
    )();

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
    const shown = await signed(w, (tx, states) => supplierOf(tx, states, { orgId: w.org, id: first ?? '' }, 'share'));
    expect(shown).toMatchObject({ outcome: 'found', supplier: { status: 'VERIFIED' } });
  });

  it('cancel: an answer refused for an account number in its hint cancels nothing (C3b’s review)', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    const leaky: FinancialRailAdapter = {
      ...payeeRail,
      getBeneficiaryState: async (ref) => {
        const answer = await payeeRail.getBeneficiaryState(ref);
        if (answer.kind !== 'registered') return answer;
        return { ...answer, beneficiary: { ...answer.beneficiary, hint: 'AE070331234567890123456' } };
      },
    };

    await (
      await payeeRegistering(w, ['cancel'], w.suppliers[0], leaky)
    )();

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
    const shown = await signed(w, (tx, states) =>
      supplierOf(tx, states, { orgId: w.org, id: w.suppliers[0] ?? '' }, 'share'),
    );
    expect(shown).toMatchObject({ outcome: 'found', supplier: { status: 'VERIFIED' } });
  });

  it('a start carrying on with the one open: the newer choice holds, either way', async () => {
    const first = await ready();
    const one = await pendingOf(first.w, first.acting);
    expect((await (await payeeRegistering(first.w, ['cancel', 'pause']))()).outcome).toBe('checked');
    await job(first.w).run();
    for (const request of [one.approved, one.waiting]) expect(await statusOf(first.w, request.id)).toBe(request.status);

    const second = await ready();
    const two = await pendingOf(second.w, second.acting);
    expect((await (await payeeRegistering(second.w, ['pause', 'cancel']))()).outcome).toBe('checked');
    for (const request of [two.approved, two.waiting]) expect(await statusOf(second.w, request.id)).toBe('DENIED');
  });
});

describe('reactivating a suspended supplier: a fresh start or an un-pause (decision 9, C3d)', () => {
  const supplierOfWorld = (w: World) => w.suppliers[0] ?? '';
  const job = (w: World) =>
    createRequestVoids({ list: () => Promise.resolve([w.org]), database: app, keys, ids, clock, logger: logger() });
  /** The world's first supplier reactivated by its admin with `choice`, stepped up with a passkey. */
  const reactivated = async (w: World, choice: PendingChoice) => {
    const changes = createSupplierChanges(services());
    const asked = await changes.reactivate(
      w.admin,
      keyed(w.admin, SUPPLIER_REACTIVATE),
      supplierOfWorld(w),
      choice,
      CORRELATION,
    );
    const challengeId = askedFor(asked);
    await stepUp(w.admin, challengeId);
    return changes.reactivateConfirm(
      w.admin,
      keyed(w.admin, SUPPLIER_REACTIVATE_CONFIRM),
      supplierOfWorld(w),
      { stepUpChallengeId: challengeId, pendingRequests: choice },
      CORRELATION,
    );
  };
  const reactivation = async (w: World) =>
    (await shared.eventsAbout(w.org, supplierOfWorld(w), 'supplier')).findLast(({ action }) =>
      action.startsWith('supplier.reactivate'),
    );

  it('a fresh start back VERIFIED: every request voided before its event, the choice kept', async () => {
    const { w, acting } = await ready();
    const { approved, waiting, elsewhere } = await pendingOf(w, acting);
    await supplierSuspended(w, 'pause');
    const before = await newestSeq(w, 'supplier', supplierOfWorld(w));

    expect(await reactivated(w, 'cancel')).toMatchObject({ supplier: { status: 'VERIFIED' } });

    const moved = await firstSeqAfter(w, 'supplier', supplierOfWorld(w), before);
    await voidedBefore(w, [approved, waiting], 'SUPPLIER_NOT_VERIFIED', moved);
    expect(await statusOf(w, elsewhere.id)).toBe('APPROVED');
    expect(await reactivation(w)).toMatchObject({
      action: 'supplier.reactivate_verified',
      details: { pendingRequests: 'cancel', pendingStatementVersion: 1 },
    });
  });

  it('an un-pause back VERIFIED: its requests stand again at once, through the job', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    await supplierSuspended(w, 'pause');

    expect(await reactivated(w, 'pause')).toMatchObject({ supplier: { status: 'VERIFIED' } });
    await job(w).run();

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
  });

  it('an un-pause back UNVERIFIED (paused by a payee change, then suspended): held until verified again, then they stand', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    expect((await (await payeeRegistering(w, ['pause']))()).outcome).toBe('checked');
    await supplierSuspended(w, 'pause');

    expect(await reactivated(w, 'pause')).toMatchObject({ supplier: { status: 'UNVERIFIED' } });
    await job(w).run();
    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
    expect(await reactivation(w)).toMatchObject({
      action: 'supplier.reactivate',
      details: { pendingRequests: 'pause' },
    });

    expect((await payeeWithdrawn(w)).outcome).toBe('changed');
    await shared.verified(w, supplierOfWorld(w));
    await job(w).run();
    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
  });

  it('a fresh start back UNVERIFIED: voided at once', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    expect((await (await payeeRegistering(w, ['pause']))()).outcome).toBe('checked');
    await supplierSuspended(w, 'pause');

    expect(await reactivated(w, 'cancel')).toMatchObject({ supplier: { status: 'UNVERIFIED' } });

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe('DENIED');
  });

  it('refuses an un-pause when its suspension cancelled them: PENDING_REQUESTS_CANCELLED, at the ask', async () => {
    const { w } = await ready();
    await supplierSuspended(w, 'cancel');

    expect(
      await createSupplierChanges(services()).reactivate(
        w.admin,
        keyed(w.admin, SUPPLIER_REACTIVATE),
        supplierOfWorld(w),
        'pause',
        CORRELATION,
      ),
    ).toEqual({ outcome: 'refused', status: 409, code: 'PENDING_REQUESTS_CANCELLED' });
  });

  it('refuses a confirm with another choice than the step-up was asked for: STEP_UP_FAILED, nothing voided', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    await supplierSuspended(w, 'pause');
    const changes = createSupplierChanges(services());
    const challengeId = askedFor(
      await changes.reactivate(w.admin, keyed(w.admin, SUPPLIER_REACTIVATE), supplierOfWorld(w), 'pause', CORRELATION),
    );
    await stepUp(w.admin, challengeId);

    expect(
      await changes.reactivateConfirm(
        w.admin,
        keyed(w.admin, SUPPLIER_REACTIVATE_CONFIRM),
        supplierOfWorld(w),
        { stepUpChallengeId: challengeId, pendingRequests: 'cancel' },
        CORRELATION,
      ),
    ).toMatchObject({ outcome: 'refused', code: 'STEP_UP_FAILED' });
    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
  });

  /** A world whose agent has `count` requests to the first supplier standing, each small enough for every limit, which is then suspended to pause. */
  const pendingAndSuspended = async (count: number) => {
    const { w, acting } = await ready();
    const many = [];
    for (let each = 0; each < count; each += 1) many.push(await ask(acting, w, { amount: AED(1_000n) }));
    expect(many.every(({ status }) => status === 'APPROVED')).toBe(true);
    await supplierSuspended(w, 'pause');
    return { w, many };
  };
  const freshStartAsked = (w: World) =>
    createSupplierChanges(services()).reactivate(
      w.admin,
      keyed(w.admin, SUPPLIER_REACTIVATE),
      supplierOfWorld(w),
      'cancel',
      CORRELATION,
    );

  it('asks a fresh start with as many pending as one brake cancels at once (20)', async () => {
    const { w } = await pendingAndSuspended(20);

    expect((await freshStartAsked(w)).outcome).toBe('asked');
  });

  it('refuses a fresh start past what one brake cancels at once: PENDING_REQUESTS_TOO_MANY; suspended to cancel, then it goes through', async () => {
    const { w, many } = await pendingAndSuspended(21);

    expect(await freshStartAsked(w)).toEqual({ outcome: 'refused', status: 409, code: 'PENDING_REQUESTS_TOO_MANY' });
    for (const request of many) expect(await statusOf(w, request.id)).toBe('APPROVED');

    // Its pause made a cancel: the brake's batch now, the job the rest; then the fresh start goes through.
    await supplierSuspended(w, 'cancel');
    await job(w).run();
    expect(await reactivated(w, 'cancel')).toMatchObject({ supplier: { status: 'VERIFIED' } });
    for (const request of many) expect(await statusOf(w, request.id)).toBe('DENIED');
  });
});

describe('freezing the organisation: the admin chooses cancel or pause; unfreezing with a passkey and a reason (D1)', () => {
  const job = (w: World) =>
    createRequestVoids({ list: () => Promise.resolve([w.org]), database: app, keys, ids, clock, logger: logger() });
  const freezes = async (w: World) =>
    (await shared.eventsAbout(w.org, w.org, 'organization')).filter(({ action }) => action === 'organization.freeze');
  const told = (w: World) =>
    withTenant(app, w.org, (tx) =>
      tx
        .selectFrom('notifications.outbox')
        .select('kind')
        .where('org_id', '=', w.org)
        .where('kind', 'in', ['organization_frozen', 'organization_unfrozen'])
        .orderBy('created_at')
        .execute(),
    );
  /** The world's organisation unfrozen by its admin with `reason`, stepped up with a passkey; `confirmedWith` at the confirm. */
  const unfrozen = async (w: World, reason: string, confirmedWith = reason) => {
    const changes = createOrganizationChanges(services());
    const challengeId = askedFor(
      await changes.unfreeze(w.admin, keyed(w.admin, UNFREEZE_OPERATION), reason, CORRELATION),
    );
    await stepUp(w.admin, challengeId);
    return changes.unfreezeConfirm(
      w.admin,
      keyed(w.admin, UNFREEZE_CONFIRM_OPERATION),
      { stepUpChallengeId: challengeId, reason: confirmedWith },
      CORRELATION,
    );
  };

  it('pause: nothing voided, the job leaves them; unfrozen, they stand again, the reason and step-up on its event', async () => {
    const { w, acting } = await ready();
    const { approved, waiting, elsewhere } = await pendingOf(w, acting);

    expect(await frozen(w, 'pause')).toMatchObject({ outcome: 'changed', organization: { status: 'FROZEN' } });
    await job(w).run();
    for (const request of [approved, waiting, elsewhere]) expect(await statusOf(w, request.id)).toBe(request.status);
    expect(await freezes(w)).toMatchObject([{ details: { pendingRequests: 'pause', pendingStatementVersion: 1 } }]);

    expect(await unfrozen(w, 'All clear')).toMatchObject({ organization: { status: 'ACTIVE' } });
    await job(w).run();
    for (const request of [approved, waiting, elsewhere]) expect(await statusOf(w, request.id)).toBe(request.status);
    const unfreeze = (await shared.eventsAbout(w.org, w.org, 'organization')).at(-1);
    expect(unfreeze).toMatchObject({ action: 'organization.unfreeze', details: { reason: 'All clear' } });
    expect(unfreeze?.details).toHaveProperty('stepUpChallengeId');
    expect(await told(w)).toEqual([{ kind: 'organization_frozen' }, { kind: 'organization_unfrozen' }]);
  });

  it('a pause made a cancel voids them; a cancel can’t be made a pause; pressed twice tells no one twice', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    await frozen(w, 'pause');

    expect(await frozen(w, 'cancel')).toMatchObject({ outcome: 'changed', organization: { status: 'FROZEN' } });

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe('DENIED');
    expect((await freezes(w)).map(({ details }) => details.pendingRequests)).toEqual(['pause', 'cancel']);
    expect(await frozen(w, 'pause')).toEqual({ outcome: 'refused', status: 409, code: 'PENDING_REQUESTS_CANCELLED' });
    expect(await frozen(w, 'cancel')).toMatchObject({ outcome: 'changed' });
    expect(await told(w)).toEqual([{ kind: 'organization_frozen' }]);
  });

  it('refuses an approver: FORBIDDEN, neither frozen nor unfrozen (any admin, and only an admin)', async () => {
    const { w } = await ready();
    const approver = await shared.member(w.org, 'approver');
    const changes = createOrganizationChanges(services());
    const forbidden = { outcome: 'refused', status: 403, code: 'FORBIDDEN' };

    expect(await changes.freeze(approver, keyed(approver, FREEZE_OPERATION), 'pause', CORRELATION)).toEqual(forbidden);
    expect(await freezes(w)).toEqual([]);
    await frozen(w, 'pause');
    expect(await changes.unfreeze(approver, keyed(approver, UNFREEZE_OPERATION), 'All clear', CORRELATION)).toEqual(
      forbidden,
    );
  });

  it('refuses an unfreeze of an organisation not frozen: ORG_NOT_FROZEN', async () => {
    const { w } = await ready();

    expect(
      await createOrganizationChanges(services()).unfreeze(
        w.admin,
        keyed(w.admin, UNFREEZE_OPERATION),
        'All clear',
        CORRELATION,
      ),
    ).toEqual({ outcome: 'refused', status: 409, code: 'ORG_NOT_FROZEN' });
  });

  it('refuses a confirm with another reason than the step-up was asked for: STEP_UP_FAILED, still frozen', async () => {
    const { w } = await ready();
    await frozen(w, 'pause');

    expect(await unfrozen(w, 'All clear', 'Something else')).toMatchObject({
      outcome: 'refused',
      code: 'STEP_UP_FAILED',
    });
  });

  it('a freeze to cancel with more left than one batch: the unfreeze refused PENDING_REQUESTS_TOO_MANY, still frozen; once the job ends them, it goes through', async () => {
    const { w, acting } = await ready();
    // 41: the freeze's batch of 20 voids, and 21 are left, past the unfreeze's own.
    const many = [];
    for (let each = 0; each < 41; each += 1) many.push(await ask(acting, w, { amount: AED(1_000n) }));
    await frozen(w, 'cancel');
    const changes = createOrganizationChanges(services());
    const tooMany = { outcome: 'refused', status: 409, code: 'PENDING_REQUESTS_TOO_MANY' };

    expect(await changes.unfreeze(w.admin, keyed(w.admin, UNFREEZE_OPERATION), 'All clear', CORRELATION)).toEqual(
      tooMany,
    );
    expect(await freezes(w)).toHaveLength(1);
    await job(w).run();
    expect(await unfrozen(w, 'All clear')).toMatchObject({ organization: { status: 'ACTIVE' } });
    for (const request of many) expect(await statusOf(w, request.id)).toBe('DENIED');
  }, 60_000);

  it('a freeze to cancel past the batch: the unfreeze voids those left, before its event', async () => {
    const { w, acting } = await ready();
    const many = [];
    for (let each = 0; each < 21; each += 1) many.push(await ask(acting, w, { amount: AED(1_000n) }));
    await frozen(w, 'cancel');
    expect(
      (await Promise.all(many.map(({ id }) => statusOf(w, id)))).filter((status) => status === 'DENIED'),
    ).toHaveLength(20);
    const before = await newestSeq(w, 'organization', w.org);

    expect(await unfrozen(w, 'All clear')).toMatchObject({ organization: { status: 'ACTIVE' } });

    const left = many.at(-1);
    await voidedBefore(
      w,
      left === undefined ? [] : [left],
      'ORG_FROZEN',
      await firstSeqAfter(w, 'organization', w.org, before),
    );
    for (const request of many) expect(await statusOf(w, request.id)).toBe('DENIED');
  });
});

describe('a brake queued behind an approval holding the request (forced)', () => {
  it.each(Object.keys(BRAKES) as Brake[])('waits for the approval, then voids it once %s', async (what) => {
    const { w, acting } = await ready();
    const mandateId = await mandateIdOf(w);
    const waiting = await ask(acting, w);
    const brake = BRAKES[what];
    const press = await brake.ready(w, mandateId);
    const key = { orgId: w.org, id: waiting.id };
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const approving = signed(w, async (tx, states) => {
      const read = await requestOf(tx, states, key, 'change');
      if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
      holding(undefined);
      await gate;
      return approveRequest(tx, states, keys, key, { userId: w.admin.userId, stepUp: {} });
    });
    await held;

    const braking = within(20_000, press(), 'the brake');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    expect(await approving).toBe('approved');
    expect(PRESSED).toContain((await braking).outcome);
    const actions = (await shared.eventsAbout(w.org, waiting.id, SPEND_REQUESTS.subject)).map(({ action }) => action);
    expect(actions.slice(-2)).toEqual(['spend_request.approved', 'spend_request.voided']);
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'RELEASED', released: true });
  });

  it('waits for a cancel holding the request, then leaves it cancelled and the kill switch still holds', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const key = { orgId: w.org, id: waiting.id };
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const cancelling = signed(w, async (tx, states) => {
      await requestOf(tx, states, key, 'change');
      holding(undefined);
      await gate;
      return cancelRequest(tx, states, keys, key, { kind: 'user', userId: w.admin.userId }, clock.now());
    });
    await held;

    const braking = within(20_000, suspended(w, 'cancel'), 'the kill switch');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    expect(await cancelling).toMatchObject({ outcome: 'ended' });
    expect(await braking).toMatchObject({ outcome: 'changed' });
    expect(await statusOf(w, waiting.id)).toBe('CANCELLED');
    const actions = (await shared.eventsAbout(w.org, waiting.id, SPEND_REQUESTS.subject)).map(({ action }) => action);
    expect(actions).not.toContain('spend_request.voided');
  });
});

describe('a voided request as the team and the agent read it (C2b)', () => {
  it('shows the team when and why, and tells the agent REQUEST_VOIDED with its cause', async () => {
    const { w, acting } = await ready();
    const { waiting } = await pendingOf(w, acting);
    await suspended(w, 'cancel');
    const reads = createSpendRequestReads({ database: app, keys, ids, logger: logger() });

    expect(await reads.show(w.org, waiting.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      shown: { request: { status: 'DENIED' } },
      rejection: null,
      voiding: { causes: ['AGENT_SUSPENDED'] },
    });
    expect(await reads.ofAgent(w.org, w.agent, waiting.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      endedBecause: ['REQUEST_VOIDED', 'AGENT_SUSPENDED'],
    });
  });
});

describe('what a brake leaves alone', () => {
  it('a partner’s answer older than the one the source holds: it ends nothing, so voids nothing', async () => {
    const { w, acting } = await ready();
    const { approved, waiting } = await pendingOf(w, acting);
    const stale = new Date(w.state.statusChangedAt.getTime() - HOUR_MS);

    expect(
      await refreshed(w, () => ({
        kind: 'found',
        source: { ...w.state, availability: 'UNAVAILABLE', consentStatus: 'Revoked', statusChangedAt: stale },
      }))(),
    ).toMatchObject({ outcome: 'changed', source: { status: 'ACTIVE' } });

    for (const request of [approved, waiting]) expect(await statusOf(w, request.id)).toBe(request.status);
  });

  it('a request already ended: cancelled, it stays so, and the brake holds', async () => {
    const { w, acting } = await ready();
    const cancelled = await ask(acting, w, { orderReference: 'INV-C' });
    await signed(w, (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: cancelled.id },
        { kind: 'user', userId: w.admin.userId },
        clock.now(),
      ),
    );
    const waiting = await ask(acting, w, { orderReference: 'INV-W' });

    expect(await suspended(w, 'cancel')).toMatchObject({ outcome: 'changed' });

    expect(await statusOf(w, cancelled.id)).toBe('CANCELLED');
    expect(await statusOf(w, waiting.id)).toBe('DENIED');
  });
});

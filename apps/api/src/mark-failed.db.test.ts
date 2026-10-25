// Phase 4 gate H10 (partner decision 38, replacing decision 35, and its S145
// heads-up; ADR-007 §10; Rule Book §1.9): two admins mark an UNKNOWN payment
// failed on their bank's written word, through the use cases the routes call,
// on the real migrated schema as the app role.
// - One admin proposes, with the bank's reference and a passkey: the proposal
//   OPEN and signed as theirs, every admin told, the payment as it was.
// - A second admin confirms with their own passkey: FAILED, its held money
//   and its order given back, `transaction.fail` naming the reference, both
//   admins, the statement confirmed and the step-up's evidence; the proposal
//   CONFIRMED; every admin told. The proposer can't confirm while another
//   admin is active (FAILURE_PROPOSAL_YOURS); a lone admin can, a day on
//   (FAILURE_PROPOSAL_TOO_RECENT before).
// - Any admin withdraws one, every admin told; one open a payment
//   (FAILURE_PROPOSAL_OPEN); none open is NO_FAILURE_PROPOSAL.
// - A payment not UNKNOWN is PAYMENT_NOT_UNKNOWN; within a day of its hand-off
//   PAYMENT_TOO_RECENT; another organisation's or none NOT_FOUND; an approver,
//   a developer or a viewer FORBIDDEN; a record that can't be believed
//   INTEGRITY_FAILED, its alarm raised. A step-up signed in with an app code,
//   or asked for another payment, another reference, another proposal or the
//   payment as it stood before the bank's word since, is STEP_UP_FAILED.
// - A frozen organisation still marks. The key answers its own replay. The
//   bank check still watches it a week. With the bank check at the same
//   payment (forced), whichever takes it first settles it.
// The routes' answers are payments.test.ts.
import { withSignedStates } from '@agentx/core/modules/audit';
import { createSessions, createStepUpChallenges, ESTABLISHED_DAYS, MEMBERSHIPS } from '@agentx/core/modules/identity';
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { MARK_FAILED_AFTER_MS, markFailed } from '@agentx/core/modules/outcomes';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { FAILURE_PROPOSALS, noteTransactionFacts, TRANSACTIONS } from '@agentx/core/modules/transactions';
import { DAY_MS } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables, HOLDS_AFTER, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { askedFor, keys, type Member, OPERATOR, PASSKEY, refused, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import {
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  createPaymentMarks,
  LONE_ADMIN_WAIT_MS,
  MARK_FAILED_CONFIRMED,
  MARK_FAILED_STATEMENT_VERSION,
  type PaymentMarks,
  PROPOSE_CONFIRM_OPERATION,
  PROPOSE_OPERATION,
  WITHDRAW_CONFIRM_OPERATION,
  WITHDRAW_OPERATION,
} from './payment-marks.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xe1c0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xe1c1_0000_0000) });
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000e1';
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;
const EVIDENCE = 'BANK-NACK-77311';
/** Agent X's own team, as the operator's command names itself: only it resumes the hand-off. */
const PAUSER = { type: 'system', id: 'operator' } as const;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let marks: PaymentMarks;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'mark-failed',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, holdingsOf, member, keyed, stepUp, quiet } = shared;
const { ready, paymentOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** A step of the fake's payment: settled at the debtor a minute on, its answer final after two (B2). */
const STEP = 60_000;

/** The fils that make the fake reject it with no proof the money stayed: UNKNOWN, reconciliation's (rail map §4). */
const REJECTED_UNPROVEN = 4n;

/** The fils that lose the hand-off's answer, the bank crediting it after two steps: UNKNOWN until then. */
const ANSWER_LOST = 2n;

const handoffOf = (w: World) =>
  createHandoff({
    list: () => Promise.resolve([w.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail: w.rail,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
  });

const checksOf = (w: World) =>
  createPaymentChecks({
    list: () => Promise.resolve([w.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail: w.rail,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
  });

/** The request's transaction as it stands. */
const transactionOf = async (w: World, requestId: string) => {
  const payment = await paymentOf(w, requestId);
  if (typeof payment.transaction !== 'object') throw new Error(`no transaction: ${String(payment.transaction)}`);
  return payment.transaction;
};

/** A payment of the world handed off with these fils, then left as the bank check finds it two steps on, unless unchecked. */
async function handedOff(fils: bigint, { checked = true } = {}) {
  const { w, acting } = await ready();
  const request = await ask(acting, w, { amount: ALLOWED(fils) });
  await handoffOf(w).run();
  clock.advanceBy(2 * STEP);
  if (checked) await checksOf(w).run();
  return { w, acting, request, transaction: await transactionOf(w, request.id) };
}

/** A new admin signed in now: a session opened before the day the mark waits for has ended (12 hours at most). */
const adminOf = (w: World) => member(w.org, 'admin');

/** The same person signed in again now, with a passkey: a new session, their membership as it was. */
async function signedInAgain(who: Member): Promise<Member> {
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, who.userId, {
    idpSessionId: 'V1_9',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  return { ...who, sessionId };
}

/** An UNKNOWN payment past the day, and two of its organisation's admins signed in now. */
async function markable(fils = REJECTED_UNPROVEN) {
  const handed = await handedOff(fils, { checked: fils === REJECTED_UNPROVEN });
  const first = await adminOf(handed.w);
  const second = await adminOf(handed.w);
  // Members long enough to be each other's second person (ADR-012 §1), and the payment past its day.
  clock.advanceBy(ESTABLISHED_MS);
  return { ...handed, first: await signedInAgain(first), second: await signedInAgain(second) };
}

/** How long a member must have been one to be a second person (ADR-012 §1), and a step past it. */
const ESTABLISHED_MS = ESTABLISHED_DAYS * DAY_MS + 1;

/** The member's role changed to admin by `by`, as membership-changes.ts records it: a role `by` granted. */
const madeAdminBy = (w: World, who: Member, by: Member) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const key = { orgId: w.org, id: who.membershipId };
    const state = await states.verifiedState(tx, MEMBERSHIPS, key, 'change');
    if (state.outcome !== 'verified') throw new Error('not verified');
    await states.record(
      tx,
      MEMBERSHIPS,
      key,
      state,
      { role: 'admin' },
      {
        actor: { type: 'user', id: by.userId },
        action: 'membership.role_changed',
        details: { roleFrom: 'approver', roleTo: 'admin' },
      },
    );
  });

/** The member removed by `by`, as membership-changes.ts records it. */
const deactivatedBy = (w: World, who: Member, by: Member) =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    states.changeStatus(tx, MEMBERSHIPS, { orgId: w.org, id: who.membershipId }, 'deactivate', {
      actor: { type: 'user', id: by.userId },
      action: 'membership.deactivated',
      details: { role: 'admin' },
    }),
  );

const proposing = (who: Member, paymentId: string, evidenceRef = EVIDENCE) =>
  marks.propose(who, keyed(who, PROPOSE_OPERATION), paymentId, evidenceRef, CORRELATION);
const confirmingProposal = (who: Member, paymentId: string, challengeId: string, evidenceRef = EVIDENCE) =>
  marks.confirmProposal(
    who,
    keyed(who, PROPOSE_CONFIRM_OPERATION),
    paymentId,
    { evidenceRef, stepUpChallengeId: challengeId },
    CORRELATION,
  );
const approving = (who: Member, paymentId: string) =>
  marks.approve(who, keyed(who, APPROVE_OPERATION), paymentId, CORRELATION);
const confirmingApproval = (who: Member, paymentId: string, challengeId: string, key?: IdempotentRequest) =>
  marks.confirmApproval(who, key ?? keyed(who, APPROVE_CONFIRM_OPERATION), paymentId, challengeId, CORRELATION);
const withdrawing = (who: Member, paymentId: string) =>
  marks.withdraw(who, keyed(who, WITHDRAW_OPERATION), paymentId, CORRELATION);
const confirmingWithdrawal = (who: Member, paymentId: string, challengeId: string) =>
  marks.confirmWithdrawal(who, keyed(who, WITHDRAW_CONFIRM_OPERATION), paymentId, challengeId, CORRELATION);

/** Proposed as the route makes it: asked, signed in again with `amr` (a passkey), confirmed. */
async function proposed(who: Member, paymentId: string, amr?: readonly string[]) {
  const challengeId = askedFor(await proposing(who, paymentId));
  await stepUp(who, challengeId, amr);
  return confirmingProposal(who, paymentId, challengeId);
}

/** Approved as the route makes it: asked, signed in again with `amr` (a passkey), confirmed. */
async function approved(who: Member, paymentId: string, amr?: readonly string[]) {
  const challengeId = askedFor(await approving(who, paymentId));
  await stepUp(who, challengeId, amr);
  return confirmingApproval(who, paymentId, challengeId);
}

/** Withdrawn as the route makes it. */
async function withdrawn(who: Member, paymentId: string) {
  const challengeId = askedFor(await withdrawing(who, paymentId));
  await stepUp(who, challengeId);
  return confirmingWithdrawal(who, paymentId, challengeId);
}

/** The signed moves of the transaction, in order, with their actors and details. */
const movesOf = (w: World, transactionId: string) => shared.eventsAbout(w.org, transactionId, TRANSACTIONS.subject);

/** The organisation's proposals' events, oldest first. */
const proposalEventsOf = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        .selectFrom('audit.events')
        .select(['action', 'actor_id', 'details'])
        .where('subject_type', '=', FAILURE_PROPOSALS.subject)
        .orderBy('seq')
        .execute()
    ).map(({ action, actor_id, details }) => ({
      action,
      actorId: actor_id,
      details: JSON.parse(details) as Record<string, unknown>,
    })),
  );

/** The world's notices about payments marked, proposed or withdrawn, by kind and the transaction each is about. */
const markNoticesOf = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        // A global table (0021): the world's own organisation's notices alone.
        .selectFrom('notifications.outbox')
        .select(['kind', 'about_id', 'recipient_user_id'])
        .where('org_id', '=', w.org)
        .where('kind', 'in', [
          'payment_marked_failed',
          'payment_mark_proposed',
          'payment_mark_withdrawn',
          'payment_mark_ended',
        ])
        .orderBy('id')
        .execute()
    ).map(({ kind, about_id, recipient_user_id }) => ({ kind, aboutId: about_id, to: recipient_user_id })),
  );

/** The IDs of the organisation's integrity holds, on its chain. */
const holdsOf = async (w: World) =>
  (
    await withTenant(app, w.org, (tx) =>
      tx.selectFrom('audit.events').select('id').where('action', '=', 'integrity_hold.set').execute(),
    )
  ).map(({ id }) => id);

const freeze = (w: World) =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'freeze', {
      actor: OPERATOR,
      action: 'organization.freeze',
      details: {},
    }),
  );

/** The proposal's ID, from its answer. */
const proposalIdOf = (answer: Awaited<ReturnType<PaymentMarks['confirmProposal']>>): string => {
  if (answer.outcome !== 'proposed') throw new Error(`not proposed: ${JSON.stringify(answer)}`);
  return answer.proposal.id;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  // Born paused (ADR-014 §4): resumed for these tests, as the operator would.
  await app
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused: false, reason: 'TEST-H10', actor: PAUSER, release: 'r-test', run: null },
      ),
    );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // The audit chain seals each event's time by the database's clock, so the tests start from now.
  clock = new FixedClock(new Date());
  capture = new LogCapture();
  const logger = testLogger(capture);
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
  marks = createPaymentMarks({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger,
  });
});

describe('one admin proposes, a second confirms (H10; decision 38; ADR-007 §10)', () => {
  it('a proposal leaves the payment as it was, signs it as the proposer’s and tells every admin', async () => {
    const { w, request, transaction, first } = await markable();

    const answer = await proposed(first, transaction.id);

    expect(answer).toMatchObject({
      outcome: 'proposed',
      proposal: { transactionId: transaction.id, evidenceRef: EVIDENCE, proposedBy: first.userId, status: 'OPEN' },
    });
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(await proposalEventsOf(w)).toEqual([
      {
        action: 'failure_proposal.made',
        actorId: first.userId,
        details: expect.objectContaining({
          transactionId: transaction.id,
          confirmed: MARK_FAILED_CONFIRMED,
          statementVersion: String(MARK_FAILED_STATEMENT_VERSION),
          methods: 'pwd user mfa',
        }) as unknown,
      },
    ]);
    expect(await markNoticesOf(w)).toEqual([{ kind: 'payment_mark_proposed', aboutId: transaction.id, to: null }]);
  });

  it('a second admin sees the proposal, confirms it, and the payment is FAILED, its money and its order given back', async () => {
    const { w, request, transaction, first, second } = await markable();
    const proposal = proposalIdOf(await proposed(first, transaction.id));

    const asked = await approving(second, transaction.id);
    expect(asked).toMatchObject({
      outcome: 'asked',
      proposal: { id: proposal, evidenceRef: EVIDENCE, proposedBy: first.userId, status: 'OPEN' },
    });
    await stepUp(second, askedFor(asked));
    expect(await confirmingApproval(second, transaction.id, askedFor(asked))).toEqual({
      outcome: 'marked',
      paymentId: transaction.id,
    });

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED', providerStatus: 'Rejected' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect((await movesOf(w, transaction.id)).at(-1)).toMatchObject({
      action: 'transaction.fail',
      actorType: 'user',
      details: {
        via: 'admin',
        evidenceRef: EVIDENCE,
        proposalId: proposal,
        proposedBy: first.userId,
        confirmed: MARK_FAILED_CONFIRMED,
        statementVersion: String(MARK_FAILED_STATEMENT_VERSION),
        methods: 'pwd user mfa',
        statusFrom: 'UNKNOWN',
      },
    });
    expect((await proposalEventsOf(w)).map(({ action, actorId }) => ({ action, actorId }))).toEqual([
      { action: 'failure_proposal.made', actorId: first.userId },
      { action: 'failure_proposal.confirmed', actorId: second.userId },
    ]);
    expect((await markNoticesOf(w)).map(({ kind }) => kind)).toEqual([
      'payment_mark_proposed',
      'payment_marked_failed',
    ]);
  });

  it('refuses the proposer’s own confirm while another admin is active: FAILURE_PROPOSAL_YOURS, a day on too', async () => {
    const { w, request, transaction, first } = await markable();
    await proposed(first, transaction.id);

    expect(await approving(first, transaction.id)).toEqual(refused(403, 'FAILURE_PROPOSAL_YOURS'));
    clock.advanceBy(LONE_ADMIN_WAIT_MS + 1);
    const again = await signedInAgain(first);
    expect(await approving(again, transaction.id)).toEqual(refused(403, 'FAILURE_PROPOSAL_YOURS'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
  });

  it('counts two admins as two: with exactly one other active admin, the proposer’s confirm is theirs to refuse', async () => {
    const { w, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    // The world's admin, and this one: two in all.
    const proposer = await adminOf(w);
    await proposed(proposer, transaction.id);
    // The world's admin a member long enough to be the second person.
    clock.advanceBy(ESTABLISHED_MS);

    expect(await approving(await signedInAgain(proposer), transaction.id)).toEqual(
      refused(403, 'FAILURE_PROPOSAL_YOURS'),
    );
    expect(await approved(await signedInAgain(w.admin), transaction.id)).toMatchObject({ outcome: 'marked' });
  });

  it('refuses a second admin who joined in the last 14 days: FAILURE_PROPOSAL_CONFIRMER_TOO_NEW (ADR-012 §1)', async () => {
    const { w, request, transaction, first } = await markable();
    await proposed(first, transaction.id);
    const newcomer = await adminOf(w);

    expect(await approving(newcomer, transaction.id)).toEqual(refused(403, 'FAILURE_PROPOSAL_CONFIRMER_TOO_NEW'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
  });

  it('refuses a second admin the proposer made admin: FAILURE_PROPOSAL_GRANTED_BY_PROPOSER (ADR-012 §1)', async () => {
    const { w, transaction } = await handedOff(REJECTED_UNPROVEN);
    const first = await adminOf(w);
    const second = await adminOf(w);
    const raised = await member(w.org, 'approver');
    await madeAdminBy(w, raised, first);
    clock.advanceBy(ESTABLISHED_MS);
    const proposer = await signedInAgain(first);
    await proposed(proposer, transaction.id);

    expect(await approving(await signedInAgain(raised), transaction.id)).toEqual(
      refused(403, 'FAILURE_PROPOSAL_GRANTED_BY_PROPOSER'),
    );
    expect(await approved(await signedInAgain(second), transaction.id)).toMatchObject({ outcome: 'marked' });
  });

  it('keeps the one-admin path shut 14 days after an admin is removed: FAILURE_PROPOSAL_ALONE_LOCKED', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    const other = await adminOf(w);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const lone = await signedInAgain(w.admin);
    await deactivatedBy(w, other, lone);
    await proposed(lone, transaction.id);
    clock.advanceBy(LONE_ADMIN_WAIT_MS + 1);

    expect(await approving(await signedInAgain(lone), transaction.id)).toEqual(
      refused(409, 'FAILURE_PROPOSAL_ALONE_LOCKED'),
    );
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });

    clock.advanceBy(ESTABLISHED_MS);
    expect(await approved(await signedInAgain(lone), transaction.id)).toMatchObject({ outcome: 'marked' });
  });

  it('lets a lone admin confirm their own proposal a day after making it, never before (partner S113)', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    // The world's admin is its only one.
    const lone = await signedInAgain(w.admin);
    await proposed(lone, transaction.id);

    clock.advanceBy(LONE_ADMIN_WAIT_MS);
    const early = await signedInAgain(lone);
    expect(await approving(early, transaction.id)).toEqual(refused(409, 'FAILURE_PROPOSAL_TOO_RECENT'));

    clock.advanceBy(1);
    const due = await signedInAgain(lone);
    expect(await approved(due, transaction.id)).toMatchObject({ outcome: 'marked' });
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED' });
  });

  it('counts only active admins: an approver joining doesn’t stop a lone admin', async () => {
    const { w, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const lone = await signedInAgain(w.admin);
    await member(w.org, 'approver');
    await proposed(lone, transaction.id);
    clock.advanceBy(LONE_ADMIN_WAIT_MS + 1);

    expect(await approved(await signedInAgain(lone), transaction.id)).toMatchObject({ outcome: 'marked' });
  });

  it('keeps one proposal open a payment: a second is FAILURE_PROPOSAL_OPEN, until it is withdrawn', async () => {
    const { w, request, transaction, first, second } = await markable();
    await proposed(first, transaction.id);

    expect(await proposing(second, transaction.id)).toEqual(refused(409, 'FAILURE_PROPOSAL_OPEN'));

    expect(await withdrawn(second, transaction.id)).toMatchObject({
      outcome: 'withdrawn',
      proposal: { status: 'WITHDRAWN' },
    });
    expect(await proposed(second, transaction.id)).toMatchObject({
      outcome: 'proposed',
      proposal: { proposedBy: second.userId, status: 'OPEN' },
    });
    expect(await approved(first, transaction.id)).toMatchObject({ outcome: 'marked' });
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED' });
  });

  it('is withdrawn by its proposer or another admin, every admin told, the payment as it was', async () => {
    const { w, request, transaction, first, second } = await markable();
    await proposed(first, transaction.id);
    expect(await withdrawn(first, transaction.id)).toMatchObject({ outcome: 'withdrawn' });
    await proposed(first, transaction.id);
    expect(await withdrawn(second, transaction.id)).toMatchObject({ outcome: 'withdrawn' });

    expect(await approving(second, transaction.id)).toEqual(refused(409, 'NO_FAILURE_PROPOSAL'));
    expect(await withdrawing(second, transaction.id)).toEqual(refused(409, 'NO_FAILURE_PROPOSAL'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect((await markNoticesOf(w)).map(({ kind }) => kind)).toEqual([
      'payment_mark_proposed',
      'payment_mark_withdrawn',
      'payment_mark_proposed',
      'payment_mark_withdrawn',
    ]);
    expect((await proposalEventsOf(w)).map(({ action, actorId }) => ({ action, actorId }))).toEqual([
      { action: 'failure_proposal.made', actorId: first.userId },
      { action: 'failure_proposal.withdrawn', actorId: first.userId },
      { action: 'failure_proposal.made', actorId: first.userId },
      { action: 'failure_proposal.withdrawn', actorId: second.userId },
    ]);
  });

  it('marks while the organisation is frozen: nothing here spends (as a reject, decision 3)', async () => {
    const { w, request, transaction, first, second } = await markable();
    await freeze(w);

    await proposed(first, transaction.id);
    expect(await approved(second, transaction.id)).toMatchObject({ outcome: 'marked' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
  });

  it('answers the confirm’s key’s replay as before: one move, one notice; asked again, PAYMENT_NOT_UNKNOWN', async () => {
    const { w, transaction, first, second } = await markable();
    await proposed(first, transaction.id);
    const challengeId = askedFor(await approving(second, transaction.id));
    await stepUp(second, challengeId);
    const key = keyed(second, APPROVE_CONFIRM_OPERATION, 'approve-once');

    const once = await confirmingApproval(second, transaction.id, challengeId, key);
    expect(once).toEqual({ outcome: 'marked', paymentId: transaction.id });
    expect(await confirmingApproval(second, transaction.id, challengeId, key)).toEqual(once);

    expect((await movesOf(w, transaction.id)).filter(({ action }) => action === 'transaction.fail')).toHaveLength(1);
    expect((await markNoticesOf(w)).filter(({ kind }) => kind === 'payment_marked_failed')).toHaveLength(1);
    expect(await approving(first, transaction.id)).toEqual(refused(409, 'PAYMENT_NOT_UNKNOWN'));
    expect(await proposing(first, transaction.id)).toEqual(refused(409, 'PAYMENT_NOT_UNKNOWN'));
  });

  it('is still watched by the bank check: the bank paying it after all is said, never applied (rail map §4)', async () => {
    // The lone admin's path, so the fake still answers about it: within days of its hand-off, not weeks.
    const { w, request, transaction } = await handedOff(ANSWER_LOST, { checked: false });
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    await proposed(await signedInAgain(w.admin), transaction.id);
    clock.advanceBy(LONE_ADMIN_WAIT_MS + 1);
    await approved(await signedInAgain(w.admin), transaction.id);

    // A new check's first run checks every one, the watched among them.
    await checksOf(w).run();

    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'FAILED',
      providerStatus: 'AcceptedCreditSettlementCompleted',
    });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(lines('payment_check.contradicts')).toEqual([
      expect.objectContaining({ transactionId: transaction.id, status: 'FAILED' }),
    ]);
  });
});

describe('refused, changing nothing', () => {
  it('a payment not UNKNOWN: PAYMENT_NOT_UNKNOWN, before any step-up', async () => {
    const { w, request, transaction } = await handedOff(0n, { checked: false });
    expect(transaction.status).toBe('PROCESSING');
    clock.advanceBy(MARK_FAILED_AFTER_MS);

    expect(await proposing(await adminOf(w), transaction.id)).toEqual(refused(409, 'PAYMENT_NOT_UNKNOWN'));
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);
    expect(await markNoticesOf(w)).toEqual([]);
  });

  it('a payment within a day of its hand-off: PAYMENT_TOO_RECENT, proposed just past it', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    // Its hand-off was two steps ago: a day on from it, to the millisecond, is still within.
    clock.advanceBy(MARK_FAILED_AFTER_MS - 2 * STEP);
    const admin = await adminOf(w);

    expect(await proposing(admin, transaction.id)).toEqual(refused(409, 'PAYMENT_TOO_RECENT'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });

    clock.advanceBy(1);
    expect(await proposed(admin, transaction.id)).toMatchObject({ outcome: 'proposed' });
  });

  it('another organisation’s payment, or none: NOT_FOUND, on every step', async () => {
    const { w, request, transaction, first } = await markable();
    await proposed(first, transaction.id);
    const other = await ready();
    const stranger = await adminOf(other.w);

    expect(await proposing(stranger, transaction.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await approving(stranger, transaction.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await withdrawing(stranger, transaction.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await proposing(first, ids.next())).toEqual(refused(404, 'NOT_FOUND'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('a %s, on every step', async (role) => {
    const { w, request, transaction, first } = await markable();
    const who = await member(w.org, role);

    expect(await proposing(who, transaction.id)).toEqual(refused(403, 'FORBIDDEN'));
    await proposed(first, transaction.id);
    expect(await approving(who, transaction.id)).toEqual(refused(403, 'FORBIDDEN'));
    expect(await withdrawing(who, transaction.id)).toEqual(refused(403, 'FORBIDDEN'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
  });

  it('a step-up signed in with an app code: STEP_UP_FAILED, to propose and to confirm', async () => {
    const { w, request, transaction, first, second } = await markable();

    expect(await proposed(first, transaction.id, APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    await proposed(first, transaction.id);
    expect(await approved(second, transaction.id, APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
  });

  it('a step-up asked for another payment or another reference: STEP_UP_FAILED', async () => {
    const { w, acting, transaction, first } = await markable();
    // Small: two of ALLOWED to one supplier would together need an approval (the split check).
    const other = await ask(acting, w, { amount: SMALL(REJECTED_UNPROVEN) });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    await checksOf(w).run();
    const otherPayment = await transactionOf(w, other.id);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await signedInAgain(first);
    const challengeId = askedFor(await proposing(admin, transaction.id));
    await stepUp(admin, challengeId);

    expect(await confirmingProposal(admin, otherPayment.id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await confirmingProposal(admin, transaction.id, challengeId, 'BANK-NACK-00000')).toEqual(
      refused(403, 'STEP_UP_FAILED'),
    );
  });

  it('a confirm asked for a proposal since withdrawn and made again: STEP_UP_FAILED', async () => {
    const { transaction, first, second } = await markable();
    await proposed(first, transaction.id);
    const challengeId = askedFor(await approving(second, transaction.id));
    await stepUp(second, challengeId);
    await withdrawn(first, transaction.id);
    await proposed(first, transaction.id);

    expect(await confirmingApproval(second, transaction.id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
  });

  it('a confirm asked before the bank’s word on the payment changed, still UNKNOWN: STEP_UP_FAILED', async () => {
    const { w, request, transaction, first, second } = await markable();
    await proposed(first, transaction.id);
    const challengeId = askedFor(await approving(second, transaction.id));
    await stepUp(second, challengeId);
    // The bank's word, read since: the payment still UNKNOWN, its latest signed event another.
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      noteTransactionFacts(
        tx,
        states,
        { orgId: w.org, id: transaction.id },
        {
          providerStatus: 'Rejected',
          paymentInstructionRef: 'PI-NEW-1',
          rejectCode: null,
          providerChangedAt: clock.now(),
        },
        { actor: OPERATOR, details: { via: 'test' } },
      ),
    );

    expect(await confirmingApproval(second, transaction.id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
  });

  it('a confirm once the bank’s word settled the payment since: PAYMENT_NOT_UNKNOWN; the proposal ENDED, all told', async () => {
    const { w, request, transaction, first, second } = await markable(ANSWER_LOST);
    // UNKNOWN until the bank's credit is read: its check left until now.
    expect(transaction).toMatchObject({ status: 'UNKNOWN' });
    await proposed(first, transaction.id);
    const challengeId = askedFor(await approving(second, transaction.id));
    await stepUp(second, challengeId);
    await checksOf(w).run();

    expect(await confirmingApproval(second, transaction.id, challengeId)).toEqual(refused(409, 'PAYMENT_NOT_UNKNOWN'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    // Ended by the bank check's move, in its transaction (partner S145): nothing left open.
    expect((await proposalEventsOf(w)).map(({ action, actorId }) => ({ action, actorId }))).toEqual([
      { action: 'failure_proposal.made', actorId: first.userId },
      { action: 'failure_proposal.ended', actorId: 'api' },
    ]);
    expect((await markNoticesOf(w)).map(({ kind }) => kind)).toEqual(['payment_mark_proposed', 'payment_mark_ended']);
    expect(await withdrawing(first, transaction.id)).toEqual(refused(409, 'NO_FAILURE_PROPOSAL'));
    expect(await proposing(first, transaction.id)).toEqual(refused(409, 'PAYMENT_NOT_UNKNOWN'));
  });
});

describe('records that can’t be believed (their alarm raised): refused, nothing changed (FX-TAMPER)', () => {
  it.each([
    ['the payment', TRANSACTIONS],
    ['its proposal', FAILURE_PROPOSALS],
  ] as const)(
    'refuses a confirm for which %s can’t be believed: INTEGRITY_FAILED, the organisation held',
    async (_name, table) => {
      const { w, request, transaction, first, second } = await markable();
      const proposal = proposalIdOf(await proposed(first, transaction.id));
      const challengeId = askedFor(await approving(second, transaction.id));
      await stepUp(second, challengeId);
      const owner = await tamperAsOwner(database, table, w.org);
      try {
        await owner.stripSeals(table === TRANSACTIONS ? transaction.id : proposal);
      } finally {
        await owner.end();
      }

      expect(await confirmingApproval(second, transaction.id, challengeId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
      expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
      expect(await holdsOf(w)).toHaveLength(1);
    },
  );

  it('fails, changing nothing, for one whose instruction can’t be believed', async () => {
    const { w, request, transaction, first, second } = await markable();
    await proposed(first, transaction.id);
    const challengeId = askedFor(await approving(second, transaction.id));
    await stepUp(second, challengeId);
    const owner = await tamperAsOwner(database, INSTRUCTIONS, w.org);
    try {
      await owner.stripSeals(transaction.instructionId);
    } finally {
      await owner.end();
    }

    await expect(confirmingApproval(second, transaction.id, challengeId)).rejects.toThrow(
      "instruction can't be believed",
    );
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
  });
});

describe('core’s markFailed, for a caller that didn’t check (its use case reads the payment first)', () => {
  it('throws for a payment under way, changing nothing, though the machine would let it fail', async () => {
    const { w, request, transaction } = await handedOff(0n, { checked: false });
    expect(transaction.status).toBe('PROCESSING');

    await expect(
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        markFailed(tx, states, createOutbox({ ids, clock }), {
          orgId: w.org,
          transactionId: transaction.id,
          userId: w.admin.userId,
          details: { evidenceRef: EVIDENCE },
          at: clock.now(),
        }),
      ),
    ).rejects.toThrow('Only an UNKNOWN payment is marked failed, not PROCESSING');
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);
  });
});

describe('with the bank check or another admin at the same payment (forced, ADR-006 §6)', () => {
  /**
   * The payment's row held as by another writer, the two queued behind it in
   * the order given, then let go: each in its turn.
   */
  async function queued(w: World, transactionId: string, first: () => Promise<unknown>, then: () => Promise<unknown>) {
    const holder = await database.connect('owner');
    try {
      await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await holder.query('begin');
      await holder.query('select id from transactions.transactions where id = $1 for no key update', [transactionId]);
      const one = first();
      await waitUntilQueued(database.as('admin'), 1);
      const two = then();
      await waitUntilQueued(database.as('admin'), 2);
      await holder.query('commit');
      return await Promise.allSettled([one, two]);
    } finally {
      await holder.end();
    }
  }

  /** Proposed, the second admin asked and signed in again for: their confirm, ready to run. */
  async function readyToConfirm(handed: Awaited<ReturnType<typeof markable>>) {
    await proposed(handed.first, handed.transaction.id);
    const challengeId = askedFor(await approving(handed.second, handed.transaction.id));
    await stepUp(handed.second, challengeId);
    return () => confirmingApproval(handed.second, handed.transaction.id, challengeId);
  }

  it('settles with its holdings locked before the head, so their holder never waits on it', async () => {
    const handed = await markable();
    const { w, request } = handed;
    const confirm = await readyToConfirm(handed);
    // Something holding the request's reservation (as an ending or a holdings page would) as the mark is made.
    const holder = await database.connect('owner');
    let marking: Promise<unknown> | undefined;
    try {
      await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await holder.query('begin');
      await holder.query('select id from limit_reservations.reservations where request_id = $1 for no key update', [
        request.id,
      ]);
      marking = confirm();
      await waitUntilQueued(database.as('admin'), 1);
      // The mark waits at the reservation (11) holding nothing of the head (12): the organisation's head is free.
      const looker = await database.connect('owner');
      try {
        await looker.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
        await expect(
          looker.query('select org_id from audit.heads where org_id = $1 for update nowait', [w.org]),
        ).resolves.toHaveLength(1);
      } finally {
        await looker.end();
      }
      await holder.query('commit');
    } finally {
      await holder.end();
    }
    await marking;

    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
  });

  it('marked first: FAILED stands, and the bank’s later credit is said as a contradiction, never applied', async () => {
    const handed = await markable(ANSWER_LOST);
    const { w, request, transaction } = handed;
    expect(transaction).toMatchObject({ status: 'UNKNOWN', providerStatus: null });
    const confirm = await readyToConfirm(handed);

    const [mark] = await queued(w, transaction.id, confirm, () => checksOf(w).run());

    expect(mark).toEqual({ status: 'fulfilled', value: { outcome: 'marked', paymentId: transaction.id } });
    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'FAILED',
      providerStatus: 'AcceptedCreditSettlementCompleted',
    });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(lines('payment_check.contradicts')).toHaveLength(1);
  });

  it('checked first: the bank’s credit settles it, and the mark is refused, changing nothing', async () => {
    const handed = await markable(ANSWER_LOST);
    const { w, request, transaction } = handed;
    const confirm = await readyToConfirm(handed);

    const [, mark] = await queued(w, transaction.id, () => checksOf(w).run(), confirm);

    expect(mark).toEqual({ status: 'fulfilled', value: refused(409, 'PAYMENT_NOT_UNKNOWN') });
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect((await markNoticesOf(w)).map(({ kind }) => kind)).toEqual(['payment_mark_proposed', 'payment_mark_ended']);
  });

  it('two admins proposing at once: one proposal, the other FAILURE_PROPOSAL_OPEN', async () => {
    const { w, transaction, first, second } = await markable();
    const confirms = [];
    for (const who of [first, second]) {
      const challengeId = askedFor(await proposing(who, transaction.id));
      await stepUp(who, challengeId);
      confirms.push(() => confirmingProposal(who, transaction.id, challengeId));
    }
    const [one, two] = confirms;
    if (one === undefined || two === undefined) throw new Error('two confirms');

    const answers = await queued(w, transaction.id, one, two);

    expect(answers).toEqual([
      { status: 'fulfilled', value: expect.objectContaining({ outcome: 'proposed' }) as unknown },
      { status: 'fulfilled', value: refused(409, 'FAILURE_PROPOSAL_OPEN') },
    ]);
  });
});

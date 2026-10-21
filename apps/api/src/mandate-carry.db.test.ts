// Phase 3 E4c: a mandate's pending spend requests carried over to its new
// version, on the real migrated schema as the app role (PRD §4.1, §11; BR-05,
// BR-09; partner decisions 15 and 17). The accepting admin chooses carry: the
// ask answers with the plan, each request weighed again under the new terms,
// and the confirm applies exactly it. Carried, a request names the new version
// (its status as it was, the admin's `spend_request.carried`), its holdings
// kept and still whole, and the request-voids job leaves it be; cancelled, it
// is DENIED with the new terms' reasons, its holdings freed. Under them: a
// waiting one still waits (17.2) and is approved afterwards; a request over
// the new per-order limit is cancelled; one a person approved stays approved
// where the new terms would ask an approval, one auto-approved is cancelled
// (17.1); when a lowered monthly limit can't hold them all, the oldest stand.
// A plan changed between the ask and the confirm refuses the step-up. Past
// 20 pending (Phase 4 A3, PL-47): the oldest 20 settled at the confirm, the
// rest left on the version replaced (the voids job leaves them be) and carried
// by the job within minutes the same way, the oldest standing; a mandate no
// longer in force leaves them to the voids job.
import { AGENTS } from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  approveRequest,
  cancelRequest,
  checkHoldings,
  requestOf,
  SPEND_REQUESTS,
} from '@agentx/core/modules/spend-requests';
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

import { ACCEPT_CONFIRM_OPERATION, ACCEPT_OPERATION, createMandateAcceptance } from './mandate-acceptance.ts';
import type { SupersedeChoice } from './mandate-carry.ts';
import {
  createMandateRegistry,
  type MandateDraft,
  type MandateRegistry,
  REDRAFT_OPERATION,
} from './mandate-registry.ts';
import { AED, askedFor, draftedOf, keys, type World } from './mandate-world.helper.test.ts';
import { createCarryRest } from './mandate-carry-rest.ts';
import { createRequestVoids } from './request-voids.ts';
import {
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  createSpendRequestApprovals,
} from './spend-request-approvals.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { changedPastTheApp, spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xe4c0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000e4';

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'mandate-carry',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, statusOf, holdingsOf, spentOf, mandateIdOf, signed, keyed, stepUp, termsOf } = shared;

const logger = () => testLogger(capture);

/** The version in force's terms: approval above AED 1,000, no split check, so each request is weighed alone. */
const FIRST: Partial<MandateDraft['terms']> = { approvalThreshold: AED(100_000n), splitCheck: false };

/** A world whose agent has a key and a mandate in force under FIRST, both suppliers verified. */
async function ready() {
  const w = await shared.world();
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, FIRST);
  return { w, acting: await shared.agentKey(w), mandateId: await mandateIdOf(w) };
}

const acceptance = () =>
  createMandateAcceptance({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger: logger(),
  });

/** A new version drafted with `terms` over FIRST's, and its acceptance asked with `choice`: the ask's answer. */
async function asking(w: World, mandateId: string, terms: Partial<MandateDraft['terms']>, choice: SupersedeChoice) {
  const drafted = draftedOf(
    await registry.redraft(
      w.admin,
      keyed(w.admin, REDRAFT_OPERATION),
      mandateId,
      { terms: termsOf(w, { ...FIRST, purpose: 'Office supplies, renewed', ...terms }), overLimit: 'refuse' },
      CORRELATION,
    ),
  );
  const versionId = drafted.pending?.version.id ?? '';
  const asked = await acceptance().accept(
    w.admin,
    keyed(w.admin, ACCEPT_OPERATION),
    mandateId,
    versionId,
    choice,
    CORRELATION,
  );
  return { asked, versionId };
}

/** The ask stepped up with a passkey and confirmed with `choice`: the confirm's answer. */
async function confirmed(w: World, mandateId: string, challengeId: string, choice: SupersedeChoice) {
  await stepUp(w.admin, challengeId);
  return acceptance().acceptConfirm(
    w.admin,
    keyed(w.admin, ACCEPT_CONFIRM_OPERATION),
    mandateId,
    challengeId,
    choice,
    CORRELATION,
  );
}

/** A new version accepted with carry, `terms` over FIRST's: the plan the ask showed, and the new version. */
async function carried(w: World, mandateId: string, terms: Partial<MandateDraft['terms']> = {}) {
  const { asked, versionId } = await asking(w, mandateId, terms, 'carry');
  if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
  const done = await confirmed(w, mandateId, asked.stepUpChallengeId, 'carry');
  if (done.outcome !== 'accepted') throw new Error(`not accepted: ${JSON.stringify(done)}`);
  return { plan: asked.carry, versionId };
}

/** A request waiting for approval, approved by a person (core approveRequest, as an approver's confirm does). */
async function approvedByAPerson(w: World, id: string) {
  await signed(w, async (tx, states) => {
    // Read for change first, as the approval's use case reads it (ADR-006 §6).
    await requestOf(tx, states, { orgId: w.org, id }, 'change');
    return approveRequest(tx, states, keys, { orgId: w.org, id }, { userId: w.admin.userId, stepUp: {} });
  });
}

/** `count` requests of AED 10, each allowed (APPROVED), a minute apart, so a carry's order is when each was made. */
async function askedInTurn(acting: Parameters<typeof ask>[0], w: World, count: number) {
  const made = [];
  for (let i = 0; i < count; i += 1) {
    made.push(await ask(acting, w, { amount: AED(1_000n), orderReference: `TURN-${String(i)}` }));
    clock.advanceBy(60_000);
  }
  return made;
}

/** The agent suspended or reactivated past its use case: only its status, as the carry job reads it. */
const agentMoved = (w: World, event: 'suspend' | 'reactivate') =>
  signed(w, (tx, states) =>
    states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, event, {
      actor: { type: 'system', id: 'mandate-carry-test' },
      action: event === 'suspend' ? 'agent.suspended' : 'agent.reactivated',
      details: {},
    }),
  );

const voids = (w: World) =>
  createRequestVoids({ list: () => Promise.resolve([w.org]), database: app, keys, ids, clock, logger: logger() });

const carryRest = (w: World) =>
  createCarryRest({ list: () => Promise.resolve([w.org]), database: app, keys, ids, clock, logger: logger() });

/** The request's version, as its row names it. */
const versionOf = (w: World, id: string) =>
  withTenant(
    app,
    w.org,
    async (tx) =>
      (
        await tx
          .selectFrom(SPEND_REQUESTS.table)
          .select('mandate_version_id')
          .where('id', '=', id)
          .executeTakeFirstOrThrow()
      ).mandate_version_id,
  );

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
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger: logger(),
  });
});

describe('carrying a mandate’s pending requests over to its new version (E4c, decision 17)', () => {
  it('carries each one the new terms allow: the new version named, its status and holdings as they were', async () => {
    const { w, acting, mandateId } = await ready();
    const waiting = await ask(acting, w);
    const approved = await ask(acting, w, { amount: AED(50_000n) });
    expect([waiting.status, approved.status]).toEqual(['APPROVAL_REQUIRED', 'APPROVED']);
    const spent = await spentOf(w, acting);

    const { plan, versionId } = await carried(w, mandateId);

    expect(plan).toEqual([
      { id: waiting.id, outcome: 'carry', reasons: ['APPROVAL_THRESHOLD'] },
      { id: approved.id, outcome: 'carry', reasons: [] },
    ]);
    for (const [request, status] of [
      [waiting, 'APPROVAL_REQUIRED'],
      [approved, 'APPROVED'],
    ] as const) {
      expect(await statusOf(w, request.id)).toBe(status);
      expect(await versionOf(w, request.id)).toBe(versionId);
      expect(await holdingsOf(w, request.id)).toEqual({ reservation: 'HELD', released: false });
      const events = await shared.eventsAbout(w.org, request.id, SPEND_REQUESTS.subject);
      expect(events.at(-1)).toMatchObject({
        action: 'spend_request.carried',
        actorType: 'user',
        details: { mandateVersionId: versionId },
      });
    }
    expect(await spentOf(w, acting)).toBe(spent);
    const accepted = (await shared.eventsAbout(w.org, mandateId, 'mandate')).at(-1);
    expect(accepted).toMatchObject({
      action: 'mandate.accepted',
      details: { pendingRequests: 'carry', pendingStatementVersion: 2, carried: 2, cancelled: 0 },
    });
    // Whole under their new version: the holdings check, and the job finds nothing to void.
    const checked = await withSignedStates(app, w.org, shared.quiet(), (tx, states) =>
      checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }),
    );
    expect(checked).toMatchObject({ mismatched: 0, tampered: 0 });
    await createRequestVoids({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      clock,
      logger: logger(),
    }).run();
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect(await statusOf(w, approved.id)).toBe('APPROVED');
  });

  it('a carried waiting one is approved afterwards by its approver, under the new version (17.2)', async () => {
    const { w, acting, mandateId } = await ready();
    const waiting = await ask(acting, w);
    await carried(w, mandateId);
    const approvals = createSpendRequestApprovals({
      database: app,
      keys,
      ids,
      clock,
      challenges: createStepUpChallenges({ ids, clock }),
      logger: logger(),
    });

    const challengeId = askedFor(
      await approvals.ask(w.admin, keyed(w.admin, APPROVE_OPERATION), waiting.id, false, CORRELATION),
    );
    await stepUp(w.admin, challengeId);
    const done = await approvals.confirm(
      w.admin,
      keyed(w.admin, APPROVE_CONFIRM_OPERATION),
      waiting.id,
      challengeId,
      false,
      CORRELATION,
    );

    expect(done).toMatchObject({ outcome: 'approved', request: { status: 'APPROVED' } });
  });

  it('cancels one the new terms refuse, with their reasons, its holdings freed; carries the rest', async () => {
    const { w, acting, mandateId } = await ready();
    const over = await ask(acting, w);
    const underLimit = await ask(acting, w, { amount: AED(50_000n) });

    const { plan } = await carried(w, mandateId, {
      perOrderLimit: AED(150_000n),
      approvalThreshold: AED(100_000n),
    });

    expect(plan).toEqual([
      { id: over.id, outcome: 'cancel', reasons: ['MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'] },
      { id: underLimit.id, outcome: 'carry', reasons: [] },
    ]);
    expect(await statusOf(w, over.id)).toBe('DENIED');
    expect(await holdingsOf(w, over.id)).toEqual({ reservation: 'RELEASED', released: true });
    const events = await shared.eventsAbout(w.org, over.id, SPEND_REQUESTS.subject);
    expect(events.at(-1)).toMatchObject({
      action: 'spend_request.voided',
      details: { causes: 'MANDATE_ORDER_LIMIT,APPROVAL_THRESHOLD' },
    });
    expect(await statusOf(w, underLimit.id)).toBe('APPROVED');
  });

  it('keeps one a person approved where the new terms would ask an approval; cancels one approved without a person (17.1)', async () => {
    const { w, acting, mandateId } = await ready();
    const byAPerson = await ask(acting, w);
    await approvedByAPerson(w, byAPerson.id);
    const unasked = await ask(acting, w, { amount: AED(50_000n) });
    expect([await statusOf(w, byAPerson.id), unasked.status]).toEqual(['APPROVED', 'APPROVED']);

    // Approval now above AED 300: both would be sent for one.
    const { plan } = await carried(w, mandateId, { approvalThreshold: AED(30_000n) });

    expect(plan).toEqual([
      { id: byAPerson.id, outcome: 'carry', reasons: ['APPROVAL_THRESHOLD'] },
      { id: unasked.id, outcome: 'cancel', reasons: ['APPROVAL_THRESHOLD'] },
    ]);
    expect(await statusOf(w, byAPerson.id)).toBe('APPROVED');
    expect(await statusOf(w, unasked.id)).toBe('DENIED');
  });

  it('lets the oldest stand when a lowered monthly limit can’t hold them all', async () => {
    const { w, acting, mandateId } = await ready();
    // A minute apart, so the carry's order is when each was made.
    const first = await ask(acting, w, { amount: AED(50_000n) });
    clock.advanceBy(60_000);
    const second = await ask(acting, w, { amount: AED(50_000n) });
    clock.advanceBy(60_000);
    const third = await ask(acting, w, { amount: AED(50_000n) });

    const { plan } = await carried(w, mandateId, {
      perOrderLimit: AED(100_000n),
      monthlyLimit: AED(100_000n),
      approvalThreshold: AED(100_000n),
    });

    expect(plan?.map(({ id, outcome }) => [id, outcome])).toEqual([
      [first.id, 'carry'],
      [second.id, 'carry'],
      [third.id, 'cancel'],
    ]);
    expect(plan?.[2]?.reasons).toContain('MANDATE_MONTHLY_LIMIT');
    expect(await statusOf(w, third.id)).toBe('DENIED');
  });

  it('weighs a split once each, under a draft turning the split check on: the oldest stand, a later one over it is cancelled', async () => {
    const { w, acting, mandateId } = await ready();
    const first = await ask(acting, w, { amount: AED(60_000n) });
    const alone = await ask(acting, w, { amount: AED(60_000n), supplierId: w.suppliers[1] ?? '' });
    const second = await ask(acting, w, { amount: AED(60_000n) });
    expect([first.status, alone.status, second.status]).toEqual(['APPROVED', 'APPROVED', 'APPROVED']);

    const { plan } = await carried(w, mandateId, { splitCheck: true });

    // Each AED 600 alone is within the AED 1,000 threshold; with the first, the second to its supplier isn't.
    expect(plan).toEqual([
      { id: first.id, outcome: 'carry', reasons: [] },
      { id: alone.id, outcome: 'carry', reasons: [] },
      { id: second.id, outcome: 'cancel', reasons: ['AGGREGATE_THRESHOLD'] },
    ]);
  });

  it('lets an older order stand over a younger lookalike to its payee, which the same plan may cancel', async () => {
    const { w, acting, mandateId } = await ready();
    // The older one approved outright; the younger, a lookalike the bank would carry the same way, sent for approval.
    const older = await ask(acting, w, { amount: AED(50_000n), orderReference: 'PO-2026/0042' });
    clock.advanceBy(60_000);
    const younger = await ask(acting, w, { amount: AED(50_000n), orderReference: 'PO_2026/0042' });
    expect([older.status, younger.status]).toEqual(['APPROVED', 'APPROVAL_REQUIRED']);
    expect(younger.reasons).toContain('POSSIBLE_DUPLICATE_ORDER');

    const { plan } = await carried(w, mandateId);

    // The older is weighed before the younger, whose claim is the plan's own: it stays approved without a person.
    expect(plan?.[0]).toEqual({ id: older.id, outcome: 'carry', reasons: [] });
    expect(plan?.[1]).toMatchObject({ id: younger.id, outcome: 'carry' });
    expect(plan?.[1]?.reasons).toContain('POSSIBLE_DUPLICATE_ORDER');
  });

  it('answers a replayed ask with the plan worked out again, the same as the first (17.4)', async () => {
    const { w, acting, mandateId } = await ready();
    const waiting = await ask(acting, w);
    const { versionId } = await asking(w, mandateId, {}, 'cancel');
    const key = keyed(w.admin, ACCEPT_OPERATION, 'e4c-replayed');
    const first = await acceptance().accept(w.admin, key, mandateId, versionId, 'carry', CORRELATION);
    const replayed = await acceptance().accept(w.admin, key, mandateId, versionId, 'carry', CORRELATION);

    expect(replayed).toEqual(first);
    expect(replayed).toMatchObject({ carry: [{ id: waiting.id, outcome: 'carry' }] });
  });

  it('refuses a carry whose request’s holdings were changed past the app, nothing moved (INTEGRITY_FAILED)', async () => {
    const { w, acting, mandateId } = await ready();
    const waiting = await ask(acting, w);
    const { asked, versionId } = await asking(w, mandateId, {}, 'carry');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    await changedPastTheApp(database, w.org, waiting.id, 'amount halved');

    expect(await confirmed(w, mandateId, asked.stepUpChallengeId, 'carry')).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
    expect(await versionOf(w, waiting.id)).not.toBe(versionId);
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses to plan over a request whose signed state was changed past the app (INTEGRITY_FAILED)', async () => {
    const { w, acting, mandateId } = await ready();
    const bad = await ask(acting, w);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(bad.id);
    } finally {
      await owner.end();
    }

    const { asked } = await asking(w, mandateId, {}, 'carry');
    expect(asked).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('refuses the confirm when the plan changed since the ask: a request ended between (17.4)', async () => {
    const { w, acting, mandateId } = await ready();
    const kept = await ask(acting, w);
    const ended = await ask(acting, w, { amount: AED(50_000n) });
    const before = await versionOf(w, kept.id);
    const { asked, versionId } = await asking(w, mandateId, {}, 'carry');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    await signed(w, (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: ended.id },
        { kind: 'user', userId: w.admin.userId },
        clock.now(),
      ),
    );

    expect(await confirmed(w, mandateId, asked.stepUpChallengeId, 'carry')).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await statusOf(w, kept.id)).toBe('APPROVAL_REQUIRED');
    expect(await versionOf(w, kept.id)).toBe(before);
    expect(before).not.toBe(versionId);
  });

  it('queues behind an approval holding a request (forced), then carries it as approved: no deadlock', async () => {
    const { w, acting, mandateId } = await ready();
    const waiting = await ask(acting, w);
    const { asked, versionId } = await asking(w, mandateId, {}, 'carry');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    await stepUp(w.admin, asked.stepUpChallengeId);
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

    const accepting = within(
      20_000,
      acceptance().acceptConfirm(
        w.admin,
        keyed(w.admin, ACCEPT_CONFIRM_OPERATION),
        mandateId,
        asked.stepUpChallengeId,
        'carry',
        CORRELATION,
      ),
      'the acceptance',
    );
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    expect(await approving).toBe('approved');
    // Approved by a person, the new terms asking an approval as they did: still carried, as the plan showed.
    expect(await accepting).toMatchObject({ outcome: 'accepted' });
    expect(await statusOf(w, waiting.id)).toBe('APPROVED');
    expect(await versionOf(w, waiting.id)).toBe(versionId);
  });

  it('settles the oldest 20 at the confirm and leaves the rest, said in the ask and on the acceptance (PL-47)', async () => {
    const { w, acting, mandateId } = await ready();
    const pending = await askedInTurn(acting, w, 22);

    const { asked, versionId } = await asking(w, mandateId, {}, 'carry');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    expect(asked.carry?.map(({ id }) => id)).toEqual(pending.slice(0, 20).map(({ id }) => id));
    expect(asked.carryLater).toBe(2);
    expect(await confirmed(w, mandateId, asked.stepUpChallengeId, 'carry')).toMatchObject({ outcome: 'accepted' });

    for (const { id } of pending.slice(0, 20)) expect(await versionOf(w, id)).toBe(versionId);
    for (const { id } of pending.slice(20)) {
      expect(await statusOf(w, id)).toBe('APPROVED');
      expect(await versionOf(w, id)).not.toBe(versionId);
    }
    expect((await shared.eventsAbout(w.org, mandateId)).at(-1)).toMatchObject({
      action: 'mandate.accepted',
      details: expect.objectContaining({ carried: 20, cancelled: 0, carryRest: true, carryLater: 2 }) as unknown,
    });
    // Waiting their turn, the voids job leaves them be.
    await voids(w).run();
    for (const { id } of pending.slice(20)) expect(await statusOf(w, id)).toBe('APPROVED');
  });

  it('carries the rest within minutes as the confirm would have, oldest first, and the oldest stand (PL-47)', async () => {
    const { w, acting, mandateId } = await ready();
    const pending = await askedInTurn(acting, w, 23);

    // Room for 22 of them a month under the new terms: the youngest, the job's last, goes.
    const { plan, versionId } = await carried(w, mandateId, {
      perOrderLimit: AED(22_000n),
      monthlyLimit: AED(22_000n),
      approvalThreshold: AED(22_000n),
    });
    expect(plan?.every(({ outcome }) => outcome === 'carry')).toBe(true);
    await carryRest(w).run();

    for (const { id } of pending.slice(0, 22)) {
      expect(await statusOf(w, id)).toBe('APPROVED');
      expect(await versionOf(w, id)).toBe(versionId);
    }
    expect(await statusOf(w, pending[22]?.id ?? '')).toBe('DENIED');
    expect(capture.lines().filter(({ event }) => event === 'mandate_carry.carried')).toEqual([
      expect.objectContaining({ mandateId, carried: 2, cancelled: 1 }),
    ]);
    expect((await shared.eventsAbout(w.org, pending[20]?.id ?? '', SPEND_REQUESTS.subject)).at(-1)).toMatchObject({
      action: 'spend_request.carried',
      actorType: 'system',
      details: expect.objectContaining({ via: 'carry_rest', mandateVersionId: versionId }) as unknown,
    });
    // Nothing left: a second run carries nothing.
    capture = new LogCapture();
    await carryRest(w).run();
    expect(capture.lines().filter(({ event }) => event === 'mandate_carry.carried')).toEqual([]);
  });

  it('carries a first acceptance’s rest under a second one too: never cancelled unweighed (PL-47)', async () => {
    const { w, acting, mandateId } = await ready();
    const pending = await askedInTurn(acting, w, 21);
    await carried(w, mandateId);
    // Another version accepted, carrying again, before the job's turn came.
    const { asked, versionId } = await asking(w, mandateId, { purpose: 'Office supplies, third' }, 'carry');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    // Every pending request of the mandate is weighed, the first rest among them: the youngest waits again.
    expect(asked.carryLater).toBe(1);
    expect(await confirmed(w, mandateId, asked.stepUpChallengeId, 'carry')).toMatchObject({ outcome: 'accepted' });

    await voids(w).run();
    expect(await statusOf(w, pending[20]?.id ?? '')).toBe('APPROVED');
    await carryRest(w).run();

    for (const { id } of pending) expect(await versionOf(w, id)).toBe(versionId);
  });

  it('refuses the confirm when some came to wait for the job since the ask, though the 20 are the same', async () => {
    const { w, acting, mandateId } = await ready();
    await askedInTurn(acting, w, 20);
    const { asked } = await asking(w, mandateId, {}, 'carry');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    expect(asked.carryLater).toBe(0);
    await ask(acting, w, { amount: AED(1_000n), orderReference: 'TURN-LATE' });

    expect(await confirmed(w, mandateId, asked.stepUpChallengeId, 'carry')).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
  });

  it('leaves out one that ends while its turn waits for it (forced), carrying the rest: no integrity failure', async () => {
    const { w, acting, mandateId } = await ready();
    const pending = await askedInTurn(acting, w, 22);
    const { versionId } = await carried(w, mandateId);
    const ending = pending[20]?.id ?? '';
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const cancelling = signed(w, async (tx, states) => {
      const ended = await cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: ending },
        { kind: 'user', userId: w.admin.userId },
        clock.now(),
      );
      holding(undefined);
      await gate;
      return ended;
    });
    await held;

    const running = within(20_000, carryRest(w).run(), 'the carry job');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    await cancelling;
    await running;

    expect(await statusOf(w, ending)).toBe('CANCELLED');
    expect(await versionOf(w, pending[21]?.id ?? '')).toBe(versionId);
    expect(capture.lines().filter(({ event }) => event === 'mandate_carry.failed')).toEqual([]);
  });

  it('refuses to approve one waiting its turn: it is weighed under the version in force first', async () => {
    const { w, acting, mandateId } = await ready();
    await askedInTurn(acting, w, 20);
    const waiting = await ask(acting, w, { amount: AED(200_000n), orderReference: 'TURN-LAST' });
    await carried(w, mandateId);
    const approvals = createSpendRequestApprovals({
      database: app,
      keys,
      ids,
      clock,
      challenges: createStepUpChallenges({ ids, clock }),
      logger: logger(),
    });

    expect(await approvals.ask(w.admin, keyed(w.admin, APPROVE_OPERATION), waiting.id, false, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'REQUEST_CHANGED',
    });
  });

  it('leaves the rest to the voids job once the mandate is no longer in force', async () => {
    const { w, acting, mandateId } = await ready();
    const pending = await askedInTurn(acting, w, 21);
    await carried(w, mandateId);
    await shared.movedPastTheUseCase(w, mandateId, 'suspend');

    await carryRest(w).run();
    expect(await statusOf(w, pending[20]?.id ?? '')).toBe('APPROVED');
    await voids(w).run();
    expect(await statusOf(w, pending[20]?.id ?? '')).toBe('DENIED');
  });

  it('takes the rest 20 at a time, and waits while the agent is suspended with its requests paused', async () => {
    const { w, acting, mandateId } = await ready();
    const pending = await askedInTurn(acting, w, 43);
    const { versionId } = await carried(w, mandateId);
    await agentMoved(w, 'suspend');

    await carryRest(w).run();
    expect(await versionOf(w, pending[20]?.id ?? '')).not.toBe(versionId);
    await agentMoved(w, 'reactivate');
    await carryRest(w).run();

    for (const { id } of pending) expect(await versionOf(w, id)).toBe(versionId);
    expect(capture.lines().filter(({ event }) => event === 'mandate_carry.carried')).toEqual([
      expect.objectContaining({ mandateId, carried: 23, cancelled: 0 }),
    ]);
  });

  it('stops when told to, logs a list it can’t read and an organisation it can’t look in, and goes on', async () => {
    const { w, acting, mandateId } = await ready();
    const pending = await askedInTurn(acting, w, 21);
    const { versionId } = await carried(w, mandateId);
    const stopped = new AbortController();
    stopped.abort();
    await carryRest(w).run(stopped.signal);
    expect(await versionOf(w, pending[20]?.id ?? '')).not.toBe(versionId);

    await createCarryRest({
      list: () => Promise.reject(new Error('no directory')),
      database: app,
      keys,
      ids,
      clock,
      logger: logger(),
    }).run();
    await createCarryRest({
      list: () => Promise.resolve(['not-an-organisation', w.org]),
      database: app,
      keys,
      ids,
      clock,
      logger: logger(),
    }).run();

    expect(capture.lines().filter(({ event }) => event === 'mandate_carry.run_failed')).toHaveLength(1);
    expect(capture.lines().filter(({ event }) => event === 'mandate_carry.failed')).toHaveLength(1);
    expect(await versionOf(w, pending[20]?.id ?? '')).toBe(versionId);
  });

  it('cancel still accepts past 20, the rest voided, never carried (17.3)', async () => {
    const { w, acting, mandateId } = await ready();
    const pending = await askedInTurn(acting, w, 21);
    const { asked, versionId } = await asking(w, mandateId, {}, 'cancel');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    expect(asked.carryLater).toBe(0);
    expect(await confirmed(w, mandateId, asked.stepUpChallengeId, 'cancel')).toMatchObject({ outcome: 'accepted' });
    // The carry job's turn first: an acceptance that chose cancel leaves it nothing to carry.
    await carryRest(w).run();
    expect(await versionOf(w, pending[20]?.id ?? '')).not.toBe(versionId);
    await voids(w).run();
    for (const { id } of pending) expect(await statusOf(w, id)).toBe('DENIED');
  });
});

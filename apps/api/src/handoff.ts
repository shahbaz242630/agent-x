// The hand-off (Phase 4 B4; PRD §5.3, §6, §11; ADR-007 §6–§10, §14; ADR-014
// §1; BR-11–BR-14; partner decisions 1–3, S135; PL-46): every approved spend
// request handed to the partner as one logical policy-approved intent, once,
// after its authority is checked again at that moment. The API's job, on a
// timer of its own (decision 1: inside the API process on staging; a worker
// app of its own before live).
//
// The queue is the request's own status (decision 2: no "send" step): an
// APPROVED request is waiting to be handed off, committed with its approval
// or decision, so nothing is lost between the two (ADR-007 §6's outbox).
// Each run takes each organisation's approved requests, oldest first, a page
// at a time, each page after the last, so a page of requests left waiting
// never keeps a younger one from its turn; each in a transaction of its own:
//
// Tx A, in ADR-006 §6's lock order:
// 1. the platform hand-off pause, FOR SHARE (level 1): paused, or a row that
//    can't be believed, leaves the request waiting (ADR-007 §14, B1);
// 2. its authority now (`authorityOf`, the voids job's own read: the
//    organisation, agent, mandate, source and supplier, levels 2–6, each
//    stop's chosen pause or cancel): a cause the voids job would void it for
//    denies it now, as the voids job would (decision 3: a stop chosen to
//    cancel, a mandate replaced and not carried, the supplier's payee changed,
//    a source that can no longer fund); a stop chosen to pause, a freeze, a
//    mandate or agent not ACTIVE, a source or supplier not usable, or a carry
//    that hasn't reached it yet, leaves it waiting, re-checked on the next run
//    (PRD §5.3: on resume every waiting request is re-checked);
//    and its agent key (3a), named by its row and held to its signed state at
//    4: one ended at once since its approval (decision 22) denies it
//    (`AGENT_KEY_ENDED`); the payee from the supplier's verified version in
//    force (6), never the request's: one without a payee leaves it waiting,
//    and one other than the version it was approved under denies it
//    (`SUPPLIER_CHANGED`: never paid to a payee no one approved);
// 4. the request itself, for change (8): APPROVED (or INSTRUCTION_READY), moved
//    to INSTRUCTION_READY then HANDED_OFF; any other status (cancelled, denied,
//    handed off by another run) leaves it be: a duplicate run hands off nothing;
// 5. the organisation's integrity hold, at the head (12): held leaves it
//    waiting (ADR-012 §2: a hold stops hand-offs as a freeze does);
// 6. its one instruction and transaction, new rows at level 10 after the
//    head: the one step past the order, which can't wait on anyone, as no one
//    else holds a row that isn't there yet and their parents are locked above
//    (ADR-006's rule is about rows two transactions both reach); the payee's
//    reference as read, the consent from the verified source, the rail's
//    payment reference from the order reference (`bankReferenceOf`), the
//    partner's identity copied for evidence; the table's key refuses a second
//    one for the request (SEC-DP-01).
//
// The partner is called only after Tx A committed, by the run that knows it
// did (ADR-007 §8), our instruction ID its idempotency key. Tx B records what
// it answered (ADR-007 §9): accepted (SUBMITTED, then the rail's state now:
// under way, credited, failed with proof, or unknown); refused with proof that
// nothing was made (FAILED); no answer that can be known (UNKNOWN: never
// resent, ADR-007 §10); the call is given PARTNER_CALL_TIMEOUT_MS, and no
// answer by then is one that can't be known. An accepted or unknowable
// answer that comes once the transaction has moved on is kept as its facts
// (B3), never a move; a refusal still settles it FAILED, its reject code the
// proof nothing was made (ADR-007 §9, §11). A run
// that dies between the two leaves the transaction SUBMISSION_PENDING: a run
// a minute marks one left so past UNKNOWN_AFTER_MS UNKNOWN (Phase 4 B5), for
// reconciliation to settle with the partner, never resent; the wait is
// refused at start unless it is longer than the call may take (ADR-007 §10).
// Each run's heartbeat is read by /health (ADR-013): a stale one says the
// hand-off has stopped.
// A handed-off request is never voided after: it is tracked to its outcome
// (PL-46, the in-flight rule). Its reservation and order claim follow its
// payment (Phase 4 C3, the outcomes module): Tx B and the sweep read the
// transaction for change (10), lock both (11), move it (the head, 12), then
// settle them as it now stands: spent on success, blocked while unknown,
// given back after a verified failure, held while under way.
//
// A run never throws: each failure is logged, naming the organisation and
// request, and the run goes on to the next.
import {
  type AuditTables,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import { instructionOf, type InstructionsTables, makeInstruction } from '@agentx/core/modules/instructions';
import { lockHoldingsOf, settleHoldings } from '@agentx/core/modules/outcomes';
import { handoffPauseOf, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import {
  type ApprovedPaymentIntent,
  type FinancialRailAdapter,
  type PaymentExecution,
  paymentStateOf,
  RailUnavailable,
} from '@agentx/core/modules/providers';
import {
  bankReferenceOf,
  decidedAgainst,
  requestOf,
  SPEND_REQUESTS,
  voidedWith,
  voidRequest,
} from '@agentx/core/modules/spend-requests';
import { versionOf } from '@agentx/core/modules/suppliers';
import {
  moveTransaction,
  openTransaction,
  TRANSACTIONS,
  transactionOf,
  type ProviderFacts,
  type TransactionEvent,
  type TransactionStatus,
  type TransactionsTables,
} from '@agentx/core/modules/transactions';
import { mayFund } from '@agentx/core/modules/funding-sources';
import type { Notice, NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { HealthCheck } from './health.ts';
import { type AuthorityRead, authorityOf, type VoidTables } from './request-voids.ts';

/** How often the approved requests are looked for, once the last run has ended: handed off within this. */
export const HANDOFF_EVERY_MS = 10_000;

/** How long the partner has to answer a hand-off (ADR-007 §8): past it the answer can't be known, and is never resent. */
const PARTNER_CALL_TIMEOUT_MS = 30_000;

/** How long a transaction may wait for its answer before it is marked UNKNOWN (ADR-007 §10): far past the call's limit. */
const UNKNOWN_AFTER_MS = 10 * 60_000;

/** How old the hand-off's heartbeat may grow before /health says it has stopped (ADR-013): many runs' worth. */
export const HEARTBEAT_STALE_MS = 5 * 60_000;

/** How often a run sweeps for transactions left waiting: often enough for UNKNOWN_AFTER_MS, few database calls. */
const SWEEP_EVERY_MS = 60_000;

/** How many of an organisation's approved requests are read at once: the run then takes the next page after them. */
const HANDOFF_PAGE = 50;

/**
 * The statuses a request is handed off from. This job never commits one
 * INSTRUCTION_READY (both moves are in one Tx A); it takes one left there all
 * the same, so a request moved there by anything else is never stranded.
 */
const HANDED_FROM = ['APPROVED', 'INSTRUCTION_READY'] as const;

/** The route the Pilot takes (BR-12: one partner rail, a push payment), and why, as the instruction keeps it. */
const ROUTE = { route: 'push', reason: 'mandate_source_push_rail' } as const;

/** The API, as the hand-off's actor in the signed events. */
const ACTOR = { type: 'system', id: 'api' } as const;

type HandoffTables = VoidTables &
  PlatformControlsTables &
  InstructionsTables &
  TransactionsTables &
  AuditTables &
  NotificationsTables;

/**
 * The notice that an approved request was stopped at its hand-off (0059,
 * Phase 4 B4b; partner decision 3: what the hand-off's re-check finds): to
 * every admin, found as it is sent, written in the transaction that denied
 * it. The voids job and the brakes tell as they did (the mandate expired,
 * the supplier's details changed, the organisation frozen each has its own
 * notice); a key ended at once and a payee changed are found only here.
 */
const stoppedNotice = (orgId: string, requestId: string): Notice[] => [
  { orgId, recipientUserId: null, kind: 'spend_request_stopped', membershipId: null, role: null, aboutId: requestId },
];
type HandoffTx = DatabaseTransaction<HandoffTables>;

/** What Tx A came to: the intent handed off with its transaction's ID; or left as it is, and why. */
type TxA =
  | { readonly outcome: 'handed_off'; readonly intent: ApprovedPaymentIntent; readonly transactionId: string }
  | { readonly outcome: 'denied'; readonly causes: string }
  | { readonly outcome: 'waiting'; readonly why: string }
  | { readonly outcome: 'not_approved' };

/**
 * What a standing request still waits for, comma-joined, or '' for nothing: a
 * stop chosen to pause (the voids job's own read leaves it standing), or a
 * carry that hasn't reached it yet (decision 3); each re-checked next run.
 */
function waitingFor({ named, authority, source, supplier }: Omit<AuthorityRead, 'agentKey'>, now: Date): string {
  return [
    authority.organizationStatus !== 'ACTIVE' && 'organization',
    authority.agentStatus !== 'ACTIVE' && 'agent',
    authority.mandate?.status !== 'ACTIVE' && 'mandate',
    named.mandateVersionId !== authority.mandate?.currentVersionId && 'carry',
    !mayFund(source, now) && 'source',
    supplier.status !== 'VERIFIED' && 'supplier',
  ]
    .filter((why) => why !== false)
    .join(',');
}

/** The partner's answer as a transaction's facts (PRD §6.2), its own words kept. */
const factsOf = (execution: PaymentExecution): ProviderFacts => ({
  providerStatus: execution.providerStatus,
  paymentInstructionRef: execution.paymentInstructionRef,
  rejectCode: execution.rejectCode,
  providerChangedAt: execution.statusChangedAt,
});

/** The move after SUBMITTED that the rail's state now asks for (rail map §4). */
const AFTER_SUBMITTED: Readonly<Record<ReturnType<typeof paymentStateOf>, TransactionEvent>> = {
  PROCESSING: 'processing',
  SUCCEEDED: 'succeed',
  FAILED: 'fail',
  UNKNOWN: 'lose_track',
};

export interface Handoff {
  /**
   * Hands off each organisation's approved requests that may go, a page at a
   * time, and marks its transactions left waiting past UNKNOWN_AFTER_MS
   * UNKNOWN, until the signal is aborted. Never throws.
   */
  run(signal?: AbortSignal): Promise<void>;
  /** Whether a run has beaten within HEARTBEAT_STALE_MS: /health's check (ADR-013). */
  beating(): boolean;
}

/** The partner gave no answer within its time: one that can't be known (ADR-007 §8). */
class PartnerTimedOut extends Error {
  constructor() {
    super("The partner didn't answer the hand-off in time");
    this.name = 'PartnerTimedOut';
  }
}

/** The partner's answer, or PartnerTimedOut once `ms` pass; a late answer is left unread (Promise.race keeps hold of it). */
async function withinTime<T>(answer: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new PartnerTimedOut());
    }, ms);
  });
  try {
    return await Promise.race([answer, late]);
  } finally {
    clearTimeout(timer);
  }
}

export function createHandoff({
  list,
  database,
  rail,
  outbox,
  keys,
  ids,
  clock,
  logger,
  page = HANDOFF_PAGE,
  callTimeoutMs = PARTNER_CALL_TIMEOUT_MS,
  unknownAfterMs = UNKNOWN_AFTER_MS,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<HandoffTables>;
  readonly rail: FinancialRailAdapter;
  /** Where a denial is written for the admins: an approved payment stopped before the bank (B4b, decision 3). */
  readonly outbox: Outbox;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** How many of an organisation's requests are read at once (HANDOFF_PAGE unless a test names fewer). */
  readonly page?: number;
  /** How long the partner is given (PARTNER_CALL_TIMEOUT_MS unless a test names less). */
  readonly callTimeoutMs?: number;
  /** How long a transaction waits for its answer before UNKNOWN (UNKNOWN_AFTER_MS unless a test names less). */
  readonly unknownAfterMs?: number;
}): Handoff {
  // Refused at start (ADR-007 §10): a wait no longer than the call could mark UNKNOWN one whose answer is on its way.
  if (unknownAfterMs <= callTimeoutMs) {
    throw new RangeError("A transaction's wait for its answer must be longer than the partner's call may take");
  }
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });
  // Its first beat is its start, so /health gives a new process HEARTBEAT_STALE_MS to make its first run; after that
  // only a run that reads its organisations beats, so one failing every time reads as stopped.
  let beat = clock.now().getTime();
  let sweptAt = Number.NEGATIVE_INFINITY;
  const beatNow = (): void => {
    beat = clock.now().getTime();
  };

  /** A page of the organisation's approved requests after `after`, oldest first, by their rows, unverified: each read through its signed state in Tx A. */
  const approvedOf = (orgId: string, after: string | undefined, log: Logger): Promise<string[]> =>
    withSignedStates(database, orgId, services(log), async (tx) =>
      (
        await tx
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state before anything moves
          .selectFrom(SPEND_REQUESTS.table)
          .select('id')
          .where('org_id', '=', orgId)
          .where('status', 'in', HANDED_FROM)
          .where((where) => (after === undefined ? where.lit(true) : where('id', '>', after)))
          .orderBy('id')
          .limit(page)
          .execute()
      ).map(({ id }) => id),
    );

  /** Tx A for one request, in the lock order above; a denial tells the admins in it (decision 3). */
  const txA = async (tx: HandoffTx, states: SignedStates, orgId: string, id: string, log: Logger): Promise<TxA> => {
    const done = await judgedA(tx, states, orgId, id, log);
    if (done.outcome === 'denied') await outbox.add(tx, stoppedNotice(orgId, id));
    return done;
  };

  /** Tx A's checks and moves for one request, in the lock order above. */
  const judgedA = async (tx: HandoffTx, states: SignedStates, orgId: string, id: string, log: Logger): Promise<TxA> => {
    const key = { orgId, id };
    const pause = await handoffPauseOf(tx, 'share', { keys, logger: log });
    if (pause.outcome !== 'running') return { outcome: 'waiting', why: `pause_${pause.outcome}` };
    const now = clock.now();
    const { named, authority, source, supplier, agentKey } = await authorityOf(tx, states, key, now);
    if (agentKey.outcome !== 'found') throw new Error(`A request's agent key can't be believed: ${id}`);
    // The payee as the supplier's verified version in force names it: one carried through a details change chosen to
    // pause (E3) has the same payee, so this is never the request's own, and never an agent's (PRD §6).
    const version = await versionOf(tx, states, { orgId, id: supplier.currentVersionId }, supplier.id);
    const approvedUnder =
      named.supplierVersionId === null
        ? ({ outcome: 'missing' } as const)
        : await versionOf(tx, states, { orgId, id: named.supplierVersionId }, supplier.id);
    // A cause the voids job would void it for: denied now, its holdings freed, as that job would (decision 3).
    const voided = await voidRequest(tx, states, keys, key, { named, authority }, now);
    if (voided.outcome === 'voided') return { outcome: 'denied', causes: voided.causes.join(',') };
    if (voided.outcome !== 'standing') return { outcome: 'not_approved' };
    const waiting = waitingFor({ named, authority, source, supplier }, now);
    if (waiting !== '') return { outcome: 'waiting', why: waiting };
    const read = await requestOf(tx, states, key, 'change');
    if (read.outcome !== 'found') throw new Error(`A request judged standing can't be read: ${id}`);
    const { request } = read;
    // The key and version read at their levels are those its signed state names, never only its row's.
    const against = decidedAgainst(read.state);
    if (against.agentKeyId !== named.agentKeyId || against.supplierVersionId !== named.supplierVersionId) {
      throw new Error(`A request's row names a key or supplier version its signed state doesn't: ${id}`);
    }
    // A key ended at once since its approval (decision 22): never handed off on authority since withdrawn.
    if (agentKey.key.status === 'REVOKED') {
      await voidedWith(tx, states, keys, key, ['AGENT_KEY_ENDED'], now);
      return { outcome: 'denied', causes: 'AGENT_KEY_ENDED' };
    }
    if (version.outcome !== 'found' || version.version.beneficiaryRef === null) {
      return { outcome: 'waiting', why: 'payee' };
    }
    // Paid only to the payee it was approved under: a version carried since (E3) keeps it, any other change denies.
    if (approvedUnder.outcome !== 'found' || approvedUnder.version.beneficiaryRef !== version.version.beneficiaryRef) {
      await voidedWith(tx, states, keys, key, ['SUPPLIER_CHANGED'], now);
      return { outcome: 'denied', causes: 'SUPPLIER_CHANGED' };
    }
    const hold = await states.integrityHold(tx, orgId, 'head');
    if (hold.outcome !== 'clear') return { outcome: 'waiting', why: `hold_${hold.outcome}` };
    if (request.status === 'APPROVED') await moveRequest(tx, states, key, 'make_ready');
    await moveRequest(tx, states, key, 'hand_off');
    const intent: ApprovedPaymentIntent = {
      organizationId: orgId,
      instructionId: ids.next(),
      accountConsentId: source.accountConsentId,
      beneficiaryRef: version.version.beneficiaryRef,
      amountMinor: request.amount.minor,
      currency: request.amount.currency,
      paymentReference: bankReferenceOf(request.orderReference, request.id),
    };
    const { identity } = rail;
    await makeInstruction(
      tx,
      states,
      {
        orgId,
        id: intent.instructionId,
        spendRequestId: id,
        route: ROUTE.route,
        routeReason: ROUTE.reason,
        fundingSourceId: request.fundingSourceId,
        partner: identity.partner,
        partnerLegalEntityId: identity.legalEntityId,
        partnerLicenceRef: identity.licenceRef,
        accountConsentId: intent.accountConsentId,
        beneficiaryRef: intent.beneficiaryRef,
        supplierVersionId: version.version.id,
        amountMinor: intent.amountMinor,
        currency: intent.currency,
        paymentReference: intent.paymentReference,
        createdAt: now,
      },
      { actor: ACTOR, details: {} },
    );
    const transactionId = ids.next();
    await openTransaction(
      tx,
      states,
      { orgId, id: transactionId, instructionId: intent.instructionId, createdAt: now },
      { actor: ACTOR, details: {} },
    );
    return { outcome: 'handed_off', intent, transactionId };
  };

  /**
   * Tx B: the partner's answer recorded on the transaction (ADR-007 §9):
   * `recorded`, or `late` when it had moved on meanwhile (marked UNKNOWN by a
   * run's sweep): the answer then kept as its facts, never a move (B3,
   * ADR-007 §9). A refusal moves even an UNKNOWN one to FAILED: its reject
   * code is the proof (§11). Throws for a transaction that can't be believed.
   */
  const txB = (
    orgId: string,
    requestId: string,
    transactionId: string,
    answer: Answer,
    log: Logger,
  ): Promise<'recorded' | 'late'> =>
    withSignedStates(database, orgId, services(log), async (tx, states) => {
      const key = { orgId, id: transactionId };
      await lockedHoldings(tx, states, key, requestId);
      /** The status it moved to, or null where its machine refused the move. */
      const move = async (
        event: TransactionEvent,
        facts: ProviderFacts,
        via: string,
      ): Promise<TransactionStatus | null> => {
        const moved = await moveTransaction(tx, states, key, event, facts, { actor: ACTOR, details: { via } });
        // Tampered (its alarm raised): the answer isn't on the record, so not "handed off".
        if (moved.outcome !== 'moved' && moved.outcome !== 'refused') {
          throw new Error(`A transaction didn't move by ${event}: ${moved.outcome}`);
        }
        return moved.outcome === 'moved' ? moved.to : null;
      };
      const settled = async (status: TransactionStatus | null): Promise<'recorded' | 'late'> => {
        if (status === null) return 'late';
        await settleHoldings(tx, { requestId, status, at: clock.now() });
        return 'recorded';
      };
      if (answer.kind === 'unknown') return settled(await move('lose_track', NO_FACTS, 'no_answer'));
      if (answer.kind === 'refused')
        return settled(await move('fail', { ...NO_FACTS, rejectCode: answer.code }, 'refused'));
      const facts = factsOf(answer.execution);
      const submitted = await move('submitted', facts, 'accepted');
      if (submitted === null) return 'late';
      return settled((await move(AFTER_SUBMITTED[paymentStateOf(answer.execution)], facts, 'accepted')) ?? submitted);
    });

  /**
   * The transaction read for change (10), then its request's reservation and
   * claim locked (11), before a move takes the head (12); throws for a
   * transaction that can't be believed (its alarm raised), or one not its request's.
   */
  const lockedHoldings = async (
    tx: HandoffTx,
    states: SignedStates,
    key: { readonly orgId: string; readonly id: string },
    requestId: string,
  ): Promise<TransactionStatus> => {
    const read = await transactionOf(tx, states, key, 'change');
    if (read.outcome !== 'found') throw new Error(`A handed-off transaction can't be believed: ${key.id}`);
    const instruction = await instructionOf(tx, states, { orgId: key.orgId, id: read.transaction.instructionId });
    if (instruction.outcome !== 'found' || instruction.instruction.spendRequestId !== requestId.toLowerCase()) {
      throw new Error(`A handed-off transaction's instruction can't be believed: ${key.id}`);
    }
    await lockHoldingsOf(tx, requestId);
    return read.transaction.status;
  };

  /** The partner's answer to the intent, within its time; any it can't give is `unknown` (never resent). */
  const answerOf = async (intent: ApprovedPaymentIntent, id: string, log: Logger): Promise<Answer> => {
    try {
      const submitted = await withinTime(rail.submitApprovedIntent(intent), callTimeoutMs);
      return submitted.kind === 'accepted' ? submitted : { kind: 'refused', code: submitted.code };
    } catch (error) {
      if (error instanceof PartnerTimedOut) log.warn('handoff.partner_timeout', { requestId: id });
      else if (!(error instanceof RailUnavailable)) log.error('handoff.partner_failed', { requestId: id, err: error });
      return { kind: 'unknown' };
    }
  };

  /** One request handed off if it may go, its outcome logged. */
  const handOff = async (orgId: string, id: string, log: Logger): Promise<void> => {
    beatNow();
    let done: TxA;
    try {
      done = await withSignedStates(database, orgId, services(log), (tx, states) => txA(tx, states, orgId, id, log));
    } catch (error) {
      // Tx A's outcome unclear (a commit lost with the connection) or a bug: the partner is never called.
      log.error('handoff.failed', { requestId: id, err: error });
      return;
    }
    if (done.outcome === 'denied') log.info('handoff.denied', { requestId: id, causes: done.causes });
    if (done.outcome === 'waiting') log.info('handoff.waiting', { requestId: id, why: done.why });
    if (done.outcome !== 'handed_off') return;
    const { intent, transactionId } = done;
    const answer = await answerOf(intent, id, log);
    try {
      const recorded = await txB(orgId, id, transactionId, answer, log);
      log.info('handoff.handed_off', {
        requestId: id,
        instructionId: intent.instructionId,
        answer: answer.kind,
        recorded,
      });
    } catch (error) {
      // The answer is lost to the record, not the partner's: the transaction stays SUBMISSION_PENDING for the sweep.
      log.error('handoff.answer_unrecorded', { requestId: id, instructionId: intent.instructionId, err: error });
    }
  };

  /** The organisation's approved requests handed off, a page at a time; false if the signal stopped the run. */
  const handOffAll = async (orgId: string, log: Logger, signal: AbortSignal | undefined): Promise<boolean> => {
    let after: string | undefined;
    for (;;) {
      let approved: string[];
      try {
        approved = await approvedOf(orgId, after, log);
      } catch (error) {
        log.error('handoff.failed', { err: error });
        return true;
      }
      for (const id of approved) {
        if (signal?.aborted === true) return false;
        await handOff(orgId, id, log);
      }
      if (approved.length < page) return true;
      after = approved.at(-1);
    }
  };

  /**
   * A page of the organisation's transactions waiting for their answer since
   * before `before`, each with its request's ID through its instruction (none
   * where that is gone: the transaction then can't be believed, and is logged),
   * by their rows, unverified (each then read through its signed state).
   */
  const waitingSince = (
    orgId: string,
    before: Date,
    log: Logger,
  ): Promise<{ readonly id: string; readonly requestId: string | null }[]> =>
    withSignedStates(database, orgId, services(log), (tx) =>
      tx
        // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state before it moves
        .selectFrom(`${TRANSACTIONS.table} as t`)
        // eslint-disable-next-line agentx/authority-tables-through-signed-state -- its request's ID alone, read again through its signed instruction before anything moves
        .leftJoin('instructions.instructions as i', (join) =>
          join.onRef('i.org_id', '=', 't.org_id').onRef('i.id', '=', 't.instruction_id'),
        )
        .select(['t.id as id', 'i.spend_request_id as requestId'])
        .where('t.org_id', '=', orgId)
        .where('t.status', '=', 'SUBMISSION_PENDING')
        .where('t.created_at', '<=', before)
        .orderBy('t.id')
        .limit(page)
        .execute(),
    );

  /**
   * The organisation's transactions left waiting for their answer past
   * unknownAfterMs marked UNKNOWN, a page a run (ADR-007 §10): each read for
   * change, and moved only if it is still waiting then, so one Tx B recorded
   * meanwhile is never undone. Never resent; reconciliation settles them.
   */
  const sweepIn = async (orgId: string, log: Logger): Promise<void> => {
    let waiting: { readonly id: string; readonly requestId: string | null }[];
    try {
      waiting = await waitingSince(orgId, new Date(clock.now().getTime() - unknownAfterMs), log);
    } catch (error) {
      log.error('handoff.sweep_failed', { err: error });
      return;
    }
    for (const transaction of waiting) {
      beatNow();
      try {
        const marked = await withSignedStates(database, orgId, services(log), async (tx, states) => {
          const key = { orgId, id: transaction.id };
          // A transaction with no instruction is refused by lockedHoldings before anything is locked.
          const requestId = transaction.requestId ?? '';
          if ((await lockedHoldings(tx, states, key, requestId)) !== 'SUBMISSION_PENDING') return false;
          const moved = await moveTransaction(tx, states, key, 'lose_track', NO_FACTS, {
            actor: ACTOR,
            details: { via: 'no_answer_in_time' },
          });
          // Read as waiting under this lock, so anything but a move is a tampered row (its alarm raised).
          if (moved.outcome !== 'moved') throw new Error(`A waiting transaction didn't lose track: ${moved.outcome}`);
          await settleHoldings(tx, { requestId, status: moved.to, at: clock.now() });
          return true;
        });
        if (marked) log.warn('handoff.marked_unknown', { transactionId: transaction.id });
      } catch (error) {
        log.error('handoff.sweep_failed', { transactionId: transaction.id, err: error });
      }
    }
  };

  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.error('handoff.run_failed', { err: error });
        return;
      }
      beatNow();
      const sweeping = clock.now().getTime() - sweptAt >= SWEEP_EVERY_MS;
      if (sweeping) sweptAt = clock.now().getTime();
      for (const orgId of orgs) {
        // Stopped between organisations too, so the process stops promptly however many there are.
        if (signal?.aborted === true) return;
        const log = logger.child({ orgId });
        if (!(await handOffAll(orgId, log, signal))) return;
        if (sweeping) await sweepIn(orgId, log);
      }
      beatNow();
    },
    beating: () => clock.now().getTime() - beat <= HEARTBEAT_STALE_MS,
  };
}

/** /health's checks for the hand-off (ADR-013): its heartbeat, where there is one. */
export const heartbeatChecks = (handoff: Handoff | undefined): HealthCheck[] =>
  handoff === undefined ? [] : [{ name: 'handoff_heartbeat', check: () => Promise.resolve(handoff.beating()) }];

/** What the partner answered, as Tx B records it. */
type Answer =
  | { readonly kind: 'accepted'; readonly execution: PaymentExecution }
  | { readonly kind: 'refused'; readonly code: string }
  | { readonly kind: 'unknown' };

const NO_FACTS: ProviderFacts = {
  providerStatus: null,
  paymentInstructionRef: null,
  rejectCode: null,
  providerChangedAt: null,
};

/** A request's move by its machine, signed, from its state read for change in this transaction. */
async function moveRequest(
  tx: HandoffTx,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  event: 'make_ready' | 'hand_off',
): Promise<void> {
  const moved = await states.changeStatus(tx, SPEND_REQUESTS, key, event, {
    actor: ACTOR,
    action: event === 'make_ready' ? 'spend_request.made_ready' : 'spend_request.handed_off',
    details: {},
  });
  if (moved.outcome !== 'changed')
    throw new Error(`A request read for its hand-off didn't move: ${key.id} (${moved.outcome})`);
}

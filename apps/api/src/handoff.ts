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
// Each run takes the organisations' approved requests in turns (fair-lanes.ts:
// one an organisation a pass), each organisation's oldest first, a page at a
// time, each page after the last and the place kept between runs, so a page of
// requests left waiting never keeps a younger one from its turn; a reason that
// is the whole organisation's ends its turn. Up to 24 at once, 4 an organisation,
// in this order: a bank slot, the database gate (2 at once), Tx A's commit, the
// gate let go, the bank's call, the gate again, ahead of any new Tx A, Tx B,
// both let go. A run starts new work for 30 s, then waits for what it started.
// A stop leaves up to 24 SUBMISSION_PENDING, as a crash would; the bank check
// settles them. No SKIP LOCKED: the page takes no locks, one copy of this job
// runs, and skipping at Tx A would break ADR-006's order; what keeps a request
// safe is Tx A's locks and compare-and-set, and `one_instruction_a_request`.
// Each in a transaction of its own:
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
// given back after a verified failure, held while under way. A payment that
// SUCCEEDED queues its supplier's remittance email in the same transaction
// (Phase 4 C2b, partner decision 34a): the setting and the address are read
// as it is sent, after this, never here, out of the lock order.
//
// A run never throws: each failure is logged, naming the organisation and
// request, and the run goes on to the next. The platform pause is read once a
// run first: while it holds every hand-off, no request is read (gate H5; Tx A
// still reads it under its lock). A request left waiting is said once a
// reason, not every run; the sweep takes every page of those past their wait.
import {
  type AuditTables,
  createAuditTrail,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import { type InstructionsTables, makeInstruction } from '@agentx/core/modules/instructions';
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
  type ProviderFacts,
  type TransactionEvent,
  type TransactionStatus,
  type TransactionsTables,
} from '@agentx/core/modules/transactions';
import { mayFund } from '@agentx/core/modules/funding-sources';
import {
  AFTER_SUBMITTED,
  answerAbout,
  factsOf,
  lockPayment,
  moveDetails,
  NO_FACTS,
  settlePayment,
} from '@agentx/core/modules/outcomes';
import type { Notice, NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { AnchorStore } from '@agentx/platform/audit-chain';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { finishedWithinStop } from './background.ts';
import { createFairLanes, createGate, type Gate, isOrganisationWide, type LaneStep } from './fair-lanes.ts';
import { alertAdmins } from './payment-alerts.ts';
import type { RailEntry, RailHealth, RailHold } from './rail-health.ts';
import { type AuthorityRead, authorityOf, type VoidTables } from './request-voids.ts';

/** The statuses a late refusal goes back on: the bank's word read as under way, or paid (decision 37b). */
const UNDER_WAY_OR_PAID: ReadonlySet<TransactionStatus> = new Set(['SUBMITTED', 'PROCESSING', 'SUCCEEDED']);

/** How often the approved requests are looked for, once the last run has ended: handed off within this. */
export const HANDOFF_EVERY_MS = 10_000;

/** How long the partner has to answer a hand-off (ADR-007 §8): past it the answer can't be known, and is never resent. */
export const PARTNER_CALL_TIMEOUT_MS = 30_000;

/** How long a transaction may wait for its answer before it is marked UNKNOWN (ADR-007 §10): far past the call's limit. */
const UNKNOWN_AFTER_MS = 10 * 60_000;

/** How old the hand-off's heartbeat may grow before /health says it has stopped (ADR-013): many runs' worth. */
export const HEARTBEAT_STALE_MS = 5 * 60_000;

/** How often a run sweeps for transactions left waiting: often enough for UNKNOWN_AFTER_MS, few database calls. */
const SWEEP_EVERY_MS = 60_000;

/** How many of an organisation's approved requests are read at once: the run then takes the next page after them. */
const HANDOFF_PAGE = 50;

/**
 * How many bank calls are under way at once, across every organisation and in
 * each (4D2e Stage F): a bank hung at 30 s takes 48 a minute against one at a
 * time's 2; a hung organisation holds 1/6. First numbers; Stage G measures.
 */
const HANDOFF_LIMITS = { total: 24, perOrganisation: 4 } as const;

/** The hand-off's transactions at once: the database, not the bank, is the ceiling. At most a third of the pool (refused at start). */
const DATABASE_GATE = 2;

/** How long a run starts new work for: about 40 s at worst, with the last calls' answers. */
export const RUN_BUDGET_MS = 30_000;

/**
 * How long a stop waits for calls under way: well inside the API's own stop deadline (25 s), which a hung bank's 30 s
 * would pass, losing the log's flush. Those left stay SUBMISSION_PENDING, as after a crash: the bank check settles them.
 */
export const STOP_WAIT_MS = 15_000;

/** First anchors made at once: each may take 120 s on a long chain, and holds no bank slot while it does. */
const ANCHOR_GATE = 2;

/**
 * The statuses a request is handed off from. This job never commits one
 * INSTRUCTION_READY (both moves are in one Tx A); it takes one left there all
 * the same, so a request moved there by anything else is never stranded.
 */
const HANDED_FROM = ['APPROVED', 'INSTRUCTION_READY'] as const;

/**
 * How long an approved request may stand, not handed off and waiting for no
 * reason the run knows, before it is said (gate H8, the queue-age alert): a
 * run every 10 s hands one off within seconds, so this is a run that never
 * reaches it, or one failing every time.
 */
export const QUEUE_STALE_MS = 15 * 60_000;
const STALE_READ_EVERY_MS = 60_000;

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

/** What the check before Tx A came to: Tx A's, with its breaker's place if sent; or never begun, and why. */
type Cleared =
  | Exclude<TxA, { outcome: 'handed_off' }>
  | (Extract<TxA, { outcome: 'handed_off' }> & { readonly settle: Extract<RailEntry, { settle: unknown }>['settle'] })
  | { readonly outcome: 'held'; readonly hold: RailHold; readonly outage: number }
  | { readonly outcome: 'stopped' };

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
export class PartnerTimedOut extends Error {
  constructor() {
    super("The partner didn't answer the hand-off in time");
    this.name = 'PartnerTimedOut';
  }
}

/** The partner's answer, or PartnerTimedOut once `ms` pass; a late answer is left unread (Promise.race keeps hold of it). */
export async function withinTime<T>(answer: Promise<T>, ms: number): Promise<T> {
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

/**
 * The gate the hand-off and the bank check share, made once for the process. Refused
 * at start where it would take over a third of the pool: past it, these jobs
 * could keep agents' decisions from their connections.
 */
export function handoffDatabaseGate(poolMax: number): Gate {
  if (DATABASE_GATE > Math.floor(poolMax / 3)) {
    throw new RangeError(`The hand-off's ${String(DATABASE_GATE)} transactions at once need a pool of at least 6`);
  }
  return createGate(DATABASE_GATE);
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
  health,
  page = HANDOFF_PAGE,
  callTimeoutMs = PARTNER_CALL_TIMEOUT_MS,
  unknownAfterMs = UNKNOWN_AFTER_MS,
  limits = HANDOFF_LIMITS,
  runBudgetMs = RUN_BUDGET_MS,
  databaseGate,
  stopWaitMs = STOP_WAIT_MS,
  anchoring,
}: {
  /** The organisations to look in: the directory's list, which job-list.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<HandoffTables>;
  readonly rail: FinancialRailAdapter;
  /** Where a denial is written for the admins: an approved payment stopped before the bank (B4b, decision 3). */
  readonly outbox: Outbox;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** The bank breaker (rail-health.ts), shared with what reopens it: job-list.ts gives the bank check the same one. */
  readonly health: RailHealth;
  /** How many of an organisation's requests are read at once (HANDOFF_PAGE unless a test names fewer). */
  readonly page?: number;
  /** How long the partner is given (PARTNER_CALL_TIMEOUT_MS unless a test names less). */
  readonly callTimeoutMs?: number;
  /** How long a transaction waits for its answer before UNKNOWN (UNKNOWN_AFTER_MS unless a test names less). */
  readonly unknownAfterMs?: number;
  /** How many bank calls at once (HANDOFF_LIMITS unless a test names fewer). */
  readonly limits?: { readonly total: number; readonly perOrganisation: number };
  /** How long a run starts new work for (RUN_BUDGET_MS unless a test names less). */
  readonly runBudgetMs?: number;
  /** Its transactions, and the bank check's, at once (`handoffDatabaseGate`). */
  readonly databaseGate: Gate;
  /** How long a stop waits for calls under way (STOP_WAIT_MS unless a test names less). */
  readonly stopWaitMs?: number;
  /**
   * The anchor check's last anchors, and its check of one organisation (job-list.ts
   * passes both): Tx A refuses a chain behind its anchor (ADR-012 §2, H11).
   * None given (some tests), nothing is compared.
   */
  readonly anchoring?: {
    readonly anchors: AnchorStore;
    readonly anchorFirst: (orgId: string, signal?: AbortSignal) => Promise<void>;
  };
}): Handoff {
  // Refused at start (ADR-007 §10): a wait no longer than the call could mark UNKNOWN one whose answer is on its way.
  if (unknownAfterMs <= callTimeoutMs) {
    throw new RangeError("A transaction's wait for its answer must be longer than the partner's call may take");
  }
  const anchorGate = createGate(ANCHOR_GATE);
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });
  // Its first beat is its start, so /health gives a new process HEARTBEAT_STALE_MS to make its first run; after that
  // only a run that reads its organisations beats, so one failing every time reads as stopped.
  let beat = clock.now().getTime();
  let sweptAt = Number.NEGATIVE_INFINITY;
  // Why hand-offs were held at the last run (gate H5): said on change.
  let heldWas: string | null = null;
  // The run under way's signal and budget: the lanes' work is one job's, and runs never overlap.
  let stopping: AbortSignal | undefined;
  let budgetEnds = Number.POSITIVE_INFINITY;
  let gaveUpWaiting = false;
  const runSpent = (): boolean => stopping?.aborted === true || clock.now().getTime() >= budgetEnds;
  // Each organisation's waiting requests and why (gate H5, H8): `said` as of its last full pass, `now` in the pass under
  // way, which may take several runs; replaced only after a full pass, so a lane cut short forgets nothing, and a lane
  // that ended its turn on its first request never reads as if the rest had stopped waiting.
  const waiting = new Map<string, { said: Map<string, string>; now: Map<string, string>; sawRows: boolean }>();
  const waitingOf = (orgId: string) => {
    const lane = waiting.get(orgId) ?? {
      said: new Map<string, string>(),
      now: new Map<string, string>(),
      sawRows: false,
    };
    waiting.set(orgId, lane);
    return lane;
  };
  // When each organisation's stale queue was last said (gate H8): at most once in QUEUE_STALE_MS.
  const staleSaid = new Map<string, number>();
  const staleRead = new Map<string, number>();
  const cutAtTheGate = new Set<string>();
  // What each organisation was told of its payments waiting for the bank: its lane's hold, and the platform's outage.
  // One signed event an outage and one a lane's hold, not one a run; an acceptance of its own clears it.
  const toldHeld = new Map<string, { readonly lane?: true; readonly bank?: number }>();
  const beatNow = (): void => {
    beat = clock.now().getTime();
  };
  /** A request left waiting noted. Said once a reason, not every run it still waits (gate H5): a long hold is one line a request. */
  const noteWaiting = (orgId: string, id: string, why: string, log: Logger): void => {
    const lane = waitingOf(orgId);
    if ((lane.now.get(id) ?? lane.said.get(id)) !== why) log.info('handoff.waiting', { requestId: id, why });
    lane.now.set(id, why);
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

  /**
   * The organisation's approved requests approved before `before` (by their
   * signed state's newest event, Postgres's clock) and not among `waiting`:
   * how many, and when the oldest was approved.
   */
  const staleOf = (orgId: string, before: Date, waiting: readonly string[], log: Logger) =>
    withSignedStates(database, orgId, services(log), (tx) =>
      tx
        // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count for an alert alone, nothing moves on it
        .selectFrom(`${SPEND_REQUESTS.table} as r`)
        .innerJoin('audit.events as e', (join) =>
          join.onRef('e.org_id', '=', 'r.org_id').onRef('e.id', '=', 'r.state_event_id'),
        )
        .select((select) => [select.fn.countAll<string>().as('count'), select.fn.min('e.recorded_at').as('oldest')])
        .where('r.org_id', '=', orgId)
        .where('r.status', 'in', HANDED_FROM)
        .where('e.recorded_at', '<', before)
        // One array, however many wait: never a parameter a request (review).
        .where((eb) => eb.not(eb('r.id', '=', eb.fn.any(eb.val(waiting)))))
        .executeTakeFirstOrThrow(),
    );

  /**
   * Says, at most once in QUEUE_STALE_MS an organisation, approved requests
   * left standing past QUEUE_STALE_MS that this run neither handed off nor
   * found waiting for a reason (gate H8): the queue-age alert reads it.
   */
  const staleIn = async (orgId: string, waitingIds: readonly string[], log: Logger): Promise<void> => {
    const now = clock.now().getTime();
    if (now - (staleSaid.get(orgId) ?? Number.NEGATIVE_INFINITY) < QUEUE_STALE_MS) return;
    // Finding none says nothing, so without this every cut lane would read again each run, past the budget (review).
    if (now - (staleRead.get(orgId) ?? Number.NEGATIVE_INFINITY) < STALE_READ_EVERY_MS) return;
    staleRead.set(orgId, now);
    try {
      const { count, oldest } = await staleOf(orgId, new Date(now - QUEUE_STALE_MS), waitingIds, log);
      // None standing: the oldest is none too.
      if (Number(count) === 0) return;
      staleSaid.set(orgId, now);
      log.warn('handoff.queue_stale', {
        requests: Number(count),
        oldestMinutes: Math.floor((now - new Date(oldest).getTime()) / 60_000),
      });
    } catch (error) {
      log.error('handoff.queue_unread', { err: error });
    }
  };

  /** Tx A for one request, in the lock order above; a denial tells the admins in it (decision 3). */
  const txA = async (tx: HandoffTx, states: SignedStates, orgId: string, id: string, log: Logger): Promise<TxA> => {
    const done = await judgedA(tx, states, orgId, id, log);
    if (done.outcome === 'denied') await outbox.add(tx, stoppedNotice(orgId, id));
    return done;
  };

  /**
   * Why the organisation's chain stops a hand-off now, read last of all under
   * its head's lock (ADR-006 §6): its integrity hold, then a chain wound back
   * since its last anchor (SEC-DB-11, H11), refused now rather than at the
   * anchor check's next run; with no anchor yet (the run's anchorFirst couldn't
   * make one), it waits rather than go uncompared (partner S146).
   */
  const chainStops = async (tx: HandoffTx, states: SignedStates, orgId: string): Promise<string | undefined> => {
    const hold = await states.integrityHold(tx, orgId, 'head');
    if (hold.outcome !== 'clear') return `hold_${hold.outcome}`;
    if (anchoring === undefined) return undefined;
    const anchor = anchoring.anchors.latest({ kind: 'organisation', orgId });
    if (anchor === undefined) return 'anchor_pending';
    return (await states.anchorKept(tx, orgId, anchor)).outcome === 'kept' ? undefined : 'hold_tampered';
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
    const stopped = await chainStops(tx, states, orgId);
    if (stopped !== undefined) return { outcome: 'waiting', why: stopped };
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
   * ADR-007 §9). A refusal moves a pending one, or one UNKNOWN with no word
   * of the bank's, to FAILED: its reject code is the proof (§11); never one
   * the bank check already read at the bank (its word stands; said).
   * An answer not about this payment (SEC-PTR-09) is never its word: a
   * pending one UNKNOWN, its money held. Throws for a transaction that can't
   * be believed.
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
      const locked = await lockPayment(tx, states, key, requestId);
      const from = locked.transaction.status;
      /** The status it moved to, or null where its machine refused the move. */
      const move = async (
        event: TransactionEvent,
        facts: ProviderFacts,
        via: string,
      ): Promise<TransactionStatus | null> => {
        const details = moveDetails(event, facts, via, locked.instruction.id);
        const moved = await moveTransaction(tx, states, key, event, facts, { actor: ACTOR, details });
        // Tampered (its alarm raised): the answer isn't on the record, so not "handed off".
        if (moved.outcome !== 'moved' && moved.outcome !== 'refused') {
          throw new Error(`A transaction didn't move by ${event}: ${moved.outcome}`);
        }
        return moved.outcome === 'moved' ? moved.to : null;
      };
      const settled = async (status: TransactionStatus | null): Promise<'recorded' | 'late'> => {
        if (status === null) return 'late';
        const at = clock.now();
        await settlePayment(tx, states, outbox, {
          orgId,
          requestId,
          transactionId,
          status,
          at,
          openProposal: locked.openProposal,
        });
        return 'recorded';
      };
      // No answer is no word at all: one the bank check (E1a) or the sweep moved meanwhile is left as they moved it.
      if (answer.kind === 'unknown') {
        return from === 'SUBMISSION_PENDING' ? settled(await move('lose_track', NO_FACTS, 'no_answer')) : 'late';
      }
      if (answer.kind === 'refused') {
        // UNKNOWN with no word of the bank's yet (the sweep's): one the bank check marked on the bank's word stays.
        const noBankWord = from === 'UNKNOWN' && locked.transaction.providerStatus === null;
        if (from === 'SUBMISSION_PENDING' || noBankWord) {
          return settled(await move('fail', { ...NO_FACTS, rejectCode: answer.code }, 'refused'));
        }
        log.error('handoff.refused_late', { transactionId, status: from });
        // Refused where the bank's word was read as under way or paid: kept and its admins told (decision
        // 37b). Failed or UNKNOWN, its word was already a rejection (or unreadable): nothing it goes back on (review).
        if (UNDER_WAY_OR_PAID.has(from)) {
          await alertAdmins(
            tx,
            { keys, ids, outbox },
            { orgId, transactionId, alert: 'contradicted', details: { status: from, refused: answer.code } },
          );
        }
        return 'late';
      }
      if (!answerAbout(answer.execution, orgId, locked)) {
        log.error('handoff.unreadable', { transactionId, status: from, why: 'not_this_payment' });
        return from === 'SUBMISSION_PENDING'
          ? settled(await move('lose_track', NO_FACTS, 'answer_unreadable'))
          : 'late';
      }
      const facts = factsOf(answer.execution);
      const state = paymentStateOf(answer.execution);
      // Rejected with no proof the money stayed, in the answer itself: reconciliation's, as the bank check says it.
      if (state === 'UNKNOWN') log.error('handoff.rejected_unproven', { transactionId });
      if ((await move('submitted', facts, 'accepted')) === null) return 'late';
      const recorded = await settled(await move(AFTER_SUBMITTED[state], facts, 'accepted'));
      // Kept and its admins told once recorded (decision 37b): a late one the bank check already told.
      if (state === 'UNKNOWN') {
        await alertAdmins(
          tx,
          { keys, ids, outbox },
          { orgId, transactionId, alert: 'rejected_unproven', details: { bank: answer.execution.providerStatus } },
        );
      }
      return recorded;
    });

  /** The transaction and its holdings locked (`lockPayment`), its status as read. */
  const lockedHoldings = async (
    tx: HandoffTx,
    states: SignedStates,
    key: { readonly orgId: string; readonly id: string },
    requestId: string,
  ): Promise<TransactionStatus> => (await lockPayment(tx, states, key, requestId)).transaction.status;

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

  /**
   * The organisation told, in its audit log, that its payments wait for the
   * bank (partner S119, S140: background actions kept where it can read them):
   * once an outage, and once a hold of its own lane. A lane's note speaks for
   * the platform's hold that follows it. One that can't be written is said and
   * tried again next run; the payments stay held either way.
   */
  const tellHeld = async (orgId: string, hold: RailHold, outage: number, log: Logger): Promise<void> => {
    const told = toldHeld.get(orgId) ?? {};
    const already =
      hold === 'lane' ? told.lane === true : told.bank === outage || (told.lane === true && told.bank === undefined);
    // Noted before it is written: several of its requests may reach the hold at once.
    toldHeld.set(orgId, hold === 'lane' ? { ...told, lane: true } : { ...told, bank: outage });
    if (already) return;
    try {
      await databaseGate.run(orgId, () =>
        withSignedStates(database, orgId, services(log), (tx) =>
          createAuditTrail({ keys, ids }).record(tx, orgId, {
            actor: ACTOR,
            action: 'handoff.held_for_bank',
            subject: { type: 'handoff_hold', id: ids.next(), version: 1 },
            details: { hold },
          }),
        ),
      );
    } catch (error) {
      toldHeld.set(orgId, told);
      log.error('handoff.held_unrecorded', { err: error });
    }
  };

  /**
   * Inside the gate, as the last thing before Tx A: the wait for the gate may
   * have outlasted the bank, the run's budget or the process (a stop leaves a
   * request as it was, rather than start one it may not be here to finish). The
   * breaker's place is taken here, so half-open's few are counted as they go.
   */
  const txAIfClear = async (orgId: string, id: string, log: Logger): Promise<Cleared> => {
    const entry = health.enter(orgId);
    if ('hold' in entry) return { outcome: 'held', hold: entry.hold, outage: entry.outage };
    const { settle } = entry;
    if (runSpent()) {
      settle('not_sent');
      return { outcome: 'stopped' };
    }
    try {
      const done = await withSignedStates(database, orgId, services(log), (tx, states) =>
        txA(tx, states, orgId, id, log),
      );
      if (done.outcome === 'handed_off') return { ...done, settle };
      settle('not_sent');
      return done;
    } catch (error) {
      settle('not_sent');
      throw error;
    }
  };

  /** One request handed off if it may go, its outcome logged: whether its organisation's turn goes on. */
  const handOff = async (orgId: string, id: string, log: Logger): Promise<LaneStep> => {
    beatNow();
    let done: Cleared;
    try {
      // Its bank slot already taken (its lane's turn), so a committed Tx A never queues before its call.
      done = await databaseGate.run(orgId, () => txAIfClear(orgId, id, log));
    } catch (error) {
      // Tx A's outcome unclear (a commit lost with the connection) or a bug: the partner is never called.
      log.error('handoff.failed', { requestId: id, err: error });
      return 'next';
    }
    if (done.outcome === 'denied') log.info('handoff.denied', { requestId: id, causes: done.causes });
    if (done.outcome === 'handed_off') await sent(orgId, id, done, log);
    if (done.outcome === 'stopped') {
      // At the default limits a backlogged lane usually ends here, not cut by the lanes themselves: still counted (review).
      cutAtTheGate.add(orgId);
      return 'end_turn';
    }
    if (done.outcome === 'held') {
      noteWaiting(orgId, id, `hold_${done.hold}`, log);
      await tellHeld(orgId, done.hold, done.outage, log);
      return 'end_turn';
    }
    if (done.outcome !== 'waiting') return 'next';
    noteWaiting(orgId, id, done.why, log);
    return isOrganisationWide(done.why) ? 'end_turn' : 'next';
  };

  /** Tx A committed, known by this run: the partner called (ADR-007 §8), and Tx B records what it answered. */
  const sent = async (
    orgId: string,
    id: string,
    { intent, transactionId, settle }: Extract<Cleared, { outcome: 'handed_off' }>,
    log: Logger,
  ): Promise<void> => {
    const answer = await answerOf(intent, id, log);
    // Before Tx B, the moment it is known, so no new Tx A can start between an outage's answers.
    const word = breakerWordOf(answer, intent);
    settle(word);
    if (word === 'accepted') toldHeld.delete(orgId);
    // The run gave up waiting for this call at a stop: its Tx B would meet a closing pool. SUBMISSION_PENDING, as after
    // a crash, for the bank check to settle.
    if (gaveUpWaiting) return;
    try {
      // Ahead of any new Tx A: it frees a bank slot, and speaks for money already at the bank.
      const recorded = await databaseGate.run(orgId, () => txB(orgId, id, transactionId, answer, log), true);
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

  /** A page of the organisation's approved requests, or null where it couldn't be read (said; its turn ends). */
  const laneRead = async (orgId: string, after: string | undefined): Promise<string[] | null> => {
    const log = logger.child({ orgId });
    try {
      const approved = await databaseGate.run(orgId, () => approvedOf(orgId, after, log));
      if (approved.length > 0) waitingOf(orgId).sawRows = true;
      return approved;
    } catch (error) {
      log.error('handoff.failed', { err: error });
      return null;
    }
  };

  /** A process just started (staging wakes from zero, a deploy) holds no anchor yet: the chain is anchored first. */
  const anchorFirstIn = (orgId: string): Promise<void> | undefined => {
    const held = anchoring?.anchors.latest({ kind: 'organisation', orgId });
    if (anchoring === undefined || held !== undefined) return undefined;
    return anchorGate.run(orgId, async () => {
      // A long queue of these may outlast the run: none begun past its budget or a stop.
      if (runSpent()) return;
      // A long chain takes minutes; a lane's next turn beats as it ends, so /health doesn't read a run of them as stopped.
      await anchoring.anchorFirst(orgId, stopping);
    });
  };

  const lanes = createFairLanes<string>({
    total: limits.total,
    // One at a time past a lane's hold, until the bank answers one of its payments (rail-health.ts).
    limitOf: (orgId) => (health.oneAtATime(orgId) ? 1 : limits.perOrganisation),
    page,
    idOf: (id) => id,
    read: laneRead,
    prepare: anchorFirstIn,
    work: (orgId, id) => handOff(orgId, id, logger.child({ orgId })),
    thrown: (orgId, error) => {
      logger.child({ orgId }).error('handoff.failed', { err: error });
    },
  });

  /**
   * Every organisation's turns at its approved requests, until each lane is
   * done, the run's budget is spent, or the run stops. What it started is waited
   * for, at a stop only so long: a hung bank must not take the process's stop
   * past its deadline. Then, for a lane that reached its end, the stale count and
   * what it waits for settled. A lane the budget cut short is counted too: those
   * it hasn't reached are waiting, and past their age say so, unless a hold has
   * them (`hold_lasting` says that). One a stop cut is counted by no one.
   */
  const handOffLanes = async (orgs: readonly string[], signal: AbortSignal | undefined): Promise<void> => {
    stopping = signal;
    gaveUpWaiting = false;
    cutAtTheGate.clear();
    budgetEnds = clock.now().getTime() + runBudgetMs;
    const outcomes = await finishedWithinStop(lanes.run(orgs, runSpent), signal, stopWaitMs);
    if (outcomes === undefined) {
      gaveUpWaiting = true;
      return;
    }
    for (const [orgId, outcome] of outcomes) {
      const lane = waitingOf(orgId);
      const cut = outcome === 'cut' || cutAtTheGate.has(orgId);
      const counted = outcome === 'whole' || (cut && health.heldFor(orgId) === undefined);
      // A pass that read no rows has nothing to count: a trip saved for each idle organisation.
      if (counted && lane.sawRows && signal?.aborted !== true) {
        await staleIn(orgId, [...lane.now.keys()], logger.child({ orgId }));
      }
      if (outcome !== 'whole') continue;
      lane.sawRows = false;
      lane.said = lane.now;
      lane.now = new Map();
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
    after: string | undefined,
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
        .where((where) => (after === undefined ? where.lit(true) : where('t.id', '>', after)))
        .orderBy('t.id')
        .limit(page)
        .execute(),
    );

  /**
   * The organisation's transactions left waiting for their answer past
   * unknownAfterMs marked UNKNOWN, a page at a time, every page (ADR-007 §10;
   * gate H5): each read for change, and moved only if it is still waiting
   * then, so one Tx B recorded meanwhile is never undone. Never resent;
   * reconciliation settles them. A page is read after the last one by its
   * cursor, so one that can't be moved never holds the sweep on it.
   */
  const sweepIn = async (orgId: string, log: Logger): Promise<void> => {
    const before = new Date(clock.now().getTime() - unknownAfterMs);
    let after: string | undefined;
    for (;;) {
      let waiting: { readonly id: string; readonly requestId: string | null }[];
      try {
        waiting = await waitingSince(orgId, before, after, log);
      } catch (error) {
        log.error('handoff.sweep_failed', { err: error });
        return;
      }
      for (const transaction of waiting) await sweptOne(orgId, transaction, log);
      if (waiting.length < page) return;
      after = waiting.at(-1)?.id;
    }
  };

  /** One transaction left waiting past its wait marked UNKNOWN, if it still is under its lock. */
  const sweptOne = async (
    orgId: string,
    transaction: { readonly id: string; readonly requestId: string | null },
    log: Logger,
  ): Promise<void> => {
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
        await settlePayment(tx, states, outbox, {
          orgId,
          requestId,
          transactionId: transaction.id,
          status: moved.to,
          at: clock.now(),
          // Waiting SUBMISSION_PENDING under this lock: only an UNKNOWN payment is ever proposed failed.
          openProposal: null,
        });
        return true;
      });
      if (marked) log.warn('handoff.marked_unknown', { transactionId: transaction.id });
    } catch (error) {
      log.error('handoff.sweep_failed', { transactionId: transaction.id, err: error });
    }
  };

  /** Why every hand-off is held now (the platform pause, or a pause that can't be read), or null where none is. */
  const heldNow = async (): Promise<string | null> => {
    try {
      const pause = await database.transaction().execute((tx) => handoffPauseOf(tx, 'share', { keys, logger }));
      return pause.outcome === 'running' ? null : `pause_${pause.outcome}`;
    } catch (error) {
      logger.error('handoff.pause_unread', { err: error });
      return 'pause_unread';
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
      // Read once a run (gate H5): while hand-offs are held, no request is read at all; Tx A still reads it again
      // under its lock for each one it hands off.
      const held = await heldNow();
      if (held !== heldWas) logger.info(held === null ? 'handoff.running' : 'handoff.held', { why: held ?? 'none' });
      heldWas = held;
      if (held === null) await handOffLanes(orgs, signal);
      // A pass of its own, once the hand-offs have ended, so it never waits behind a lane or holds one up.
      for (const orgId of sweeping ? orgs : []) {
        // Stopped between organisations too, so the process stops promptly however many there are.
        if (signal?.aborted === true) return;
        await sweepIn(orgId, logger.child({ orgId }));
      }
      beatNow();
    },
    beating: () => clock.now().getTime() - beat <= HEARTBEAT_STALE_MS,
  };
}

/** What the partner answered, as Tx B records it. */
type Answer =
  | { readonly kind: 'accepted'; readonly execution: PaymentExecution }
  | { readonly kind: 'refused'; readonly code: string }
  | { readonly kind: 'unknown' };

/**
 * What the partner's answer says of the way a payment takes, for the bank
 * breaker. Only a clear acceptance of this very payment is an acceptance: an
 * answer about another payment, or a rejection with no proof, leaves its outcome
 * unknown as surely as a timeout does. A rejection with its proof is a refusal.
 *
 * For the Phase 5 adapter: a refusal here means the bank weighed this payment and
 * turned it down. Our own 401, 403 and 429 must never arrive as `refused`: throw
 * RailUnavailable, so they count as unknown and hold the way, not as neutral.
 */
function breakerWord(answer: Answer, intent: ApprovedPaymentIntent): 'accepted' | 'refused' | 'unknown' {
  if (answer.kind !== 'accepted') return answer.kind;
  const instruction = { id: intent.instructionId, amountMinor: intent.amountMinor, currency: intent.currency };
  if (!answerAbout(answer.execution, intent.organizationId, { instruction })) return 'unknown';
  const state = paymentStateOf(answer.execution);
  if (state === 'UNKNOWN') return 'unknown';
  return state === 'FAILED' ? 'refused' : 'accepted';
}

/** The word on an answer, one too malformed to read counting as unknown, so the breaker's place is always given back. */
function breakerWordOf(answer: Answer, intent: ApprovedPaymentIntent): 'accepted' | 'refused' | 'unknown' {
  try {
    return breakerWord(answer, intent);
  } catch {
    return 'unknown';
  }
}

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

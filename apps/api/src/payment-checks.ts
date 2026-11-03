// The bank's word on each payment under way (Phase 4 E1a; ADR-007 §10–§13;
// rail map §4; SEC-PTR-02, -09): the API's job, on a timer of its own, asks
// the bank how each handed-off payment stands (`getExecution`, the lookup by
// our instruction ID) and moves its transaction to match. The bank's status
// query is its word: a message from it (E1b) only makes this check sooner, so
// messages early, late, twice or missed change nothing. Nothing is ever sent
// to the bank again (ADR-007 §10).
//
// Each run takes the partner's messages waiting in the inbox (E1b), and checks
// the payments each names, ahead of their turn; a message is taken once the bank
// answered for each, tried at most 5 runs. Beside them, never behind, it takes
// the organisations' transactions still under way (SUBMISSION_PENDING past its
// answer's time, SUBMITTED, PROCESSING, UNKNOWN) in turns (fair-lanes.ts, 4D2e
// Stage F: up to 8 calls at once, 2 of them the messages', 2 an organisation and
// 1 more for a message, slots of its own beside the hand-off's), each organisation's
// oldest first, a page at a time: one under 15 minutes old every run, one under
// a day old every 5th run (the real partner's rate limits). Every 30th run, the
// first after a start among them, two laps begin: every UNKNOWN of any age, then
// the rest under way with those paid or failed in the last 7 days. A lap carries
// on run after run, each with its own part of the budget, the UNKNOWNs' larger,
// until every organisation has had its turn: an UNKNOWN is asked again within 30
// runs and that lap's length, and one that outlasts its time is said. None is
// asked twice in a run. The bank is asked outside any
// database transaction; then one transaction a payment, in ADR-006 §6's lock order, as Tx B (`lockPayment`:
// the transaction for change, 10; its holdings, 11; the move, the head, 12),
// and every move settled by `settlePayment` (its holdings; on SUCCEEDED, the
// supplier's remittance email).
//
// What the bank says (rail map §4, `paymentStateOf`): under way → PROCESSING;
// the creditor credited → SUCCEEDED; Rejected with its proof of no debit →
// FAILED; Rejected without it → UNKNOWN and a reconciliation alert; not found
// proves nothing (left as it is, ADR-007 §11); an answer that can't be read or
// isn't about this payment → UNKNOWN and an alert, never success (SEC-PTR-09);
// the bank unreachable → asked again next time (3 in a row end that
// organisation's turn, not the run: one hung organisation can't keep the bank's
// answer from another). Every answer tells the hand-off's breaker
// (rail-health.ts), these lookups being what lets it open again, so they must
// reach everyone. A run starts new work for 30 s, and a stop waits for calls under
// way only 15 s. One SUBMISSION_PENDING (its run died before Tx B)
// takes both steps in one transaction, each in its history (ADR-007 §13). A
// move its machine doesn't allow (an UNKNOWN said to be under way) keeps the
// bank's facts alone. A payment already settled that the bank now contradicts
// (credited, then Rejected) stays as it is, the facts kept, and an alert raised
// (rail map §4): a paid or failed one (two admins' mark among them, H10) is
// checked every 30th run for 7 days from its last move (gate H3). An answer
// older than the word kept is one already read, and changes nothing. An
// UNKNOWN unresolved past a day is said each time it is checked, for
// reconciliation (E1c). A contradiction, a rejection without proof and an
// UNKNOWN past a day are each also kept in the organisation's audit log and
// emailed to its admins (decision 37b, `alertAdmins`), the first two as the
// bank first says them, the last once.
//
// A run never throws: each failure is logged, naming the organisation and
// transaction, and the run goes on to the next. Its heartbeat is read by
// /health (ADR-013).
//
// A check that changed nothing, neither our status nor the bank's, has no line of
// its own: a run's `payment_check.run_unchanged` counts them, a bank's not-found
// apart (4D2e Stage F). The count is a run's, not an exact tally: a check still
// applying after a run gave up at a stop can miss it, or land in the next run's.
// A not-found on a payment the bank has spoken of keeps its line, its word having
// changed; one handed off past UNKNOWN_AFTER_MS is said at warn on each check that
// finds it so, the payment staying waiting, and its admins are emailed once
// (`bank_lost`, partner S170): following it up is the user's with their bank,
// decision 38.
import { type AuditTables, type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import type { InstructionsTables } from '@agentx/core/modules/instructions';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import {
  AFTER_SUBMITTED,
  answerAbout,
  factsOf,
  lockPayment,
  moveDetails,
  NO_FACTS,
  settlePayment,
} from '@agentx/core/modules/outcomes';
import {
  MOST_TRIES,
  type Nudge,
  type ProviderEvents,
  type ProviderEventsTables,
} from '@agentx/core/modules/provider-events';
import {
  type ExecutionLookup,
  type FinancialRailAdapter,
  type PaymentState,
  paymentStateOf,
  RailUnavailable,
} from '@agentx/core/modules/providers';
import {
  isSettled,
  moveTransaction,
  noteTransactionFacts,
  type ProviderFacts,
  TRANSACTIONS,
  transactionDueNow,
  type TransactionEvent,
  type TransactionsTables,
  type TransactionStatus,
} from '@agentx/core/modules/transactions';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { finishedWithinStop } from './background.ts';
import { createFairLanes, type FairLanes, type Gate, type LaneStep } from './fair-lanes.ts';
import {
  HEARTBEAT_STALE_MS,
  PARTNER_CALL_TIMEOUT_MS,
  PartnerTimedOut,
  RUN_BUDGET_MS,
  STOP_WAIT_MS,
  UNKNOWN_AFTER_MS,
  withinTime,
} from './handoff.ts';
import { alertAdmins, type PaymentAlert } from './payment-alerts.ts';
import type { RailHealth } from './rail-health.ts';
import type { VoidTables } from './request-voids.ts';

/** How often the payments under way are checked, once the last run has ended. */
export const PAYMENT_CHECKS_EVERY_MS = 60_000;

/** How many of an organisation's payments are read at once: the run then takes the next page after them. */
const CHECK_PAGE = 50;

/** A payment younger than this is checked every run; older ones less often (the partner's rate limits). */
const FRESH_MS = 15 * 60_000;

const DAY_MS = 24 * 60 * 60_000;

/** Every this many runs, the payments up to a day old are checked too; every ALL_EVERY runs, every one. */
const DAY_EVERY = 5;
const ALL_EVERY = 30;

/** How long a SUBMISSION_PENDING one is left to its own Tx B: past the partner's call, so its answer isn't on its way. */
const ANSWER_DUE_MS = 60_000;

/**
 * How long a paid one is still checked (every ALL_EVERY runs), so the bank
 * rejecting it after its credit is seen (rail map §4). Until the partner's
 * answer to STA-4 says how late a status can change.
 */
const PAID_WATCH_MS = 7 * DAY_MS;

/** How long an UNKNOWN payment may stay unresolved before each check says so (reconciliation). */
const STILL_UNKNOWN_MS = DAY_MS;

/** The statuses a payment is checked in: its outcome can still move. */
const UNDER_WAY = ['SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN'] as const;

/**
 * The settled ones still watched for PAID_WATCH_MS from their last move: paid,
 * or failed (two admins' mark among them, H10: a week from the mark, gate H3).
 */
const WATCHED = ['SUCCEEDED', 'FAILED'] as const;

/** How long a watch lasts, as Postgres reads an interval (its type from date_add's and date_subtract's, Postgres 16 on). */
const PAID_WATCH = `${String(PAID_WATCH_MS / 1000)} seconds`;

type DueTx = DatabaseTransaction<TransactionsTables & AuditTables>;

/**
 * Whether the organisation has a payment paid or failed whose last move was within PAID_WATCH_MS, on Postgres's clock:
 * from that week's events, each to the payment whose newest it is (0048's index, then the key), so the read is a week's
 * events, never every payment the organisation has made.
 */
const watchedIn = (tx: DueTx, orgId: string) =>
  tx
    .selectFrom('audit.events as e')
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- whether one stands alone, for choosing when to look
    .innerJoin(`${TRANSACTIONS.table} as t`, (join) =>
      join.onRef('t.org_id', '=', 'e.org_id').onRef('t.id', '=', 'e.subject_id').onRef('t.state_event_id', '=', 'e.id'),
    )
    .select('t.id')
    .where('e.org_id', '=', orgId)
    .where((eb) =>
      eb('e.recorded_at', '>=', eb.fn<Date>('pg_catalog.date_subtract', [eb.fn('pg_catalog.now'), eb.val(PAID_WATCH)])),
    )
    .where('e.subject_type', '=', TRANSACTIONS.subject)
    .where('t.status', 'in', WATCHED);

/**
 * When the checks next have work in an organisation, not run: now if a payment is under way; a watch's length on if
 * one is only watched, as its laps take every mark, due or not (4D2e D7), and the regular runs none; null if neither.
 * Every payment watched was born under way and marked then, so its mark stands from there for as long as this says.
 */
export const paymentCheckDue = (tx: DueTx, orgId: string) =>
  tx.selectNoFrom((eb) => {
    const now = eb.fn<Date>('pg_catalog.now');
    return eb
      .case()
      .when(eb.exists(transactionDueNow(tx, orgId, UNDER_WAY)))
      .then(now)
      .when(eb.exists(watchedIn(tx, orgId)))
      .then(eb.fn<Date>('pg_catalog.date_add', [now, eb.val(PAID_WATCH)]))
      .else(null)
      .end()
      .as('due');
  });

/** How many of the partner's messages a run takes, oldest first: the rest wait for the next. */
const NUDGES_A_RUN = 100;

/** How many unanswered calls in a row end an organisation's turn: each would wait its time limit. */
const UNREACHED_IN_A_ROW = 3;

/** How many calls to the bank at once, across every organisation and in each: slots of their own, beside the hand-off's. */
const CHECK_LIMITS = { total: 8, perOrganisation: 2 } as const;

/** How the run's budget is parted: the regular turns, then each lap. A message's pass has the whole of it, beside them. */
const REGULAR_SHARE = 1 / 2;
const UNKNOWN_LAP_SHARE = 1 / 3;
const WATCH_LAP_SHARE = 1 / 6;

/** How long the UNKNOWNs' lap may take before it is said: by then the next is due. */
const LAP_DUE_MS = ALL_EVERY * PAYMENT_CHECKS_EVERY_MS;

/** The API, as the check's actor in the signed events. */
const ACTOR = { type: 'system', id: 'api' } as const;

type CheckTables = VoidTables & InstructionsTables & TransactionsTables & NotificationsTables & ProviderEventsTables;

/** A payment under way as listed, by its rows, unverified: each read through its signed state before it moves. */
interface Listed {
  readonly id: string;
  readonly instructionId: string;
  /** Its request's ID through its instruction; none where that is gone (the transaction then can't be believed). */
  readonly requestId: string | null;
}

/** What the bank said, as the check reads it. */
type Word = ExecutionLookup | { readonly kind: 'unavailable' } | { readonly kind: 'unreadable' };

/** Which payments a sweep checks: those in `statuses` made since `since` (all where none), and the paid ones or not. */
interface Due {
  readonly statuses: readonly TransactionStatus[];
  readonly since: Date | undefined;
  readonly watchPaid: boolean;
}

/** What a check of one payment came to. */
type CheckOutcome = 'checked' | 'unreached' | 'failed';

/** A run's own count: the bank's unanswered calls, in all and each organisation's in a row, and the payments checked once. */
interface Run {
  unreached: number;
  /** How many organisations' turns ended on UNREACHED_IN_A_ROW. */
  endedTurns: number;
  /** How many payments the bank's word left as they were: counted once a run, as most are at volume (4D2e Stage F). */
  unchanged: number;
  /** As `unchanged`, where its word was that it can't find the payment. */
  notFound: number;
  readonly inRow: Map<string, number>;
  readonly checks: Map<string, Promise<CheckOutcome>>;
  readonly unreadable: Set<string>;
}

const newRun = (): Run => ({
  unreached: 0,
  endedTurns: 0,
  unchanged: 0,
  notFound: 0,
  inRow: new Map(),
  checks: new Map(),
  unreadable: new Set(),
});

/** One of the sweeps that reach every payment of its kind, over as many runs as they take. */
interface Lap {
  readonly sweep: string;
  readonly lanes: FairLanes;
  readonly share: number;
  /** How long it may take before it is said. */
  readonly outlastsMs: number;
  /** Its organisations as it begins, where not the run's own (those under way): the watch's take the paid ones too. */
  readonly begins?: () => Promise<readonly string[]>;
  /** The organisations yet to have their turn: empty between laps. */
  left: readonly string[];
  startedAt: number;
  said: boolean;
}

/** Where a check found the payment, and left it. */
interface Checked {
  readonly from: TransactionStatus;
  readonly to: TransactionStatus;
  /** The bank's status, where this check is the first to read it; else null. */
  readonly newBankStatus: string | null;
  /** The bank's last status, where it now says it can't find the payment; else null. */
  readonly bankLost: string | null;
}

/** Whether a check left all as it was, so its count says enough. */
const nothingNew = ({ from, to, newBankStatus, bankLost }: Checked): boolean =>
  from === to && newBankStatus === null && bankLost === null;

/** Whether the bank not finding this one by now is worth saying: handed to it, and past when its answer was due. */
const lostTooLong = (status: TransactionStatus, createdAt: Date, now: Date): boolean =>
  (status === 'SUBMITTED' || status === 'PROCESSING') && now.getTime() - createdAt.getTime() > UNKNOWN_AFTER_MS;

/** Whether a settled payment's bank state contradicts it: paid and then not, or failed and then paid (rail map §4). */
const contradicts = (status: TransactionStatus, state: PaymentState): boolean =>
  status === 'SUCCEEDED' || status === 'REVERSED'
    ? state === 'FAILED' || state === 'UNKNOWN'
    : state === 'SUCCEEDED' || state === 'PROCESSING';

export interface PaymentChecks {
  /** Checks each organisation's payments under way that are due, a page at a time, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
  /** Whether a run has beaten within HEARTBEAT_STALE_MS: /health's check (ADR-013). */
  beating(): boolean;
}

export function createPaymentChecks({
  list,
  watchList,
  database,
  rail,
  outbox,
  keys,
  ids,
  clock,
  logger,
  events,
  health,
  databaseGate,
  page = CHECK_PAGE,
  callTimeoutMs = PARTNER_CALL_TIMEOUT_MS,
  limits = CHECK_LIMITS,
  runBudgetMs = RUN_BUDGET_MS,
  stopWaitMs = STOP_WAIT_MS,
}: {
  /** The organisations to look in: those marked due (org-work.ts), which job-list.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  /** Those the watch's lap takes as it begins, read only then: every one marked, due or not; the run's own unless given. */
  readonly watchList?: () => Promise<readonly string[]>;
  readonly database: Database<CheckTables>;
  readonly rail: FinancialRailAdapter;
  /** Where a payment that SUCCEEDED queues its supplier's remittance email (`settlePayment`). */
  readonly outbox: Outbox;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** The partner's messages taken in (E1b): each names payments this checks first, ahead of their turn; none where there is no inbox. */
  readonly events?: ProviderEvents;
  /** The bank breaker it shares with the hand-off: every lookup that answers is told it, as the only way to reopen it. */
  readonly health: RailHealth;
  /** The hand-off's own: their transactions together stay within it (`handoffDatabaseGate`). */
  readonly databaseGate: Gate;
  /** How many of an organisation's payments are read at once (CHECK_PAGE unless a test names fewer). */
  readonly page?: number;
  /** How long the bank has to answer (PARTNER_CALL_TIMEOUT_MS unless a test names less). */
  readonly callTimeoutMs?: number;
  /** How many calls at once (CHECK_LIMITS unless a test names fewer). */
  readonly limits?: { readonly total: number; readonly perOrganisation: number };
  /** How long a run starts new work for (RUN_BUDGET_MS unless a test names less). */
  readonly runBudgetMs?: number;
  /** How long a stop waits for calls under way (STOP_WAIT_MS unless a test names less). */
  readonly stopWaitMs?: number;
}): PaymentChecks {
  // Refused at start: an answer still on its way to its Tx B must never be read as the bank's silence.
  if (ANSWER_DUE_MS <= callTimeoutMs) {
    throw new RangeError("A payment's answer must be due after the bank's call may take");
  }
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });
  // As the hand-off's: its first beat is its start, then only a run that reads its organisations beats.
  let beat = clock.now().getTime();
  let runs = 0;
  // A quarter of the calls the messages': enough to go on, never all of them.
  const nudgeSlots = Math.max(1, Math.floor(limits.total / 4));
  // The run under way's, as the lanes' work needs them; runs never overlap.
  let run = newRun();
  let spent: () => boolean = () => false;
  let gaveUpWaiting = false;
  const beatNow = (): void => {
    beat = clock.now().getTime();
  };

  /** A page of the organisation's due payments (`Due`), after `after`, by ID. */
  const underWay = (
    orgId: string,
    after: string | undefined,
    { statuses, since, watchPaid }: Due,
    log: Logger,
  ): Promise<Listed[]> =>
    withSignedStates(database, orgId, services(log), (tx) => {
      const answerDue = new Date(clock.now().getTime() - ANSWER_DUE_MS);
      return (
        tx
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state before it moves
          .selectFrom(`${TRANSACTIONS.table} as t`)
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- its request's ID alone, read again through its signed instruction before anything moves
          .leftJoin('instructions.instructions as i', (join) =>
            join.onRef('i.org_id', '=', 't.org_id').onRef('i.id', '=', 't.instruction_id'),
          )
          // When it last moved (its signed state's newest event, Postgres's clock): a watch runs from there (gate H3).
          .leftJoin('audit.events as e', (join) =>
            join.onRef('e.org_id', '=', 't.org_id').onRef('e.id', '=', 't.state_event_id'),
          )
          .select(['t.id as id', 't.instruction_id as instructionId', 'i.spend_request_id as requestId'])
          .where('t.org_id', '=', orgId)
          .where((where) =>
            where.or([
              where.and([
                where('t.status', 'in', statuses),
                // One still waiting for its own answer is its Tx B's (or the hand-off's sweep's) until the answer is due.
                where.or([where('t.status', '!=', 'SUBMISSION_PENDING'), where('t.created_at', '<=', answerDue)]),
                since === undefined ? where.lit(true) : where('t.created_at', '>=', since),
              ]),
              // Paid and failed ones too, every ALL_EVERY runs, for PAID_WATCH_MS: the bank going back on one is said (rail map §4).
              watchPaid
                ? where.and([
                    where('t.status', 'in', WATCHED),
                    where('e.recorded_at', '>=', new Date(clock.now().getTime() - PAID_WATCH_MS)),
                  ])
                : where.lit(false),
            ]),
          )
          .where((where) => (after === undefined ? where.lit(true) : where('t.id', '>', after)))
          .orderBy('t.id')
          .limit(page)
          .execute()
      );
    });

  /**
   * The payments a partner's message names, by their rows, unverified (each
   * then read through its signed state): its instruction's, whatever its
   * status (one settled may be contradicted, rail map §4); or a consent's,
   * a page of those under way or settled (paid or failed) in PAID_WATCH_MS.
   */
  const namedBy = (nudge: Nudge, log: Logger): Promise<Listed[]> =>
    withSignedStates(database, nudge.orgId, services(log), (tx) => {
      const paidSince = new Date(clock.now().getTime() - PAID_WATCH_MS);
      const { reference } = nudge;
      return (
        tx
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state before it moves
          .selectFrom(`${TRANSACTIONS.table} as t`)
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- its request's ID and consent alone, read again through its signed instruction before anything moves
          .innerJoin('instructions.instructions as i', (join) =>
            join.onRef('i.org_id', '=', 't.org_id').onRef('i.id', '=', 't.instruction_id'),
          )
          // When it last moved (its signed state's newest event, Postgres's clock): a watch runs from there (gate H3).
          .leftJoin('audit.events as e', (join) =>
            join.onRef('e.org_id', '=', 't.org_id').onRef('e.id', '=', 't.state_event_id'),
          )
          .select(['t.id as id', 't.instruction_id as instructionId', 'i.spend_request_id as requestId'])
          .where('t.org_id', '=', nudge.orgId)
          .where((where) =>
            reference.kind === 'instruction'
              ? where('i.id', '=', reference.instructionId)
              : where.and([
                  where('i.account_consent_id', '=', reference.consentId),
                  where.or([
                    where('t.status', 'in', UNDER_WAY),
                    where.and([where('t.status', 'in', WATCHED), where('e.recorded_at', '>=', paidSince)]),
                  ]),
                ]),
          )
          .orderBy('t.id')
          .limit(page)
          .execute()
      );
    });

  /** The bank's unanswered call counted against its organisation; `end_turn` once UNREACHED_IN_A_ROW went unanswered. */
  const stepOf = (orgId: string, checked: CheckOutcome): LaneStep => {
    const inRow = checked === 'unreached' ? (run.inRow.get(orgId) ?? 0) + 1 : 0;
    run.inRow.set(orgId, inRow);
    if (inRow < UNREACHED_IN_A_ROW) return 'next';
    run.endedTurns += 1;
    return 'end_turn';
  };

  /**
   * One message's payments checked with the bank now, ahead of their turn, then
   * the message taken once the bank answered for its own payments and each was
   * recorded; else tried again next run, up to MOST_TRIES: then left to the
   * regular check, so it never holds up the messages behind it.
   */
  const checkOneNudge = async (nudge: Nudge, inbox: ProviderEvents): Promise<LaneStep> => {
    const { orgId } = nudge;
    const log = logger.child({ orgId });
    try {
      const tries = await databaseGate.run(orgId, () => inbox.tried(database, nudge.id));
      let answered = true;
      const named = await databaseGate.run(orgId, () => namedBy(nudge, log));
      for (const payment of named) {
        if (spent()) return 'end_turn';
        const fresh = !run.checks.has(payment.id);
        const checked = await checkOnce(orgId, payment, log);
        answered &&= checked === 'checked';
        if (fresh && stepOf(orgId, checked) === 'end_turn') return 'end_turn';
      }
      if (answered) await databaseGate.run(orgId, () => inbox.taken(database, nudge.id));
      else if (tries >= MOST_TRIES) log.warn('payment_check.nudge_given_up', { messageId: nudge.id });
    } catch (error) {
      log.error('payment_check.nudge_failed', { err: error });
    }
    return 'next';
  };

  /** The partner's messages waiting in the inbox, in turns by organisation. A list of this run's own: no place to keep. */
  const checkNudged = async (): Promise<void> => {
    if (events === undefined) return;
    let nudges: Nudge[];
    try {
      nudges = await events.waiting(database, NUDGES_A_RUN);
    } catch (error) {
      logger.error('payment_check.nudge_failed', { err: error });
      return;
    }
    const lanes = createFairLanes<Nudge>({
      total: nudgeSlots,
      limitOf: () => 1,
      thrown: laneThrown,
      // Past the most a run takes, so each lane's one read is its last.
      page: NUDGES_A_RUN + 1,
      idOf: ({ id }) => id,
      read: (orgId) => Promise.resolve(nudges.filter((nudge) => nudge.orgId === orgId)),
      work: (_orgId, nudge) => checkOneNudge(nudge, events),
    });
    await lanes.run([...new Set(nudges.map(({ orgId }) => orgId))], spent);
  };

  /** The bank's word on the payment, within its time: unreachable is asked again; anything else it can't give is unreadable. */
  const wordOf = async (orgId: string, listed: Listed, log: Logger): Promise<Word> => {
    // Begun before the call, so one under way at a trip proves nothing since it.
    const answered = health.lookupBegun(orgId);
    try {
      const word = await withinTime(
        rail.getExecution({ organizationId: orgId, instructionId: listed.instructionId }),
        callTimeoutMs,
      );
      answered();
      return word;
    } catch (error) {
      if (error instanceof RailUnavailable || error instanceof PartnerTimedOut) return { kind: 'unavailable' };
      log.error('payment_check.unreadable', { transactionId: listed.id, err: error });
      return { kind: 'unreadable' };
    }
  };

  /** The bank's word applied to one payment, in the lock order above: where it was, and is. Throws for one that can't be believed. */
  const applied = (orgId: string, listed: Listed, word: Exclude<Word, { kind: 'unavailable' }>, log: Logger) =>
    withSignedStates(database, orgId, services(log), async (tx, states): Promise<Checked> => {
      const key = { orgId, id: listed.id };
      // Read for change through its signed state: the instruction the bank was asked about (its row's) is the signed
      // one, as a row changed past the app reads as tampered. One with no instruction is refused before any lock.
      const locked = await lockPayment(tx, states, key, listed.requestId ?? '');
      const { transaction } = locked;
      const from = transaction.status;
      /** What the bank's word raised for the organisation's admins (decision 37b), told once it is applied. */
      const alerts: { readonly alert: PaymentAlert; readonly details: Record<string, string> }[] = [];
      let newBankStatus: string | null = null;
      let bankLost: string | null = null;

      /** The status it moved to, or null where its machine refused the move (its facts still kept). */
      const move = async (event: TransactionEvent, facts: ProviderFacts, via: string) => {
        const details = moveDetails(event, facts, via, listed.instructionId);
        const moved = await moveTransaction(tx, states, key, event, facts, { actor: ACTOR, details });
        // Read for change under this lock: anything but a move or a refusal is something past the app.
        if (moved.outcome !== 'moved' && moved.outcome !== 'refused') {
          throw new Error(`A payment didn't move by ${event}: ${moved.outcome}`);
        }
        return moved.outcome === 'moved' ? moved.to : null;
      };

      /** Not found proves nothing: left as it is, said where it has gone on too long. */
      const notFound = (): TransactionStatus => {
        bankLost = transaction.providerStatus;
        if (lostTooLong(from, transaction.createdAt, clock.now())) {
          log.warn('payment_check.not_found_long', { transactionId: listed.id });
          // Its admins told once a payment (`alertAdmins`), to take it to their bank (partner S170).
          alerts.push({ alert: 'bank_lost', details: { bank: transaction.providerStatus ?? 'none' } });
        }
        return from;
      };

      /** Never success on an answer that can't be read (SEC-PTR-09): UNKNOWN, its money held. */
      const unreadable = async (): Promise<TransactionStatus> => {
        if (word.kind === 'found') {
          log.error('payment_check.unreadable', { transactionId: listed.id, why: 'not_this_payment' });
        }
        return (await move('lose_track', NO_FACTS, 'bank_unreadable')) ?? from;
      };

      /** Where the bank's word takes it. */
      const movedBy = async (): Promise<TransactionStatus> => {
        if (word.kind === 'not_found') return notFound();
        const found = word.kind === 'found' && answerAbout(word.execution, orgId, locked) ? word.execution : undefined;
        if (found === undefined) return unreadable();
        // Older than the word kept (another check's newer answer won the lock): already read, nothing new.
        if (transaction.providerChangedAt !== null && found.statusChangedAt < transaction.providerChangedAt)
          return from;
        const facts = factsOf(found);
        const state = paymentStateOf(found);
        // Said once, as the bank first says it: a check that finds it as it was says nothing more.
        const newly = found.providerStatus !== transaction.providerStatus;
        if (newly) newBankStatus = found.providerStatus;
        if (isSettled(from)) {
          await noteTransactionFacts(tx, states, key, facts, { actor: ACTOR, details: { via: 'bank_check' } });
          if (newly && contradicts(from, state)) {
            log.error('payment_check.contradicts', {
              transactionId: listed.id,
              status: from,
              bank: found.providerStatus,
            });
            alerts.push({ alert: 'contradicted', details: { status: from, bank: found.providerStatus } });
          }
          return from;
        }
        // Rejected with no proof the money stayed: reconciliation's (rail map §4).
        if (state === 'UNKNOWN' && newly) {
          log.error('payment_check.rejected_unproven', { transactionId: listed.id });
          alerts.push({ alert: 'rejected_unproven', details: { bank: found.providerStatus } });
        }
        // Its run died before Tx B: both steps here, each in its history (ADR-007 §13).
        const submitted = from === 'SUBMISSION_PENDING' ? await move('submitted', facts, 'bank_check') : null;
        return (await move(AFTER_SUBMITTED[state], facts, 'bank_check')) ?? submitted ?? from;
      };

      const to = await movedBy();
      if (to !== from) {
        await settlePayment(tx, states, outbox, {
          orgId,
          requestId: locked.instruction.spendRequestId,
          transactionId: listed.id,
          status: to,
          at: clock.now(),
          openProposal: locked.openProposal,
        });
      }
      if (to === 'UNKNOWN' && clock.now().getTime() - transaction.createdAt.getTime() > STILL_UNKNOWN_MS) {
        log.warn('payment_check.still_unknown', { transactionId: listed.id });
        alerts.push({ alert: 'still_unknown', details: {} });
      }
      for (const { alert, details } of alerts) {
        await alertAdmins(tx, { keys, ids, outbox }, { orgId, transactionId: listed.id, alert, details });
      }
      return { from, to, newBankStatus, bankLost };
    });

  /** One payment checked with the bank, its outcome logged. */
  const check = async (orgId: string, listed: Listed, log: Logger): Promise<CheckOutcome> => {
    beatNow();
    const word = await wordOf(orgId, listed, log);
    if (word.kind === 'unavailable') return 'unreached';
    // The run gave up waiting for this call at a stop: its move would meet a closing pool, and the next check makes it.
    if (gaveUpWaiting) return 'unreached';
    try {
      const checked = await databaseGate.run(orgId, () => applied(orgId, listed, word, log));
      if (nothingNew(checked)) {
        run[word.kind === 'not_found' ? 'notFound' : 'unchanged'] += 1;
      } else log.info('payment_check.checked', { transactionId: listed.id, answer: word.kind, ...checked });
      return 'checked';
    } catch (error) {
      log.error('payment_check.failed', { transactionId: listed.id, err: error });
      return 'failed';
    }
  };

  /** One payment checked, once a run however many messages name it: each waits on the one check, and counts its answer. */
  const checkOnce = (orgId: string, payment: Listed, log: Logger): Promise<CheckOutcome> => {
    const under = run.checks.get(payment.id);
    if (under !== undefined) return under;
    const checking = check(orgId, payment, log).then((checked) => {
      if (checked === 'unreached') run.unreached += 1;
      return checked;
    });
    run.checks.set(payment.id, checking);
    return checking;
  };

  /** A page of the organisation's due payments, or null where it couldn't be read (said; its turn ends). */
  const laneRead = async (orgId: string, after: string | undefined, due: Due): Promise<Listed[] | null> => {
    // Said once a run, however many sweeps come to it.
    if (run.unreadable.has(orgId)) return null;
    const log = logger.child({ orgId });
    try {
      return await databaseGate.run(orgId, () => underWay(orgId, after, due, log));
    } catch (error) {
      run.unreadable.add(orgId);
      log.error('payment_check.list_failed', { err: error });
      return null;
    }
  };

  const laneThrown = (orgId: string, error: unknown): void => {
    logger.child({ orgId }).error('payment_check.failed', { err: error });
  };

  /** One payment's turn; an organisation already gone unanswered this run is asked no more, whichever sweep found it so. */
  const payment = async (orgId: string, listed: Listed): Promise<LaneStep> => {
    if ((run.inRow.get(orgId) ?? 0) >= UNREACHED_IN_A_ROW) return 'end_turn';
    // Asked already this run, by a message or another sweep: no new call, so nothing to count.
    if (run.checks.has(listed.id)) return 'next';
    return stepOf(orgId, await checkOnce(orgId, listed, logger.child({ orgId })));
  };

  const lanesOf = (dueNow: () => Due): FairLanes =>
    createFairLanes<Listed>({
      total: Math.max(1, limits.total - nudgeSlots),
      limitOf: () => limits.perOrganisation,
      thrown: laneThrown,
      page,
      idOf: ({ id }) => id,
      read: (orgId, after) => laneRead(orgId, after, dueNow()),
      work: payment,
    });

  const since = (ms: number) => new Date(clock.now().getTime() - ms);
  // A place kept for each sweep, so one cut short goes on where it left off at its next.
  const everyRunLanes = lanesOf(() => ({ statuses: UNDER_WAY, since: since(FRESH_MS), watchPaid: false }));
  const daysLanes = lanesOf(() => ({ statuses: UNDER_WAY, since: since(DAY_MS), watchPaid: false }));

  const lapOf = (
    sweep: string,
    due: Due,
    share: number,
    outlastsMs: number,
    begins?: () => Promise<readonly string[]>,
  ): Lap => ({
    sweep,
    ...(begins === undefined ? {} : { begins }),
    lanes: lanesOf(() => due),
    share,
    outlastsMs,
    left: [],
    startedAt: 0,
    said: false,
  });
  // The UNKNOWNs a lap of their own, ahead of the paid watch: at volume the watch may never end a lap, and these must.
  const laps = [
    lapOf('unknown', { statuses: ['UNKNOWN'], since: undefined, watchPaid: false }, UNKNOWN_LAP_SHARE, LAP_DUE_MS),
    lapOf(
      'watched',
      { statuses: UNDER_WAY.filter((status) => status !== 'UNKNOWN'), since: undefined, watchPaid: true },
      WATCH_LAP_SHARE,
      PAID_WATCH_MS,
      watchList,
    ),
  ];

  /** A part of the run's budget, from now: a sweep that spends its own leaves the next its turn. */
  const partOfBudget = (share: number, signal: AbortSignal | undefined): (() => boolean) => {
    const ends = clock.now().getTime() + runBudgetMs * share;
    return () => signal?.aborted === true || clock.now().getTime() >= ends;
  };

  /** A lap's next part: its organisations not yet had their turn; one hung or unreadable has had it, and tries again next lap. */
  const lapPart = async (lap: Lap, signal: AbortSignal | undefined): Promise<void> => {
    if (lap.left.length === 0) return;
    const outcomes = await lap.lanes.run(lap.left, partOfBudget(lap.share, signal));
    lap.left = lap.left.filter((orgId) => outcomes.get(orgId) === 'cut');
    if (lap.left.length === 0 || lap.said || clock.now().getTime() - lap.startedAt < lap.outlastsMs) return;
    lap.said = true;
    logger.warn('payment_check.lap_behind', { sweep: lap.sweep, organisations: lap.left.length });
  };

  /** The regular turns, then the laps under way, each with its part of the budget. */
  const sweeps = async (n: number, orgs: readonly string[], signal: AbortSignal | undefined): Promise<void> => {
    const regular = n % DAY_EVERY === 0 ? daysLanes : everyRunLanes;
    await regular.run(orgs, partOfBudget(REGULAR_SHARE, signal));
    for (const lap of laps) await lapPart(lap, signal);
  };

  /** A lap's organisations as it begins: its own read's, or the run's; one that can't be read is said, and waits a lap. */
  const lapBegun = async ({ begins }: Lap, orgs: readonly string[]): Promise<readonly string[] | undefined> => {
    if (begins === undefined) return orgs;
    try {
      return await begins();
    } catch (error) {
      logger.error('payment_check.run_failed', { err: error });
      return undefined;
    }
  };

  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.error('payment_check.run_failed', { err: error });
        return;
      }
      beatNow();
      const n = runs;
      runs += 1;
      // The first run after a start is among these, so none waits half an hour for a restart. One still going keeps on.
      for (const lap of n % ALL_EVERY === 0 ? laps.filter(({ left }) => left.length === 0) : []) {
        const begun = await lapBegun(lap, orgs);
        if (begun === undefined) continue;
        lap.left = begun;
        lap.startedAt = clock.now().getTime();
        lap.said = false;
      }
      run = newRun();
      spent = partOfBudget(1, signal);
      gaveUpWaiting = false;
      // Side by side: a hung lookup under a message must never spend the regular turns' budget.
      const finished = await finishedWithinStop(
        Promise.all([checkNudged(), sweeps(n, orgs, signal)]),
        signal,
        stopWaitMs,
      );
      gaveUpWaiting = finished === undefined;
      beatNow();
      if (run.unchanged + run.notFound > 0) {
        logger.info('payment_check.run_unchanged', { unchanged: run.unchanged, notFound: run.notFound });
      }
      // Once a run, not once a payment: the bank down is one thing to say.
      if (run.unreached > 0) {
        logger.warn('payment_check.bank_unavailable', { unreached: run.unreached, stopped: run.endedTurns > 0 });
      }
    },
    beating: () => clock.now().getTime() - beat <= HEARTBEAT_STALE_MS,
  };
}

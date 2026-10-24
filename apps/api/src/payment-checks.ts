// The bank's word on each payment under way (Phase 4 E1a; ADR-007 §10–§13;
// rail map §4; SEC-PTR-02, -09): the API's job, on a timer of its own, asks
// the bank how each handed-off payment stands (`getExecution`, the lookup by
// our instruction ID) and moves its transaction to match. The bank's status
// query is its word: a message from it (E1b) only makes this check sooner, so
// messages early, late, twice or missed change nothing. Nothing is ever sent
// to the bank again (ADR-007 §10).
//
// Each run first takes the partner's messages waiting in the inbox (E1b), and
// checks the payments each names, ahead of their turn; a message is taken once
// the bank answered for each, tried at most 5 runs. Then it takes each
// organisation's transactions still under way (SUBMISSION_PENDING past its
// answer's time, SUBMITTED, PROCESSING, UNKNOWN), oldest first, a page at a
// time: one under 15 minutes old every run, one under a day old every 5th
// run, every one every 30th (the real partner's rate limits), with those paid
// in the last 7 days; none twice in a run. The bank is asked outside any
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
// the bank unreachable → asked again next time (3 in a row end the run: each
// would wait its time limit). One SUBMISSION_PENDING (its run died before Tx B)
// takes both steps in one transaction, each in its history (ADR-007 §13). A
// move its machine doesn't allow (an UNKNOWN said to be under way) keeps the
// bank's facts alone. A payment already settled that the bank now contradicts
// (credited, then Rejected) stays as it is, the facts kept, and an alert raised
// (rail map §4): a paid or failed one (our team's mark among them, E1c) is
// checked every 30th run for 7 days after it was
// handed off. An answer older than the word kept is one already read, and
// changes nothing. An UNKNOWN unresolved past a day is said each time it is
// checked, for reconciliation (E1c).
//
// A run never throws: each failure is logged, naming the organisation and
// transaction, and the run goes on to the next. Its heartbeat is read by
// /health (ADR-013).
import { type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
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
  type TransactionEvent,
  type TransactionsTables,
  type TransactionStatus,
} from '@agentx/core/modules/transactions';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { HEARTBEAT_STALE_MS, PARTNER_CALL_TIMEOUT_MS, PartnerTimedOut, withinTime } from './handoff.ts';
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
 * or failed (our team's mark among them, E1c: a week from the mark, gate H3).
 */
const WATCHED = ['SUCCEEDED', 'FAILED'] as const;

/** How many of the partner's messages a run takes, oldest first: the rest wait for the next. */
const NUDGES_A_RUN = 100;

/** How many unanswered calls in a row end a run: the bank is down, and each would wait its time limit. */
const UNREACHED_IN_A_ROW = 3;

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

/** Which payments a run checks: those under way made since `since` (all where none), and the paid ones or not. */
interface Due {
  readonly since: Date | undefined;
  readonly watchPaid: boolean;
}

/** A run's own count: the bank's unanswered calls (in a row, and in all), checks that failed, and the payments checked. */
interface Run {
  unreached: number;
  inRow: number;
  failed: number;
  readonly seen: Set<string>;
}

/** Where a check found the payment, and left it. */
interface Checked {
  readonly from: TransactionStatus;
  readonly to: TransactionStatus;
}

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
  database,
  rail,
  outbox,
  keys,
  ids,
  clock,
  logger,
  events,
  page = CHECK_PAGE,
  callTimeoutMs = PARTNER_CALL_TIMEOUT_MS,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
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
  /** How many of an organisation's payments are read at once (CHECK_PAGE unless a test names fewer). */
  readonly page?: number;
  /** How long the bank has to answer (PARTNER_CALL_TIMEOUT_MS unless a test names less). */
  readonly callTimeoutMs?: number;
}): PaymentChecks {
  // Refused at start: an answer still on its way to its Tx B must never be read as the bank's silence.
  if (ANSWER_DUE_MS <= callTimeoutMs) {
    throw new RangeError("A payment's answer must be due after the bank's call may take");
  }
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });
  // As the hand-off's: its first beat is its start, then only a run that reads its organisations beats.
  let beat = clock.now().getTime();
  let runs = 0;
  const beatNow = (): void => {
    beat = clock.now().getTime();
  };

  /** A page of the organisation's due payments (`Due`), after `after`, by ID. */
  const underWay = (
    orgId: string,
    after: string | undefined,
    { since, watchPaid }: Due,
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
                where('t.status', 'in', UNDER_WAY),
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

  /**
   * The partner's messages waiting in the inbox, each one's payments checked
   * with the bank now, ahead of their turn, then the message taken once the
   * bank answered for each. False if the signal stopped the run or the bank
   * went unanswered UNREACHED_IN_A_ROW times: the rest wait for the next run.
   */
  const checkNudged = async (run: Run, signal: AbortSignal | undefined): Promise<boolean> => {
    if (events === undefined) return true;
    let nudges: Nudge[];
    try {
      nudges = await events.waiting(database, NUDGES_A_RUN);
    } catch (error) {
      logger.error('payment_check.nudge_failed', { err: error });
      return true;
    }
    for (const nudge of nudges) {
      const log = logger.child({ orgId: nudge.orgId });
      try {
        const tries = await events.tried(database, nudge.id);
        const { unreached, failed } = run;
        for (const payment of await namedBy(nudge, log)) {
          if (signal?.aborted === true || !(await checkCounted(nudge.orgId, payment, run, log))) return false;
        }
        // Taken once the bank answered for every payment it names and each was recorded; else tried again next run,
        // up to MOST_TRIES: then left to the regular check, so it never holds up the messages behind it.
        if (run.unreached === unreached && run.failed === failed) await events.taken(database, nudge.id);
        else if (tries >= MOST_TRIES) log.warn('payment_check.nudge_given_up', { messageId: nudge.id });
      } catch (error) {
        log.error('payment_check.nudge_failed', { err: error });
      }
    }
    return true;
  };

  /** The bank's word on the payment, within its time: unreachable is asked again; anything else it can't give is unreadable. */
  const wordOf = async (orgId: string, listed: Listed, log: Logger): Promise<Word> => {
    try {
      return await withinTime(
        rail.getExecution({ organizationId: orgId, instructionId: listed.instructionId }),
        callTimeoutMs,
      );
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

      /** Where the bank's word takes it. */
      const movedBy = async (): Promise<TransactionStatus> => {
        if (word.kind === 'not_found') return from;
        const found = word.kind === 'found' && answerAbout(word.execution, orgId, locked) ? word.execution : undefined;
        if (found === undefined) {
          if (word.kind === 'found') {
            log.error('payment_check.unreadable', { transactionId: listed.id, why: 'not_this_payment' });
          }
          // Never success on an answer that can't be read (SEC-PTR-09): UNKNOWN, its money held.
          return (await move('lose_track', NO_FACTS, 'bank_unreadable')) ?? from;
        }
        // Older than the word kept (another check's newer answer won the lock): already read, nothing new.
        if (transaction.providerChangedAt !== null && found.statusChangedAt < transaction.providerChangedAt)
          return from;
        const facts = factsOf(found);
        const state = paymentStateOf(found);
        // Said once, as the bank first says it: a check that finds it as it was says nothing more.
        const newly = found.providerStatus !== transaction.providerStatus;
        if (isSettled(from)) {
          await noteTransactionFacts(tx, states, key, facts, { actor: ACTOR, details: { via: 'bank_check' } });
          if (newly && contradicts(from, state)) {
            log.error('payment_check.contradicts', {
              transactionId: listed.id,
              status: from,
              bank: found.providerStatus,
            });
          }
          return from;
        }
        // Rejected with no proof the money stayed: reconciliation's (rail map §4).
        if (state === 'UNKNOWN' && newly) log.error('payment_check.rejected_unproven', { transactionId: listed.id });
        // Its run died before Tx B: both steps here, each in its history (ADR-007 §13).
        const submitted = from === 'SUBMISSION_PENDING' ? await move('submitted', facts, 'bank_check') : null;
        return (await move(AFTER_SUBMITTED[state], facts, 'bank_check')) ?? submitted ?? from;
      };

      const to = await movedBy();
      if (to !== from) {
        await settlePayment(tx, outbox, {
          orgId,
          requestId: locked.instruction.spendRequestId,
          transactionId: listed.id,
          status: to,
          at: clock.now(),
        });
      }
      if (to === 'UNKNOWN' && clock.now().getTime() - transaction.createdAt.getTime() > STILL_UNKNOWN_MS) {
        log.warn('payment_check.still_unknown', { transactionId: listed.id });
      }
      return { from, to };
    });

  /** One payment checked with the bank, its outcome logged; false where the bank couldn't be reached. */
  const check = async (orgId: string, listed: Listed, log: Logger): Promise<'checked' | 'unreached' | 'failed'> => {
    beatNow();
    const word = await wordOf(orgId, listed, log);
    if (word.kind === 'unavailable') return 'unreached';
    try {
      const checked = await applied(orgId, listed, word, log);
      log.info('payment_check.checked', { transactionId: listed.id, answer: word.kind, ...checked });
      return 'checked';
    } catch (error) {
      log.error('payment_check.failed', { transactionId: listed.id, err: error });
      return 'failed';
    }
  };

  /**
   * One payment checked, unless this run checked it already (a message named
   * it), counted in `run`; false once UNREACHED_IN_A_ROW went unanswered.
   */
  const checkCounted = async (orgId: string, payment: Listed, run: Run, log: Logger): Promise<boolean> => {
    if (run.seen.has(payment.id)) return true;
    run.seen.add(payment.id);
    const checked = await check(orgId, payment, log);
    run.inRow = checked === 'unreached' ? run.inRow + 1 : 0;
    if (checked === 'unreached') run.unreached += 1;
    if (checked === 'failed') run.failed += 1;
    return run.inRow < UNREACHED_IN_A_ROW;
  };

  /**
   * The organisation's due payments checked, a page at a time, the bank's
   * unanswered calls counted in `run`; false if the signal stopped the run,
   * or the bank left UNREACHED_IN_A_ROW unanswered.
   */
  const checkAll = async (
    orgId: string,
    due: Due,
    run: Run,
    log: Logger,
    signal: AbortSignal | undefined,
  ): Promise<boolean> => {
    let after: string | undefined;
    for (;;) {
      let listed: Listed[];
      try {
        listed = await underWay(orgId, after, due, log);
      } catch (error) {
        log.error('payment_check.list_failed', { err: error });
        return true;
      }
      for (const payment of listed) {
        if (signal?.aborted === true || !(await checkCounted(orgId, payment, run, log))) return false;
      }
      if (listed.length < page) return true;
      after = listed.at(-1)?.id;
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
      const now = clock.now().getTime();
      // The first run after a start checks every one, so none waits half an hour for a restart.
      const all = n % ALL_EVERY === 0;
      const due = {
        since: all ? undefined : new Date(now - (n % DAY_EVERY === 0 ? DAY_MS : FRESH_MS)),
        watchPaid: all,
      };
      const run: Run = { unreached: 0, inRow: 0, failed: 0, seen: new Set() };
      try {
        if (!(await checkNudged(run, signal))) return;
        for (const orgId of orgs) {
          if (signal?.aborted === true) return;
          if (!(await checkAll(orgId, due, run, logger.child({ orgId }), signal))) return;
        }
        beatNow();
      } finally {
        // Once a run, not once a payment: the bank down is one thing to say.
        if (run.unreached > 0) {
          logger.warn('payment_check.bank_unavailable', {
            unreached: run.unreached,
            stopped: run.inRow >= UNREACHED_IN_A_ROW,
          });
        }
      }
    },
    beating: () => clock.now().getTime() - beat <= HEARTBEAT_STALE_MS,
  };
}

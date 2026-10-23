// The bank's word on each payment under way (Phase 4 E1a; ADR-007 §10–§13;
// rail map §4; SEC-PTR-02, -09): the API's job, on a timer of its own, asks
// the bank how each handed-off payment stands (`getExecution`, the lookup by
// our instruction ID) and moves its transaction to match. The bank's status
// query is its word: a message from it (E1b) only makes this check sooner, so
// messages early, late, twice or missed change nothing. Nothing is ever sent
// to the bank again (ADR-007 §10).
//
// Each run takes each organisation's transactions still under way
// (SUBMISSION_PENDING past its answer's time, SUBMITTED, PROCESSING, UNKNOWN),
// oldest first, a page at a time: one under 15 minutes old every run, one
// under a day old every 5th run, every one every 30th (the real partner's rate
// limits), with those paid in the last 7 days. The bank is asked outside any database transaction; then one
// transaction a payment, in ADR-006 §6's lock order, as Tx B (`lockPayment`:
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
// (rail map §4): a paid one is checked every 30th run for 7 days after it was
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
  type ExecutionLookup,
  type FinancialRailAdapter,
  type PaymentExecution,
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
import {
  AFTER_SUBMITTED,
  factsOf,
  type LockedPayment,
  lockPayment,
  NO_FACTS,
  settlePayment,
} from './payment-outcome.ts';
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

/** How many unanswered calls in a row end a run: the bank is down, and each would wait its time limit. */
const UNREACHED_IN_A_ROW = 3;

/** The API, as the check's actor in the signed events. */
const ACTOR = { type: 'system', id: 'api' } as const;

type CheckTables = VoidTables & InstructionsTables & TransactionsTables & NotificationsTables;

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

/** Whether the bank's answer is about this payment: its organisation, our instruction, its amount and currency. */
const about = (execution: PaymentExecution, orgId: string, { instruction }: LockedPayment): boolean =>
  execution.organizationId.toLowerCase() === orgId.toLowerCase() &&
  execution.instructionId.toLowerCase() === instruction.id &&
  execution.amountMinor === instruction.amountMinor &&
  execution.currency === instruction.currency;

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
              // Paid ones too, every ALL_EVERY runs, for PAID_WATCH_MS: the bank going back on one is said (rail map §4).
              watchPaid
                ? where.and([
                    where('t.status', '=', 'SUCCEEDED'),
                    where('t.created_at', '>=', new Date(clock.now().getTime() - PAID_WATCH_MS)),
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
        const details =
          event === 'fail' && facts.rejectCode === null
            ? // The bank's own word proved no debit with no code: its reference is the evidence (ADR-007 §9).
              { via, evidenceRef: `bank_status:${facts.paymentInstructionRef ?? listed.instructionId}` }
            : { via };
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
        const found = word.kind === 'found' && about(word.execution, orgId, locked) ? word.execution : undefined;
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
  const check = async (orgId: string, listed: Listed, log: Logger): Promise<boolean> => {
    beatNow();
    const word = await wordOf(orgId, listed, log);
    if (word.kind === 'unavailable') return false;
    try {
      const checked = await applied(orgId, listed, word, log);
      log.info('payment_check.checked', { transactionId: listed.id, answer: word.kind, ...checked });
    } catch (error) {
      log.error('payment_check.failed', { transactionId: listed.id, err: error });
    }
    return true;
  };

  /** One payment checked, the bank's unanswered calls counted in `bank`; false once UNREACHED_IN_A_ROW went unanswered. */
  const checkCounted = async (
    orgId: string,
    payment: Listed,
    bank: { unreached: number; inRow: number },
    log: Logger,
  ): Promise<boolean> => {
    const reached = await check(orgId, payment, log);
    bank.inRow = reached ? 0 : bank.inRow + 1;
    if (!reached) bank.unreached += 1;
    return bank.inRow < UNREACHED_IN_A_ROW;
  };

  /**
   * The organisation's due payments checked, a page at a time, the bank's
   * unanswered calls counted in `bank`; false if the signal stopped the run,
   * or the bank left UNREACHED_IN_A_ROW unanswered.
   */
  const checkAll = async (
    orgId: string,
    due: Due,
    bank: { unreached: number; inRow: number },
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
        if (signal?.aborted === true || !(await checkCounted(orgId, payment, bank, log))) return false;
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
      const bank = { unreached: 0, inRow: 0 };
      try {
        for (const orgId of orgs) {
          if (signal?.aborted === true) return;
          if (!(await checkAll(orgId, due, bank, logger.child({ orgId }), signal))) return;
        }
        beatNow();
      } finally {
        // Once a run, not once a payment: the bank down is one thing to say.
        if (bank.unreached > 0) {
          logger.warn('payment_check.bank_unavailable', {
            unreached: bank.unreached,
            stopped: bank.inRow >= UNREACHED_IN_A_ROW,
          });
        }
      }
    },
    beating: () => clock.now().getTime() - beat <= HEARTBEAT_STALE_MS,
  };
}

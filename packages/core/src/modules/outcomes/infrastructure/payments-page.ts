// The organisation's payments as its team reads them (Phase 6 C1): a payment
// is a transaction and the instruction it follows (0058), both read through
// their signed states, so nothing is shown that can't be believed. A page is
// newest first by the transaction's ID (a UUIDv7, so by when it was handed
// off): every payment, or those in some statuses, or the exception list
// (BR-17): every UNKNOWN payment, and every contradicted one. Never the
// payee's reference, the consent or the partner's legal references: a payment
// as listed carries none of them.
//
// Contradicted (S196 decision, revised after review): the verified row's kept
// bank word still contradicts its status (`contradictedNow`) AND the bank
// check raised a `payment.contradicted` alert for the payment, verified in the
// audit log. The word alone isn't enough: a move that keeps no facts (a lost
// track, two admins' mark failed) keeps the bank's word from before, so a
// payment PROCESSING (Pending), then UNKNOWN, then marked FAILED reads Pending
// against FAILED though the bank never went back on anything. The alert is
// raised only for a settled payment and UNKNOWN is reached only from states
// not settled, so every such move into a settled status comes through states
// where no contradiction alert can be; a real contradiction has its alert. It
// still leaves the list by itself once the bank agrees again (the row's word),
// the alert staying in the log.
import { assertTenant } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import {
  type AuditTables,
  checkOf,
  type HistoryToRead,
  MOST_HISTORIES_READ,
  type PageAsked,
  type TamperSign,
  type SignedStates,
  type VerifiedPage,
  verifiedPage,
} from '../../audit/index.ts';
import {
  instructionFrom,
  type InstructionRecord,
  INSTRUCTIONS,
  type InstructionsTables,
} from '../../instructions/index.ts';
import {
  TRANSACTIONS,
  transactionFrom,
  type TransactionRecord,
  type TransactionsTables,
  type TransactionStatus,
} from '../../transactions/index.ts';
import { money, type Money } from '../../../shared-kernel/index.ts';
import { CONTRADICTED_ALERT, CONTRADICTING, contradictedNow, PAYMENT_ALERT_SUBJECT } from './contradiction.ts';

/** The most payments a page holds. */
export const MOST_PAYMENTS_A_PAGE = 50;

/** A payment as its signed transaction and instruction hold it, with what its team is shown of it. */
export interface PaymentRecord {
  readonly transaction: TransactionRecord;
  /** When its transaction's latest move was signed. */
  readonly changedAt: Date;
  readonly spendRequestId: string;
  /** The supplier's details it was handed off to pay. */
  readonly supplierVersionId: string;
  readonly amount: Money;
  /** The rail's payment reference it went with. */
  readonly paymentReference: string;
  /** Settled, the bank's word on it, as its row keeps it, contradicts that, and the bank check said so (S196 decision, revised). */
  readonly contradicted: boolean;
}

/** Which payments a page lists: every one (`statuses` null), those in some statuses, or the exceptions (BR-17). */
export type PaymentsAsked = { readonly statuses: readonly TransactionStatus[] | null } | 'exceptions';

type PaymentsTransaction = Transaction<TransactionsTables & InstructionsTables & AuditTables>;

/** The payment its verified transaction and instruction make; `alerted` from contradictionsOf. */
export function paymentOf(
  transaction: TransactionRecord,
  changedAt: Date,
  instruction: InstructionRecord,
  alerted: ReadonlySet<string>,
): PaymentRecord {
  return {
    transaction,
    changedAt,
    spendRequestId: instruction.spendRequestId,
    supplierVersionId: instruction.supplierVersionId,
    amount: money(instruction.amountMinor, instruction.currency),
    paymentReference: instruction.paymentReference,
    contradicted: alerted.has(transaction.id) && contradictedNow(transaction.status, transaction.providerStatus),
  };
}

/**
 * The IDs of those of these transactions the bank contradicts (S196 decision,
 * revised): their kept word contradicting them (contradictedNow, a few at
 * most), each with the bank check's alert found in the audit log, read through
 * its verified history, newest alone (at most MOST_HISTORIES_READ in a
 * statement). An alert that can't be believed refuses it all (its alarm raised).
 */
export async function contradictionsOf(
  tx: PaymentsTransaction,
  states: SignedStates,
  orgId: string,
  transactions: readonly TransactionRecord[],
): Promise<
  | { readonly outcome: 'read'; readonly alerted: ReadonlySet<string> }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const finds = transactions
    .filter(({ status, providerStatus }) => contradictedNow(status, providerStatus))
    .map(({ id }): HistoryToRead & { readonly subjectId: string } => ({
      subjectTypes: [PAYMENT_ALERT_SUBJECT],
      subjectId: id,
      actions: [CONTRADICTED_ALERT],
      limit: 1,
      newest: true,
    }));
  const alerted = new Set<string>();
  for (let start = 0; start < finds.length; start += MOST_HISTORIES_READ) {
    const part = finds.slice(start, start + MOST_HISTORIES_READ);
    // One statement for the part: each historyOf below answers from it.
    await states.gatherHistories(tx, orgId, part);
    for (const find of part) {
      const history = await states.historyOf(tx, orgId, find);
      if (history.outcome === 'tampered') return history;
      if (history.events.length > 0) alerted.add(find.subjectId);
    }
  }
  return { outcome: 'read', alerted };
}

/**
 * The IDs of the organisation's exceptions after `after`, newest first, at
 * most `limit` + 1, in one statement after the tenant's check: UNKNOWN, or
 * settled with a kept word that contradicts it (CONTRADICTING, made from
 * contradictedNow) and the bank check's alert in the log. The row's own
 * columns and the alert's event only choose them; each row is then verified,
 * and its alert read through the verified log (contradictionsOf).
 */
const exceptionIds = (tx: PaymentsTransaction, orgId: string) => async (after: string | null, limit: number) => {
  await assertTenant(tx, orgId);
  let query = tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- their IDs alone, each then read through its signed state
    .selectFrom(`${TRANSACTIONS.table} as t`)
    .select('t.id')
    .where('t.org_id', '=', orgId)
    .where((row) =>
      row.or([
        row('t.status', '=', 'UNKNOWN'),
        row.and([
          row.or(
            CONTRADICTING.map(([status, words]) =>
              row.and([row('t.status', '=', status), row('t.provider_status', 'in', words)]),
            ),
          ),
          row.exists(
            row
              .selectFrom('audit.events as e')
              .select('e.seq')
              .whereRef('e.org_id', '=', 't.org_id')
              .where('e.subject_type', '=', PAYMENT_ALERT_SUBJECT)
              .whereRef('e.subject_id', '=', 't.id')
              .where('e.action', '=', CONTRADICTED_ALERT),
          ),
        ]),
      ]),
    );
  if (after !== null) query = query.where('t.id', '<', after);
  const rows = await query
    .orderBy('t.id', 'desc')
    .limit(limit + 1)
    .execute();
  return rows.map(({ id }) => id);
};

/** How a page of `which` chooses its rows: the exceptions by their own query, the rest by status, or every one. */
function chosenBy(tx: PaymentsTransaction, orgId: string, which: PaymentsAsked) {
  if (which === 'exceptions') return { ids: exceptionIds(tx, orgId) };
  return which.statuses === null ? {} : { statuses: which.statuses };
}

/**
 * A page of the organisation's payments, newest first, in the caller's
 * transaction, which must be withSignedStates' for it (verifiedPage): the
 * page's transactions verified together, then their instructions, each
 * locked `share` (ADR-006 §6: both at 10, the transaction first, as
 * `lockPayment`). A payment whose instruction can't be checked now (a backlog
 * of events) is left out and named; one tampered with refuses the page (its
 * alarm raised). An instruction a verified transaction names is there (0058's
 * key): one missing is a bug, thrown. Those whose kept word contradicts them
 * have their alerts read too (contradictionsOf). A limit outside 1 to
 * MOST_PAYMENTS_A_PAGE is refused before any SQL runs.
 */
export async function paymentsPage(
  tx: PaymentsTransaction,
  states: SignedStates,
  orgId: string,
  page: PageAsked,
  which: PaymentsAsked,
): Promise<VerifiedPage<PaymentRecord>> {
  return verifiedPage(
    tx,
    states,
    TRANSACTIONS,
    orgId,
    page,
    { most: MOST_PAYMENTS_A_PAGE, rows: 'payments', order: 'newest', ...chosenBy(tx, orgId, which) },
    async (verified) => {
      const transactions = verified.map(({ id, state }) => ({
        transaction: transactionFrom(id, state.fields),
        changedAt: state.recordedAt,
      }));
      const checks = await states.pageStates(
        tx,
        INSTRUCTIONS,
        orgId,
        transactions.map(({ transaction }) => transaction.instructionId),
      );
      const alerts = await contradictionsOf(
        tx,
        states,
        orgId,
        transactions.map(({ transaction }) => transaction),
      );
      if (alerts.outcome === 'tampered') return alerts;
      const items: PaymentRecord[] = [];
      const unchecked: string[] = [];
      for (const { transaction, changedAt } of transactions) {
        const check = checkOf(checks, transaction.instructionId.toLowerCase());
        if (check.outcome === 'tampered') return check;
        if (check.outcome === 'missing') {
          throw new Error(`A verified transaction's instruction is missing: ${transaction.id}`);
        }
        if (check.outcome === 'backlog') unchecked.push(transaction.id);
        else {
          const instruction = instructionFrom(transaction.instructionId, check.fields);
          items.push(paymentOf(transaction, changedAt, instruction, alerts.alerted));
        }
      }
      return { outcome: 'shown', items, unchecked };
    },
  );
}

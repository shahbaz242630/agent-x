// The organisation's payments as its team reads them (Phase 6 C1): a payment
// is a transaction and the instruction it follows (0058), both read through
// their signed states, so nothing is shown that can't be believed. A page is
// newest first by the transaction's ID (a UUIDv7, so by when it was handed
// off): every payment, or those in some statuses, or the exception list
// (BR-17): every UNKNOWN payment, and every settled one the bank's word on its
// row still contradicts (S196 decision, `contradictedNow`), which leaves the
// list by itself once the bank agrees again. Never the payee's reference, the
// consent or the partner's legal references: a payment as listed carries
// none of them.
import type { Transaction } from 'kysely';

import {
  type AuditTables,
  checkOf,
  type PageAsked,
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
import { CONTRADICTING, contradictedNow } from './contradiction.ts';

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
  /** Settled, and the bank's word on it, as its row keeps it, contradicts that (S196 decision). */
  readonly contradicted: boolean;
}

/** Which payments a page lists: every one (`statuses` null), those in some statuses, or the exceptions (BR-17). */
export type PaymentsAsked = { readonly statuses: readonly TransactionStatus[] | null } | 'exceptions';

type PaymentsTransaction = Transaction<TransactionsTables & InstructionsTables & AuditTables>;

/** The payment its verified transaction and instruction make. */
export function paymentOf(
  transaction: TransactionRecord,
  changedAt: Date,
  instruction: InstructionRecord,
): PaymentRecord {
  return {
    transaction,
    changedAt,
    spendRequestId: instruction.spendRequestId,
    supplierVersionId: instruction.supplierVersionId,
    amount: money(instruction.amountMinor, instruction.currency),
    paymentReference: instruction.paymentReference,
    contradicted: contradictedNow(transaction.status, transaction.providerStatus),
  };
}

/**
 * The IDs of the organisation's exceptions after `after`, newest first, at
 * most `limit` + 1, in one statement: UNKNOWN, or settled with a kept word
 * that contradicts it (CONTRADICTING, made from contradictedNow). The row's
 * own columns choose them; each is then verified, and shown by its verified
 * state alone.
 */
const exceptionIds = (tx: PaymentsTransaction, orgId: string) => async (after: string | null, limit: number) => {
  let query = tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- their IDs alone, each then read through its signed state
    .selectFrom(TRANSACTIONS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where((row) =>
      row.or([
        row('status', '=', 'UNKNOWN'),
        ...CONTRADICTING.map(([status, words]) =>
          row.and([row('status', '=', status), row('provider_status', 'in', words)]),
        ),
      ]),
    );
  if (after !== null) query = query.where('id', '<', after);
  const rows = await query
    .orderBy('id', 'desc')
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
 * key): one missing is a bug, thrown. A limit outside 1 to
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
      const items: PaymentRecord[] = [];
      const unchecked: string[] = [];
      for (const { transaction, changedAt } of transactions) {
        const check = checkOf(checks, transaction.instructionId.toLowerCase());
        if (check.outcome === 'tampered') return check;
        if (check.outcome === 'missing') {
          throw new Error(`A verified transaction's instruction is missing: ${transaction.id}`);
        }
        if (check.outcome === 'backlog') unchecked.push(transaction.id);
        else items.push(paymentOf(transaction, changedAt, instructionFrom(transaction.instructionId, check.fields)));
      }
      return { outcome: 'shown', items, unchecked };
    },
  );
}

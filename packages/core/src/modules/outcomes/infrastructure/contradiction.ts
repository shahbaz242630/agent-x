// Whether the bank's word on a settled payment contradicts our status (rail
// map §4; Phase 4 E1a): the one rule the bank check raises its `contradicted`
// alert by (payment-checks.ts), and the one the team's exception list shows a
// payment by while the word its row keeps still contradicts it (Phase 6 C1,
// BR-17; S196 decision), written once.
import { type PaymentState, paymentStateOf, PROVIDER_STATUSES, type ProviderStatus } from '../../providers/index.ts';
import { isSettled, TRANSACTION, type TransactionStatus } from '../../transactions/index.ts';

/** Whether a settled payment's bank state contradicts it: paid and then not, or failed and then paid (rail map §4). */
export const contradicts = (status: TransactionStatus, state: PaymentState): boolean =>
  status === 'SUCCEEDED' || status === 'REVERSED'
    ? state === 'FAILED' || state === 'UNKNOWN'
    : state === 'SUCCEEDED' || state === 'PROCESSING';

const isProviderStatus = (text: string): text is ProviderStatus =>
  (PROVIDER_STATUSES as readonly string[]).includes(text);

/**
 * Whether the bank's word a payment's row keeps (its provider status) still
 * contradicts its status (S196 decision): settled, and that word mapped to its
 * state as the bank check maps it (`paymentStateOf`) contradicting it. The row
 * doesn't keep whether the bank proved no debit, which only splits a
 * `Rejected` between FAILED and UNKNOWN: for every settled status both give
 * the same verdict (SUCCEEDED and REVERSED: both contradict; FAILED and
 * CANCELLED: neither), so it is read as unproven. No word, or one the rail map
 * doesn't name, contradicts nothing. Once the bank agrees again, it no longer does.
 */
export function contradictedNow(status: TransactionStatus, providerStatus: string | null): boolean {
  if (!isSettled(status) || providerStatus === null || !isProviderStatus(providerStatus)) return false;
  return contradicts(status, paymentStateOf({ providerStatus, noDebitProven: false }));
}

/**
 * Each settled status with the kept provider statuses that contradict it, for
 * a query to find them by: made from contradictedNow, never a list of its own.
 */
export const CONTRADICTING: readonly (readonly [TransactionStatus, readonly ProviderStatus[]])[] =
  TRANSACTION.states.flatMap((status) => {
    const words = PROVIDER_STATUSES.filter((word) => contradictedNow(status, word));
    return words.length === 0 ? [] : [[status, words] as const];
  });

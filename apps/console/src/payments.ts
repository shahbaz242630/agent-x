// Payments as the console reads them (6C1): every payment newest first, or
// one group's (GET /v1/payments?status=), the ones to follow up with the bank
// (GET /v1/payments/exceptions, BR-17) and one in full with its history (GET
// /v1/payments/{id}). The shapes are the contract's (payments.ts in the API);
// the console only shows them. A payment whose records can't be checked right
// now is never listed: its ID comes back in `unchecked`, which the page says.
// Marking an UNKNOWN payment failed is two admins' (decision 38): the rules
// for what they type, and the refusals they can meet, are here too.
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';

import { api, isIntegrityFailed, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import { pageQuery } from './requests.ts';
import { t } from './text.ts';

type PaymentStatus =
  'SUBMISSION_PENDING' | 'SUBMITTED' | 'PROCESSING' | 'SUCCEEDED' | 'FAILED' | 'CANCELLED' | 'UNKNOWN' | 'REVERSED';

/** The groups a list may be filtered to, as the API's `status` takes them, in the order the filter offers them. */
export const GROUPS = ['pending', 'paid', 'failed', 'cancelled', 'unknown', 'reversed'] as const;
export type Group = (typeof GROUPS)[number];

export interface ListedPayment {
  readonly id: string;
  readonly spendRequestId: string;
  readonly status: PaymentStatus;
  readonly amountMinor: number;
  readonly currency: string;
  /** The supplier paid, by the name its details carried when the payment was handed off. */
  readonly supplier: { readonly id: string; readonly name: string };
  readonly bankReference: string;
  readonly partnerReference: string | null;
  readonly bankStatus: string | null;
  readonly rejectCode: string | null;
  readonly createdAt: string;
  readonly changedAt: string;
  /** Settled, and the bank's latest word on it says otherwise. */
  readonly contradicted: boolean;
}

/** An admin's proposal to mark a payment failed, waiting for a second admin. */
export interface Proposal {
  readonly id: string;
  readonly paymentId: string;
  readonly evidenceRef: string;
  readonly proposedBy: string;
  readonly status: 'OPEN' | 'WITHDRAWN' | 'CONFIRMED' | 'ENDED';
  readonly proposedAt: string;
}

export interface TimelineEntry {
  readonly at: string;
  /** What happened, as the audit log names it (`transaction.succeed`). */
  readonly what: string;
  readonly status: PaymentStatus | null;
  readonly by: { readonly type: 'user' | 'agent' | 'system'; readonly id: string };
  readonly via: string | null;
  readonly evidenceRef: string | null;
}

export interface PaymentDetails extends ListedPayment {
  /** For an UNKNOWN payment, where marking it failed stands; null for any other. */
  readonly markFailed: { readonly markableFrom: string; readonly openProposal: Proposal | null } | null;
  /** Its newest events, oldest first. */
  readonly timeline: readonly TimelineEntry[];
  /** Whether older events were left out of `timeline`. */
  readonly earlier: boolean;
}

interface Page {
  readonly payments: readonly ListedPayment[];
  readonly next: string | null;
  readonly unchecked: readonly string[];
}

/** Which list: every payment, one group's, or the exceptions. */
export type Which = Group | 'all' | 'exceptions';

/** The list's address: the exceptions' own, or the payments' with the group asked for. */
function pathOf(which: Which, after: string | undefined): string {
  if (which === 'exceptions') return `/v1/payments/exceptions?${pageQuery(after)}`;
  const status = which === 'all' ? '' : `&${new URLSearchParams({ status: which }).toString()}`;
  return `/v1/payments?${pageQuery(after)}${status}`;
}

/** One list of the organisation's payments, a page at a time. */
export function usePaymentList(which: Which, organization: string) {
  return useInfiniteQuery({
    queryKey: ['payments', organization, which],
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last: Page) => last.next ?? undefined,
    queryFn: ({ pageParam }) => api.get<Page>(pathOf(which, pageParam), { organization }),
  });
}

/** One payment in full; asked for only by a UUID, as any other address names no payment (shown as not found). */
export function usePayment(id: string, organization: string) {
  return useQuery({
    queryKey: ['payments', organization, 'one', id],
    enabled: isUuid(id),
    queryFn: () => api.get<PaymentDetails>(`/v1/payments/${encodeURIComponent(id)}`, { organization }),
  });
}

/** The group an address's `?status=` names; every payment for none, or for anything the API doesn't take. */
export function groupIn(search: string): Group | 'all' {
  const asked = new URLSearchParams(search).get('status');
  return GROUPS.find((group) => group === asked) ?? 'all';
}

/** The bank's reference for its written statement, as the API takes it (EVIDENCE_REFERENCE): 3 to 64 of these. */
export const EVIDENCE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._/-]{2,63}$/;
export const EVIDENCE_MOST = 64;

/** The choice each admin's request makes explicit, confirming the `mark_failed` words. */
export const MARK_FAILED_CONFIRMED = 'invoice_can_be_paid_again';

/** The refusals marking a payment failed can meet that the person can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'PAYMENT_NOT_UNKNOWN',
  'PAYMENT_TOO_RECENT',
  'FAILURE_PROPOSAL_OPEN',
  'NO_FAILURE_PROPOSAL',
  'FAILURE_PROPOSAL_TOO_RECENT',
  'FAILURE_PROPOSAL_YOURS',
  'FAILURE_PROPOSAL_GRANTED_BY_PROPOSER',
  'FAILURE_PROPOSAL_CONFIRMER_TOO_NEW',
  'FAILURE_PROPOSAL_ALONE_LOCKED',
  'STEP_UP_NOT_ASKED',
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/** A proposal's own words for a code: what it sent that can be refused is the bank's reference. */
const PROPOSE_WORDS = { BAD_REQUEST: 'payments.refused.badReference' } as const;

/**
 * What a refusal or failure marking a payment failed says: a record that
 * failed the integrity check first (a 503, said as itself); a proposal's
 * BAD_REQUEST is about the bank's reference, any other step's isn't.
 */
export function markRefusal(error: unknown, step: 'propose' | 'approve' | 'withdraw'): string {
  if (isIntegrityFailed(error)) return t('payments.integrity');
  return refusalText(error, REFUSALS, 'payments.refused', step === 'propose' ? PROPOSE_WORDS : {});
}

/**
 * Saves the payment and its history as the API answered them, as a JSON file
 * named by the payment's ID (CO6: the trail downloadable): made in the
 * browser, so nothing more is asked of the API.
 */
export function downloadHistory(payment: PaymentDetails): void {
  const file = new Blob([JSON.stringify(payment, null, 2)], { type: 'application/json' });
  const address = URL.createObjectURL(file);
  const link = document.createElement('a');
  link.href = address;
  link.download = `payment-${payment.id}.json`;
  link.click();
  // Freed once the click has been handled: some browsers (older Safari, Firefox) cancel a download freed at once.
  setTimeout(() => {
    URL.revokeObjectURL(address);
  }, 0);
}

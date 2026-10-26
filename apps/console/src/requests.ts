// Spend requests as the console reads them (6B1): the ones waiting for
// approval (GET /v1/approvals, soonest to expire first), all of them (GET
// /v1/spend-requests, newest first) and one in full (GET
// /v1/spend-requests/{id}). The shapes are the contract's; the console only
// shows them. A request whose records failed Agent X's integrity check is
// never listed: its ID comes back in `unchecked`, which the page says.
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';

import { api } from './api.ts';

export type Status =
  | 'VALIDATING'
  | 'DENIED'
  | 'APPROVAL_REQUIRED'
  | 'APPROVED'
  | 'INSTRUCTION_READY'
  | 'HANDED_OFF'
  | 'EXPIRED'
  | 'CANCELLED';

interface Reason {
  readonly code: string;
  readonly message: string;
}

interface Named {
  readonly id: string;
  readonly name: string;
}

export interface ListedRequest {
  readonly id: string;
  readonly status: Status;
  readonly decision: 'DENY' | 'REQUIRE_NEW_MANDATE' | 'REQUIRE_APPROVAL' | 'ALLOW';
  readonly reasons: readonly Reason[];
  readonly amountMinor: number;
  readonly currency: string;
  readonly agent: Named;
  readonly supplier: Named;
  readonly fundingSourceId: string;
  readonly mandateId: string | null;
  readonly bankReference: string;
  readonly changedAt: string;
  readonly expiresAt: string | null;
  /** The supplier's details changed after it was decided and were verified again: approving re-checks it. */
  readonly needsRecheck: boolean;
}

export interface RequestDetails extends ListedRequest {
  /** The agent's own words: shown as written, never trusted to decide anything. */
  readonly agentWrote: { readonly purpose: string; readonly orderReference: string };
  readonly rejection: { readonly byUserId: string; readonly at: string; readonly reason: string } | null;
  readonly voiding: { readonly at: string; readonly reasons: readonly Reason[] } | null;
}

interface Page {
  readonly requests: readonly ListedRequest[];
  readonly next: string | null;
  readonly unchecked: readonly string[];
}

/** The contract's page size cap: 50 a page. */
const PAGE = 50;

const pageQuery = (after: string | undefined): string =>
  new URLSearchParams({ limit: String(PAGE), ...(after !== undefined && { after }) }).toString();

/** One of the two lists, a page at a time: `waiting` for approval, or `all` the organisation's. */
export function useRequestList(list: 'waiting' | 'all', organization: string) {
  return useInfiniteQuery({
    queryKey: ['requests', organization, list],
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last: Page) => last.next ?? undefined,
    queryFn: async ({ pageParam }): Promise<Page> => {
      const query = pageQuery(pageParam);
      if (list === 'waiting') {
        const { waiting, next, unchecked } = await api.get<{
          readonly waiting: readonly ListedRequest[];
          readonly next: string | null;
          readonly unchecked: readonly string[];
        }>(`/v1/approvals?${query}`, { organization });
        return { requests: waiting, next, unchecked };
      }
      const { spendRequests, next, unchecked } = await api.get<{
        readonly spendRequests: readonly ListedRequest[];
        readonly next: string | null;
        readonly unchecked: readonly string[];
      }>(`/v1/spend-requests?${query}`, { organization });
      return { requests: spendRequests, next, unchecked };
    },
  });
}

export function useRequest(id: string, organization: string) {
  return useQuery({
    queryKey: ['requests', organization, 'one', id],
    queryFn: () => api.get<RequestDetails>(`/v1/spend-requests/${encodeURIComponent(id)}`, { organization }),
  });
}

/** Still before hand-off, so an admin or approver may cancel it (spend-request-cancels.ts). */
export const isCancellable = (status: Status): boolean =>
  status === 'APPROVAL_REQUIRED' || status === 'APPROVED' || status === 'INSTRUCTION_READY';

/** A currency's minor digits as Intl knows them (AED: 2); 2 for a code it doesn't. */
function minorDigits(currency: string): number {
  try {
    return new Intl.NumberFormat('en', { style: 'currency', currency }).resolvedOptions().maximumFractionDigits ?? 2;
  } catch {
    return 2;
  }
}

/**
 * An amount as a statement shows it: `AED 2,500.00`. Built from the whole
 * and minor parts as integers, so no fils is lost to floating point. Amounts
 * are never below zero (the contract's requests are payments out).
 */
export function amountText(amountMinor: number, currency: string): string {
  const digits = minorDigits(currency);
  const scale = 10 ** digits;
  const whole = Math.floor(amountMinor / scale);
  const minor = amountMinor % scale;
  const grouped = new Intl.NumberFormat('en').format(whole);
  const fraction = digits > 0 ? '.' + String(minor).padStart(digits, '0') : '';
  return `${currency} ${grouped}${fraction}`;
}

const AT = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** A time in the browser's own zone. */
export const timeText = (at: string): string => AT.format(new Date(at));

/** How long is left before `at`, in whole hours (minutes under one): `22 h`, `40 min`; none once past. */
export function leftText(
  at: string,
  now: number = Date.now(),
): { readonly hours: number } | { readonly minutes: number } | null {
  const left = new Date(at).getTime() - now;
  if (left <= 0) return null;
  const minutes = Math.floor(left / 60_000);
  return minutes >= 60 ? { hours: Math.floor(minutes / 60) } : { minutes: Math.max(minutes, 1) };
}
